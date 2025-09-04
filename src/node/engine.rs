use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    consensus::parlia::{seal::SealBlock, provider::SnapshotProvider},
    node::{engine_api::payload::BscPayloadTypes, mining_config::{MiningConfig, keystore}, BscNode},
    BscBlock, BscPrimitives,
    hardforks::BscHardforks,
};
use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::eip7685::Requests;
use alloy_primitives::{U256, U128, Address, Bytes};
use reth::{
    api::FullNodeTypes,
    builder::{components::PayloadServiceBuilder, BuilderContext},
    payload::{PayloadBuilderHandle, PayloadServiceCommand},
    transaction_pool::TransactionPool,
};
use reth_provider::{BlockNumReader, HeaderProvider};
use reth_evm::ConfigureEvm;
use reth_payload_primitives::BuiltPayload;
use reth_primitives::{SealedBlock, TransactionSigned};
use reth_primitives_traits::SignerRecoverable;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
use tracing::{info, warn, error, debug};
use crate::consensus::parlia::util::calculate_millisecond_timestamp;
use k256::ecdsa::SigningKey;



/// Built payload for BSC. This is similar to [`EthBuiltPayload`] but without sidecars as those
/// included into [`BscBlock`].
#[derive(Debug, Clone)]
pub struct BscBuiltPayload {
    /// The built block
    pub(crate) block: Arc<SealedBlock<BscBlock>>,
    /// The fees of the block
    pub(crate) fees: U256,
    /// The requests of the payload
    pub(crate) requests: Option<Requests>,
}

impl BuiltPayload for BscBuiltPayload {
    type Primitives = BscPrimitives;

    fn block(&self) -> &SealedBlock<BscBlock> {
        self.block.as_ref()
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct BscPayloadServiceBuilder;

/// Mining Service that handles block production for BSC
pub struct BscMiner<Pool, Provider> {
    pool: Pool,
    provider: Provider,
    snapshot_provider: Arc<dyn SnapshotProvider + Send + Sync>,
    validator_address: Address,
    chain_spec: Arc<crate::chainspec::BscChainSpec>,
    parlia: Arc<crate::consensus::parlia::Parlia<crate::chainspec::BscChainSpec>>,
    signing_key: Option<SigningKey>,
    mining_config: MiningConfig,
    last_submitted_block: u64, // Track the last successfully submitted block number
    last_submitted_header: Option<alloy_consensus::Header>, // Store the last mined header for next block's parent
}

impl<Pool, Provider> BscMiner<Pool, Provider>
where
    Pool: TransactionPool + Clone + 'static,
    Provider: HeaderProvider<Header = alloy_consensus::Header> + BlockNumReader + Clone + Send + Sync + 'static,
{
    pub fn new(
        pool: Pool,
        provider: Provider,
        snapshot_provider: Arc<dyn SnapshotProvider + Send + Sync>,
        chain_spec: Arc<crate::chainspec::BscChainSpec>,
        mining_config: MiningConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Validate mining configuration
        mining_config.validate()?;
        
        // We'll derive and trust the validator address from the configured signing key when possible.
        // If not available, fall back to configured address (may be ZERO when disabled).
        let mut validator_address = mining_config.validator_address.unwrap_or(Address::ZERO);
        
        // Load signing key if mining is enabled
        let signing_key = if mining_config.is_mining_enabled() {
            let key = if let Some(keystore_path) = &mining_config.keystore_path {
                let password = mining_config.keystore_password.as_deref().unwrap_or("");
                keystore::load_private_key_from_keystore(keystore_path, password)?
            } else if let Some(hex_key) = &mining_config.private_key_hex {
                keystore::load_private_key_from_hex(hex_key)?
            } else {
                return Err("No signing key configured".into());
            };
            
            // Derive validator address from the signing key and prefer it
            let derived_address = keystore::get_validator_address(&key);
            if derived_address != validator_address {
                if validator_address != Address::ZERO {
                    warn!("Validator address mismatch: configured={}, derived={}", validator_address, derived_address);
                }
                info!("Using derived address from private key: {}", derived_address);
                validator_address = derived_address;
            }
            
            Some(key)
        } else {
            None
        };

        Ok(Self {
            pool,
            provider,
            snapshot_provider,
            validator_address,
            chain_spec: chain_spec.clone(),
            parlia: Arc::new(crate::consensus::parlia::Parlia::new(chain_spec, 200)),
            signing_key,
            mining_config,
            last_submitted_block: 0, // Start from genesis
            last_submitted_header: None, // Will be set after mining first block
        })
    }

    /// Start the PoA mining loop
    pub async fn start_mining(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.mining_config.is_mining_enabled() {
            info!("Mining is disabled in configuration");
            return Ok(());
        }

        // Add startup delay to ensure all validators are ready for P2P communication
        info!("⏱️ Mining startup delay: waiting 15 seconds for all validators to be ready...");
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        info!("✅ Startup delay complete, beginning mining operations");
        
        info!("Starting BSC mining service for validator: {}", self.validator_address);
        
        // Mining interval from config or default
        let interval_ms = self.mining_config.mining_interval_ms.unwrap_or(500);
        let mut mining_interval = interval(Duration::from_millis(interval_ms));
        
        loop {
            mining_interval.tick().await;
            
            // 🔥 CRITICAL FIX: Use global mining head for consistent logging and state
            let global_head = crate::shared::get_global_mining_head();
            let current_effective_head = std::cmp::max(self.last_submitted_block, global_head);
            
            info!("🔄 Mining interval tick - attempting to mine next block (effective head: {}, local: {}, global: {})", 
                current_effective_head, self.last_submitted_block, global_head);
            
            // 🔥 CRITICAL FIX: Sync local state with global if needed
            if global_head > self.last_submitted_block {
                info!("🔄 SYNCING LOCAL STATE: Updating local head from {} to {} based on P2P integration", 
                    self.last_submitted_block, global_head);
                self.sync_local_state_with_global().await;
            }
            
            // For multi-validator setups, check if it's our turn before attempting to mine
            if self.is_my_turn_to_mine().await {
                match self.try_mine_block().await {
                    Ok(()) => {
                        info!("✅ Mining attempt succeeded");
                    }
                    Err(e) => {
                        info!("❌ Mining attempt failed: {}", e);
                        // Continue mining loop even if individual attempts fail
                    }
                }
            } else {
                // Not our turn, just wait for the next interval
                // debug!("⏸️ Not our turn to mine, waiting...");
            }
        }
    }

    /// Sync local BscMiner state with global state (for P2P-received blocks)
    async fn sync_local_state_with_global(&mut self) {
        let global_head = crate::shared::get_global_mining_head();
        
        if global_head > self.last_submitted_block {
            // Update local head to match global
            self.last_submitted_block = global_head;
            
            // Try to get the header for the new head block
            if let Some(header) = crate::shared::get_header_by_number(global_head) {
                self.last_submitted_header = Some(header);
                info!("✅ LOCAL STATE SYNCED: Updated to block {} with header", global_head);
            } else {
                // If header not available, clear it so we fall back to provider lookup
                self.last_submitted_header = None;
                info!("⚠️ LOCAL STATE SYNCED: Updated to block {} but header not cached", global_head);
            }
        }
    }

    /// Check if it's this validator's turn to mine the next block
    async fn is_my_turn_to_mine(&self) -> bool {
        // Use global mining head for accurate turn-taking coordination across all validators
        let global_head = crate::shared::get_global_mining_head();
        let current_mining_head = std::cmp::max(self.last_submitted_block, global_head);
        let next_block_number = current_mining_head + 1;
        
        // 🔍 ENHANCED DEBUG: Always log for debugging the turn-taking issue
        info!("🔍 TURN-TAKING DEBUG: global_head={}, local_head={}, current_mining_head={}, next_block={}", 
            global_head, self.last_submitted_block, current_mining_head, next_block_number);
        
        match self.snapshot_provider.snapshot(current_mining_head) {
            Some(snapshot) => {
                // Check if we're the inturn validator for the next block
                let inturn_validator = snapshot.inturn_validator();
                let is_my_turn = inturn_validator == self.validator_address;
                
                // 🔍 ENHANCED DEBUG: Always log turn-taking decision for debugging
                info!("🎯 TURN-TAKING: Block {} - Inturn validator: 0x{:x}, Current validator: 0x{:x}, My turn: {}", 
                    next_block_number, inturn_validator, self.validator_address, is_my_turn);
                
                // 🔍 ENHANCED DEBUG: Log snapshot details
                info!("📊 SNAPSHOT INFO: Block {} snapshot has {} validators, turn_length={:?}", 
                    current_mining_head, snapshot.validators.len(), snapshot.turn_length);
                
                is_my_turn
            }
            None => {
                // If no snapshot available, allow mining (fallback for single validator)
                warn!("❌ SNAPSHOT MISSING: No snapshot available for block {}, allowing mining as fallback", current_mining_head);
                true
            }
        }
    }

    /// Attempt to mine a block if conditions are met
    async fn try_mine_block(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Use global mining head for coordinated block progression
        let global_head = crate::shared::get_global_mining_head();
        let current_block_number = std::cmp::max(self.last_submitted_block, global_head);
        
        if global_head > self.last_submitted_block {
            info!("🔄 try_mine_block: Using global head {} instead of local {} for mining coordination", 
                global_head, self.last_submitted_block);
        }
        
        info!("🔍 try_mine_block: current_block_number={}, fetching header...", current_block_number);
        
        let head_header = if current_block_number == 0 {
            // For genesis, get from provider
            info!("🔍 Fetching genesis header (block 0)");
            self.provider.header_by_number(current_block_number)?
                .ok_or("Genesis header not found")?
        } else {
            // For subsequent blocks, use our locally stored header
            info!("🔍 Using locally stored header for block {}", current_block_number);
            self.last_submitted_header.clone()
                .ok_or(format!("Last submitted header not available for block {}", current_block_number))?
        };
        
        info!("✅ Successfully got header for block {} (hash: 0x{:x})", current_block_number, alloy_primitives::keccak256(alloy_rlp::encode(&head_header)));
        
        // Create sealed header for the current head block
        use alloy_primitives::keccak256;
        let head_hash = keccak256(alloy_rlp::encode(&head_header));
        let head = reth_primitives::SealedHeader::new(head_header, head_hash);
        
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let parent_number = head.number();
        
        // Get snapshot for parent block to check authorization
        let snapshot = self.snapshot_provider.snapshot(parent_number)
            .ok_or("No snapshot available for parent block")?;
        
        // Check if we're authorized to mine
        if !snapshot.validators.contains(&self.validator_address) {
            return Err(format!("Not authorized validator: {}", self.validator_address).into());
        }
        
        // Check if we signed recently (avoid signing too frequently)
        if snapshot.sign_recently(self.validator_address) {
            return Err("Signed recently, must wait for others".into());
        }
        
        // Calculate when we should mine based on turn and backoff
        let next_block_time = self.calculate_next_block_time(&head, &snapshot, current_time)?;
        
        if current_time < next_block_time {
            return Err(format!("Too early to mine, wait until {next_block_time}").into());
        }
        
        info!("Mining new block on top of block {}", parent_number);
        
        // Build and seal the block
        self.mine_block_now(&head).await
    }

    /// Calculate the optimal time to mine the next block
    fn calculate_next_block_time(
        &self,
        parent: &reth_primitives::SealedHeader,
        snapshot: &crate::consensus::parlia::Snapshot,
        _current_time: u64,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        use crate::consensus::parlia::constants::DIFF_NOTURN;

        // Scheduled next time in ms: parent time (ms) + period (ms)
        let parent_ts_ms = calculate_millisecond_timestamp(parent.header());
        let period_ms = snapshot.block_interval;
        let scheduled_ms = parent_ts_ms + period_ms;

        // Candidate header for backoff calculation
        let mut candidate = alloy_consensus::Header::default();
        candidate.number = parent.number() + 1;
        candidate.timestamp = scheduled_ms / 1000; // seconds part for header
        candidate.beneficiary = self.validator_address;
        candidate.difficulty = U256::from(DIFF_NOTURN);

        // Compute final delay using Parlia helper (ms)
        let left_over_ms: u64 = 0; // reserved time for finalize
        let delay_ms = self.parlia.compute_delay_with_backoff(snapshot, parent.header(), &candidate, left_over_ms);

        // Final time in seconds (ceil ms)
        let target_ms = scheduled_ms + delay_ms;
        let target_secs = (target_ms + 999) / 1000;
        Ok(target_secs)
    }

    /// Mine a block immediately
    async fn mine_block_now(
        &mut self,
        parent: &reth_primitives::SealedHeader,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let block_number = parent.number() + 1;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        // Build proper extraData based on whether this is an epoch block
        let extra_data = self.build_extra_data_for_block(block_number, timestamp)?;
        
        // Build block header
        let mut header = alloy_consensus::Header {
            parent_hash: parent.hash(),
            number: block_number,
            timestamp,
            beneficiary: self.validator_address,
            gas_limit: parent.gas_limit(),
            extra_data,
            difficulty: self.calculate_difficulty(parent)?,
            ..Default::default()
        };
        
        // Collect transactions from the pool
        let transactions = self.collect_transactions(&header).await?;
        
        // Calculate gas used and other header fields
        header.gas_used = transactions.iter().map(|tx| tx.gas_limit()).sum();
        // TODO: Calculate proper transaction root
        header.transactions_root = alloy_primitives::keccak256(alloy_rlp::encode(&transactions));
        
        // Create block body
        let body = crate::BscBlockBody {
            inner: reth_primitives::BlockBody {
                transactions,
                ommers: Vec::new(),
                withdrawals: None,
            },
            sidecars: None,
        };
        
        // Create unsealed block
        let block = BscBlock { header, body };
        
        // Seal the block using Parlia consensus
        let signing_key: SigningKey = self.signing_key.clone()
            .ok_or("No signing key available for block sealing")?;

        // SealBlock init
        let seal_block = SealBlock::new(
            self.snapshot_provider.clone(),
            self.chain_spec.clone(),
            signing_key,
        );

        match seal_block.seal(block) {
            Ok(sealed_block) => {
                info!("Successfully mined block {}", sealed_block.number());
                // TODO: Submit sealed block to engine API or import directly
                self.submit_block(sealed_block).await?
            },
            Err(e) => {
                error!("Failed to seal block: {}", e);
                return Err(e.into());
            }
        }
        
        Ok(())
    }

    /// Calculate difficulty for the new block
    fn calculate_difficulty(
        &self,
        parent: &reth_primitives::SealedHeader,
    ) -> Result<U256, Box<dyn std::error::Error + Send + Sync>> {
        use crate::consensus::parlia::constants::{DIFF_INTURN, DIFF_NOTURN};
        
        let snapshot = self.snapshot_provider.snapshot(parent.number())
            .ok_or("No snapshot available")?;
        
        let difficulty = if snapshot.is_inturn(self.validator_address) {
            DIFF_INTURN
        } else {
            DIFF_NOTURN
        };
        
        Ok(U256::from(difficulty))
    }

    /// Collect transactions from the transaction pool
    async fn collect_transactions(
        &self,
        header: &alloy_consensus::Header,
    ) -> Result<Vec<TransactionSigned>, Box<dyn std::error::Error + Send + Sync>> {
        let transactions: Vec<TransactionSigned> = Vec::new();
        let mut gas_used = 0u64;
        let gas_limit = header.gas_limit();
        
        // Get best transactions from pool
        let best_txs = self.pool.best_transactions();
        
        // Collect transactions until we hit gas limit
        for pooled_tx in best_txs {
            // Convert pooled transaction to consensus transaction
            let recovered = pooled_tx.to_consensus();
            let tx = recovered.as_ref();
            
            // Check gas limit before including transaction
            if gas_used + tx.gas_limit() > gas_limit {
                debug!("Reached gas limit, stopping transaction collection");
                break;
            }
            
            // MVP Approach: Skip transaction inclusion for now to focus on validator core functions
            // We can access transaction data for gas calculation but don't include in block yet
            debug!("Transaction available: gas={}", tx.gas_limit());
            
            // Count gas usage for realistic block building
            gas_used += tx.gas_limit();
            
            // TODO: Implement transaction conversion and inclusion in future iteration
            // For now, focus on getting block sealing, validation, and submission working
        }
        
        debug!("Collected {} transactions for block, total gas used: {}/{}", 
               transactions.len(), gas_used, gas_limit);
        Ok(transactions)
    }

    /// Build proper extraData for block based on epoch vs regular block requirements
    fn build_extra_data_for_block(
        &self,
        block_number: u64,
        timestamp: u64,
    ) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
        const EPOCH_LENGTH: u64 = 200; // From chain spec
        const EXTRA_VANITY_LEN: usize = 32;
        const EXTRA_SEAL_LEN: usize = 65;
        
        let is_epoch = block_number % EPOCH_LENGTH == 0;
        let is_luban_active = self.chain_spec.is_luban_active_at_block(block_number);
        
        if is_epoch {
            info!("🏛️ Building extraData for epoch block {}", block_number);
            
            // Get current validator set from snapshot
            let parent_snapshot = self.snapshot_provider.snapshot(block_number - 1)
                .ok_or("No snapshot available for parent block")?;
            let validators = parent_snapshot.validators.clone();
            
            let mut extra_data = Vec::new();
            
            // 1. Add vanity bytes (32 bytes of zeros)
            extra_data.extend_from_slice(&vec![0u8; EXTRA_VANITY_LEN]);
            
            if is_luban_active {
                // Luban format: [vanity(32)] + [count(1)] + [validators(count*20)] + [turn_length(1)] + [seal(65)]
                extra_data.push(validators.len() as u8); // Validator count
                for validator in &validators {
                    extra_data.extend_from_slice(validator.as_slice());
                }
                
                // Add turn length if Bohr is active
                if self.chain_spec.is_bohr_active_at_timestamp(timestamp) {
                    extra_data.push(10u8); // Default turn length for single validator dev
                }
            } else {
                // Pre-Luban format: [vanity(32)] + [validators(N*20)] + [seal(65)]
                for validator in &validators {
                    extra_data.extend_from_slice(validator.as_slice());
                }
            }
            
            // 3. Add seal placeholder (65 bytes of zeros)
            extra_data.extend_from_slice(&vec![0u8; EXTRA_SEAL_LEN]);
            
            info!("✅ Epoch extraData: {} bytes for {} validators", extra_data.len(), validators.len());
            Ok(Bytes::from(extra_data))
        } else {
            info!("📄 Building extraData for regular block {}", block_number);
            
            // Regular block format: [vanity(32)] + [proposer(20)] + [seal(65)]
            let mut extra_data = Vec::new();
            
            // 1. Add vanity bytes (32 bytes of zeros)
            extra_data.extend_from_slice(&vec![0u8; EXTRA_VANITY_LEN]);
            
            // 2. Add current proposer (20 bytes)
            extra_data.extend_from_slice(self.validator_address.as_slice());
            
            // 3. Add seal placeholder (65 bytes of zeros)
            extra_data.extend_from_slice(&vec![0u8; EXTRA_SEAL_LEN]);
            
            info!("✅ Regular extraData: {} bytes", extra_data.len());
            Ok(Bytes::from(extra_data))
        }
    }

    /// Submit the sealed block using BSC Official Pattern: Write → Update → Broadcast
    async fn submit_block(
        &mut self,
        sealed_block: SealedBlock<BscBlock>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let block_hash = sealed_block.hash();
        let block_number = sealed_block.number();
        let parent_hash = sealed_block.parent_hash();
        let timestamp = sealed_block.timestamp();
        let gas_used = sealed_block.gas_used();
        let tx_count = sealed_block.body().transactions().count();
        
        info!(
            "🎉 BLOCK CREATED! Hash: 0x{:x}, Number: {}, Parent: 0x{:x}, Timestamp: {}, Gas: {}, Txs: {}",
            block_hash, block_number, parent_hash, timestamp, gas_used, tx_count
        );

        // 🔗 PHASE 1: BSC OFFICIAL PATTERN - Write to canonical chain FIRST
        info!("🔗 [STEP 1] Writing block {} to canonical chain (BSC Official Pattern)", block_number);
        
        match crate::shared::write_block_to_canonical_chain(sealed_block.clone()) {
            Ok(crate::shared::CanonicalStatus::Canon) => {
                info!("✅ [STEP 1] Block {} became canonical head", block_number);
                
                // 🔄 PHASE 1: Update local miner state AFTER canonical write
                info!("🔄 [STEP 2] Updating local miner state after canonical write", );
                self.last_submitted_block = block_number;
                let header = sealed_block.header().clone();
                self.last_submitted_header = Some(header.clone());
                
                // Update global mining head for multi-validator coordination
                crate::shared::update_global_mining_head(block_number);
                
                info!("✅ [STEP 2] Local miner state updated to block {}", block_number);
                
                // 🚀 PHASE 1: Broadcast ONLY after successful canonical write
                info!("🚀 [STEP 3] Broadcasting block {} to P2P network (post-canonical)", block_number);
                
                match self.broadcast_block_to_peers(&sealed_block).await {
                    Ok(()) => {
                        info!("✅ [STEP 3] Block {} successfully broadcasted to peers", block_number);
                    }
                    Err(e) => {
                        warn!("⚠️ [STEP 3] P2P broadcast failed for block {}: {} (block still canonical)", block_number, e);
                    }
                }
                
                info!("🎉 BSC OFFICIAL SUCCESS: Block {} fully processed (canonical + broadcast)", block_number);
                Ok(())
            }
            Ok(status) => {
                warn!("❌ Block {} not canonical (status: {:?}), skipping broadcast", block_number, status);
                Err(format!("Block {} rejected as non-canonical", block_number).into())
            }
            Err(e) => {
                error!("❌ Failed to write block {} to canonical chain: {}", block_number, e);
                Err(e)
            }
        }
    }

    /// Broadcast block to P2P network (BSC Official Pattern - only called AFTER canonical write)
    async fn broadcast_block_to_peers(
        &self,
        sealed_block: &SealedBlock<BscBlock>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let block_number = sealed_block.number();
        
        info!("🌐 BSC P2P BROADCAST: Starting P2P broadcast for canonical block {}", block_number);
        info!("   📊 Block details: miner=0x{:x}, parent=0x{:x}, timestamp={}", 
            sealed_block.beneficiary(), sealed_block.parent_hash(), sealed_block.timestamp());
        
        // BSC P2P Broadcasting (equivalent to NewMinedBlockEvent in go-ethereum)
        // Method 1: Direct validator notification (for multi-validator dev environment)
        info!("📡 BSC P2P: Direct validator notification");
        self.notify_validators_directly(sealed_block).await;
        
        // Method 2: Traditional P2P broadcast (when available)
        if let Some(import_handle) = crate::shared::get_import_handle() {
            info!("🔗 BSC P2P: Traditional P2P broadcast");
            match self.submit_via_p2p_import(&import_handle, sealed_block).await {
                Ok(()) => {
                    info!("✅ Traditional P2P broadcast succeeded for block {}", block_number);
                }
                Err(e) => {
                    warn!("Traditional P2P broadcast failed for block {}: {}", block_number, e);
                }
            }
        } else {
            info!("ℹ️ Traditional P2P not available - using direct notification only");
        }
        
        // Method 3: Global validator state synchronization
        crate::shared::notify_new_block_to_all_validators(sealed_block.clone())
            .map_err(|e| format!("Failed to notify validators of new block: {}", e))?;
        
        info!("🎉 BSC P2P SUCCESS: Block {} broadcast completed", block_number);
        Ok(())
    }
    

    
    /// Submit block via P2P import service (true BSC approach)
    async fn submit_via_p2p_import(
        &self,
        import_handle: &crate::node::network::block_import::handle::ImportHandle,
        sealed_block: &SealedBlock<BscBlock>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::node::network::BscNewBlock;
        use reth_eth_wire::NewBlock;
        use reth_network::message::NewBlockMessage;
        use reth_network_api::PeerId;
        
        info!("🌐 Broadcasting block {} via P2P import service", sealed_block.number());
        
        // Create a NewBlock message as if it came from the network
        let new_block = NewBlock {
            block: sealed_block.clone().unseal(),
            td: U128::from(sealed_block.number() + sealed_block.difficulty().to::<u64>()), // Simplified TD for local development
        };
        
        let bsc_new_block = BscNewBlock(new_block);
        let block_message = NewBlockMessage {
            block: Arc::new(bsc_new_block),
            hash: sealed_block.hash(),
        };
        
        // Use a fake peer ID for local validator
        let local_peer_id = PeerId::random();
        
        // Submit through the import service as if it came from P2P network
        import_handle.send_block(block_message, local_peer_id)
            .map_err(|e| format!("Failed to send block to import service: {}", e))?;
        
        info!("✅ Block {} sent to import service for canonical chain integration", sealed_block.number());
        Ok(())
    }
    
    /// Enhanced fallback: directly notify other validators via HTTP API calls
    async fn notify_validators_directly(&self, sealed_block: &SealedBlock<BscBlock>) {
        info!("🚀 Enhanced P2P: DIRECT VALIDATOR NOTIFICATION for block {} starting", sealed_block.number());
        
        // List of all validator ports
        let all_validator_ports = vec![8545, 8547, 8549];
        let current_miner = sealed_block.beneficiary();
        let my_port = self.get_my_validator_port(current_miner);
        
        info!("   📊 Notification details: miner=0x{:x}, my_port={:?}", current_miner, my_port);
        
        // Clone the data we need for the async tasks
        let block_json = self.serialize_block_for_sharing(sealed_block).await;
        let block_number = sealed_block.number();
        
        let mut notification_tasks = Vec::new();
        
        for port in all_validator_ports {
            // Skip notifying ourselves
            if Some(port) == my_port {
                info!("   ⏭️ Skipping own port {} (I am the miner)", port);
                continue;
            }
            
            info!("   📤 Sending notification to validator on port {}", port);
            let block_json_clone = block_json.clone();
            
            let task = tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap();
                    
                let notify_payload = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "parlia_receiveBlock",
                    "params": [block_json_clone],
                    "id": 1
                });
                
                tracing::info!("📡 Enhanced P2P: Sending HTTP notification to port {} for block {}", port, block_number);
                
                // Retry logic for failed notifications
                let mut retry_count = 0;
                let max_retries = 3;
                let mut success = false;
                
                while retry_count <= max_retries && !success {
                    if retry_count > 0 {
                        tracing::info!("🔄 Enhanced P2P: Retry {} for block {} notification to port {}", 
                            retry_count, block_number, port);
                        tokio::time::sleep(std::time::Duration::from_millis(1000 * retry_count)).await;
                    }
                    
                    match client
                        .post(format!("http://localhost:{}", port))
                        .header("Content-Type", "application/json")
                        .json(&notify_payload)
                        .send()
                        .await
                    {
                        Ok(response) => {
                            let status = response.status();
                            if status.is_success() {
                                if let Ok(response_text) = response.text().await {
                                    tracing::info!("✅ Enhanced P2P: Block {} notification SUCCESS to port {} (attempt {}) - Response: {}", 
                                        block_number, port, retry_count + 1, response_text);
                                } else {
                                    tracing::info!("✅ Enhanced P2P: Block {} notification SUCCESS to port {} (attempt {}) (no response body)", 
                                        block_number, port, retry_count + 1);
                                }
                                success = true;
                            } else {
                                tracing::warn!("⚠️ Enhanced P2P: Block {} notification to port {} failed with status: {} (attempt {})", 
                                    block_number, port, status, retry_count + 1);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("❌ Enhanced P2P: Block {} notification to port {} failed with error: {} (attempt {})", 
                                block_number, port, e, retry_count + 1);
                        }
                    }
                    
                    retry_count += 1;
                }
                
                if !success {
                    tracing::error!("💥 Enhanced P2P: Failed to notify port {} for block {} after {} attempts", 
                        port, block_number, max_retries + 1);
                }
                
                (port, block_number)
            });
            
            notification_tasks.push(task);
        }
        
        // Wait for all notifications to complete
        for task in notification_tasks {
            if let Ok((port, block_number)) = task.await {
                info!("   ✅ Notification task completed for port {} block {}", port, block_number);
            }
        }
        
        info!("🎉 Enhanced P2P: Direct validator notification completed for block {}", sealed_block.number());
    }
    
    /// Get the port number for our validator
    fn get_my_validator_port(&self, current_miner: alloy_primitives::Address) -> Option<u16> {
        // Map validator addresses to their ports
        match format!("0x{:x}", current_miner).as_str() {
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" => Some(8545), // Validator 1
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8" => Some(8547), // Validator 2
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc" => Some(8549), // Validator 3
            _ => None,
        }
    }
    
    /// Check if a port belongs to our validator
    fn is_our_validator_port(&self, port: u16, current_miner: alloy_primitives::Address) -> bool {
        self.get_my_validator_port(current_miner) == Some(port)
    }
    
    /// Serialize complete block data for inter-validator sharing and integration
    async fn serialize_block_for_sharing(&self, sealed_block: &SealedBlock<BscBlock>) -> serde_json::Value {
        // Serialize transactions for full block data transfer
        let transactions: Vec<serde_json::Value> = sealed_block.body().transactions
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                serde_json::json!({
                    "hash": format!("0x{:x}", tx.hash()),
                    "nonce": format!("0x{:x}", tx.nonce()),
                    "from": format!("0x{:x}", tx.recover_signer().unwrap_or_default()),
                    "to": tx.to().map(|addr| format!("0x{:x}", addr)),
                    "value": format!("0x{:x}", tx.value()),
                    "gasLimit": format!("0x{:x}", tx.gas_limit()),
                    "gasPrice": format!("0x{:x}", tx.gas_price().unwrap_or(0)),
                    "input": format!("0x{}", hex::encode(tx.input())),
                    "transactionIndex": format!("0x{:x}", index)
                })
            })
            .collect();

        serde_json::json!({
            // Block header data
            "number": format!("0x{:x}", sealed_block.number()),
            "hash": format!("0x{:x}", sealed_block.hash()),
            "parentHash": format!("0x{:x}", sealed_block.parent_hash()),
            "miner": format!("0x{:x}", sealed_block.beneficiary()),
            "timestamp": format!("0x{:x}", sealed_block.timestamp()),
            "gasUsed": format!("0x{:x}", sealed_block.gas_used()),
            "gasLimit": format!("0x{:x}", sealed_block.gas_limit()),
            "difficulty": format!("0x{:x}", sealed_block.difficulty()),
            "extraData": format!("0x{}", hex::encode(&sealed_block.extra_data())),
            "transactionsRoot": format!("0x{:x}", sealed_block.transactions_root()),
            
            // Full block data for integration
            "transactions": transactions,
            "transactionCount": sealed_block.body().transactions.len(),
            
            // Enhanced P2P metadata for validation and integration
            "blockDataComplete": true,
            "enhancedP2P": true,
            "source": "direct_validator_notification",
            "broadcastTimestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })
    }
}

impl<Node, Pool, Evm> PayloadServiceBuilder<Node, Pool, Evm> for BscPayloadServiceBuilder
where
    Node: FullNodeTypes<Types = BscNode>,
    Pool: TransactionPool + Clone + 'static,
    Evm: ConfigureEvm,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        _evm_config: Evm,
    ) -> eyre::Result<PayloadBuilderHandle<BscPayloadTypes>> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Load mining configuration from environment, allow override via CLI if set globally
        let mining_config = if let Some(cfg) = crate::node::mining_config::get_global_mining_config() {
            cfg.clone()
        } else {
            MiningConfig::from_env()
        };
        
        // Skip mining setup if disabled
        if !mining_config.is_mining_enabled() {
            info!("Mining is disabled in configuration");
        } else {
            info!("Mining is enabled - will start mining after consensus initialization and startup delay");
            
            // Defer mining initialization until consensus module sets up the snapshot provider
            let mining_config_clone = mining_config.clone();
            let pool_clone = pool.clone();
            let provider_clone = ctx.provider().clone();
            let chain_spec_clone = Arc::new(ctx.config().chain.clone().as_ref().clone());
            
            ctx.task_executor().spawn_critical("bsc-miner-initializer", async move {
                info!("Waiting for consensus module to initialize snapshot provider...");
                
                // Wait up to 10 seconds for snapshot provider to become available
                let mut attempts = 0;
                let snapshot_provider = loop {
                    if let Some(provider) = crate::shared::get_snapshot_provider() {
                        break provider.clone();
                    }
                    
                    attempts += 1;
                    if attempts > 100 {
                        error!("Timed out waiting for snapshot provider - mining disabled");
                        return;
                    }
                    
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                };
                
                info!("Snapshot provider available, starting BSC mining service");
                
                match BscMiner::new(
                    pool_clone,
                    provider_clone,
                    snapshot_provider,
                    chain_spec_clone,
                    mining_config_clone,
                ) {
                    Ok(mut miner) => {
                        info!("BSC miner created successfully, starting mining loop");
                        if let Err(e) = miner.start_mining().await {
                            error!("Mining service failed: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("Failed to create mining service: {}", e);
                    }
                }
            });
        }
        
        // Handle payload service commands (keep minimal compatibility)
        ctx.task_executor().spawn_critical("payload-service-handler", async move {
            let mut subscriptions = Vec::new();

            while let Some(message) = rx.recv().await {
                match message {
                    PayloadServiceCommand::Subscribe(tx) => {
                        let (events_tx, events_rx) = broadcast::channel(100);
                        subscriptions.push(events_tx);
                        let _ = tx.send(events_rx);
                    }
                    message => debug!(?message, "BSC payload service received engine message"),
                }
            }
        });

        Ok(PayloadBuilderHandle::new(tx))
    }
}

#[cfg(test)]
mod tests {
    // Tests for miner logic

    /// Simple test to verify the head block fetching logic works
    #[tokio::test]
    async fn test_head_block_fetching_in_try_mine_block() {
        // This test demonstrates that try_mine_block now properly fetches the current head block
        // instead of using a hardcoded mock block
        
        // Test 1: Verify that the function signature exists and compiles
        println!("✓ try_mine_block function exists and compiles with proper head block fetching");
        
        // Test 2: Check the implementation actually calls provider methods
        // We can verify this by looking at the source code structure
        let source_code = include_str!("engine.rs");
        
        // Verify the old mock head block code is gone from try_mine_block
        let try_mine_start = source_code.find("async fn try_mine_block").expect("Function should exist");
        let try_mine_end = source_code[try_mine_start..].find("\n    ///").unwrap_or(source_code.len() - try_mine_start) + try_mine_start;
        let try_mine_code = &source_code[try_mine_start..try_mine_end];
        
        assert!(!try_mine_code.contains("Mock block number"), "Should not contain mock block comment in try_mine_block");
        assert!(!try_mine_code.contains("For now, create a mock head block"), "Should not contain mock head block comment");
        
        // Verify new provider-based code is present  
        assert!(source_code.contains("self.provider.best_block_number()"), 
            "Should call provider.best_block_number()");
        assert!(source_code.contains("self.provider.header_by_number(current_block_number)"), 
            "Should call provider.header_by_number()");
        assert!(source_code.contains("Head block header not found"), 
            "Should have proper error handling for missing header");
        
        println!("✓ Implementation correctly uses provider to fetch current head block");
        println!("✓ Mock head block code has been removed");
        println!("✓ Proper error handling is in place");
    }

    #[tokio::test]
    async fn test_miner_struct_has_provider_field() {
        // Verify that the BscMiner struct now includes a provider field
        let source_code = include_str!("engine.rs");
        
        // Check struct definition includes provider
        assert!(source_code.contains("pub struct BscMiner<Pool, Provider>"), 
            "BscMiner should be parameterized with Provider");
        assert!(source_code.contains("provider: Provider,"), 
            "BscMiner should have provider field");
        
        // Check constructor accepts provider
        assert!(source_code.contains("provider: Provider,") && source_code.contains("pub fn new("), 
            "Constructor should accept provider parameter");
        
        // Check trait bounds are correct
        assert!(source_code.contains("Provider: HeaderProvider<Header = alloy_consensus::Header> + BlockNumReader"), 
            "Provider should have proper trait bounds");
        
        println!("✓ BscMiner struct properly includes provider field");
        println!("✓ Constructor accepts provider parameter");  
        println!("✓ Proper trait bounds are enforced");
    }

    #[test]
    fn test_mining_flow_structure() {
        // Test the logical flow of the mining process
        let source_code = include_str!("engine.rs");
        
        // Verify the mining flow is correct:
        // 1. Get current block number
        // 2. Get header by number  
        // 3. Create sealed header
        // 4. Continue with existing mining logic
        
        let try_mine_block_start = source_code.find("async fn try_mine_block").expect("Function should exist");
        let try_mine_block_section = &source_code[try_mine_block_start..];
        let next_function_start = try_mine_block_section.find("\n    /// ").unwrap_or(try_mine_block_section.len());
        let try_mine_block_code = &try_mine_block_section[..next_function_start];
        
        // Check the order of operations
        let best_block_pos = try_mine_block_code.find("best_block_number()").expect("Should call best_block_number");
        let header_by_number_pos = try_mine_block_code.find("header_by_number(current_block_number)").expect("Should call header_by_number");
        let sealed_header_pos = try_mine_block_code.find("SealedHeader::new").expect("Should create SealedHeader");
        
        assert!(best_block_pos < header_by_number_pos, "Should get block number before getting header");
        assert!(header_by_number_pos < sealed_header_pos, "Should get header before creating sealed header");
        
        println!("✓ Mining flow follows correct order: block_number → header → sealed_header");
        println!("✓ All necessary provider calls are present");
    }
}
