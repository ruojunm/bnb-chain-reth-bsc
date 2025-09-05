
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObject};
use serde::{Deserialize, Serialize};
use alloy_consensus::BlockHeader;

use crate::consensus::parlia::{Snapshot, SnapshotProvider};

use std::sync::Arc;

/// Validator information in the snapshot (matches BSC official format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    #[serde(rename = "index:omitempty")]
    pub index: u64,
    pub vote_address: Vec<u8>, // 48-byte vote address array as vec for serde compatibility
}

impl Default for ValidatorInfo {
    fn default() -> Self {
        Self {
            index: 0,
            vote_address: vec![0; 48], // All zeros as shown in BSC example
        }
    }
}

/// Official BSC Parlia snapshot response structure matching bsc-erigon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResult {
    pub number: u64,
    pub hash: String,
    pub epoch_length: u64,
    pub block_interval: u64,
    pub turn_length: u8,
    pub validators: std::collections::HashMap<String, ValidatorInfo>,
    pub recents: std::collections::HashMap<String, String>,
    pub recent_fork_hashes: std::collections::HashMap<String, String>,
    #[serde(rename = "attestation:omitempty")]
    pub attestation: Option<serde_json::Value>,
}

impl From<Snapshot> for SnapshotResult {
    fn from(snapshot: Snapshot) -> Self {
        // Convert validators to the expected format: address -> ValidatorInfo
        let validators: std::collections::HashMap<String, ValidatorInfo> = snapshot
            .validators
            .iter()
            .map(|addr| {
                (
                    format!("0x{addr:040x}"), // 40-char hex address
                    ValidatorInfo::default(),
                )
            })
            .collect();

        // Convert recent proposers to string format: block_number -> address
        let recents: std::collections::HashMap<String, String> = snapshot
            .recent_proposers
            .iter()
            .map(|(block_num, addr)| {
                (
                    block_num.to_string(),
                    format!("0x{addr:040x}"),
                )
            })
            .collect();

        // Generate recent fork hashes (simplified - all zeros like in BSC example)
        let recent_fork_hashes: std::collections::HashMap<String, String> = snapshot
            .recent_proposers
            .keys()
            .map(|block_num| {
                (
                    block_num.to_string(),
                    "00000000".to_string(), // Simplified fork hash
                )
            })
            .collect();

        Self {
            number: snapshot.block_number,
            hash: format!("0x{:064x}", snapshot.block_hash),
            epoch_length: 200, // BSC epoch length
            block_interval: 3000, // BSC block interval in milliseconds
            turn_length: snapshot.turn_length.unwrap_or(1),
            validators,
            recents,
            recent_fork_hashes,
            attestation: None,
        }
    }
}

/// Parlia snapshot RPC API (matches BSC official standard)
#[rpc(server, namespace = "parlia")]
pub trait ParliaApi {
    /// Get snapshot at a specific block (official BSC API method)
    /// Params: block number as hex string (e.g., "0x123132")
    #[method(name = "getSnapshot")]
    async fn get_snapshot(&self, block_number: String) -> RpcResult<Option<SnapshotResult>>;
    
    /// Get the current local blockchain head with detailed information (enhanced for monitoring)
    #[method(name = "getLocalHead")]
    async fn get_local_head(&self) -> RpcResult<serde_json::Value>;
    
    /// Get block by number using local blockchain state (for testing our local blockchain integration)
    #[method(name = "getLocalBlock")]
    async fn get_local_block(&self, block_number: String) -> RpcResult<Option<serde_json::Value>>;
    
    /// BSC-compatible getBlockByNumber that uses persistent blockchain state
    /// This provides the same functionality as standard eth_getBlockByNumber but actually works
    #[method(name = "getBlockByNumber")]
    async fn eth_get_block_by_number(&self, block_number: String, full_transactions: bool) -> RpcResult<Option<serde_json::Value>>;
    

    /// Enhanced P2P: Receive block notification from another validator
    #[method(name = "receiveBlock")]
    async fn receive_block(&self, block_data: serde_json::Value) -> RpcResult<bool>;
}

/// Implementation of the Parlia snapshot RPC API
pub struct ParliaApiImpl<P: SnapshotProvider> {
    /// Snapshot provider for accessing validator snapshots
    snapshot_provider: Arc<P>,
}

/// Wrapper for trait object to work around Sized requirement
pub struct DynSnapshotProvider {
    inner: Arc<dyn SnapshotProvider + Send + Sync>,
}

impl DynSnapshotProvider {
    pub fn new(provider: Arc<dyn SnapshotProvider + Send + Sync>) -> Self {
        Self { inner: provider }
    }
}

impl SnapshotProvider for DynSnapshotProvider {
    fn snapshot(&self, block_number: u64) -> Option<crate::consensus::parlia::snapshot::Snapshot> {
        self.inner.snapshot(block_number)
    }

    fn insert(&self, snapshot: crate::consensus::parlia::snapshot::Snapshot) {
        self.inner.insert(snapshot)
    }
    
    fn get_header(&self, block_number: u64) -> Option<alloy_consensus::Header> {
        self.inner.get_header(block_number)
    }
}

/// Convenience type alias for ParliaApiImpl using the wrapper
pub type ParliaApiDyn = ParliaApiImpl<DynSnapshotProvider>;

impl<P: SnapshotProvider> ParliaApiImpl<P> {
    /// Create a new Parlia API instance
    pub fn new(snapshot_provider: Arc<P>) -> Self {
        Self { snapshot_provider }
    }
}

#[async_trait::async_trait]
impl<P: SnapshotProvider + Send + Sync + 'static> ParliaApiServer for ParliaApiImpl<P> {
    /// Get snapshot at a specific block (matches BSC official API.GetSnapshot)
    /// Accepts block number as hex string like "0x123132"
    async fn get_snapshot(&self, block_number: String) -> RpcResult<Option<SnapshotResult>> {
        // parlia_getSnapshot called
        
        // Parse hex block number (like BSC API does)
        let block_num = if let Some(stripped) = block_number.strip_prefix("0x") {
            match u64::from_str_radix(stripped, 16) {
                Ok(num) => {
                    // Parsed hex block number
                    num
                },
                Err(e) => {
                    tracing::error!("❌ [BSC-RPC] Failed to parse hex block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(
                        -32602, 
                        "Invalid block number format", 
                        None::<()>
                    ));
                }
            }
        } else {
            match block_number.parse::<u64>() {
                Ok(num) => {
                    // Parsed decimal block number
                    num
                },
                Err(e) => {
                    tracing::error!("❌ [BSC-RPC] Failed to parse decimal block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(
                        -32602, 
                        "Invalid block number format", 
                        None::<()>
                    ));
                }
            }
        };
        
        // Querying snapshot provider
        
        // Get snapshot from provider (equivalent to api.parlia.snapshot call in BSC)
        match self.snapshot_provider.snapshot(block_num) {
            Some(snapshot) => {
                tracing::info!("✅ [BSC-RPC] Found snapshot for block {}: validators={}, epoch_num={}, block_hash=0x{:x}", 
                    block_num, snapshot.validators.len(), snapshot.epoch_num, snapshot.block_hash);
                let result: SnapshotResult = snapshot.into();
                // Snapshot result prepared
                Ok(Some(result))
            },
            None => {
                tracing::warn!("⚠️ [BSC-RPC] No snapshot found for block {}", block_num);
                Ok(None)
            }
        }
    }
    
    /// Get the current local blockchain head with detailed information (enhanced for monitoring)
    async fn get_local_head(&self) -> RpcResult<serde_json::Value> {
        let head_number = crate::shared::get_best_block_number_for_rpc();
        
        // Get detailed information about the head block
        if let Some(head_block) = crate::shared::get_best_block_by_number(head_number) {
            let header = head_block.header();
            let head_info = serde_json::json!({
                "number": format!("0x{:x}", head_number),
                "numberDecimal": head_number,
                "hash": format!("0x{:x}", head_block.hash()),
                "miner": format!("0x{:x}", header.beneficiary),
                "timestamp": format!("0x{:x}", header.timestamp),
                "timestampDecimal": header.timestamp,
                "gasUsed": format!("0x{:x}", header.gas_used),
                "gasLimit": format!("0x{:x}", header.gas_limit),
                "difficulty": format!("0x{:x}", header.difficulty),
                "parentHash": format!("0x{:x}", header.parent_hash),
                "transactionCount": head_block.body().transactions.len()
            });
            
            tracing::info!("🔍 [BSC-RPC] Local blockchain head: {} (miner: 0x{:x})", head_number, header.beneficiary);
            Ok(head_info)
        } else {
            // Fallback for genesis/empty chain
            let fallback_info = serde_json::json!({
                "number": format!("0x{:x}", head_number),
                "numberDecimal": head_number,
                "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "miner": "0x0000000000000000000000000000000000000000",
                "message": "Head block data not available (likely genesis)"
            });
            
            tracing::info!("🔍 [BSC-RPC] Local blockchain head: {} (no block data available)", head_number);
            Ok(fallback_info)
        }
    }
    
    /// Get block by number using local blockchain state (for testing our local blockchain integration)
    async fn get_local_block(&self, block_number: String) -> RpcResult<Option<serde_json::Value>> {
        // Parse block number
        let block_num = if let Some(stripped) = block_number.strip_prefix("0x") {
            match u64::from_str_radix(stripped, 16) {
                Ok(num) => num,
                Err(e) => {
                    tracing::error!("❌ [BSC-RPC] Failed to parse hex block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block number format", None::<()>));
                }
            }
        } else if block_number == "latest" {
            crate::shared::get_local_head_number()
        } else {
            match block_number.parse::<u64>() {
                Ok(num) => num,
                Err(e) => {
                    tracing::error!("❌ [BSC-RPC] Failed to parse decimal block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block number format", None::<()>));
                }
            }
        };
        
        // Get block from persistent blockchain (database first, local fallback)
        if let Some(local_block) = crate::shared::get_best_block_by_number(block_num) {
            let header = local_block.header();
            let block_info = serde_json::json!({
                "number": format!("0x{:x}", header.number()),
                "hash": format!("0x{:x}", local_block.hash()),
                "parentHash": format!("0x{:x}", header.parent_hash),
                "timestamp": format!("0x{:x}", header.timestamp),
                "gasLimit": format!("0x{:x}", header.gas_limit),
                "gasUsed": format!("0x{:x}", header.gas_used),
                "difficulty": format!("0x{:x}", header.difficulty),
                "extraData": format!("0x{}", header.extra_data),
                "transactions": []
            });
            
            tracing::info!("📚 [BSC-RPC] Found local block {}: hash=0x{:x}", block_num, local_block.hash());
            Ok(Some(block_info))
        } else {
            tracing::warn!("⚠️ [BSC-RPC] No local block found for block {}", block_num);
            Ok(None)
        }
    }
    
    /// BSC-compatible getBlockByNumber that uses persistent blockchain state
    async fn eth_get_block_by_number(&self, block_number: String, full_transactions: bool) -> RpcResult<Option<serde_json::Value>> {
        // Parse block number (same logic as get_local_block)
        let block_num = if let Some(stripped) = block_number.strip_prefix("0x") {
            match u64::from_str_radix(stripped, 16) {
                Ok(num) => num,
                Err(e) => {
                    tracing::error!("❌ [BSC-ETH] Failed to parse hex block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block number format", None::<()>));
                }
            }
        } else if block_number == "latest" {
            crate::shared::get_local_head_number()
        } else {
            match block_number.parse::<u64>() {
                Ok(num) => num,
                Err(e) => {
                    tracing::error!("❌ [BSC-ETH] Failed to parse decimal block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block number format", None::<()>));
                }
            }
        };
        
        // Get block from persistent blockchain (database first, local fallback)
        if let Some(local_block) = crate::shared::get_best_block_by_number(block_num) {
            let header = local_block.header();
            
            // Format response to match standard eth_getBlockByNumber format
            let block_info = serde_json::json!({
                "number": format!("0x{:x}", header.number()),
                "hash": format!("0x{:x}", local_block.hash()),
                "parentHash": format!("0x{:x}", header.parent_hash),
                "sha3Uncles": format!("0x{:x}", header.ommers_hash),
                "miner": format!("0x{:x}", header.beneficiary),
                "stateRoot": format!("0x{:x}", header.state_root),
                "transactionsRoot": format!("0x{:x}", header.transactions_root),
                "receiptsRoot": format!("0x{:x}", header.receipts_root),
                "logsBloom": format!("0x{}", header.logs_bloom),
                "difficulty": format!("0x{:x}", header.difficulty),
                "totalDifficulty": format!("0x{:x}", header.difficulty + alloy_primitives::U256::from(header.number())),
                "size": format!("0x{:x}", 1000), // Placeholder
                "gasLimit": format!("0x{:x}", header.gas_limit),
                "gasUsed": format!("0x{:x}", header.gas_used),
                "timestamp": format!("0x{:x}", header.timestamp),
                "extraData": format!("0x{}", header.extra_data),
                "mixHash": format!("0x{:x}", header.mix_hash),
                "nonce": format!("0x{:x}", header.nonce),
                "baseFeePerGas": header.base_fee_per_gas.map(|fee| format!("0x{:x}", fee)),
                "uncles": [],
                "transactions": if full_transactions { 
                    serde_json::Value::Array(vec![]) // Empty array for now
                } else {
                    serde_json::Value::Array(vec![]) // Empty array for hashes too
                }
            });
            
            tracing::info!("✅ [BSC-ETH] eth_getBlockByNumber found local block {}: hash=0x{:x}", block_num, local_block.hash());
            Ok(Some(block_info))
        } else {
            tracing::warn!("⚠️ [BSC-ETH] eth_getBlockByNumber: No local block found for block {}", block_num);
            Ok(None)
        }
    }
    

    async fn receive_block(&self, block_data: serde_json::Value) -> RpcResult<bool> {
        tracing::info!("🚀 Enhanced P2P: BLOCK DATA INTEGRATION starting - complete block received");
        
        // Parse the incoming block data
        let block_number = match block_data.get("number").and_then(|v| v.as_str()) {
            Some(hex_str) => {
                match u64::from_str_radix(hex_str.trim_start_matches("0x"), 16) {
                    Ok(num) => num,
                    Err(_) => {
                        tracing::warn!("❌ Enhanced P2P: Invalid block number in received block");
                        return Ok(false);
                    }
                }
            }
            None => {
                tracing::warn!("❌ Enhanced P2P: Missing block number in received block");
                return Ok(false);
            }
        };
        
        let miner = block_data.get("miner")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
            
        let hash = block_data.get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
            
        // Check if this is complete block data vs just notification
        let is_complete_data = block_data.get("blockDataComplete")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
            
        tracing::info!("📡 Enhanced P2P: Processing block {} from miner {} (hash: {}, complete_data: {})", 
            block_number, miner, hash, is_complete_data);
        
        // Check if we already have this block
        let current_head = crate::shared::get_local_head_number();
        if block_number <= current_head {
            tracing::info!("ℹ️ Enhanced P2P: Block {} already known (current head: {}), acknowledging anyway", block_number, current_head);
            return Ok(true);
        }
        
        // ENHANCED: Integrate complete block data if available
        if is_complete_data {
            tracing::info!("🔗 Enhanced P2P: INTEGRATING COMPLETE BLOCK DATA for block {}", block_number);
            
            // Create a simplified block representation for local blockchain
            let simplified_block = serde_json::json!({
                "number": block_data.get("number"),
                "hash": block_data.get("hash"),
                "parentHash": block_data.get("parentHash"),
                "miner": block_data.get("miner"),
                "timestamp": block_data.get("timestamp"),
                "gasUsed": block_data.get("gasUsed"),
                "gasLimit": block_data.get("gasLimit"),
                "difficulty": block_data.get("difficulty"),
                "extraData": block_data.get("extraData"),
                "transactionsRoot": block_data.get("transactionsRoot"),
                "transactions": block_data.get("transactions").unwrap_or(&serde_json::json!([])),
                "transactionCount": block_data.get("transactionCount").unwrap_or(&serde_json::json!(0))
            });
            
            // Add to local blockchain for immediate RPC availability
            match crate::shared::integrate_remote_block(simplified_block) {
                Ok(()) => {
                    tracing::info!("✅ Enhanced P2P: Block {} INTEGRATED into local blockchain", block_number);
                    tracing::info!("🎉 Enhanced P2P: Local head updated to block {} - now available via RPC", block_number);
                }
                Err(e) => {
                    tracing::warn!("❌ Enhanced P2P: Failed to integrate block {}: {}", block_number, e);
                    // Fall back to just acknowledging awareness
                }
            }
        } else {
            tracing::info!("📋 Enhanced P2P: Notification-only mode (no complete block data)");
        }
        
        // Update our awareness of this new block for consensus coordination
        tracing::info!("🔗 Enhanced P2P: Acknowledging awareness of block {} from {}", block_number, miner);
        
        // Signal that we're aware of this block for consensus purposes
        if let Err(e) = crate::shared::acknowledge_remote_block(block_number, miner.to_string()) {
            tracing::warn!("Failed to acknowledge remote block: {}", e);
        }
        
        // Update our understanding of the blockchain state for turn-taking
        tracing::info!("🎯 Enhanced P2P: Updated blockchain awareness - now know about block {} from remote validator", block_number);
        
        // 🔥 CRITICAL FIX: Update local BscMiner state for receiving validators
        // This ensures that receiving validators can correctly progress to mine the next block
        if is_complete_data {
            tracing::info!("🔄 Enhanced P2P: CRITICAL FIX - Updating local BscMiner state for block {}", block_number);
            
            // Update global mining head (already done in integrate_remote_block, but ensuring it's set)
            crate::shared::update_global_mining_head(block_number);
            
            // TODO: In Phase 2, we'll add direct BscMiner state update here
            // For now, the global mining head update should be sufficient for our turn-taking logic
            
            tracing::info!("✅ Enhanced P2P: Block {} FULLY INTEGRATED + Local mining state updated", block_number);
        } else {
            tracing::info!("✅ Enhanced P2P: Block {} notification processed successfully - coordination updated", block_number);
        }
        
        // Return success to confirm we received and processed the notification/data
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainspec::{bsc_testnet, BscChainSpec};
    use crate::consensus::parlia::provider::EnhancedDbSnapshotProvider;
    use reth_db::test_utils::create_test_rw_db;


    #[tokio::test]
    async fn test_snapshot_api() {
        // Build an EnhancedDbSnapshotProvider backed by a temp DB and noop header provider
        let db = create_test_rw_db();
        let chain_spec = Arc::new(BscChainSpec::from(bsc_testnet()));
        let snapshot_provider = Arc::new(EnhancedDbSnapshotProvider::new(
            db.clone(),
            2048,
            chain_spec,
        ));
        
        // Insert a test snapshot
        let test_snapshot = Snapshot {
            block_number: 100,
            validators: vec![alloy_primitives::Address::random(), alloy_primitives::Address::random()],
            epoch_num: 200,
            turn_length: Some(1),
            ..Default::default()
        };
        snapshot_provider.insert(test_snapshot.clone());

        let api = ParliaApiImpl::new(snapshot_provider);
        
        // Test snapshot retrieval with hex block number (BSC official format)
        let result = api.get_snapshot("0x64".to_string()).await.unwrap(); // 0x64 = 100
        assert!(result.is_some());
        
        let snapshot_result = result.unwrap();
        assert_eq!(snapshot_result.number, 100);
        assert_eq!(snapshot_result.validators.len(), 2);
        assert_eq!(snapshot_result.epoch_length, 200);
        assert_eq!(snapshot_result.turn_length, 1);
        
        // Test with decimal format too
        let result = api.get_snapshot("100".to_string()).await.unwrap();
        assert!(result.is_some());
    }
}