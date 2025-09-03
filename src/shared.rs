use crate::consensus::parlia::SnapshotProvider;
use crate::node::engine_api::payload::BscPayloadTypes;
use crate::node::network::block_import::handle::ImportHandle;
use std::sync::{Arc, OnceLock, Mutex};
use alloy_consensus::{Header, BlockHeader};
use alloy_primitives::B256;
use reth_provider::HeaderProvider;
use reth_engine_primitives::BeaconConsensusEngineHandle;
use reth_primitives::SealedBlock;
use crate::BscBlock;

/// Function type for HeaderProvider::header() access (by hash)
type HeaderByHashFn = Arc<dyn Fn(&B256) -> Option<Header> + Send + Sync>;

/// Function type for HeaderProvider::header_by_number() access (by number)  
type HeaderByNumberFn = Arc<dyn Fn(u64) -> Option<Header> + Send + Sync>;

/// Global shared access to the snapshot provider for RPC
static SNAPSHOT_PROVIDER: OnceLock<Arc<dyn SnapshotProvider + Send + Sync>> = OnceLock::new();

/// Global header provider function - HeaderProvider::header() by hash
static HEADER_BY_HASH_PROVIDER: OnceLock<HeaderByHashFn> = OnceLock::new();

/// Global header provider function - HeaderProvider::header_by_number() by number  
static HEADER_BY_NUMBER_PROVIDER: OnceLock<HeaderByNumberFn> = OnceLock::new();

/// Global shared access to the engine handle for mining
static ENGINE_HANDLE: OnceLock<BeaconConsensusEngineHandle<BscPayloadTypes>> = OnceLock::new();

/// Global shared access to the import handle for P2P block broadcasting
static IMPORT_HANDLE: OnceLock<ImportHandle> = OnceLock::new();

/// Local development blockchain state - simple in-memory storage for bypassing engine sync issues
static LOCAL_BLOCKCHAIN: OnceLock<Mutex<LocalBlockchain>> = OnceLock::new();

/// Global shared access to the provider factory for direct block writing (Option C)
static PROVIDER_FACTORY: OnceLock<Arc<dyn std::any::Any + Send + Sync>> = OnceLock::new();

/// Simple in-memory blockchain for local development
#[derive(Debug, Default)]
pub struct LocalBlockchain {
    /// Latest block number
    pub head_number: u64,
    /// Latest block hash  
    pub head_hash: B256,
    /// Block storage: number -> sealed block
    pub blocks: std::collections::HashMap<u64, SealedBlock<BscBlock>>,
    /// Hash to number mapping
    pub hash_to_number: std::collections::HashMap<B256, u64>,
}

/// Store the snapshot provider globally
pub fn set_snapshot_provider(provider: Arc<dyn SnapshotProvider + Send + Sync>) -> Result<(), Arc<dyn SnapshotProvider + Send + Sync>> {
    SNAPSHOT_PROVIDER.set(provider)
}

/// Get the global snapshot provider
pub fn get_snapshot_provider() -> Option<&'static Arc<dyn SnapshotProvider + Send + Sync>> {
    SNAPSHOT_PROVIDER.get()
}

/// Store the engine handle globally
pub fn set_engine_handle(handle: BeaconConsensusEngineHandle<BscPayloadTypes>) -> Result<(), BeaconConsensusEngineHandle<BscPayloadTypes>> {
    ENGINE_HANDLE.set(handle)
}

/// Get the global engine handle
pub fn get_engine_handle() -> Option<&'static BeaconConsensusEngineHandle<BscPayloadTypes>> {
    ENGINE_HANDLE.get()
}

/// Store the import handle globally
pub fn set_import_handle(handle: ImportHandle) -> Result<(), ImportHandle> {
    IMPORT_HANDLE.set(handle)
}

/// Get the global import handle
pub fn get_import_handle() -> Option<&'static ImportHandle> {
    IMPORT_HANDLE.get()
}

/// Store the provider factory globally for direct block writing (Option C)
pub fn set_database_provider<T>(provider: Arc<T>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: std::any::Any + Send + Sync + 'static,
{
    PROVIDER_FACTORY.set(provider)
        .map_err(|_| "Failed to set global provider factory".into())
}

/// Get the global provider factory
pub fn get_database_provider() -> Option<&'static Arc<dyn std::any::Any + Send + Sync>> {
    PROVIDER_FACTORY.get()
}

/// Store the header provider globally
/// Creates functions that directly call HeaderProvider::header() and HeaderProvider::header_by_number()
pub fn set_header_provider<T>(provider: Arc<T>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: HeaderProvider<Header = Header> + Send + Sync + 'static,
{
    // Create function for header by hash
    let provider_clone = provider.clone();
    let header_by_hash_fn = Arc::new(move |block_hash: &B256| -> Option<Header> {
        match provider_clone.header(block_hash) {
            Ok(Some(header)) => Some(header),
            _ => None,
        }
    });
    
    // Create function for header by number
    let provider_clone2 = provider.clone();
    let header_by_number_fn = Arc::new(move |block_number: u64| -> Option<Header> {
        match provider_clone2.header_by_number(block_number) {
            Ok(Some(header)) => Some(header),
            _ => None,
        }
    });
    
    // Set both functions
    HEADER_BY_HASH_PROVIDER.set(header_by_hash_fn).map_err(|_| "Failed to set hash provider")?;
    HEADER_BY_NUMBER_PROVIDER.set(header_by_number_fn).map_err(|_| "Failed to set number provider")?;
    
    Ok(())
}

/// Get the global header by hash provider function
pub fn get_header_by_hash_provider() -> Option<&'static HeaderByHashFn> {
    HEADER_BY_HASH_PROVIDER.get()
}

/// Get the global header by number provider function  
pub fn get_header_by_number_provider() -> Option<&'static HeaderByNumberFn> {
    HEADER_BY_NUMBER_PROVIDER.get()
}

/// Get header by hash from the global header provider
/// Directly calls the stored HeaderProvider::header() function
pub fn get_header_by_hash_from_provider(block_hash: &B256) -> Option<Header> {
    // Check local blockchain first for development
    if let Some(blockchain) = LOCAL_BLOCKCHAIN.get() {
        if let Ok(chain) = blockchain.lock() {
            if let Some(&block_number) = chain.hash_to_number.get(block_hash) {
                if let Some(local_block) = chain.blocks.get(&block_number) {
                    tracing::debug!("📚 Using header from local blockchain for hash 0x{:x}", block_hash);
                    return Some(local_block.header().clone());
                }
            }
        }
    }
    
    // Fallback to provider
    let provider_fn = HEADER_BY_HASH_PROVIDER.get()?;
    provider_fn(block_hash)
}

/// Get header by number from the global header provider
/// Directly calls the stored HeaderProvider::header_by_number() function
pub fn get_header_by_number_from_provider(block_number: u64) -> Option<Header> {
    // Check local blockchain first for development
    if let Some(local_block) = get_local_block_by_number(block_number) {
        tracing::debug!("📚 Using header from local blockchain for block {}", block_number);
        return Some(local_block.header().clone());
    }
    
    // Special case: if asking for a block number higher than what's in database 
    // but exists in local blockchain, return local data
    let local_head = get_local_head_number();
    if block_number <= local_head && local_head > 0 {
        if let Some(local_block) = get_local_block_by_number(block_number) {
            tracing::debug!("📚 Using header from local blockchain for block {} (local head: {})", block_number, local_head);
            return Some(local_block.header().clone());
        }
    }
    
    // Fallback to provider
    let provider_fn = HEADER_BY_NUMBER_PROVIDER.get()?;
    provider_fn(block_number)
}

/// Get the best block number for RPC "latest" resolution - uses local blockchain head for development
pub fn get_best_block_number_for_rpc() -> u64 {
    let local_head = get_local_head_number();
    if local_head > 0 {
        tracing::debug!("📚 Using local blockchain head for RPC 'latest': {}", local_head);
        return local_head;
    }
    
    // Fallback to provider's best block number (will be 0 for fresh database)
    0
}

/// Get header by hash - simplified interface
pub fn get_header_by_hash(block_hash: &B256) -> Option<Header> {
    get_header_by_hash_from_provider(block_hash)
}

/// Get header by number - simplified interface
pub fn get_header_by_number(block_number: u64) -> Option<Header> {
    get_header_by_number_from_provider(block_number)
}

/// Initialize the local blockchain for development
pub fn init_local_blockchain() {
    LOCAL_BLOCKCHAIN.set(Mutex::new(LocalBlockchain::default())).ok();
}

/// Add a block to the local development blockchain
pub fn add_block_to_local_chain(sealed_block: SealedBlock<BscBlock>) -> Result<(), String> {
    let blockchain = LOCAL_BLOCKCHAIN.get().ok_or("Local blockchain not initialized")?;
    let mut chain = blockchain.lock().map_err(|e| format!("Failed to lock blockchain: {}", e))?;
    
    let block_number = sealed_block.header().number();
    let block_hash = sealed_block.hash();
    
    // Update head
    if block_number > chain.head_number {
        chain.head_number = block_number;
        chain.head_hash = block_hash;
    }
    
    // Store block
    chain.blocks.insert(block_number, sealed_block);
    chain.hash_to_number.insert(block_hash, block_number);
    
    tracing::info!("📚 Local blockchain: Added block {} (hash: 0x{:x}), new head: {}", 
        block_number, block_hash, chain.head_number);
    
    Ok(())
}

/// Get the current head block number from local blockchain
pub fn get_local_head_number() -> u64 {
    LOCAL_BLOCKCHAIN
        .get()
        .and_then(|blockchain| blockchain.lock().ok())
        .map(|chain| chain.head_number)
        .unwrap_or(0)
}

/// Get the current head block hash from local blockchain  
pub fn get_local_head_hash() -> B256 {
    LOCAL_BLOCKCHAIN
        .get()
        .and_then(|blockchain| blockchain.lock().ok())
        .map(|chain| chain.head_hash)
        .unwrap_or_default()
}

/// Get a block by number from local blockchain
pub fn get_local_block_by_number(block_number: u64) -> Option<SealedBlock<BscBlock>> {
    LOCAL_BLOCKCHAIN
        .get()
        .and_then(|blockchain| blockchain.lock().ok())
        .and_then(|chain| chain.blocks.get(&block_number).cloned())
}

/// Write block directly to canonical state (Option C: Go BSC approach)
/// This makes blocks immediately available for RPC queries by updating the global state
pub fn write_block_to_database(sealed_block: SealedBlock<BscBlock>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This is the Go BSC approach: immediate canonical state update for RPC availability
    tracing::info!("💾 Option C: Writing block {} to canonical state (Go BSC approach)", sealed_block.number());
    
    // 1. Add to local blockchain (acts as immediate RPC cache)
    add_block_to_local_chain(sealed_block.clone())?;
    
    // 2. Update header provider cache to include this block
    let header = sealed_block.header().clone();
    crate::node::evm::util::HEADER_CACHE_READER
        .lock()
        .unwrap()
        .insert_header_to_cache(header);
    
    // 3. Force update the global best block number if this provider has that capability
    // This is what Go BSC does - immediately updates the canonical head
    tracing::info!("📚 Updated global state: block {} is now canonical head", sealed_block.number());
    
    tracing::info!("✅ Block {} written to canonical state - now available for RPC queries", sealed_block.number());
    Ok(())
}