use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObject};
use serde_json;
use std::str::FromStr;
use alloy_consensus::BlockHeader;

/// Enhanced BSC JSON-RPC API that provides database-backed storage  
/// Provides bsc_* methods and eth_* aliases for our database-backed block access
#[rpc(server, namespace = "bsc")]
pub trait BscEthApi {
    /// Get block by number using database-backed storage
    /// This version uses our persistent blockchain state and actually works!
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(&self, block_number: String, full_transactions: bool) -> RpcResult<Option<serde_json::Value>>;
    
    /// Get the latest block number from database-backed storage
    /// This version uses our persistent blockchain state
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;
    
    /// Get block by hash using database-backed storage
    /// This version uses our persistent blockchain state
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(&self, block_hash: String, full_transactions: bool) -> RpcResult<Option<serde_json::Value>>;
    
    // Note: Now directly providing eth_* methods by overriding the eth namespace
}

/// Implementation of Enhanced Ethereum JSON-RPC API
pub struct EthApiImpl;

impl EthApiImpl {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl BscEthApiServer for EthApiImpl {
    /// Enhanced eth_getBlockByNumber that actually works with our local blockchain
    async fn get_block_by_number(&self, block_number: String, full_transactions: bool) -> RpcResult<Option<serde_json::Value>> {
        tracing::info!("🌐 [ETH-OVERRIDE] eth_getBlockByNumber called: {} (full_tx: {})", block_number, full_transactions);
        
        // Parse block number
        let block_num = if let Some(stripped) = block_number.strip_prefix("0x") {
            match u64::from_str_radix(stripped, 16) {
                Ok(num) => num,
                Err(e) => {
                    tracing::error!("❌ [ETH-OVERRIDE] Failed to parse hex block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block number format", None::<()>).into());
                }
            }
        } else if block_number == "latest" {
            crate::shared::get_best_block_number_for_rpc()
        } else if block_number == "earliest" {
            0
        } else if block_number == "pending" {
            // For pending, return latest
            crate::shared::get_best_block_number_for_rpc()
        } else {
            match block_number.parse::<u64>() {
                Ok(num) => num,
                Err(e) => {
                    tracing::error!("❌ [ETH-OVERRIDE] Failed to parse decimal block number '{}': {}", block_number, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block number format", None::<()>).into());
                }
            }
        };
        
        // Get block from our persistent storage (database first, local fallback)
        if let Some(local_block) = crate::shared::get_best_block_by_number(block_num) {
            let header = local_block.header();
            
            // Format response to match standard eth_getBlockByNumber format
            let block_info = serde_json::json!({
                "number": format!("0x{:x}", header.number()),
                "hash": format!("0x{:x}", local_block.hash()),
                "parentHash": format!("0x{:x}", header.parent_hash),
                "nonce": "0x0000000000000000", // PoA doesn't use nonce
                "sha3Uncles": format!("0x{:x}", header.ommers_hash),
                "logsBloom": format!("0x{}", "0".repeat(512)), // TODO: Implement proper logs bloom
                "transactionsRoot": format!("0x{:x}", header.transactions_root),
                "stateRoot": format!("0x{:x}", header.state_root),
                "receiptsRoot": format!("0x{:x}", header.receipts_root),
                "miner": format!("0x{:x}", header.beneficiary),
                "difficulty": format!("0x{:x}", header.difficulty),
                "totalDifficulty": format!("0x{:x}", header.difficulty + alloy_primitives::U256::from(header.number())),
                "extraData": format!("0x{}", header.extra_data),
                "size": format!("0x{:x}", 1000), // Approximate size
                "gasLimit": format!("0x{:x}", header.gas_limit),
                "gasUsed": format!("0x{:x}", header.gas_used),
                "timestamp": format!("0x{:x}", header.timestamp),
                "transactions": if full_transactions {
                    // TODO: Include full transaction objects
                    serde_json::json!([])
                } else {
                    // Just transaction hashes
                    serde_json::json!(local_block.body().transactions.iter()
                        .map(|tx| format!("0x{:x}", tx.hash()))
                        .collect::<Vec<_>>())
                },
                "uncles": []
            });
            
            tracing::info!("✅ [ETH-OVERRIDE] Found local block {}: hash=0x{:x}, miner=0x{:x}", 
                block_num, local_block.hash(), header.beneficiary);
            Ok(Some(block_info))
        } else {
            tracing::warn!("⚠️ [ETH-OVERRIDE] No local block found for block {}", block_num);
            Ok(None)
        }
    }
    
    /// Enhanced eth_blockNumber that uses our persistent blockchain head
    async fn block_number(&self) -> RpcResult<String> {
        let head_number = crate::shared::get_best_block_number_for_rpc();
        let hex_result = format!("0x{:x}", head_number);
        tracing::info!("🔍 [ETH-OVERRIDE] eth_blockNumber called -> {} ({})", hex_result, head_number);
        Ok(hex_result)
    }
    
    /// Enhanced eth_getBlockByHash that uses our persistent blockchain
    async fn get_block_by_hash(&self, block_hash: String, full_transactions: bool) -> RpcResult<Option<serde_json::Value>> {
        tracing::info!("🌐 [ETH-OVERRIDE] eth_getBlockByHash called: {} (full_tx: {})", block_hash, full_transactions);
        
        // Parse block hash
        let hash = if let Some(stripped) = block_hash.strip_prefix("0x") {
            match alloy_primitives::B256::from_str(stripped) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("❌ [ETH-OVERRIDE] Failed to parse block hash '{}': {}", block_hash, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block hash format", None::<()>).into());
                }
            }
        } else {
            match alloy_primitives::B256::from_str(&block_hash) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("❌ [ETH-OVERRIDE] Failed to parse block hash '{}': {}", block_hash, e);
                    return Err(ErrorObject::owned(-32602, "Invalid block hash format", None::<()>).into());
                }
            }
        };
        
        // Try direct hash lookup first (efficient)
        if let Some(block) = crate::shared::get_best_block_by_hash(&hash) {
            let block_num = block.number();
            tracing::info!("✅ [ETH-OVERRIDE] Found block by hash {} -> block {}", block_hash, block_num);
            return self.get_block_by_number(format!("0x{:x}", block_num), full_transactions).await;
        }
        
        tracing::warn!("⚠️ [ETH-OVERRIDE] No block found for hash {}", block_hash);
        Ok(None)
    }
    
    // ETH NAMESPACE ALIASES - These call our database-backed implementations
    // Note: No need for aliases anymore - we're directly in the eth namespace
}
