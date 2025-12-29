//! RPC types

use frychain_core::address::Address;
use frychain_core::types::{BlockHeight, Gas, GasPrice, Hash256, TokenAmount};
use serde::{Deserialize, Serialize};

/// Block information for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcBlock {
    pub hash: String,
    pub parent_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub miner: String,
    pub difficulty: String,
    pub total_difficulty: String,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub transaction_count: usize,
    pub transactions: Vec<String>,
}

/// Transaction information for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcTransaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: String,
    pub data: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
    pub transaction_index: Option<u32>,
}

/// Transaction receipt for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcReceipt {
    pub transaction_hash: String,
    pub block_hash: String,
    pub block_height: u64,
    pub transaction_index: u32,
    pub from: String,
    pub to: String,
    pub contract_address: Option<String>,
    pub gas_used: u64,
    pub success: bool,
    pub logs: Vec<RpcLog>,
}

/// Log for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_height: u64,
    pub transaction_hash: String,
    pub log_index: u32,
}

/// Account information for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcAccount {
    pub address: String,
    pub balance: String,
    pub nonce: u64,
    pub is_contract: bool,
    pub code_hash: Option<String>,
}

/// Chain info for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcChainInfo {
    pub chain_id: u64,
    pub network_id: u64,
    pub chain_name: String,
    pub best_block_height: u64,
    pub best_block_hash: String,
    pub total_difficulty: String,
    pub genesis_hash: String,
    pub syncing: bool,
    pub peer_count: usize,
}

/// Mining info for RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcMiningInfo {
    pub mining: bool,
    pub hashrate: f64,
    pub difficulty: String,
    pub miner_address: Option<String>,
}

/// Send transaction request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<String>,
    pub data: Option<String>,
    pub nonce: Option<u64>,
}

/// Call request (read-only contract call)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallRequest {
    pub from: Option<String>,
    pub to: String,
    pub value: Option<String>,
    pub gas_limit: Option<u64>,
    pub data: Option<String>,
}
