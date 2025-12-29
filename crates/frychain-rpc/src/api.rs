//! RPC API implementation

use crate::types::*;
use crate::{RpcError, RpcResult};
use frychain_core::types::BlockHeight;
use std::sync::Arc;

/// RPC API trait
pub trait RpcApi: Send + Sync {
    // Chain methods
    fn chain_id(&self) -> RpcResult<u64>;
    fn network_id(&self) -> RpcResult<u64>;
    fn chain_info(&self) -> RpcResult<RpcChainInfo>;
    fn syncing(&self) -> RpcResult<bool>;
    fn peer_count(&self) -> RpcResult<usize>;

    // Block methods
    fn block_height(&self) -> RpcResult<u64>;
    fn get_block_by_hash(&self, hash: &str, full_tx: bool) -> RpcResult<Option<RpcBlock>>;
    fn get_block_by_height(&self, height: u64, full_tx: bool) -> RpcResult<Option<RpcBlock>>;

    // Transaction methods
    fn get_transaction(&self, hash: &str) -> RpcResult<Option<RpcTransaction>>;
    fn get_receipt(&self, hash: &str) -> RpcResult<Option<RpcReceipt>>;
    fn send_raw_transaction(&self, raw_tx: &str) -> RpcResult<String>;
    fn estimate_gas(&self, call: CallRequest) -> RpcResult<u64>;

    // Account methods
    fn get_balance(&self, address: &str) -> RpcResult<String>;
    fn get_nonce(&self, address: &str) -> RpcResult<u64>;
    fn get_account(&self, address: &str) -> RpcResult<Option<RpcAccount>>;
    fn get_code(&self, address: &str) -> RpcResult<Option<String>>;

    // Mining methods
    fn mining_info(&self) -> RpcResult<RpcMiningInfo>;

    // Utility methods
    fn gas_price(&self) -> RpcResult<String>;
}

/// Mock RPC API for testing
pub struct MockRpcApi {
    chain_id: u64,
    network_id: u64,
}

impl MockRpcApi {
    pub fn new(chain_id: u64, network_id: u64) -> Self {
        Self {
            chain_id,
            network_id,
        }
    }
}

impl RpcApi for MockRpcApi {
    fn chain_id(&self) -> RpcResult<u64> {
        Ok(self.chain_id)
    }

    fn network_id(&self) -> RpcResult<u64> {
        Ok(self.network_id)
    }

    fn chain_info(&self) -> RpcResult<RpcChainInfo> {
        Ok(RpcChainInfo {
            chain_id: self.chain_id,
            network_id: self.network_id,
            chain_name: "FryChain".to_string(),
            best_block_height: 0,
            best_block_hash: "0x".repeat(32),
            total_difficulty: "0".to_string(),
            genesis_hash: "0x".repeat(32),
            syncing: false,
            peer_count: 0,
        })
    }

    fn syncing(&self) -> RpcResult<bool> {
        Ok(false)
    }

    fn peer_count(&self) -> RpcResult<usize> {
        Ok(0)
    }

    fn block_height(&self) -> RpcResult<u64> {
        Ok(0)
    }

    fn get_block_by_hash(&self, _hash: &str, _full_tx: bool) -> RpcResult<Option<RpcBlock>> {
        Ok(None)
    }

    fn get_block_by_height(&self, _height: u64, _full_tx: bool) -> RpcResult<Option<RpcBlock>> {
        Ok(None)
    }

    fn get_transaction(&self, _hash: &str) -> RpcResult<Option<RpcTransaction>> {
        Ok(None)
    }

    fn get_receipt(&self, _hash: &str) -> RpcResult<Option<RpcReceipt>> {
        Ok(None)
    }

    fn send_raw_transaction(&self, _raw_tx: &str) -> RpcResult<String> {
        Err(RpcError::InternalError("Not implemented".to_string()))
    }

    fn estimate_gas(&self, _call: CallRequest) -> RpcResult<u64> {
        Ok(21000)
    }

    fn get_balance(&self, _address: &str) -> RpcResult<String> {
        Ok("0".to_string())
    }

    fn get_nonce(&self, _address: &str) -> RpcResult<u64> {
        Ok(0)
    }

    fn get_account(&self, _address: &str) -> RpcResult<Option<RpcAccount>> {
        Ok(None)
    }

    fn get_code(&self, _address: &str) -> RpcResult<Option<String>> {
        Ok(None)
    }

    fn mining_info(&self) -> RpcResult<RpcMiningInfo> {
        Ok(RpcMiningInfo {
            mining: false,
            hashrate: 0.0,
            difficulty: "0".to_string(),
            miner_address: None,
        })
    }

    fn gas_price(&self) -> RpcResult<String> {
        Ok("1000000000".to_string()) // 1 Gwei
    }
}
