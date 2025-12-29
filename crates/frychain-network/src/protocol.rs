//! Network protocol messages

use frychain_core::block::Block;
use frychain_core::transaction::SignedTransaction;
use frychain_core::types::{BlockHeight, Hash256};
use serde::{Deserialize, Serialize};

/// Network message types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    // Handshake
    Hello(HelloMessage),
    HelloAck(HelloAckMessage),

    // Block messages
    NewBlock(Block, Hash256), // Block + PoW hash
    GetBlocks(GetBlocksRequest),
    Blocks(Vec<Block>),
    GetBlockHeaders(GetBlockHeadersRequest),
    BlockHeaders(Vec<frychain_core::block::BlockHeader>),

    // Transaction messages
    NewTransaction(SignedTransaction),
    GetTransactions(Vec<Hash256>),
    Transactions(Vec<SignedTransaction>),

    // Status
    GetStatus,
    Status(StatusMessage),

    // Ping/Pong
    Ping(u64),
    Pong(u64),
}

/// Hello message for handshake
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloMessage {
    pub protocol_version: u32,
    pub network_id: u64,
    pub chain_id: u64,
    pub genesis_hash: Hash256,
    pub best_height: BlockHeight,
    pub best_hash: Hash256,
    pub total_difficulty: u128,
    pub client_version: String,
}

/// Hello acknowledgment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloAckMessage {
    pub accepted: bool,
    pub reason: Option<String>,
}

/// Get blocks request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlocksRequest {
    pub from_height: BlockHeight,
    pub to_height: BlockHeight,
    pub max_blocks: u32,
}

/// Get block headers request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlockHeadersRequest {
    pub from_hash: Hash256,
    pub max_headers: u32,
    pub reverse: bool,
}

/// Status message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusMessage {
    pub best_height: BlockHeight,
    pub best_hash: Hash256,
    pub total_difficulty: u128,
    pub peer_count: usize,
    pub syncing: bool,
}

/// Network protocol handler
pub struct NetworkProtocol {
    pub protocol_version: u32,
    pub network_id: u64,
    pub chain_id: u64,
}

impl NetworkProtocol {
    pub fn new(network_id: u64, chain_id: u64) -> Self {
        Self {
            protocol_version: 1,
            network_id,
            chain_id,
        }
    }

    pub fn create_hello(
        &self,
        genesis_hash: Hash256,
        best_height: BlockHeight,
        best_hash: Hash256,
        total_difficulty: u128,
    ) -> NetworkMessage {
        NetworkMessage::Hello(HelloMessage {
            protocol_version: self.protocol_version,
            network_id: self.network_id,
            chain_id: self.chain_id,
            genesis_hash,
            best_height,
            best_hash,
            total_difficulty,
            client_version: format!("frychain/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    pub fn validate_hello(&self, hello: &HelloMessage) -> Result<(), String> {
        if hello.protocol_version != self.protocol_version {
            return Err(format!(
                "Protocol version mismatch: {} vs {}",
                hello.protocol_version, self.protocol_version
            ));
        }
        if hello.network_id != self.network_id {
            return Err(format!(
                "Network ID mismatch: {} vs {}",
                hello.network_id, self.network_id
            ));
        }
        if hello.chain_id != self.chain_id {
            return Err(format!(
                "Chain ID mismatch: {} vs {}",
                hello.chain_id, self.chain_id
            ));
        }
        Ok(())
    }
}
