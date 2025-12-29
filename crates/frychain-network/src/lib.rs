//! FryChain P2P Networking
//!
//! Implements libp2p-based peer-to-peer networking for:
//! - Block propagation
//! - Transaction gossip
//! - Peer discovery
//! - Chain synchronization

pub mod protocol;
pub mod peer;
pub mod sync;

pub use protocol::{NetworkMessage, NetworkProtocol};
pub use peer::{PeerManager, PeerInfo};

use thiserror::Error;

/// Network errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type NetworkResult<T> = Result<T, NetworkError>;
