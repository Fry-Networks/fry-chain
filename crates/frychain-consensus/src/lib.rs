//! FryChain Consensus
//!
//! Implements Proof-of-Work consensus using CryptoNight-STC
//! with dynamic difficulty adjustment.

pub mod pow;
pub mod difficulty;
pub mod validation;
pub mod chain;

pub use pow::{mine_block, verify_pow, MiningResult};
pub use difficulty::DifficultyAdjuster;
pub use validation::BlockValidator;
pub use chain::Blockchain;

use thiserror::Error;

/// Consensus errors
#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid proof of work")]
    InvalidProofOfWork,

    #[error("Invalid difficulty")]
    InvalidDifficulty,

    #[error("Invalid parent")]
    InvalidParent,

    #[error("Block too old")]
    BlockTooOld,

    #[error("Block from future")]
    BlockFromFuture,

    #[error("Storage error: {0}")]
    StorageError(#[from] frychain_storage::StorageError),

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Result type for consensus operations
pub type ConsensusResult<T> = Result<T, ConsensusError>;
