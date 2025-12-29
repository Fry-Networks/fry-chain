//! Error types for FryChain core

use thiserror::Error;

/// Core error type for FryChain
#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Contract not found: {0}")]
    ContractNotFound(String),

    #[error("Merkle proof verification failed")]
    MerkleProofFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Block height mismatch: expected {expected}, got {got}")]
    BlockHeightMismatch { expected: u64, got: u64 },

    #[error("Invalid parent hash")]
    InvalidParentHash,

    #[error("Difficulty too low")]
    DifficultyTooLow,

    #[error("Invalid proof of work")]
    InvalidProofOfWork,

    #[error("Block too large: {size} bytes, max {max} bytes")]
    BlockTooLarge { size: usize, max: usize },

    #[error("Too many transactions: {count}, max {max}")]
    TooManyTransactions { count: usize, max: usize },

    #[error("Gas limit exceeded: used {used}, limit {limit}")]
    GasLimitExceeded { used: u64, limit: u64 },

    #[error("VM execution error: {0}")]
    VMError(String),

    #[error("DePIN error: {0}")]
    DePINError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for core operations
pub type CoreResult<T> = Result<T, CoreError>;
