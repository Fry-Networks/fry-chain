//! FryChain Storage Layer
//!
//! Persistent storage using RocksDB for:
//! - Blocks and block headers
//! - Transactions and receipts
//! - Account state
//! - Contract code and storage

pub mod db;
pub mod chain;
pub mod state;

pub use db::{Database, DatabaseConfig};
pub use chain::ChainStore;
pub use state::StateStore;

use thiserror::Error;

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;
