//! FryChain JSON-RPC API
//!
//! Provides HTTP and WebSocket JSON-RPC endpoints for:
//! - Blockchain queries
//! - Transaction submission
//! - Account management
//! - Mining information

pub mod api;
pub mod server;
pub mod types;

pub use api::RpcApi;
pub use server::RpcServer;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Invalid params: {0}")]
    InvalidParams(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Block not found")]
    BlockNotFound,

    #[error("Transaction not found")]
    TransactionNotFound,

    #[error("Account not found")]
    AccountNotFound,
}

pub type RpcResult<T> = Result<T, RpcError>;
