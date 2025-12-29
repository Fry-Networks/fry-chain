//! FryChain Virtual Machine
//!
//! Dual VM supporting both:
//! - Solana-style (SBF/eBPF) smart contracts (Rust compiled)
//! - Algorand-style (AVM/TEAL) smart contracts (stack-based)
//!
//! This provides maximum developer flexibility while maintaining
//! a unified execution environment.

pub mod executor;
pub mod sbf;
pub mod avm;
pub mod types;
pub mod precompiles;
pub mod gas;

pub use executor::{VMExecutor, ExecutionResult};
pub use types::{ContractType, VMError, VMResult};
pub use gas::GasMeter;

use thiserror::Error;

/// VM errors
#[derive(Error, Debug)]
pub enum VMExecutionError {
    #[error("Out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    #[error("Invalid opcode: {0}")]
    InvalidOpcode(u8),

    #[error("Stack overflow")]
    StackOverflow,

    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Invalid memory access at {address}")]
    InvalidMemoryAccess { address: u64 },

    #[error("Invalid contract: {0}")]
    InvalidContract(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Account error: {0}")]
    AccountError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Revert: {0}")]
    Revert(String),

    #[error("Unsupported VM type: {0}")]
    UnsupportedVMType(String),
}
