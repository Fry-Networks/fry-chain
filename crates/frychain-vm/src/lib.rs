//! FryChain Virtual Machine
//!
//! Multi-VM supporting smart contracts from multiple blockchain ecosystems:
//! - Solana-style (SBF/eBPF) smart contracts (Rust compiled)
//! - Algorand-style (AVM/TEAL) smart contracts (stack-based)
//! - Kadena-style (Pact) smart contracts (Lisp-like with formal verification)
//! - Kaspa-style (Script) smart contracts (Bitcoin-like with KIP-1 extensions)
//!
//! This provides maximum developer flexibility while maintaining
//! a unified execution environment, allowing dApps from multiple ecosystems
//! to easily port to FryChain.

pub mod executor;
pub mod sbf;
pub mod avm;
pub mod pact;
pub mod kaspa;
pub mod types;
pub mod precompiles;
pub mod gas;

pub use executor::{VMExecutor, ExecutionResult};
pub use types::{ContractType, VMError, VMResult};
pub use gas::GasMeter;
pub use pact::{compile_pact, PactVM, PactValue};
pub use kaspa::{compile_kaspa_script, create_p2pkh_script, create_p2sh_script, create_multisig_script, KaspaVM};

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

    #[error("Gas error: {0}")]
    GasError(String),
}

impl From<gas::GasError> for VMExecutionError {
    fn from(err: gas::GasError) -> Self {
        match err {
            gas::GasError::OutOfGas { used, limit } => VMExecutionError::OutOfGas { used, limit },
            gas::GasError::Overflow => VMExecutionError::GasError("Gas overflow".to_string()),
        }
    }
}
