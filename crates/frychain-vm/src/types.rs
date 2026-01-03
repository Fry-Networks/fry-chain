//! VM types and common structures

use frychain_core::address::Address;
use frychain_core::types::{Gas, Hash256, TokenAmount};
use serde::{Deserialize, Serialize};

/// Contract type identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractType {
    /// Solana-style SBF/eBPF bytecode
    SBF,
    /// Algorand-style AVM/TEAL bytecode
    AVM,
    /// Kadena-style Pact smart contracts (Lisp-like with formal verification)
    Pact,
    /// Kaspa-style UTXO scripts (Bitcoin-like with KIP-1 extensions)
    Kaspa,
    /// Native precompiled contract
    Native,
}

impl ContractType {
    /// Detect contract type from bytecode magic bytes
    pub fn from_bytecode(bytecode: &[u8]) -> Option<Self> {
        if bytecode.len() < 4 {
            return None;
        }

        // SBF magic: 0x7f 'E' 'L' 'F' (ELF header)
        if bytecode[0..4] == [0x7f, b'E', b'L', b'F'] {
            return Some(ContractType::SBF);
        }

        // Pact magic: "PACT" (0x50, 0x41, 0x43, 0x54)
        if bytecode[0..4] == [0x50, 0x41, 0x43, 0x54] {
            return Some(ContractType::Pact);
        }

        // Kaspa magic: "KASP" (0x4B, 0x41, 0x53, 0x50)
        if bytecode[0..4] == [0x4B, 0x41, 0x53, 0x50] {
            return Some(ContractType::Kaspa);
        }

        // AVM magic: 0x00-0x0A (TEAL version pragma)
        // Check this last since it's a single-byte match
        if bytecode[0] <= 0x0A {
            // TEAL versions 0-10
            return Some(ContractType::AVM);
        }

        None
    }

    /// Get the magic bytes for this contract type
    pub fn magic_bytes(&self) -> &'static [u8] {
        match self {
            ContractType::SBF => &[0x7f, b'E', b'L', b'F'],
            ContractType::AVM => &[0x06], // TEAL v6
            ContractType::Pact => &[0x50, 0x41, 0x43, 0x54], // "PACT"
            ContractType::Kaspa => &[0x4B, 0x41, 0x53, 0x50], // "KASP"
            ContractType::Native => &[0xFF, 0xFF],
        }
    }

    /// Get a human-readable name for this contract type
    pub fn name(&self) -> &'static str {
        match self {
            ContractType::SBF => "Solana SBF/eBPF",
            ContractType::AVM => "Algorand AVM/TEAL",
            ContractType::Pact => "Kadena Pact",
            ContractType::Kaspa => "Kaspa Script",
            ContractType::Native => "Native Precompile",
        }
    }

    /// Get the source ecosystem for this contract type
    pub fn ecosystem(&self) -> &'static str {
        match self {
            ContractType::SBF => "Solana",
            ContractType::AVM => "Algorand",
            ContractType::Pact => "Kadena",
            ContractType::Kaspa => "Kaspa",
            ContractType::Native => "FryChain",
        }
    }
}

/// VM execution result
#[derive(Clone, Debug)]
pub struct VMResult {
    /// Whether execution succeeded
    pub success: bool,
    /// Gas used
    pub gas_used: Gas,
    /// Return data
    pub return_data: Vec<u8>,
    /// Error message if failed
    pub error: Option<String>,
    /// Logs emitted
    pub logs: Vec<VMLog>,
    /// State changes
    pub state_changes: VMStateChanges,
}

impl VMResult {
    /// Create a successful result
    pub fn success(gas_used: Gas, return_data: Vec<u8>) -> Self {
        Self {
            success: true,
            gas_used,
            return_data,
            error: None,
            logs: Vec::new(),
            state_changes: VMStateChanges::default(),
        }
    }

    /// Create a failed result
    pub fn failure(gas_used: Gas, error: String) -> Self {
        Self {
            success: false,
            gas_used,
            return_data: Vec::new(),
            error: Some(error),
            logs: Vec::new(),
            state_changes: VMStateChanges::default(),
        }
    }
}

/// Log emitted during execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VMLog {
    /// Contract that emitted the log
    pub address: Address,
    /// Indexed topics
    pub topics: Vec<Hash256>,
    /// Log data
    pub data: Vec<u8>,
}

/// State changes from VM execution
#[derive(Clone, Debug, Default)]
pub struct VMStateChanges {
    /// Balance changes (address, delta - positive for increase, negative for decrease)
    pub balance_changes: Vec<(Address, i128)>,
    /// Storage writes (contract, key, value)
    pub storage_writes: Vec<(Address, Hash256, Hash256)>,
    /// New contracts created
    pub created_contracts: Vec<(Address, Vec<u8>)>,
    /// Deleted contracts
    pub deleted_contracts: Vec<Address>,
}

/// Execution context passed to VM
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    /// Caller address
    pub caller: Address,
    /// Contract address being called
    pub address: Address,
    /// Value being transferred
    pub value: TokenAmount,
    /// Gas limit
    pub gas_limit: Gas,
    /// Call depth (for nested calls)
    pub depth: u32,
    /// Is this a static call (read-only)
    pub is_static: bool,
    /// Block height
    pub block_height: u64,
    /// Block timestamp
    pub block_timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(
        caller: Address,
        address: Address,
        value: TokenAmount,
        gas_limit: Gas,
    ) -> Self {
        Self {
            caller,
            address,
            value,
            gas_limit,
            depth: 0,
            is_static: false,
            block_height: 0,
            block_timestamp: 0,
            chain_id: 1,
        }
    }

    /// Create a child context for nested calls
    pub fn child(&self, address: Address, value: TokenAmount, gas_limit: Gas) -> Self {
        Self {
            caller: self.address,
            address,
            value,
            gas_limit,
            depth: self.depth + 1,
            is_static: self.is_static,
            block_height: self.block_height,
            block_timestamp: self.block_timestamp,
            chain_id: self.chain_id,
        }
    }

    /// Check if max call depth exceeded
    pub fn is_depth_exceeded(&self) -> bool {
        self.depth > 1024
    }
}

/// VM error type
pub type VMError = crate::VMExecutionError;
