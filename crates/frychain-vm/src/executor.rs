//! Unified VM executor
//!
//! Supports multiple VM backends:
//! - SBF/eBPF (Solana-style) - Rust compiled to BPF
//! - AVM/TEAL (Algorand-style) - Stack-based assembly
//! - Pact (Kadena-style) - Lisp-like with formal verification
//! - Kaspa Script (Kaspa-style) - Bitcoin-like with KIP-1 extensions

use crate::avm::AVMInterpreter;
use crate::kaspa::KaspaVM;
use crate::pact::PactVM;
use crate::sbf::SbfVM;
use crate::types::{ContractType, ExecutionContext, VMResult};
use crate::VMExecutionError;
use frychain_core::address::Address;
use frychain_core::state::AccountState;
use frychain_core::types::{Gas, Hash256, TokenAmount};

/// Execution result with detailed information
#[derive(Clone, Debug)]
pub struct ExecutionResult {
    /// Success status
    pub success: bool,
    /// Gas used
    pub gas_used: Gas,
    /// Return data
    pub return_data: Vec<u8>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Created contract address (if deployment)
    pub contract_address: Option<Address>,
    /// Logs emitted
    pub logs: Vec<crate::types::VMLog>,
}

/// Unified VM executor that handles both SBF and AVM contracts
pub struct VMExecutor {
    /// Max call depth
    max_depth: u32,
}

impl VMExecutor {
    /// Create a new VM executor
    pub fn new() -> Self {
        Self { max_depth: 1024 }
    }

    /// Execute a contract call
    pub fn execute(
        &self,
        bytecode: &[u8],
        input: &[u8],
        context: ExecutionContext,
        state: &AccountState,
    ) -> ExecutionResult {
        // Check depth
        if context.depth > self.max_depth {
            return ExecutionResult {
                success: false,
                gas_used: Gas(0),
                return_data: Vec::new(),
                error: Some("Max call depth exceeded".to_string()),
                contract_address: None,
                logs: Vec::new(),
            };
        }

        // Detect contract type
        let contract_type = match ContractType::from_bytecode(bytecode) {
            Some(t) => t,
            None => {
                return ExecutionResult {
                    success: false,
                    gas_used: Gas(0),
                    return_data: Vec::new(),
                    error: Some("Unknown contract type".to_string()),
                    contract_address: None,
                    logs: Vec::new(),
                };
            }
        };

        // Execute based on type
        let vm_result = match contract_type {
            ContractType::SBF => self.execute_sbf(bytecode, input, context),
            ContractType::AVM => self.execute_avm(bytecode, input, context),
            ContractType::Pact => self.execute_pact(bytecode, input, context),
            ContractType::Kaspa => self.execute_kaspa(bytecode, input, context),
            ContractType::Native => {
                return ExecutionResult {
                    success: false,
                    gas_used: Gas(0),
                    return_data: Vec::new(),
                    error: Some("Native contracts not yet implemented".to_string()),
                    contract_address: None,
                    logs: Vec::new(),
                };
            }
        };

        ExecutionResult {
            success: vm_result.success,
            gas_used: vm_result.gas_used,
            return_data: vm_result.return_data,
            error: vm_result.error,
            contract_address: None,
            logs: vm_result.logs,
        }
    }

    /// Execute an SBF (Solana-style) contract
    fn execute_sbf(
        &self,
        bytecode: &[u8],
        _input: &[u8],
        context: ExecutionContext,
    ) -> VMResult {
        match SbfVM::new(bytecode, context) {
            Ok(mut vm) => vm.execute(),
            Err(e) => VMResult::failure(Gas(0), e.to_string()),
        }
    }

    /// Execute an AVM (Algorand-style) contract
    fn execute_avm(
        &self,
        bytecode: &[u8],
        _input: &[u8],
        context: ExecutionContext,
    ) -> VMResult {
        let mut vm = AVMInterpreter::new(bytecode.to_vec(), context);
        vm.execute()
    }

    /// Execute a Pact (Kadena-style) contract
    fn execute_pact(
        &self,
        bytecode: &[u8],
        input: &[u8],
        context: ExecutionContext,
    ) -> VMResult {
        let mut vm = PactVM::new(context);
        vm.execute(bytecode, input)
    }

    /// Execute a Kaspa Script contract
    fn execute_kaspa(
        &self,
        bytecode: &[u8],
        input: &[u8],
        context: ExecutionContext,
    ) -> VMResult {
        let mut vm = KaspaVM::new(context);
        vm.execute(bytecode, input)
    }

    /// Deploy a new contract
    pub fn deploy(
        &self,
        bytecode: &[u8],
        creator: Address,
        nonce: u64,
        value: TokenAmount,
        gas_limit: Gas,
    ) -> ExecutionResult {
        // Validate bytecode
        let contract_type = match ContractType::from_bytecode(bytecode) {
            Some(t) => t,
            None => {
                return ExecutionResult {
                    success: false,
                    gas_used: Gas(0),
                    return_data: Vec::new(),
                    error: Some("Unknown contract type".to_string()),
                    contract_address: None,
                    logs: Vec::new(),
                };
            }
        };

        // Calculate contract address
        let contract_address = Address::contract_address(&creator, nonce);

        // Create deployment context
        let context = ExecutionContext::new(creator, contract_address, value, gas_limit);

        // For deployment, we run the constructor/init code
        let vm_result = match contract_type {
            ContractType::SBF => self.execute_sbf(bytecode, &[], context),
            ContractType::AVM => self.execute_avm(bytecode, &[], context),
            ContractType::Pact => self.execute_pact(bytecode, &[], context),
            ContractType::Kaspa => self.execute_kaspa(bytecode, &[], context),
            ContractType::Native => {
                return ExecutionResult {
                    success: false,
                    gas_used: Gas(0),
                    return_data: Vec::new(),
                    error: Some("Cannot deploy native contracts".to_string()),
                    contract_address: None,
                    logs: Vec::new(),
                };
            }
        };

        ExecutionResult {
            success: vm_result.success,
            gas_used: vm_result.gas_used,
            return_data: vm_result.return_data,
            error: vm_result.error,
            contract_address: if vm_result.success {
                Some(contract_address)
            } else {
                None
            },
            logs: vm_result.logs,
        }
    }

    /// Estimate gas for a call
    pub fn estimate_gas(
        &self,
        bytecode: &[u8],
        input: &[u8],
        context: ExecutionContext,
        state: &AccountState,
    ) -> Gas {
        // Run with high gas limit
        let mut estimate_context = context;
        estimate_context.gas_limit = Gas::new(100_000_000);

        let result = self.execute(bytecode, input, estimate_context, state);

        // Add 10% buffer
        Gas::new((result.gas_used.0 as f64 * 1.1) as u64)
    }
}

impl Default for VMExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::state::AccountState;

    #[test]
    fn test_detect_avm_contract() {
        let bytecode = vec![6u8, 0x20, 1, 1, 0x22, 0, 0x43]; // TEAL v6
        let contract_type = ContractType::from_bytecode(&bytecode);
        assert_eq!(contract_type, Some(ContractType::AVM));
    }

    #[test]
    fn test_detect_sbf_contract() {
        let bytecode = b"\x7fELF\x00\x00\x00\x00".to_vec();
        let contract_type = ContractType::from_bytecode(&bytecode);
        assert_eq!(contract_type, Some(ContractType::SBF));
    }

    #[test]
    fn test_executor_avm() {
        let executor = VMExecutor::new();
        let state = AccountState::new();

        // Simple TEAL that returns true
        let bytecode = vec![6u8, 0x20, 1, 1, 0x22, 0, 0x43];

        let context = ExecutionContext::new(
            Address::zero(),
            Address::zero(),
            TokenAmount::ZERO,
            Gas::new(1_000_000),
        );

        let result = executor.execute(&bytecode, &[], context, &state);
        assert!(result.success);
    }
}
