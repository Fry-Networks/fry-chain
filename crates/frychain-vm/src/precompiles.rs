//! Native precompiled contracts

use crate::types::{ExecutionContext, VMResult};
use crate::VMExecutionError;
use frychain_core::address::Address;
use frychain_core::types::{Gas, Hash256};
use sha3::{Digest, Keccak256, Sha3_256};
use std::collections::HashMap;

/// Precompiled contract trait
pub trait Precompile: Send + Sync {
    /// Execute the precompile
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult;

    /// Get the gas cost for this input
    fn gas_cost(&self, input: &[u8]) -> u64;
}

/// Precompile execution result
pub struct PrecompileResult {
    pub success: bool,
    pub gas_used: u64,
    pub output: Vec<u8>,
    pub error: Option<String>,
}

impl PrecompileResult {
    pub fn success(gas_used: u64, output: Vec<u8>) -> Self {
        Self {
            success: true,
            gas_used,
            output,
            error: None,
        }
    }

    pub fn failure(gas_used: u64, error: String) -> Self {
        Self {
            success: false,
            gas_used,
            output: Vec::new(),
            error: Some(error),
        }
    }
}

/// SHA3-256 precompile
pub struct Sha3Precompile;

impl Precompile for Sha3Precompile {
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_cost = self.gas_cost(input);
        if gas_cost > gas_limit {
            return PrecompileResult::failure(gas_limit, "Out of gas".to_string());
        }

        let hash = Sha3_256::digest(input);
        PrecompileResult::success(gas_cost, hash.to_vec())
    }

    fn gas_cost(&self, input: &[u8]) -> u64 {
        30 + 6 * ((input.len() as u64 + 31) / 32)
    }
}

/// Keccak-256 precompile (Ethereum-compatible)
pub struct Keccak256Precompile;

impl Precompile for Keccak256Precompile {
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_cost = self.gas_cost(input);
        if gas_cost > gas_limit {
            return PrecompileResult::failure(gas_limit, "Out of gas".to_string());
        }

        let hash = Keccak256::digest(input);
        PrecompileResult::success(gas_cost, hash.to_vec())
    }

    fn gas_cost(&self, input: &[u8]) -> u64 {
        30 + 6 * ((input.len() as u64 + 31) / 32)
    }
}

/// BLAKE3 hash precompile
pub struct Blake3Precompile;

impl Precompile for Blake3Precompile {
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_cost = self.gas_cost(input);
        if gas_cost > gas_limit {
            return PrecompileResult::failure(gas_limit, "Out of gas".to_string());
        }

        let hash = blake3::hash(input);
        PrecompileResult::success(gas_cost, hash.as_bytes().to_vec())
    }

    fn gas_cost(&self, input: &[u8]) -> u64 {
        // BLAKE3 is faster than SHA3
        15 + 3 * ((input.len() as u64 + 31) / 32)
    }
}

/// Identity precompile (returns input unchanged)
pub struct IdentityPrecompile;

impl Precompile for IdentityPrecompile {
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_cost = self.gas_cost(input);
        if gas_cost > gas_limit {
            return PrecompileResult::failure(gas_limit, "Out of gas".to_string());
        }

        PrecompileResult::success(gas_cost, input.to_vec())
    }

    fn gas_cost(&self, input: &[u8]) -> u64 {
        15 + 3 * ((input.len() as u64 + 31) / 32)
    }
}

/// Post-quantum signature verification precompile
pub struct DilithiumVerifyPrecompile;

impl Precompile for DilithiumVerifyPrecompile {
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_cost = self.gas_cost(input);
        if gas_cost > gas_limit {
            return PrecompileResult::failure(gas_limit, "Out of gas".to_string());
        }

        // Input format: [32-byte message hash][public key][signature]
        if input.len() < 32 {
            return PrecompileResult::failure(gas_cost, "Invalid input length".to_string());
        }

        let message = &input[0..32];

        // Parse public key and signature (remaining bytes)
        // For now, just return success if format is valid
        // Real implementation would verify using frychain_crypto::dilithium

        // Return 1 for valid, 0 for invalid
        PrecompileResult::success(gas_cost, vec![1])
    }

    fn gas_cost(&self, _input: &[u8]) -> u64 {
        // Dilithium verification is relatively cheap
        3000
    }
}

/// Registry of precompiled contracts
pub struct PrecompileRegistry {
    precompiles: HashMap<Address, Box<dyn Precompile>>,
}

impl PrecompileRegistry {
    /// Create a new registry with standard precompiles
    pub fn standard() -> Self {
        let mut registry = Self {
            precompiles: HashMap::new(),
        };

        // Standard precompiles at addresses 0x01 - 0x09
        registry.register(address_from_u8(1), Box::new(IdentityPrecompile));
        registry.register(address_from_u8(2), Box::new(Sha3Precompile));
        registry.register(address_from_u8(3), Box::new(Keccak256Precompile));
        registry.register(address_from_u8(4), Box::new(Blake3Precompile));
        registry.register(address_from_u8(5), Box::new(DilithiumVerifyPrecompile));

        registry
    }

    /// Register a precompile at an address
    pub fn register(&mut self, address: Address, precompile: Box<dyn Precompile>) {
        self.precompiles.insert(address, precompile);
    }

    /// Check if an address is a precompile
    pub fn is_precompile(&self, address: &Address) -> bool {
        self.precompiles.contains_key(address)
    }

    /// Execute a precompile
    pub fn execute(
        &self,
        address: &Address,
        input: &[u8],
        gas_limit: u64,
    ) -> Option<PrecompileResult> {
        self.precompiles
            .get(address)
            .map(|p| p.execute(input, gas_limit))
    }

    /// Get gas cost for a precompile call
    pub fn gas_cost(&self, address: &Address, input: &[u8]) -> Option<u64> {
        self.precompiles.get(address).map(|p| p.gas_cost(input))
    }
}

/// Create an address from a single byte (for precompile addresses)
fn address_from_u8(n: u8) -> Address {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    Address::new(frychain_core::address::AddressType::System, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_precompile() {
        let precompile = Sha3Precompile;
        let result = precompile.execute(b"hello", 10000);
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
    }

    #[test]
    fn test_identity_precompile() {
        let precompile = IdentityPrecompile;
        let input = b"test data";
        let result = precompile.execute(input, 10000);
        assert!(result.success);
        assert_eq!(result.output, input);
    }

    #[test]
    fn test_precompile_registry() {
        let registry = PrecompileRegistry::standard();

        let sha3_addr = address_from_u8(2);
        assert!(registry.is_precompile(&sha3_addr));

        let result = registry.execute(&sha3_addr, b"test", 10000).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_out_of_gas() {
        let precompile = Sha3Precompile;
        let result = precompile.execute(b"hello", 1); // Very low gas
        assert!(!result.success);
    }
}
