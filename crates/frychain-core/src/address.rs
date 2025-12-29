//! FryChain address types
//!
//! FryChain uses a Bech32-inspired address format with quantum-resistant support:
//! - Standard addresses: fry1... (32 bytes, from post-quantum public key hash)
//! - Contract addresses: fryc1... (derived from creator + nonce)
//! - Device addresses: fryd1... (for DePIN devices)

use crate::error::{CoreError, CoreResult};
use crate::types::Hash256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

/// Address type prefix
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressType {
    /// Standard user account
    Standard,
    /// Smart contract
    Contract,
    /// DePIN device
    Device,
    /// System/built-in
    System,
}

impl AddressType {
    pub fn prefix(&self) -> &'static str {
        match self {
            AddressType::Standard => "fry1",
            AddressType::Contract => "fryc1",
            AddressType::Device => "fryd1",
            AddressType::System => "frys1",
        }
    }

    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "fry1" => Some(AddressType::Standard),
            "fryc1" => Some(AddressType::Contract),
            "fryd1" => Some(AddressType::Device),
            "frys1" => Some(AddressType::System),
            _ => None,
        }
    }
}

/// A 32-byte address on FryChain
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Address {
    /// Address type
    pub addr_type: AddressType,
    /// 32-byte address payload
    pub bytes: [u8; 32],
}

impl Default for AddressType {
    fn default() -> Self {
        AddressType::Standard
    }
}

impl Address {
    /// Create a new address from raw bytes
    pub fn new(addr_type: AddressType, bytes: [u8; 32]) -> Self {
        Self { addr_type, bytes }
    }

    /// Create a standard address from a post-quantum public key
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self {
            addr_type: AddressType::Standard,
            bytes,
        }
    }

    /// Create a contract address from creator address and nonce
    pub fn contract_address(creator: &Address, nonce: u64) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(&creator.bytes);
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self {
            addr_type: AddressType::Contract,
            bytes,
        }
    }

    /// Create a device address from device public key and device ID
    pub fn device_address(device_pubkey: &[u8], device_id: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"device:");
        hasher.update(device_pubkey);
        hasher.update(device_id);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self {
            addr_type: AddressType::Device,
            bytes,
        }
    }

    /// Create a system address from a name
    pub fn system_address(name: &str) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"system:");
        hasher.update(name.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self {
            addr_type: AddressType::System,
            bytes,
        }
    }

    /// Zero address (burn address)
    pub fn zero() -> Self {
        Self {
            addr_type: AddressType::Standard,
            bytes: [0u8; 32],
        }
    }

    /// Check if this is the zero address
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to Hash256 for hashing operations
    pub fn to_hash(&self) -> Hash256 {
        Hash256(self.bytes)
    }

    /// Encode to string format (prefix + base58)
    pub fn to_string_repr(&self) -> String {
        format!("{}{}", self.addr_type.prefix(), bs58::encode(&self.bytes).into_string())
    }

    /// Parse from string format
    pub fn from_string(s: &str) -> CoreResult<Self> {
        // Try each prefix
        for prefix in ["fry1", "fryc1", "fryd1", "frys1"] {
            if let Some(rest) = s.strip_prefix(prefix) {
                let addr_type = AddressType::from_prefix(prefix)
                    .ok_or_else(|| CoreError::InvalidAddress("Invalid prefix".to_string()))?;

                let decoded = bs58::decode(rest)
                    .into_vec()
                    .map_err(|e| CoreError::InvalidAddress(format!("Base58 decode error: {}", e)))?;

                if decoded.len() != 32 {
                    return Err(CoreError::InvalidAddress(format!(
                        "Invalid address length: expected 32, got {}",
                        decoded.len()
                    )));
                }

                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&decoded);

                return Ok(Self { addr_type, bytes });
            }
        }

        Err(CoreError::InvalidAddress("Invalid address prefix".to_string()))
    }

    /// Create from hex (without prefix, for internal use)
    pub fn from_hex(s: &str) -> CoreResult<Self> {
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| CoreError::InvalidAddress(format!("Hex decode error: {}", e)))?;

        if bytes.len() != 32 {
            return Err(CoreError::InvalidAddress(format!(
                "Invalid address length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        Ok(Self {
            addr_type: AddressType::Standard,
            bytes: arr,
        })
    }

    /// Convert to hex string (without prefix)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.bytes))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_string_repr())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_repr())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Well-known system addresses
pub mod system_addresses {
    use super::*;
    use once_cell::sync::Lazy;

    /// Coinbase/miner reward address (placeholder, actual reward goes to miner)
    pub static COINBASE: Lazy<Address> = Lazy::new(|| Address::system_address("coinbase"));

    /// Fee burn address
    pub static FEE_BURN: Lazy<Address> = Lazy::new(|| Address::system_address("fee_burn"));

    /// Staking contract address
    pub static STAKING: Lazy<Address> = Lazy::new(|| Address::system_address("staking"));

    /// DePIN registry contract address
    pub static DEPIN_REGISTRY: Lazy<Address> = Lazy::new(|| Address::system_address("depin_registry"));

    /// VM precompile base address
    pub static PRECOMPILE_BASE: Lazy<Address> = Lazy::new(|| Address::system_address("precompile"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_pubkey() {
        let pubkey = [1u8; 64]; // Dummy public key
        let addr = Address::from_public_key(&pubkey);
        assert_eq!(addr.addr_type, AddressType::Standard);
        assert!(!addr.is_zero());
    }

    #[test]
    fn test_address_string_roundtrip() {
        let addr = Address::from_public_key(&[42u8; 64]);
        let s = addr.to_string_repr();
        let parsed = Address::from_string(&s).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_contract_address() {
        let creator = Address::from_public_key(&[1u8; 64]);
        let contract1 = Address::contract_address(&creator, 0);
        let contract2 = Address::contract_address(&creator, 1);
        assert_eq!(contract1.addr_type, AddressType::Contract);
        assert_ne!(contract1, contract2);
    }

    #[test]
    fn test_device_address() {
        let addr = Address::device_address(&[1u8; 32], b"device-001");
        assert_eq!(addr.addr_type, AddressType::Device);
    }
}
