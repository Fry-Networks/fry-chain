//! Common types used throughout FryChain

use serde::{Deserialize, Serialize};
use std::fmt;

/// 256-bit hash (32 bytes) - used for block hashes, transaction hashes, etc.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Create a new Hash256 from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a zero hash
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Check if this is a zero hash
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Get the bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from a hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s.trim_start_matches("0x"))?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Create from a byte slice (must be exactly 32 bytes)
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
        Self(arr)
    }

    /// Get leading zeros count (for PoW difficulty comparison)
    pub fn leading_zeros(&self) -> u32 {
        let mut zeros = 0u32;
        for byte in self.0.iter() {
            if *byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros
    }

    /// Compare against difficulty target (hash must be less than target)
    pub fn meets_difficulty(&self, target: &Hash256) -> bool {
        for (h, t) in self.0.iter().zip(target.0.iter()) {
            match h.cmp(t) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        true // Equal is valid
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 512-bit hash (64 bytes) - used for extended hashes
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash512(pub [u8; 64]);

impl Default for Hash512 {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Serialize for Hash512 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as hex string for JSON compatibility
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Hash512 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("expected 64 bytes"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(Hash512(arr))
        } else {
            let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("expected 64 bytes"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(Hash512(arr))
        }
    }
}

impl Hash512 {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn zero() -> Self {
        Self([0u8; 64])
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash512({}...)", &self.to_hex()[..18])
    }
}

/// Nonce type for transactions and mining
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Nonce(pub u64);

impl Nonce {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for Nonce {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Mining difficulty
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Difficulty(pub u128);

impl Difficulty {
    /// Minimum difficulty
    pub const MIN: Difficulty = Difficulty(1);

    /// Initial network difficulty
    pub const INITIAL: Difficulty = Difficulty(0x0000_FFFF_FFFF_FFFF);

    pub fn new(value: u128) -> Self {
        Self(value.max(1))
    }

    pub fn value(&self) -> u128 {
        self.0
    }

    /// Convert difficulty to target hash
    /// Target = MAX_HASH / difficulty
    pub fn to_target(&self) -> Hash256 {
        // Use simplified target calculation
        // Higher difficulty = lower target = more leading zeros needed
        let leading_zeros = (self.0.leading_zeros() as usize).min(31);
        let mut target = [0xFF; 32];
        for i in 0..leading_zeros {
            target[i] = 0;
        }
        if leading_zeros < 32 {
            target[leading_zeros] = (0xFF >> (self.0.trailing_zeros() % 8)) as u8;
        }
        Hash256(target)
    }

    /// Adjust difficulty based on actual vs target block time
    pub fn adjust(&self, actual_time_secs: u64, target_time_secs: u64) -> Self {
        let ratio = actual_time_secs as f64 / target_time_secs as f64;
        // Limit adjustment to 4x in either direction
        let clamped_ratio = ratio.clamp(0.25, 4.0);
        let new_diff = (self.0 as f64 / clamped_ratio) as u128;
        Difficulty::new(new_diff.max(1))
    }
}

impl Default for Difficulty {
    fn default() -> Self {
        Self::INITIAL
    }
}

/// Block height
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    pub fn genesis() -> Self {
        Self(0)
    }

    pub fn new(height: u64) -> Self {
        Self(height)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn prev(&self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(Self(self.0 - 1))
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for BlockHeight {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Token amount in base units (1 FRY = 10^18 base units)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct TokenAmount(pub u128);

impl TokenAmount {
    pub const ZERO: TokenAmount = TokenAmount(0);

    pub fn new(value: u128) -> Self {
        Self(value)
    }

    /// Create from FRY (whole tokens)
    pub fn from_fry(fry: u64) -> Self {
        Self((fry as u128) * crate::UNITS_PER_FRY)
    }

    /// Create from FRY with decimals
    pub fn from_fry_decimal(fry: f64) -> Self {
        Self((fry * crate::UNITS_PER_FRY as f64) as u128)
    }

    pub fn value(&self) -> u128 {
        self.0
    }

    pub fn to_fry(&self) -> f64 {
        self.0 as f64 / crate::UNITS_PER_FRY as f64
    }

    pub fn checked_add(&self, other: TokenAmount) -> Option<TokenAmount> {
        self.0.checked_add(other.0).map(TokenAmount)
    }

    pub fn checked_sub(&self, other: TokenAmount) -> Option<TokenAmount> {
        self.0.checked_sub(other.0).map(TokenAmount)
    }

    pub fn saturating_add(&self, other: TokenAmount) -> TokenAmount {
        TokenAmount(self.0.saturating_add(other.0))
    }

    pub fn saturating_sub(&self, other: TokenAmount) -> TokenAmount {
        TokenAmount(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Add for TokenAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for TokenAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6} FRY", self.to_fry())
    }
}

/// Gas units for transaction execution
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Gas(pub u64);

impl Gas {
    pub const ZERO: Gas = Gas(0);

    /// Minimum gas for a simple transfer
    pub const TRANSFER_MIN: Gas = Gas(21_000);

    /// Gas per byte of data
    pub const PER_BYTE: Gas = Gas(16);

    /// Gas per contract creation
    pub const CONTRACT_CREATE: Gas = Gas(32_000);

    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, other: Gas) -> Option<Gas> {
        self.0.checked_add(other.0).map(Gas)
    }

    pub fn checked_sub(&self, other: Gas) -> Option<Gas> {
        self.0.checked_sub(other.0).map(Gas)
    }

    pub fn saturating_sub(&self, other: Gas) -> Gas {
        Gas(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Add for Gas {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Gas {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

/// Gas price in base token units per gas unit
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct GasPrice(pub u128);

impl GasPrice {
    /// Minimum gas price (1 Gwei equivalent)
    pub const MIN: GasPrice = GasPrice(1_000_000_000);

    pub fn new(value: u128) -> Self {
        Self(value)
    }

    pub fn value(&self) -> u128 {
        self.0
    }

    /// Calculate total fee for given gas amount
    pub fn total_fee(&self, gas: Gas) -> TokenAmount {
        TokenAmount(self.0 * gas.0 as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256_hex() {
        let hash = Hash256::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        assert_eq!(hash.to_hex(), "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    }

    #[test]
    fn test_hash256_leading_zeros() {
        let hash = Hash256::new([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(hash.leading_zeros(), 39); // 4 bytes * 8 + 7 leading zeros in 0x01
    }

    #[test]
    fn test_token_amount_conversion() {
        let amount = TokenAmount::from_fry(100);
        assert_eq!(amount.0, 100 * crate::UNITS_PER_FRY);
        assert!((amount.to_fry() - 100.0).abs() < 0.0001);
    }
}
