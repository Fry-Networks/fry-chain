//! Hash utility functions

use frychain_core::types::Hash256;
use sha3::{Digest, Keccak256, Sha3_256};

/// Compute Keccak-256 hash (Ethereum-compatible)
pub fn keccak256(data: &[u8]) -> Hash256 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256(bytes)
}

/// Compute SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256(bytes)
}

/// Compute BLAKE3 hash
pub fn blake3_hash(data: &[u8]) -> Hash256 {
    let hash = blake3::hash(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());
    Hash256(bytes)
}

/// Compute double SHA3-256 hash (for extra security)
pub fn double_sha3_256(data: &[u8]) -> Hash256 {
    sha3_256(sha3_256(data).as_bytes())
}

/// Compute hash of multiple inputs concatenated
pub fn hash_concat(inputs: &[&[u8]]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    for input in inputs {
        hasher.update(input);
    }
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256(bytes)
}

/// Domain-separated hashing (prevents cross-protocol attacks)
pub fn domain_hash(domain: &str, data: &[u8]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    // Length-prefix the domain to prevent ambiguity
    let domain_bytes = domain.as_bytes();
    hasher.update(&(domain_bytes.len() as u64).to_le_bytes());
    hasher.update(domain_bytes);
    hasher.update(data);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello");
        assert!(!hash.is_zero());

        // Should be deterministic
        let hash2 = keccak256(b"hello");
        assert_eq!(hash, hash2);

        // Different input = different hash
        let hash3 = keccak256(b"world");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"hello");
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_blake3() {
        let hash = blake3_hash(b"hello");
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_domain_hash() {
        let hash1 = domain_hash("tx", b"data");
        let hash2 = domain_hash("block", b"data");

        // Same data, different domain = different hash
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_concat() {
        let hash1 = hash_concat(&[b"hello", b"world"]);
        let hash2 = sha3_256(b"helloworld");

        assert_eq!(hash1, hash2);
    }
}
