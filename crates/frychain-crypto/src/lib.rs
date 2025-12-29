//! FryChain Cryptography
//!
//! This crate provides cryptographic primitives for FryChain:
//! - CryptoNight-STC proof-of-work algorithm
//! - Post-quantum signatures (CRYSTALS-Dilithium, SPHINCS+)
//! - Classical signatures (Ed25519) for compatibility
//! - Key generation and management

pub mod cryptonight;
pub mod dilithium;
pub mod sphincs;
pub mod ed25519;
pub mod keys;
pub mod hash;

pub use cryptonight::CryptoNightStc;
pub use dilithium::{DilithiumKeypair, DilithiumSignature};
pub use sphincs::{SphincsKeypair, SphincsSignature};
pub use ed25519::{Ed25519Keypair, Ed25519Signature};
pub use keys::{Keypair, KeypairType, PrivateKey, PublicKey};
pub use hash::{keccak256, sha3_256, blake3_hash};

use thiserror::Error;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Hash computation failed: {0}")]
    HashError(String),
}

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Signature trait for all signature types
pub trait SignatureScheme {
    type PublicKey;
    type PrivateKey;
    type Signature;

    /// Sign a message
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Self::Signature;

    /// Verify a signature
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool;

    /// Get the algorithm name
    fn algorithm_name() -> &'static str;

    /// Check if this is a post-quantum algorithm
    fn is_post_quantum() -> bool;
}
