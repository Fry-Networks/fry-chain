//! Ed25519 Classical Signature Scheme
//!
//! Provides Ed25519 signatures for backwards compatibility with
//! classical cryptography. Note: Ed25519 is NOT post-quantum secure.
//! Use Dilithium or SPHINCS+ for quantum resistance.

use crate::{CryptoError, CryptoResult, SignatureScheme};
use ed25519_dalek::{Signer, Verifier};
use frychain_core::address::Address;
use serde::{Deserialize, Serialize};

/// Ed25519 public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the address derived from this public key
    pub fn to_address(&self) -> Address {
        Address::from_public_key(&self.0)
    }
}

/// Ed25519 private key
#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519PrivateKey(pub [u8; 32]);

impl Ed25519PrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PrivateKey([REDACTED])")
    }
}

/// Ed25519 signature
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519Signature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignatureLength {
                expected: 64,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Ed25519 keypair
#[derive(Clone, Serialize, Deserialize)]
pub struct Ed25519Keypair {
    pub public_key: Ed25519PublicKey,
    pub private_key: Ed25519PrivateKey,
}

impl Ed25519Keypair {
    /// Generate a new random keypair
    pub fn generate() -> CryptoResult<Self> {
        use rand::rngs::OsRng;

        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            public_key: Ed25519PublicKey(verifying_key.to_bytes()),
            private_key: Ed25519PrivateKey(signing_key.to_bytes()),
        })
    }

    /// Create from raw key bytes
    pub fn from_bytes(public_key: &[u8], private_key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            public_key: Ed25519PublicKey::from_bytes(public_key)?,
            private_key: Ed25519PrivateKey::from_bytes(private_key)?,
        })
    }

    /// Create from private key only (derives public key)
    pub fn from_private_key(private_key: &[u8]) -> CryptoResult<Self> {
        let sk = Ed25519PrivateKey::from_bytes(private_key)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk.0);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            public_key: Ed25519PublicKey(verifying_key.to_bytes()),
            private_key: sk,
        })
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.private_key.0);
        let signature = signing_key.sign(message);
        Ed25519Signature(signature.to_bytes())
    }

    /// Verify a signature
    pub fn verify(
        public_key: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> bool {
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key.0) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        verifying_key.verify(message, &sig).is_ok()
    }

    /// Get the address for this keypair
    pub fn address(&self) -> Address {
        self.public_key.to_address()
    }
}

impl std::fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Keypair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl SignatureScheme for Ed25519Keypair {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key.0);
        let signature = signing_key.sign(message);
        Ed25519Signature(signature.to_bytes())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        Ed25519Keypair::verify(public_key, message, signature)
    }

    fn algorithm_name() -> &'static str {
        "Ed25519"
    }

    fn is_post_quantum() -> bool {
        false // Ed25519 is NOT post-quantum secure
    }
}

/// Key and signature sizes
pub mod sizes {
    pub const PUBLIC_KEY_BYTES: usize = 32;
    pub const PRIVATE_KEY_BYTES: usize = 32;
    pub const SIGNATURE_BYTES: usize = 64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_generation() {
        let keypair = Ed25519Keypair::generate().unwrap();
        assert_eq!(keypair.public_key.0.len(), 32);
        assert_eq!(keypair.private_key.0.len(), 32);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = Ed25519Keypair::generate().unwrap();
        let message = b"Hello, classical cryptography!";

        let signature = keypair.sign(message);
        assert!(Ed25519Keypair::verify(
            &keypair.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_ed25519_invalid_signature() {
        let keypair = Ed25519Keypair::generate().unwrap();
        let message = b"Hello, classical cryptography!";

        let signature = keypair.sign(message);

        // Wrong message
        assert!(!Ed25519Keypair::verify(
            &keypair.public_key,
            b"Wrong message",
            &signature
        ));

        // Wrong public key
        let other_keypair = Ed25519Keypair::generate().unwrap();
        assert!(!Ed25519Keypair::verify(
            &other_keypair.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_ed25519_from_private_key() {
        let keypair1 = Ed25519Keypair::generate().unwrap();
        let keypair2 = Ed25519Keypair::from_private_key(&keypair1.private_key.0).unwrap();

        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_ed25519_not_post_quantum() {
        assert!(!Ed25519Keypair::is_post_quantum());
    }
}
