//! SPHINCS+ Post-Quantum Signature Scheme
//!
//! SPHINCS+ is a stateless hash-based signature scheme that provides
//! post-quantum security. It has larger signatures than Dilithium but
//! is based on well-understood hash function security assumptions.
//!
//! This implementation uses SPHINCS+-SHAKE-128s (small signatures variant)

use crate::{CryptoError, CryptoResult, SignatureScheme};
use frychain_core::address::Address;
use pqcrypto_sphincsplus::sphincsshake128ssimple as sphincs;
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, SignedMessage};
use serde::{Deserialize, Serialize};

/// SPHINCS+ public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SphincsPublicKey(pub Vec<u8>);

impl SphincsPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != sphincs::public_key_bytes() {
            return Err(CryptoError::InvalidKeyLength {
                expected: sphincs::public_key_bytes(),
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the address derived from this public key
    pub fn to_address(&self) -> Address {
        Address::from_public_key(&self.0)
    }
}

/// SPHINCS+ private key
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsPrivateKey(pub Vec<u8>);

impl SphincsPrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != sphincs::secret_key_bytes() {
            return Err(CryptoError::InvalidKeyLength {
                expected: sphincs::secret_key_bytes(),
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SphincsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SphincsPrivateKey([REDACTED])")
    }
}

/// SPHINCS+ signature
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SphincsSignature(pub Vec<u8>);

impl SphincsSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// SPHINCS+ keypair
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsKeypair {
    pub public_key: SphincsPublicKey,
    pub private_key: SphincsPrivateKey,
}

impl SphincsKeypair {
    /// Generate a new random keypair
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = sphincs::keypair();

        Ok(Self {
            public_key: SphincsPublicKey(pk.as_bytes().to_vec()),
            private_key: SphincsPrivateKey(sk.as_bytes().to_vec()),
        })
    }

    /// Create from raw key bytes
    pub fn from_bytes(public_key: &[u8], private_key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            public_key: SphincsPublicKey::from_bytes(public_key)?,
            private_key: SphincsPrivateKey::from_bytes(private_key)?,
        })
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> SphincsSignature {
        let sk = sphincs::SecretKey::from_bytes(&self.private_key.0)
            .expect("Valid secret key");

        let signed_message = sphincs::sign(message, &sk);
        // Extract just the signature part
        let sig_len = signed_message.as_bytes().len() - message.len();
        SphincsSignature(signed_message.as_bytes()[..sig_len].to_vec())
    }

    /// Verify a signature
    pub fn verify(
        public_key: &SphincsPublicKey,
        message: &[u8],
        signature: &SphincsSignature,
    ) -> bool {
        let pk = match sphincs::PublicKey::from_bytes(&public_key.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Reconstruct signed message
        let mut signed_msg = signature.0.clone();
        signed_msg.extend_from_slice(message);

        let sm = match sphincs::SignedMessage::from_bytes(&signed_msg) {
            Ok(sm) => sm,
            Err(_) => return false,
        };

        sphincs::open(&sm, &pk).is_ok()
    }

    /// Get the address for this keypair
    pub fn address(&self) -> Address {
        self.public_key.to_address()
    }
}

impl std::fmt::Debug for SphincsKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SphincsKeypair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl SignatureScheme for SphincsKeypair {
    type PublicKey = SphincsPublicKey;
    type PrivateKey = SphincsPrivateKey;
    type Signature = SphincsSignature;

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
        let sk = sphincs::SecretKey::from_bytes(&private_key.0)
            .expect("Valid secret key");

        let signed_message = sphincs::sign(message, &sk);
        let sig_len = signed_message.as_bytes().len() - message.len();
        SphincsSignature(signed_message.as_bytes()[..sig_len].to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        SphincsKeypair::verify(public_key, message, signature)
    }

    fn algorithm_name() -> &'static str {
        "SPHINCS+-SHAKE-128s"
    }

    fn is_post_quantum() -> bool {
        true
    }
}

/// Key sizes for SPHINCS+
pub mod sizes {
    use pqcrypto_sphincsplus::sphincsshake128ssimple as sphincs;

    pub fn public_key_bytes() -> usize {
        sphincs::public_key_bytes()
    }

    pub fn secret_key_bytes() -> usize {
        sphincs::secret_key_bytes()
    }

    pub fn signature_bytes() -> usize {
        sphincs::signature_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_keypair_generation() {
        let keypair = SphincsKeypair::generate().unwrap();
        assert!(!keypair.public_key.0.is_empty());
        assert!(!keypair.private_key.0.is_empty());
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let keypair = SphincsKeypair::generate().unwrap();
        let message = b"Hello, hash-based signatures!";

        let signature = keypair.sign(message);
        assert!(SphincsKeypair::verify(
            &keypair.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_sphincs_invalid_signature() {
        let keypair = SphincsKeypair::generate().unwrap();
        let message = b"Hello, hash-based signatures!";

        let signature = keypair.sign(message);

        // Wrong message
        assert!(!SphincsKeypair::verify(
            &keypair.public_key,
            b"Wrong message",
            &signature
        ));
    }

    #[test]
    fn test_sphincs_key_sizes() {
        // SPHINCS+ has larger keys and signatures than Dilithium
        assert!(sizes::public_key_bytes() > 0);
        assert!(sizes::secret_key_bytes() > 0);
        assert!(sizes::signature_bytes() > 0);
    }
}
