//! CRYSTALS-Dilithium Post-Quantum Signature Scheme
//!
//! Dilithium is a lattice-based digital signature scheme that is
//! resistant to attacks by quantum computers. It is one of the
//! NIST post-quantum cryptography standards.
//!
//! Key sizes and security levels:
//! - Dilithium2: 128-bit security (used here for balance)
//! - Dilithium3: 192-bit security
//! - Dilithium5: 256-bit security

use crate::{CryptoError, CryptoResult, SignatureScheme};
use frychain_core::address::Address;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, SignedMessage};
use serde::{Deserialize, Serialize};

/// Dilithium public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumPublicKey(pub Vec<u8>);

impl DilithiumPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != dilithium2::public_key_bytes() {
            return Err(CryptoError::InvalidKeyLength {
                expected: dilithium2::public_key_bytes(),
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

/// Dilithium private key
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumPrivateKey(pub Vec<u8>);

impl DilithiumPrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != dilithium2::secret_key_bytes() {
            return Err(CryptoError::InvalidKeyLength {
                expected: dilithium2::secret_key_bytes(),
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

impl std::fmt::Debug for DilithiumPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumPrivateKey([REDACTED])")
    }
}

/// Dilithium signature
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumSignature(pub Vec<u8>);

impl DilithiumSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Dilithium keypair
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumKeypair {
    pub public_key: DilithiumPublicKey,
    pub private_key: DilithiumPrivateKey,
}

impl DilithiumKeypair {
    /// Generate a new random keypair
    pub fn generate() -> CryptoResult<Self> {
        let (pk, sk) = dilithium2::keypair();

        Ok(Self {
            public_key: DilithiumPublicKey(pk.as_bytes().to_vec()),
            private_key: DilithiumPrivateKey(sk.as_bytes().to_vec()),
        })
    }

    /// Create from raw key bytes
    pub fn from_bytes(public_key: &[u8], private_key: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            public_key: DilithiumPublicKey::from_bytes(public_key)?,
            private_key: DilithiumPrivateKey::from_bytes(private_key)?,
        })
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let sk = dilithium2::SecretKey::from_bytes(&self.private_key.0)
            .expect("Valid secret key");

        let signed_message = dilithium2::sign(message, &sk);
        // The signed message contains signature + original message
        // We only want the signature part
        let sig_len = signed_message.as_bytes().len() - message.len();
        DilithiumSignature(signed_message.as_bytes()[..sig_len].to_vec())
    }

    /// Verify a signature
    pub fn verify(
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> bool {
        let pk = match dilithium2::PublicKey::from_bytes(&public_key.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Reconstruct signed message (signature + message)
        let mut signed_msg = signature.0.clone();
        signed_msg.extend_from_slice(message);

        let sm = match dilithium2::SignedMessage::from_bytes(&signed_msg) {
            Ok(sm) => sm,
            Err(_) => return false,
        };

        dilithium2::open(&sm, &pk).is_ok()
    }

    /// Get the address for this keypair
    pub fn address(&self) -> Address {
        self.public_key.to_address()
    }
}

impl std::fmt::Debug for DilithiumKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DilithiumKeypair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl SignatureScheme for DilithiumKeypair {
    type PublicKey = DilithiumPublicKey;
    type PrivateKey = DilithiumPrivateKey;
    type Signature = DilithiumSignature;

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
        let sk = dilithium2::SecretKey::from_bytes(&private_key.0)
            .expect("Valid secret key");

        let signed_message = dilithium2::sign(message, &sk);
        let sig_len = signed_message.as_bytes().len() - message.len();
        DilithiumSignature(signed_message.as_bytes()[..sig_len].to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        DilithiumKeypair::verify(public_key, message, signature)
    }

    fn algorithm_name() -> &'static str {
        "Dilithium2"
    }

    fn is_post_quantum() -> bool {
        true
    }
}

/// Key sizes for Dilithium2
pub mod sizes {
    use pqcrypto_dilithium::dilithium2;

    pub fn public_key_bytes() -> usize {
        dilithium2::public_key_bytes()
    }

    pub fn secret_key_bytes() -> usize {
        dilithium2::secret_key_bytes()
    }

    pub fn signature_bytes() -> usize {
        dilithium2::signature_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_keypair_generation() {
        let keypair = DilithiumKeypair::generate().unwrap();
        assert!(!keypair.public_key.0.is_empty());
        assert!(!keypair.private_key.0.is_empty());
    }

    #[test]
    fn test_dilithium_sign_verify() {
        let keypair = DilithiumKeypair::generate().unwrap();
        let message = b"Hello, post-quantum world!";

        let signature = keypair.sign(message);
        assert!(DilithiumKeypair::verify(
            &keypair.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_dilithium_invalid_signature() {
        let keypair = DilithiumKeypair::generate().unwrap();
        let message = b"Hello, post-quantum world!";

        let signature = keypair.sign(message);

        // Wrong message
        assert!(!DilithiumKeypair::verify(
            &keypair.public_key,
            b"Wrong message",
            &signature
        ));

        // Wrong public key
        let other_keypair = DilithiumKeypair::generate().unwrap();
        assert!(!DilithiumKeypair::verify(
            &other_keypair.public_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_dilithium_address_derivation() {
        let keypair = DilithiumKeypair::generate().unwrap();
        let address = keypair.address();

        assert!(!address.is_zero());
        assert_eq!(address.addr_type, frychain_core::address::AddressType::Standard);
    }

    #[test]
    fn test_dilithium_key_sizes() {
        assert!(sizes::public_key_bytes() > 0);
        assert!(sizes::secret_key_bytes() > 0);
        assert!(sizes::signature_bytes() > 0);
    }
}
