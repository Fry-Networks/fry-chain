//! Unified key management for FryChain
//!
//! Provides a unified interface for managing different key types:
//! - Dilithium (post-quantum, default)
//! - SPHINCS+ (post-quantum, hash-based)
//! - Ed25519 (classical, for compatibility)

use crate::{
    dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature},
    ed25519::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature},
    sphincs::{SphincsKeypair, SphincsPublicKey, SphincsSignature},
    CryptoError, CryptoResult,
};
use frychain_core::address::Address;
use frychain_core::transaction::{Signature, SignatureType};
use serde::{Deserialize, Serialize};

/// Key type enumeration
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeypairType {
    /// CRYSTALS-Dilithium (default, post-quantum)
    Dilithium,
    /// SPHINCS+ (post-quantum, hash-based)
    SphincsPlus,
    /// Ed25519 (classical, NOT post-quantum)
    Ed25519,
}

impl KeypairType {
    /// Check if this key type is post-quantum secure
    pub fn is_post_quantum(&self) -> bool {
        match self {
            KeypairType::Dilithium => true,
            KeypairType::SphincsPlus => true,
            KeypairType::Ed25519 => false,
        }
    }

    /// Get the algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            KeypairType::Dilithium => "Dilithium2",
            KeypairType::SphincsPlus => "SPHINCS+-SHAKE-128s",
            KeypairType::Ed25519 => "Ed25519",
        }
    }
}

impl Default for KeypairType {
    fn default() -> Self {
        KeypairType::Dilithium
    }
}

/// Unified public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Dilithium(DilithiumPublicKey),
    SphincsPlus(SphincsPublicKey),
    Ed25519(Ed25519PublicKey),
}

impl PublicKey {
    /// Get the key type
    pub fn key_type(&self) -> KeypairType {
        match self {
            PublicKey::Dilithium(_) => KeypairType::Dilithium,
            PublicKey::SphincsPlus(_) => KeypairType::SphincsPlus,
            PublicKey::Ed25519(_) => KeypairType::Ed25519,
        }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Dilithium(pk) => pk.as_bytes(),
            PublicKey::SphincsPlus(pk) => pk.as_bytes(),
            PublicKey::Ed25519(pk) => pk.as_bytes(),
        }
    }

    /// Get the address for this public key
    pub fn to_address(&self) -> Address {
        match self {
            PublicKey::Dilithium(pk) => pk.to_address(),
            PublicKey::SphincsPlus(pk) => pk.to_address(),
            PublicKey::Ed25519(pk) => pk.to_address(),
        }
    }

    /// Check if this is a post-quantum key
    pub fn is_post_quantum(&self) -> bool {
        self.key_type().is_post_quantum()
    }
}

/// Unified private key
#[derive(Clone, Serialize, Deserialize)]
pub enum PrivateKey {
    Dilithium(crate::dilithium::DilithiumPrivateKey),
    SphincsPlus(crate::sphincs::SphincsPrivateKey),
    Ed25519(crate::ed25519::Ed25519PrivateKey),
}

impl PrivateKey {
    /// Get the key type
    pub fn key_type(&self) -> KeypairType {
        match self {
            PrivateKey::Dilithium(_) => KeypairType::Dilithium,
            PrivateKey::SphincsPlus(_) => KeypairType::SphincsPlus,
            PrivateKey::Ed25519(_) => KeypairType::Ed25519,
        }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PrivateKey::Dilithium(sk) => sk.as_bytes(),
            PrivateKey::SphincsPlus(sk) => sk.as_bytes(),
            PrivateKey::Ed25519(sk) => sk.as_bytes(),
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey({:?}, [REDACTED])", self.key_type())
    }
}

/// Unified keypair
#[derive(Clone, Serialize, Deserialize)]
pub enum Keypair {
    Dilithium(DilithiumKeypair),
    SphincsPlus(SphincsKeypair),
    Ed25519(Ed25519Keypair),
}

impl Keypair {
    /// Generate a new keypair of the specified type
    pub fn generate(key_type: KeypairType) -> CryptoResult<Self> {
        match key_type {
            KeypairType::Dilithium => {
                Ok(Keypair::Dilithium(DilithiumKeypair::generate()?))
            }
            KeypairType::SphincsPlus => {
                Ok(Keypair::SphincsPlus(SphincsKeypair::generate()?))
            }
            KeypairType::Ed25519 => {
                Ok(Keypair::Ed25519(Ed25519Keypair::generate()?))
            }
        }
    }

    /// Generate a new Dilithium keypair (default, post-quantum)
    pub fn generate_default() -> CryptoResult<Self> {
        Self::generate(KeypairType::Dilithium)
    }

    /// Get the key type
    pub fn key_type(&self) -> KeypairType {
        match self {
            Keypair::Dilithium(_) => KeypairType::Dilithium,
            Keypair::SphincsPlus(_) => KeypairType::SphincsPlus,
            Keypair::Ed25519(_) => KeypairType::Ed25519,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        match self {
            Keypair::Dilithium(kp) => PublicKey::Dilithium(kp.public_key.clone()),
            Keypair::SphincsPlus(kp) => PublicKey::SphincsPlus(kp.public_key.clone()),
            Keypair::Ed25519(kp) => PublicKey::Ed25519(kp.public_key.clone()),
        }
    }

    /// Get the private key
    pub fn private_key(&self) -> PrivateKey {
        match self {
            Keypair::Dilithium(kp) => PrivateKey::Dilithium(kp.private_key.clone()),
            Keypair::SphincsPlus(kp) => PrivateKey::SphincsPlus(kp.private_key.clone()),
            Keypair::Ed25519(kp) => PrivateKey::Ed25519(kp.private_key.clone()),
        }
    }

    /// Get the address
    pub fn address(&self) -> Address {
        match self {
            Keypair::Dilithium(kp) => kp.address(),
            Keypair::SphincsPlus(kp) => kp.address(),
            Keypair::Ed25519(kp) => kp.address(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            Keypair::Dilithium(kp) => {
                let sig = kp.sign(message);
                Signature::new(
                    SignatureType::Dilithium,
                    sig.as_bytes().to_vec(),
                    kp.public_key.as_bytes().to_vec(),
                )
            }
            Keypair::SphincsPlus(kp) => {
                let sig = kp.sign(message);
                Signature::new(
                    SignatureType::SphincsPlus,
                    sig.as_bytes().to_vec(),
                    kp.public_key.as_bytes().to_vec(),
                )
            }
            Keypair::Ed25519(kp) => {
                let sig = kp.sign(message);
                Signature::new(
                    SignatureType::Ed25519,
                    sig.as_bytes().to_vec(),
                    kp.public_key.as_bytes().to_vec(),
                )
            }
        }
    }

    /// Check if this is a post-quantum keypair
    pub fn is_post_quantum(&self) -> bool {
        self.key_type().is_post_quantum()
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("type", &self.key_type())
            .field("address", &self.address())
            .finish()
    }
}

/// Verify a signature using the appropriate algorithm
pub fn verify_signature(signature: &Signature, message: &[u8]) -> bool {
    match signature.sig_type {
        SignatureType::Dilithium => {
            let pk = match DilithiumPublicKey::from_bytes(&signature.public_key) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = DilithiumSignature::from_bytes(&signature.bytes);
            DilithiumKeypair::verify(&pk, message, &sig)
        }
        SignatureType::SphincsPlus => {
            let pk = match SphincsPublicKey::from_bytes(&signature.public_key) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = SphincsSignature::from_bytes(&signature.bytes);
            SphincsKeypair::verify(&pk, message, &sig)
        }
        SignatureType::Ed25519 => {
            let pk = match Ed25519PublicKey::from_bytes(&signature.public_key) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = match Ed25519Signature::from_bytes(&signature.bytes) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            Ed25519Keypair::verify(&pk, message, &sig)
        }
    }
}

/// Get the address from a signature's public key
pub fn address_from_signature(signature: &Signature) -> Address {
    Address::from_public_key(&signature.public_key)
}

/// Check if a signature is post-quantum
pub fn is_signature_post_quantum(signature: &Signature) -> bool {
    matches!(
        signature.sig_type,
        SignatureType::Dilithium | SignatureType::SphincsPlus
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all_types() {
        for key_type in [KeypairType::Dilithium, KeypairType::SphincsPlus, KeypairType::Ed25519] {
            let keypair = Keypair::generate(key_type).unwrap();
            assert_eq!(keypair.key_type(), key_type);
        }
    }

    #[test]
    fn test_sign_verify_all_types() {
        let message = b"Test message for all signature types";

        for key_type in [KeypairType::Dilithium, KeypairType::SphincsPlus, KeypairType::Ed25519] {
            let keypair = Keypair::generate(key_type).unwrap();
            let signature = keypair.sign(message);

            assert!(verify_signature(&signature, message));
            assert!(!verify_signature(&signature, b"Wrong message"));
        }
    }

    #[test]
    fn test_address_consistency() {
        let keypair = Keypair::generate_default().unwrap();
        let addr1 = keypair.address();
        let addr2 = keypair.public_key().to_address();
        let addr3 = address_from_signature(&keypair.sign(b"test"));

        assert_eq!(addr1, addr2);
        assert_eq!(addr2, addr3);
    }

    #[test]
    fn test_post_quantum_check() {
        let dilithium = Keypair::generate(KeypairType::Dilithium).unwrap();
        let sphincs = Keypair::generate(KeypairType::SphincsPlus).unwrap();
        let ed25519 = Keypair::generate(KeypairType::Ed25519).unwrap();

        assert!(dilithium.is_post_quantum());
        assert!(sphincs.is_post_quantum());
        assert!(!ed25519.is_post_quantum());

        assert!(is_signature_post_quantum(&dilithium.sign(b"test")));
        assert!(is_signature_post_quantum(&sphincs.sign(b"test")));
        assert!(!is_signature_post_quantum(&ed25519.sign(b"test")));
    }
}
