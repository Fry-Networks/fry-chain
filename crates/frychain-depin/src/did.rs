//! Device Decentralized Identifiers (DIDs)
//!
//! Implements W3C DID-compatible device identities for FryChain DePIN.

use crate::{DePINError, DePINResult};
use frychain_core::address::Address;
use frychain_core::types::Hash256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Device DID format: did:fry:<address>
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceDID {
    /// The DID string
    pub did: String,
    /// The device address
    pub address: Address,
}

impl DeviceDID {
    /// Create a new device DID from an address
    pub fn new(address: Address) -> Self {
        let did = format!("did:fry:{}", address);
        Self { did, address }
    }

    /// Parse a DID string
    pub fn parse(did_str: &str) -> DePINResult<Self> {
        if !did_str.starts_with("did:fry:") {
            return Err(DePINError::InvalidDIDDocument(
                "Invalid DID prefix".to_string(),
            ));
        }

        let address_str = &did_str[8..];
        let address = Address::from_string(address_str)
            .map_err(|e| DePINError::InvalidDIDDocument(e.to_string()))?;

        Ok(Self {
            did: did_str.to_string(),
            address,
        })
    }

    /// Get the DID string
    pub fn as_str(&self) -> &str {
        &self.did
    }

    /// Get the device address
    pub fn device_address(&self) -> Address {
        self.address
    }
}

impl std::fmt::Display for DeviceDID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.did)
    }
}

/// DID Document containing device information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DIDDocument {
    /// The DID this document describes
    pub id: DeviceDID,
    /// Verification methods (public keys)
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication methods
    pub authentication: Vec<String>,
    /// Service endpoints
    pub service: Vec<ServiceEndpoint>,
    /// Device attributes
    pub attributes: Vec<DeviceAttribute>,
    /// Creation timestamp
    pub created: u64,
    /// Last updated timestamp
    pub updated: u64,
    /// Document version
    pub version: u32,
}

impl DIDDocument {
    /// Create a new DID document
    pub fn new(did: DeviceDID, public_key: Vec<u8>) -> Self {
        let verification_id = format!("{}#keys-1", did.as_str());

        Self {
            id: did.clone(),
            verification_method: vec![VerificationMethod {
                id: verification_id.clone(),
                controller: did.as_str().to_string(),
                method_type: "Dilithium2VerificationKey2024".to_string(),
                public_key_multibase: format!("z{}", bs58::encode(&public_key).into_string()),
            }],
            authentication: vec![verification_id],
            service: Vec::new(),
            attributes: Vec::new(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            updated: 0,
            version: 1,
        }
    }

    /// Add a service endpoint
    pub fn add_service(&mut self, service: ServiceEndpoint) {
        self.service.push(service);
        self.touch();
    }

    /// Add a device attribute
    pub fn add_attribute(&mut self, attribute: DeviceAttribute) {
        self.attributes.push(attribute);
        self.touch();
    }

    /// Update the document
    fn touch(&mut self) {
        self.updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.version += 1;
    }

    /// Calculate document hash
    pub fn hash(&self) -> Hash256 {
        let json = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(&json);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Validate the document
    pub fn validate(&self) -> DePINResult<()> {
        if self.verification_method.is_empty() {
            return Err(DePINError::InvalidDIDDocument(
                "No verification method".to_string(),
            ));
        }

        if self.authentication.is_empty() {
            return Err(DePINError::InvalidDIDDocument(
                "No authentication method".to_string(),
            ));
        }

        Ok(())
    }
}

/// Verification method (public key)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Unique ID for this method
    pub id: String,
    /// Controller DID
    pub controller: String,
    /// Key type
    pub method_type: String,
    /// Public key in multibase format
    pub public_key_multibase: String,
}

/// Service endpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Unique ID
    pub id: String,
    /// Service type
    pub service_type: String,
    /// Endpoint URL
    pub service_endpoint: String,
    /// Optional description
    pub description: Option<String>,
}

impl ServiceEndpoint {
    /// Create a new data service endpoint
    pub fn data_service(did: &DeviceDID, endpoint: &str) -> Self {
        Self {
            id: format!("{}#data-service", did.as_str()),
            service_type: "DataService".to_string(),
            service_endpoint: endpoint.to_string(),
            description: Some("Device data streaming endpoint".to_string()),
        }
    }

    /// Create an M2M messaging endpoint
    pub fn m2m_messaging(did: &DeviceDID, endpoint: &str) -> Self {
        Self {
            id: format!("{}#m2m-messaging", did.as_str()),
            service_type: "M2MMessaging".to_string(),
            service_endpoint: endpoint.to_string(),
            description: Some("Machine-to-machine messaging".to_string()),
        }
    }
}

/// Device attribute
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceAttribute {
    /// Attribute name
    pub name: String,
    /// Attribute value
    pub value: String,
    /// Attribute type (e.g., "string", "number", "boolean")
    pub attr_type: String,
    /// Is this attribute publicly visible
    pub public: bool,
}

impl DeviceAttribute {
    /// Create a device type attribute
    pub fn device_type(device_type: &str) -> Self {
        Self {
            name: "deviceType".to_string(),
            value: device_type.to_string(),
            attr_type: "string".to_string(),
            public: true,
        }
    }

    /// Create a manufacturer attribute
    pub fn manufacturer(manufacturer: &str) -> Self {
        Self {
            name: "manufacturer".to_string(),
            value: manufacturer.to_string(),
            attr_type: "string".to_string(),
            public: true,
        }
    }

    /// Create a model attribute
    pub fn model(model: &str) -> Self {
        Self {
            name: "model".to_string(),
            value: model.to_string(),
            attr_type: "string".to_string(),
            public: true,
        }
    }

    /// Create a firmware version attribute
    pub fn firmware_version(version: &str) -> Self {
        Self {
            name: "firmwareVersion".to_string(),
            value: version.to_string(),
            attr_type: "string".to_string(),
            public: true,
        }
    }

    /// Create a location attribute
    pub fn location(latitude: f64, longitude: f64) -> Self {
        Self {
            name: "location".to_string(),
            value: format!("{},{}", latitude, longitude),
            attr_type: "geo".to_string(),
            public: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_did_creation() {
        let address = Address::from_public_key(&[1u8; 64]);
        let did = DeviceDID::new(address);

        assert!(did.as_str().starts_with("did:fry:"));
        assert_eq!(did.device_address(), address);
    }

    #[test]
    fn test_did_document() {
        let address = Address::from_public_key(&[1u8; 64]);
        let did = DeviceDID::new(address);
        let doc = DIDDocument::new(did, vec![1, 2, 3, 4]);

        assert!(doc.validate().is_ok());
        assert_eq!(doc.version, 1);
        assert!(!doc.verification_method.is_empty());
    }

    #[test]
    fn test_did_parse() {
        let address = Address::from_public_key(&[1u8; 64]);
        let did = DeviceDID::new(address);
        let parsed = DeviceDID::parse(did.as_str()).unwrap();

        assert_eq!(did, parsed);
    }
}
