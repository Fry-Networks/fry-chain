//! Device Registry for DePIN

use crate::did::{DeviceAttribute, DeviceDID, DIDDocument};
use crate::{DePINError, DePINResult};
use frychain_core::address::Address;
use frychain_core::types::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Device status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    /// Device is registered and active
    Active,
    /// Device is temporarily suspended
    Suspended,
    /// Device is deactivated
    Deactivated,
    /// Device registration is pending verification
    Pending,
}

/// Device information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device DID
    pub did: DeviceDID,
    /// Device owner address
    pub owner: Address,
    /// DID Document hash
    pub did_doc_hash: Hash256,
    /// Device status
    pub status: DeviceStatus,
    /// Device type
    pub device_type: String,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Reputation score (0-1000)
    pub reputation: u32,
    /// Total data contributions
    pub data_contributions: u64,
    /// Total earnings in base units
    pub total_earnings: u128,
}

impl DeviceInfo {
    /// Create new device info
    pub fn new(did: DeviceDID, owner: Address, did_doc_hash: Hash256, device_type: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            did,
            owner,
            did_doc_hash,
            status: DeviceStatus::Pending,
            device_type,
            registered_at: now,
            last_seen: now,
            reputation: 500, // Start at neutral
            data_contributions: 0,
            total_earnings: 0,
        }
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Activate the device
    pub fn activate(&mut self) {
        self.status = DeviceStatus::Active;
    }

    /// Suspend the device
    pub fn suspend(&mut self) {
        self.status = DeviceStatus::Suspended;
    }

    /// Deactivate the device
    pub fn deactivate(&mut self) {
        self.status = DeviceStatus::Deactivated;
    }

    /// Update reputation
    pub fn update_reputation(&mut self, delta: i32) {
        let new_rep = (self.reputation as i32 + delta).clamp(0, 1000);
        self.reputation = new_rep as u32;
    }

    /// Record a data contribution
    pub fn record_contribution(&mut self, earnings: u128) {
        self.data_contributions += 1;
        self.total_earnings += earnings;
        self.update_reputation(1); // Small reputation boost
        self.touch();
    }
}

/// Device registry
#[derive(Clone, Debug, Default)]
pub struct DeviceRegistry {
    /// Devices by DID
    devices: HashMap<String, DeviceInfo>,
    /// DID Documents by DID
    did_documents: HashMap<String, DIDDocument>,
    /// Devices by owner
    devices_by_owner: HashMap<Address, Vec<String>>,
    /// Devices by type
    devices_by_type: HashMap<String, Vec<String>>,
}

impl DeviceRegistry {
    /// Create a new device registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new device
    pub fn register(
        &mut self,
        owner: Address,
        did_document: DIDDocument,
        device_type: String,
    ) -> DePINResult<DeviceInfo> {
        // Validate DID document
        did_document.validate()?;

        let did_str = did_document.id.as_str().to_string();

        // Check if already registered
        if self.devices.contains_key(&did_str) {
            return Err(DePINError::DeviceAlreadyRegistered(did_str));
        }

        let did = did_document.id.clone();
        let doc_hash = did_document.hash();

        // Create device info
        let device_info = DeviceInfo::new(did.clone(), owner, doc_hash, device_type.clone());

        // Store device
        self.devices.insert(did_str.clone(), device_info.clone());
        self.did_documents.insert(did_str.clone(), did_document);

        // Index by owner
        self.devices_by_owner
            .entry(owner)
            .or_default()
            .push(did_str.clone());

        // Index by type
        self.devices_by_type
            .entry(device_type)
            .or_default()
            .push(did_str);

        Ok(device_info)
    }

    /// Get device info by DID
    pub fn get_device(&self, did: &str) -> Option<&DeviceInfo> {
        self.devices.get(did)
    }

    /// Get device info mutably
    pub fn get_device_mut(&mut self, did: &str) -> Option<&mut DeviceInfo> {
        self.devices.get_mut(did)
    }

    /// Get DID document
    pub fn get_did_document(&self, did: &str) -> Option<&DIDDocument> {
        self.did_documents.get(did)
    }

    /// Get devices owned by an address
    pub fn get_devices_by_owner(&self, owner: &Address) -> Vec<&DeviceInfo> {
        self.devices_by_owner
            .get(owner)
            .map(|dids| {
                dids.iter()
                    .filter_map(|did| self.devices.get(did))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get devices by type
    pub fn get_devices_by_type(&self, device_type: &str) -> Vec<&DeviceInfo> {
        self.devices_by_type
            .get(device_type)
            .map(|dids| {
                dids.iter()
                    .filter_map(|did| self.devices.get(did))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all active devices
    pub fn get_active_devices(&self) -> Vec<&DeviceInfo> {
        self.devices
            .values()
            .filter(|d| d.status == DeviceStatus::Active)
            .collect()
    }

    /// Activate a device
    pub fn activate_device(&mut self, did: &str, by: &Address) -> DePINResult<()> {
        let device = self
            .devices
            .get_mut(did)
            .ok_or_else(|| DePINError::DeviceNotFound(did.to_string()))?;

        if &device.owner != by {
            return Err(DePINError::Unauthorized);
        }

        device.activate();
        Ok(())
    }

    /// Suspend a device
    pub fn suspend_device(&mut self, did: &str, by: &Address) -> DePINResult<()> {
        let device = self
            .devices
            .get_mut(did)
            .ok_or_else(|| DePINError::DeviceNotFound(did.to_string()))?;

        if &device.owner != by {
            return Err(DePINError::Unauthorized);
        }

        device.suspend();
        Ok(())
    }

    /// Deregister a device
    pub fn deregister(&mut self, did: &str, by: &Address) -> DePINResult<()> {
        let device = self
            .devices
            .get(did)
            .ok_or_else(|| DePINError::DeviceNotFound(did.to_string()))?;

        if &device.owner != by {
            return Err(DePINError::Unauthorized);
        }

        let owner = device.owner;
        let device_type = device.device_type.clone();

        // Remove from indexes
        if let Some(owner_devices) = self.devices_by_owner.get_mut(&owner) {
            owner_devices.retain(|d| d != did);
        }

        if let Some(type_devices) = self.devices_by_type.get_mut(&device_type) {
            type_devices.retain(|d| d != did);
        }

        // Remove device and document
        self.devices.remove(did);
        self.did_documents.remove(did);

        Ok(())
    }

    /// Update DID document
    pub fn update_did_document(
        &mut self,
        did: &str,
        new_doc: DIDDocument,
        by: &Address,
    ) -> DePINResult<()> {
        new_doc.validate()?;

        let device = self
            .devices
            .get_mut(did)
            .ok_or_else(|| DePINError::DeviceNotFound(did.to_string()))?;

        if &device.owner != by {
            return Err(DePINError::Unauthorized);
        }

        device.did_doc_hash = new_doc.hash();
        self.did_documents.insert(did.to_string(), new_doc);

        Ok(())
    }

    /// Get total device count
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Get active device count
    pub fn active_device_count(&self) -> usize {
        self.devices
            .values()
            .filter(|d| d.status == DeviceStatus::Active)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_did_document() -> (Address, DIDDocument) {
        let owner = Address::from_public_key(&[1u8; 64]);
        let device_address = Address::device_address(&[2u8; 32], b"device-001");
        let did = DeviceDID::new(device_address);
        let doc = DIDDocument::new(did, vec![1, 2, 3, 4]);
        (owner, doc)
    }

    #[test]
    fn test_device_registration() {
        let mut registry = DeviceRegistry::new();
        let (owner, doc) = create_did_document();

        let device = registry
            .register(owner, doc.clone(), "sensor".to_string())
            .unwrap();

        assert_eq!(device.status, DeviceStatus::Pending);
        assert_eq!(device.owner, owner);
        assert_eq!(registry.device_count(), 1);
    }

    #[test]
    fn test_device_activation() {
        let mut registry = DeviceRegistry::new();
        let (owner, doc) = create_did_document();
        let did = doc.id.as_str().to_string();

        registry
            .register(owner, doc, "sensor".to_string())
            .unwrap();
        registry.activate_device(&did, &owner).unwrap();

        let device = registry.get_device(&did).unwrap();
        assert_eq!(device.status, DeviceStatus::Active);
    }

    #[test]
    fn test_unauthorized_operation() {
        let mut registry = DeviceRegistry::new();
        let (owner, doc) = create_did_document();
        let did = doc.id.as_str().to_string();
        let other = Address::from_public_key(&[99u8; 64]);

        registry
            .register(owner, doc, "sensor".to_string())
            .unwrap();

        // Other user can't activate
        let result = registry.activate_device(&did, &other);
        assert!(matches!(result, Err(DePINError::Unauthorized)));
    }
}
