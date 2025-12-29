//! FryChain DePIN (Decentralized Physical Infrastructure Network)
//!
//! Implements IoTeX and Peaq-inspired DePIN features:
//! - Device Identity (DID) management
//! - Device registration and verification
//! - Machine-to-Machine (M2M) transactions
//! - Data marketplace integration

pub mod did;
pub mod registry;
pub mod m2m;
pub mod data;

pub use did::{DeviceDID, DIDDocument};
pub use registry::{DeviceRegistry, DeviceInfo, DeviceStatus};
pub use m2m::{M2MTransaction, M2MProtocol};
pub use data::{DataMarketplace, DataListing};

use thiserror::Error;

/// DePIN errors
#[derive(Error, Debug)]
pub enum DePINError {
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Device already registered: {0}")]
    DeviceAlreadyRegistered(String),

    #[error("Invalid device signature")]
    InvalidDeviceSignature,

    #[error("Device suspended: {0}")]
    DeviceSuspended(String),

    #[error("Invalid DID document: {0}")]
    InvalidDIDDocument(String),

    #[error("Unauthorized operation")]
    Unauthorized,

    #[error("Invalid data listing: {0}")]
    InvalidDataListing(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Result type for DePIN operations
pub type DePINResult<T> = Result<T, DePINError>;
