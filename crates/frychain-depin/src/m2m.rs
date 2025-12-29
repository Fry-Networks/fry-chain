//! Machine-to-Machine (M2M) transaction protocol

use crate::did::DeviceDID;
use crate::{DePINError, DePINResult};
use frychain_core::address::Address;
use frychain_core::types::{Hash256, TokenAmount};
use serde::{Deserialize, Serialize};

/// M2M transaction types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum M2MTransactionType {
    /// Device data submission
    DataSubmission,
    /// Device service request
    ServiceRequest,
    /// Device service response
    ServiceResponse,
    /// Device heartbeat/status update
    Heartbeat,
    /// Device task assignment
    TaskAssignment,
    /// Device task completion
    TaskCompletion,
    /// Device reward distribution
    Reward,
}

/// M2M transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct M2MTransaction {
    /// Transaction type
    pub tx_type: M2MTransactionType,
    /// Source device DID
    pub from_device: DeviceDID,
    /// Target device DID (optional for broadcasts)
    pub to_device: Option<DeviceDID>,
    /// Transaction nonce
    pub nonce: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Payload data
    pub payload: Vec<u8>,
    /// Value transfer (if any)
    pub value: TokenAmount,
    /// Signature by source device
    pub signature: Vec<u8>,
}

impl M2MTransaction {
    /// Create a new M2M transaction
    pub fn new(
        tx_type: M2MTransactionType,
        from_device: DeviceDID,
        to_device: Option<DeviceDID>,
        nonce: u64,
        payload: Vec<u8>,
        value: TokenAmount,
    ) -> Self {
        Self {
            tx_type,
            from_device,
            to_device,
            nonce,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload,
            value,
            signature: Vec::new(),
        }
    }

    /// Create a data submission transaction
    pub fn data_submission(from: DeviceDID, data: Vec<u8>, nonce: u64) -> Self {
        Self::new(
            M2MTransactionType::DataSubmission,
            from,
            None,
            nonce,
            data,
            TokenAmount::ZERO,
        )
    }

    /// Create a heartbeat transaction
    pub fn heartbeat(from: DeviceDID, status: DeviceHeartbeat, nonce: u64) -> Self {
        let payload = serde_json::to_vec(&status).unwrap_or_default();
        Self::new(
            M2MTransactionType::Heartbeat,
            from,
            None,
            nonce,
            payload,
            TokenAmount::ZERO,
        )
    }

    /// Create a task assignment transaction
    pub fn task_assignment(
        from: DeviceDID,
        to: DeviceDID,
        task: TaskAssignment,
        reward: TokenAmount,
        nonce: u64,
    ) -> Self {
        let payload = serde_json::to_vec(&task).unwrap_or_default();
        Self::new(
            M2MTransactionType::TaskAssignment,
            from,
            Some(to),
            nonce,
            payload,
            reward,
        )
    }

    /// Create a task completion transaction
    pub fn task_completion(
        from: DeviceDID,
        to: DeviceDID,
        result: TaskResult,
        nonce: u64,
    ) -> Self {
        let payload = serde_json::to_vec(&result).unwrap_or_default();
        Self::new(
            M2MTransactionType::TaskCompletion,
            from,
            Some(to),
            nonce,
            payload,
            TokenAmount::ZERO,
        )
    }

    /// Get the transaction hash
    pub fn hash(&self) -> Hash256 {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&[self.tx_type.clone() as u8]);
        hasher.update(self.from_device.as_str().as_bytes());
        if let Some(ref to) = self.to_device {
            hasher.update(to.as_str().as_bytes());
        }
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.payload);
        hasher.update(&self.value.0.to_le_bytes());

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Set signature
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Device heartbeat data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceHeartbeat {
    /// Device status
    pub status: String,
    /// CPU usage (0-100)
    pub cpu_usage: u8,
    /// Memory usage (0-100)
    pub memory_usage: u8,
    /// Disk usage (0-100)
    pub disk_usage: u8,
    /// Network latency in ms
    pub network_latency: u32,
    /// Current tasks count
    pub active_tasks: u32,
    /// Custom metrics
    pub custom_metrics: Vec<(String, String)>,
}

impl DeviceHeartbeat {
    pub fn new() -> Self {
        Self {
            status: "online".to_string(),
            cpu_usage: 0,
            memory_usage: 0,
            disk_usage: 0,
            network_latency: 0,
            active_tasks: 0,
            custom_metrics: Vec::new(),
        }
    }
}

impl Default for DeviceHeartbeat {
    fn default() -> Self {
        Self::new()
    }
}

/// Task assignment data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskAssignment {
    /// Task ID
    pub task_id: String,
    /// Task type
    pub task_type: String,
    /// Task parameters
    pub parameters: serde_json::Value,
    /// Deadline (Unix timestamp)
    pub deadline: u64,
    /// Offered reward
    pub reward: TokenAmount,
    /// Required attestation
    pub requires_attestation: bool,
}

/// Task result data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task ID
    pub task_id: String,
    /// Success status
    pub success: bool,
    /// Result data
    pub result: serde_json::Value,
    /// Completion timestamp
    pub completed_at: u64,
    /// Attestation (if required)
    pub attestation: Option<Vec<u8>>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// M2M protocol handler
pub struct M2MProtocol {
    /// Pending transactions
    pending: Vec<M2MTransaction>,
    /// Completed transactions
    completed: Vec<M2MTransaction>,
}

impl M2MProtocol {
    /// Create a new M2M protocol handler
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            completed: Vec::new(),
        }
    }

    /// Submit a transaction
    pub fn submit(&mut self, tx: M2MTransaction) -> DePINResult<Hash256> {
        let hash = tx.hash();
        self.pending.push(tx);
        Ok(hash)
    }

    /// Get pending transaction count
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Process pending transactions
    pub fn process_pending(&mut self) -> Vec<M2MTransaction> {
        let processed: Vec<_> = self.pending.drain(..).collect();
        self.completed.extend(processed.clone());
        processed
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, hash: &Hash256) -> Option<&M2MTransaction> {
        self.pending
            .iter()
            .chain(self.completed.iter())
            .find(|tx| tx.hash() == *hash)
    }
}

impl Default for M2MProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_device_did() -> DeviceDID {
        let address = Address::device_address(&[1u8; 32], b"test-device");
        DeviceDID::new(address)
    }

    #[test]
    fn test_m2m_data_submission() {
        let did = create_device_did();
        let tx = M2MTransaction::data_submission(did.clone(), vec![1, 2, 3], 1);

        assert_eq!(tx.tx_type, M2MTransactionType::DataSubmission);
        assert_eq!(tx.from_device, did);
        assert!(!tx.hash().is_zero());
    }

    #[test]
    fn test_m2m_heartbeat() {
        let did = create_device_did();
        let heartbeat = DeviceHeartbeat {
            status: "online".to_string(),
            cpu_usage: 50,
            memory_usage: 60,
            disk_usage: 70,
            network_latency: 100,
            active_tasks: 2,
            custom_metrics: Vec::new(),
        };

        let tx = M2MTransaction::heartbeat(did, heartbeat, 1);
        assert_eq!(tx.tx_type, M2MTransactionType::Heartbeat);
    }

    #[test]
    fn test_m2m_protocol() {
        let mut protocol = M2MProtocol::new();
        let did = create_device_did();

        let tx = M2MTransaction::data_submission(did, vec![1, 2, 3], 1);
        let hash = protocol.submit(tx.clone()).unwrap();

        assert_eq!(protocol.pending_count(), 1);
        assert!(protocol.get_transaction(&hash).is_some());
    }
}
