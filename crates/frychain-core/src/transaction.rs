//! Transaction types for FryChain

use crate::address::Address;
use crate::types::{Gas, GasPrice, Hash256, Nonce, TokenAmount};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Transaction type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Simple token transfer
    Transfer,
    /// Deploy a new smart contract
    ContractDeploy,
    /// Call an existing smart contract
    ContractCall,
    /// DePIN device registration
    DeviceRegister,
    /// DePIN device data submission
    DeviceData,
    /// DePIN device deregistration
    DeviceDeregister,
    /// Stake tokens for rewards
    Stake,
    /// Unstake tokens
    Unstake,
}

impl TransactionType {
    /// Get the type ID for serialization
    pub fn type_id(&self) -> u8 {
        match self {
            TransactionType::Transfer => 0,
            TransactionType::ContractDeploy => 1,
            TransactionType::ContractCall => 2,
            TransactionType::DeviceRegister => 3,
            TransactionType::DeviceData => 4,
            TransactionType::DeviceDeregister => 5,
            TransactionType::Stake => 6,
            TransactionType::Unstake => 7,
        }
    }

    /// Create from type ID
    pub fn from_type_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(TransactionType::Transfer),
            1 => Some(TransactionType::ContractDeploy),
            2 => Some(TransactionType::ContractCall),
            3 => Some(TransactionType::DeviceRegister),
            4 => Some(TransactionType::DeviceData),
            5 => Some(TransactionType::DeviceDeregister),
            6 => Some(TransactionType::Stake),
            7 => Some(TransactionType::Unstake),
            _ => None,
        }
    }
}

/// Core transaction data (unsigned)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    pub tx_type: TransactionType,
    /// Sender address
    pub from: Address,
    /// Recipient address (zero for contract deploy)
    pub to: Address,
    /// Amount to transfer
    pub value: TokenAmount,
    /// Transaction nonce (sender's transaction count)
    pub nonce: Nonce,
    /// Gas limit for execution
    pub gas_limit: Gas,
    /// Gas price per unit
    pub gas_price: GasPrice,
    /// Input data (contract code for deploy, call data for calls)
    pub data: Vec<u8>,
    /// Chain ID for replay protection
    pub chain_id: u64,
}

impl Transaction {
    /// Create a simple transfer transaction
    pub fn transfer(
        from: Address,
        to: Address,
        value: TokenAmount,
        nonce: Nonce,
        gas_price: GasPrice,
        chain_id: u64,
    ) -> Self {
        Self {
            tx_type: TransactionType::Transfer,
            from,
            to,
            value,
            nonce,
            gas_limit: Gas::TRANSFER_MIN,
            gas_price,
            data: Vec::new(),
            chain_id,
        }
    }

    /// Create a contract deployment transaction
    pub fn contract_deploy(
        from: Address,
        bytecode: Vec<u8>,
        value: TokenAmount,
        nonce: Nonce,
        gas_limit: Gas,
        gas_price: GasPrice,
        chain_id: u64,
    ) -> Self {
        Self {
            tx_type: TransactionType::ContractDeploy,
            from,
            to: Address::zero(),
            value,
            nonce,
            gas_limit,
            gas_price,
            data: bytecode,
            chain_id,
        }
    }

    /// Create a contract call transaction
    pub fn contract_call(
        from: Address,
        contract: Address,
        call_data: Vec<u8>,
        value: TokenAmount,
        nonce: Nonce,
        gas_limit: Gas,
        gas_price: GasPrice,
        chain_id: u64,
    ) -> Self {
        Self {
            tx_type: TransactionType::ContractCall,
            from,
            to: contract,
            value,
            nonce,
            gas_limit,
            gas_price,
            data: call_data,
            chain_id,
        }
    }

    /// Create a device registration transaction
    pub fn device_register(
        from: Address,
        device_data: Vec<u8>,
        nonce: Nonce,
        gas_price: GasPrice,
        chain_id: u64,
    ) -> Self {
        Self {
            tx_type: TransactionType::DeviceRegister,
            from,
            to: crate::address::system_addresses::DEPIN_REGISTRY.clone(),
            value: TokenAmount::ZERO,
            nonce,
            gas_limit: Gas::new(100_000),
            gas_price,
            data: device_data,
            chain_id,
        }
    }

    /// Calculate the hash of this transaction (for signing)
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(&[self.tx_type.type_id()]);
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(&self.value.0.to_le_bytes());
        hasher.update(&self.nonce.0.to_le_bytes());
        hasher.update(&self.gas_limit.0.to_le_bytes());
        hasher.update(&self.gas_price.0.to_le_bytes());
        hasher.update(&(self.data.len() as u32).to_le_bytes());
        hasher.update(&self.data);
        hasher.update(&self.chain_id.to_le_bytes());

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Calculate the maximum fee this transaction can cost
    pub fn max_fee(&self) -> TokenAmount {
        self.gas_price.total_fee(self.gas_limit)
    }

    /// Calculate the total cost (value + max fee)
    pub fn total_cost(&self) -> TokenAmount {
        TokenAmount(self.value.0 + self.max_fee().0)
    }

    /// Estimate the gas for this transaction
    pub fn estimate_gas(&self) -> Gas {
        let base_gas = match self.tx_type {
            TransactionType::Transfer => Gas::TRANSFER_MIN.0,
            TransactionType::ContractDeploy => Gas::CONTRACT_CREATE.0 + Gas::TRANSFER_MIN.0,
            TransactionType::ContractCall => Gas::TRANSFER_MIN.0,
            TransactionType::DeviceRegister => 100_000,
            TransactionType::DeviceData => 50_000,
            TransactionType::DeviceDeregister => 50_000,
            TransactionType::Stake => 50_000,
            TransactionType::Unstake => 50_000,
        };

        let data_gas = self.data.len() as u64 * Gas::PER_BYTE.0;
        Gas::new(base_gas + data_gas)
    }

    /// Get the expected contract address (for deploy transactions)
    pub fn contract_address(&self) -> Option<Address> {
        if matches!(self.tx_type, TransactionType::ContractDeploy) {
            Some(Address::contract_address(&self.from, self.nonce.0))
        } else {
            None
        }
    }
}

/// Signature type (post-quantum or classical)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    /// CRYSTALS-Dilithium post-quantum signature
    Dilithium,
    /// SPHINCS+ post-quantum signature
    SphincsPlus,
    /// Ed25519 classical signature (for compatibility)
    Ed25519,
}

/// Post-quantum signature
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Signature type
    pub sig_type: SignatureType,
    /// Signature bytes
    pub bytes: Vec<u8>,
    /// Public key bytes (needed for verification)
    pub public_key: Vec<u8>,
}

impl Signature {
    /// Create a new signature
    pub fn new(sig_type: SignatureType, bytes: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            sig_type,
            bytes,
            public_key,
        }
    }

    /// Check if this is a post-quantum signature
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self.sig_type,
            SignatureType::Dilithium | SignatureType::SphincsPlus
        )
    }
}

/// A signed transaction
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The transaction
    pub transaction: Transaction,
    /// The signature
    pub signature: Signature,
}

impl SignedTransaction {
    /// Create a new signed transaction
    pub fn new(transaction: Transaction, signature: Signature) -> Self {
        Self {
            transaction,
            signature,
        }
    }

    /// Get the transaction hash (for indexing)
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(self.transaction.hash().as_bytes());
        hasher.update(&self.signature.bytes);

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Get the sender address
    pub fn sender(&self) -> Address {
        self.transaction.from
    }

    /// Get the recipient address
    pub fn recipient(&self) -> Address {
        self.transaction.to
    }

    /// Get the nonce
    pub fn nonce(&self) -> Nonce {
        self.transaction.nonce
    }

    /// Get the value
    pub fn value(&self) -> TokenAmount {
        self.transaction.value
    }

    /// Get the gas limit
    pub fn gas_limit(&self) -> Gas {
        self.transaction.gas_limit
    }

    /// Get the gas price
    pub fn gas_price(&self) -> GasPrice {
        self.transaction.gas_price
    }

    /// Get the data
    pub fn data(&self) -> &[u8] {
        &self.transaction.data
    }

    /// Get the transaction type
    pub fn tx_type(&self) -> &TransactionType {
        &self.transaction.tx_type
    }

    /// Calculate size in bytes
    pub fn size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
}

/// Transaction receipt (result of execution)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: Hash256,
    /// Block hash
    pub block_hash: Hash256,
    /// Block height
    pub block_height: u64,
    /// Index in block
    pub tx_index: u32,
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Address,
    /// Contract address (if deployment)
    pub contract_address: Option<Address>,
    /// Gas used
    pub gas_used: Gas,
    /// Execution success
    pub success: bool,
    /// Return data
    pub return_data: Vec<u8>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Logs emitted
    pub logs: Vec<Log>,
}

/// Event log from contract execution
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    /// Contract address that emitted this log
    pub address: Address,
    /// Log topics (indexed parameters)
    pub topics: Vec<Hash256>,
    /// Log data (non-indexed parameters)
    pub data: Vec<u8>,
}

impl TransactionReceipt {
    /// Create a successful receipt
    pub fn success(
        tx_hash: Hash256,
        block_hash: Hash256,
        block_height: u64,
        tx_index: u32,
        from: Address,
        to: Address,
        gas_used: Gas,
    ) -> Self {
        Self {
            tx_hash,
            block_hash,
            block_height,
            tx_index,
            from,
            to,
            contract_address: None,
            gas_used,
            success: true,
            return_data: Vec::new(),
            error: None,
            logs: Vec::new(),
        }
    }

    /// Create a failed receipt
    pub fn failure(
        tx_hash: Hash256,
        block_hash: Hash256,
        block_height: u64,
        tx_index: u32,
        from: Address,
        to: Address,
        gas_used: Gas,
        error: String,
    ) -> Self {
        Self {
            tx_hash,
            block_hash,
            block_height,
            tx_index,
            from,
            to,
            contract_address: None,
            gas_used,
            success: false,
            return_data: Vec::new(),
            error: Some(error),
            logs: Vec::new(),
        }
    }

    /// Calculate receipt hash
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(self.tx_hash.as_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(&self.block_height.to_le_bytes());
        hasher.update(&self.tx_index.to_le_bytes());
        hasher.update(&[self.success as u8]);
        hasher.update(&self.gas_used.0.to_le_bytes());

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_transaction() {
        let from = Address::from_public_key(&[1u8; 64]);
        let to = Address::from_public_key(&[2u8; 64]);

        let tx = Transaction::transfer(
            from,
            to,
            TokenAmount::from_fry(100),
            Nonce::new(0),
            GasPrice::MIN,
            1,
        );

        assert_eq!(tx.tx_type, TransactionType::Transfer);
        assert_eq!(tx.from, from);
        assert_eq!(tx.to, to);
    }

    #[test]
    fn test_transaction_hash_deterministic() {
        let from = Address::from_public_key(&[1u8; 64]);
        let to = Address::from_public_key(&[2u8; 64]);

        let tx = Transaction::transfer(
            from,
            to,
            TokenAmount::from_fry(100),
            Nonce::new(0),
            GasPrice::MIN,
            1,
        );

        let hash1 = tx.hash();
        let hash2 = tx.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_contract_address_derivation() {
        let from = Address::from_public_key(&[1u8; 64]);

        let tx = Transaction::contract_deploy(
            from,
            vec![0x60, 0x80, 0x60, 0x40], // Dummy bytecode
            TokenAmount::ZERO,
            Nonce::new(0),
            Gas::new(1_000_000),
            GasPrice::MIN,
            1,
        );

        let contract_addr = tx.contract_address().unwrap();
        assert_eq!(contract_addr.addr_type, crate::address::AddressType::Contract);
    }
}
