//! Block data structures for FryChain

use crate::address::Address;
use crate::merkle::MerkleTree;
use crate::transaction::SignedTransaction;
use crate::types::{BlockHeight, Difficulty, Hash256, Nonce};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Block header containing metadata and PoW solution
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Protocol version
    pub version: u32,
    /// Height of this block
    pub height: BlockHeight,
    /// Timestamp (Unix timestamp in seconds)
    pub timestamp: u64,
    /// Hash of the previous block
    pub parent_hash: Hash256,
    /// Merkle root of transactions
    pub transactions_root: Hash256,
    /// Merkle root of state after applying this block
    pub state_root: Hash256,
    /// Merkle root of transaction receipts
    pub receipts_root: Hash256,
    /// Address of the miner who solved this block
    pub miner: Address,
    /// Current difficulty target
    pub difficulty: Difficulty,
    /// Nonce that solves the PoW puzzle
    pub nonce: Nonce,
    /// Extra data (up to 32 bytes, for miner messages)
    pub extra_data: Vec<u8>,
    /// Total gas used in this block
    pub gas_used: u64,
    /// Gas limit for this block
    pub gas_limit: u64,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        height: BlockHeight,
        parent_hash: Hash256,
        miner: Address,
        difficulty: Difficulty,
    ) -> Self {
        Self {
            version: 1,
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            parent_hash,
            transactions_root: Hash256::zero(),
            state_root: Hash256::zero(),
            receipts_root: Hash256::zero(),
            miner,
            difficulty,
            nonce: Nonce::new(0),
            extra_data: Vec::new(),
            gas_used: 0,
            gas_limit: 30_000_000, // Default 30M gas limit
        }
    }

    /// Calculate the hash of this header (used for PoW)
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.height.0.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(self.parent_hash.as_bytes());
        hasher.update(self.transactions_root.as_bytes());
        hasher.update(self.state_root.as_bytes());
        hasher.update(self.receipts_root.as_bytes());
        hasher.update(self.miner.as_bytes());
        hasher.update(&self.difficulty.0.to_le_bytes());
        hasher.update(&self.nonce.0.to_le_bytes());
        hasher.update(&self.extra_data);
        hasher.update(&self.gas_used.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Get serializable bytes for mining (CryptoNight-STC input)
    pub fn mining_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(256);
        blob.extend_from_slice(&self.version.to_le_bytes());
        blob.extend_from_slice(&self.height.0.to_le_bytes());
        blob.extend_from_slice(&self.timestamp.to_le_bytes());
        blob.extend_from_slice(self.parent_hash.as_bytes());
        blob.extend_from_slice(self.transactions_root.as_bytes());
        blob.extend_from_slice(self.state_root.as_bytes());
        blob.extend_from_slice(self.receipts_root.as_bytes());
        blob.extend_from_slice(self.miner.as_bytes());
        blob.extend_from_slice(&self.difficulty.0.to_le_bytes());
        blob.extend_from_slice(&self.nonce.0.to_le_bytes());
        blob
    }

    /// Check if this header's PoW is valid
    pub fn verify_pow(&self, pow_hash: &Hash256) -> bool {
        let target = self.difficulty.to_target();
        pow_hash.meets_difficulty(&target)
    }

    /// Set timestamp to current time
    pub fn update_timestamp(&mut self) {
        self.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Block body containing transactions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockBody {
    /// Transactions in this block
    pub transactions: Vec<SignedTransaction>,
}

impl BlockBody {
    /// Create a new block body
    pub fn new(transactions: Vec<SignedTransaction>) -> Self {
        Self { transactions }
    }

    /// Create an empty block body
    pub fn empty() -> Self {
        Self {
            transactions: Vec::new(),
        }
    }

    /// Calculate the Merkle root of transactions
    pub fn calculate_transactions_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::zero();
        }

        let tx_hashes: Vec<Hash256> = self.transactions.iter().map(|tx| tx.hash()).collect();

        let merkle_tree = MerkleTree::from_hashes(tx_hashes);
        merkle_tree.root()
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Calculate total size in bytes
    pub fn size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }
}

/// A complete block
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Block body
    pub body: BlockBody,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// Create the genesis block
    pub fn genesis(miner: Address, initial_difficulty: Difficulty) -> Self {
        let mut header = BlockHeader::new(
            BlockHeight::genesis(),
            Hash256::zero(),
            miner,
            initial_difficulty,
        );
        header.timestamp = 1704067200; // 2024-01-01 00:00:00 UTC
        header.extra_data = b"FryChain Genesis Block".to_vec();

        Self {
            header,
            body: BlockBody::empty(),
        }
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// Get the block height
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Get the parent hash
    pub fn parent_hash(&self) -> Hash256 {
        self.header.parent_hash
    }

    /// Get the miner address
    pub fn miner(&self) -> Address {
        self.header.miner
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Get the difficulty
    pub fn difficulty(&self) -> Difficulty {
        self.header.difficulty
    }

    /// Get transactions
    pub fn transactions(&self) -> &[SignedTransaction] {
        &self.body.transactions
    }

    /// Get transaction count
    pub fn tx_count(&self) -> usize {
        self.body.tx_count()
    }

    /// Calculate total block size
    pub fn size(&self) -> usize {
        bincode::serialized_size(self).unwrap_or(0) as usize
    }

    /// Finalize block before mining (calculate merkle roots)
    pub fn finalize(&mut self) {
        self.header.transactions_root = self.body.calculate_transactions_root();
    }

    /// Verify block structure (not PoW or state transitions)
    pub fn verify_structure(&self) -> Result<(), &'static str> {
        // Check transactions root
        let calculated_root = self.body.calculate_transactions_root();
        if calculated_root != self.header.transactions_root {
            return Err("Invalid transactions root");
        }

        // Check block size
        if self.size() > crate::MAX_BLOCK_SIZE {
            return Err("Block too large");
        }

        // Check transaction count
        if self.tx_count() > crate::MAX_TXS_PER_BLOCK {
            return Err("Too many transactions");
        }

        // Check extra data size
        if self.header.extra_data.len() > 32 {
            return Err("Extra data too long");
        }

        Ok(())
    }
}

/// Block with additional metadata for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredBlock {
    /// The block
    pub block: Block,
    /// PoW hash (CryptoNight-STC result)
    pub pow_hash: Hash256,
    /// Total difficulty up to and including this block
    pub total_difficulty: u128,
    /// Whether this block is on the canonical chain
    pub is_canonical: bool,
}

impl StoredBlock {
    pub fn new(block: Block, pow_hash: Hash256, total_difficulty: u128) -> Self {
        Self {
            block,
            pow_hash,
            total_difficulty,
            is_canonical: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let miner = Address::from_public_key(&[1u8; 64]);
        let genesis = Block::genesis(miner, Difficulty::INITIAL);

        assert_eq!(genesis.height().0, 0);
        assert!(genesis.parent_hash().is_zero());
        assert_eq!(genesis.tx_count(), 0);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let miner = Address::from_public_key(&[1u8; 64]);
        let block = Block::genesis(miner, Difficulty::INITIAL);

        let hash1 = block.hash();
        let hash2 = block.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_finalize() {
        let miner = Address::from_public_key(&[1u8; 64]);
        let mut block = Block::genesis(miner, Difficulty::INITIAL);
        block.finalize();

        assert!(block.verify_structure().is_ok());
    }
}
