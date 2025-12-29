//! Chain storage for blocks and transactions

use crate::db::{cf, Database, StorageBatch};
use crate::{StorageError, StorageResult};
use frychain_core::block::{Block, BlockHeader, StoredBlock};
use frychain_core::transaction::{SignedTransaction, TransactionReceipt};
use frychain_core::types::{BlockHeight, Hash256};

/// Chain storage for blocks, transactions, and receipts
#[derive(Clone)]
pub struct ChainStore {
    db: Database,
}

impl ChainStore {
    /// Create a new chain store
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ========== Block Operations ==========

    /// Store a block with its PoW hash and total difficulty
    pub fn put_block(&self, block: &StoredBlock) -> StorageResult<()> {
        let hash = block.block.hash();
        let height = block.block.height();

        let mut batch = StorageBatch::new();

        // Store header
        let header_bytes = bincode::serialize(&block.block.header)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        batch.put(cf::HEADERS, hash.as_bytes().to_vec(), header_bytes);

        // Store body
        let body_bytes = bincode::serialize(&block.block.body)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        batch.put(cf::BODIES, hash.as_bytes().to_vec(), body_bytes);

        // Store height -> hash mapping (for canonical chain)
        if block.is_canonical {
            batch.put(
                cf::HEIGHT_TO_HASH,
                height.0.to_be_bytes().to_vec(),
                hash.as_bytes().to_vec(),
            );
        }

        // Store metadata (PoW hash, total difficulty, canonical status)
        let meta = BlockMeta {
            pow_hash: block.pow_hash,
            total_difficulty: block.total_difficulty,
            is_canonical: block.is_canonical,
        };
        let meta_bytes = bincode::serialize(&meta)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        batch.put(cf::META, format!("block:{}", hash).into_bytes(), meta_bytes);

        // Store transactions
        for (idx, tx) in block.block.body.transactions.iter().enumerate() {
            let tx_hash = tx.hash();
            let tx_loc = TxLocation {
                block_hash: hash,
                block_height: height.0,
                tx_index: idx as u32,
            };
            let loc_bytes = bincode::serialize(&tx_loc)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            batch.put(cf::TRANSACTIONS, tx_hash.as_bytes().to_vec(), loc_bytes);
        }

        self.db.write_batch(batch)
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &Hash256) -> StorageResult<Option<Block>> {
        let header = match self.get_header(hash)? {
            Some(h) => h,
            None => return Ok(None),
        };

        let body_bytes = match self.db.get(cf::BODIES, hash.as_bytes())? {
            Some(b) => b,
            None => return Ok(None),
        };

        let body = bincode::deserialize(&body_bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

        Ok(Some(Block::new(header, body)))
    }

    /// Get a stored block (with metadata) by hash
    pub fn get_stored_block(&self, hash: &Hash256) -> StorageResult<Option<StoredBlock>> {
        let block = match self.get_block(hash)? {
            Some(b) => b,
            None => return Ok(None),
        };

        let meta = match self.get_block_meta(hash)? {
            Some(m) => m,
            None => return Ok(None),
        };

        Ok(Some(StoredBlock {
            block,
            pow_hash: meta.pow_hash,
            total_difficulty: meta.total_difficulty,
            is_canonical: meta.is_canonical,
        }))
    }

    /// Get a block header by hash
    pub fn get_header(&self, hash: &Hash256) -> StorageResult<Option<BlockHeader>> {
        let bytes = match self.db.get(cf::HEADERS, hash.as_bytes())? {
            Some(b) => b,
            None => return Ok(None),
        };

        let header = bincode::deserialize(&bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

        Ok(Some(header))
    }

    /// Get block by height (canonical chain only)
    pub fn get_block_by_height(&self, height: BlockHeight) -> StorageResult<Option<Block>> {
        let hash = match self.get_hash_by_height(height)? {
            Some(h) => h,
            None => return Ok(None),
        };

        self.get_block(&hash)
    }

    /// Get block hash by height
    pub fn get_hash_by_height(&self, height: BlockHeight) -> StorageResult<Option<Hash256>> {
        let bytes = match self.db.get(cf::HEIGHT_TO_HASH, &height.0.to_be_bytes())? {
            Some(b) => b,
            None => return Ok(None),
        };

        if bytes.len() != 32 {
            return Err(StorageError::DeserializationError(
                "Invalid hash length".to_string(),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Some(Hash256(hash)))
    }

    /// Get block metadata
    fn get_block_meta(&self, hash: &Hash256) -> StorageResult<Option<BlockMeta>> {
        let bytes = match self
            .db
            .get(cf::META, format!("block:{}", hash).as_bytes())?
        {
            Some(b) => b,
            None => return Ok(None),
        };

        let meta = bincode::deserialize(&bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

        Ok(Some(meta))
    }

    /// Check if a block exists
    pub fn has_block(&self, hash: &Hash256) -> StorageResult<bool> {
        self.db.contains(cf::HEADERS, hash.as_bytes())
    }

    // ========== Transaction Operations ==========

    /// Get a transaction by hash
    pub fn get_transaction(&self, hash: &Hash256) -> StorageResult<Option<SignedTransaction>> {
        let loc = match self.get_tx_location(hash)? {
            Some(l) => l,
            None => return Ok(None),
        };

        let block = match self.get_block(&loc.block_hash)? {
            Some(b) => b,
            None => return Ok(None),
        };

        block
            .body
            .transactions
            .get(loc.tx_index as usize)
            .cloned()
            .map(Some)
            .ok_or_else(|| StorageError::TransactionNotFound(hash.to_string()))
    }

    /// Get transaction location
    pub fn get_tx_location(&self, hash: &Hash256) -> StorageResult<Option<TxLocation>> {
        let bytes = match self.db.get(cf::TRANSACTIONS, hash.as_bytes())? {
            Some(b) => b,
            None => return Ok(None),
        };

        let loc = bincode::deserialize(&bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

        Ok(Some(loc))
    }

    /// Store a transaction receipt
    pub fn put_receipt(&self, tx_hash: &Hash256, receipt: &TransactionReceipt) -> StorageResult<()> {
        let bytes = bincode::serialize(receipt)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put(cf::RECEIPTS, tx_hash.as_bytes(), &bytes)
    }

    /// Get a transaction receipt
    pub fn get_receipt(&self, tx_hash: &Hash256) -> StorageResult<Option<TransactionReceipt>> {
        let bytes = match self.db.get(cf::RECEIPTS, tx_hash.as_bytes())? {
            Some(b) => b,
            None => return Ok(None),
        };

        let receipt = bincode::deserialize(&bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

        Ok(Some(receipt))
    }

    // ========== Chain State Operations ==========

    /// Get the latest block height
    pub fn get_latest_height(&self) -> StorageResult<Option<BlockHeight>> {
        let bytes = match self.db.get(cf::META, b"latest_height")? {
            Some(b) => b,
            None => return Ok(None),
        };

        if bytes.len() != 8 {
            return Err(StorageError::DeserializationError(
                "Invalid height encoding".to_string(),
            ));
        }

        let height = u64::from_be_bytes(bytes.try_into().unwrap());
        Ok(Some(BlockHeight(height)))
    }

    /// Set the latest block height
    pub fn set_latest_height(&self, height: BlockHeight) -> StorageResult<()> {
        self.db
            .put(cf::META, b"latest_height", &height.0.to_be_bytes())
    }

    /// Get the latest block hash
    pub fn get_latest_hash(&self) -> StorageResult<Option<Hash256>> {
        match self.get_latest_height()? {
            Some(height) => self.get_hash_by_height(height),
            None => Ok(None),
        }
    }

    /// Get the genesis block hash
    pub fn get_genesis_hash(&self) -> StorageResult<Option<Hash256>> {
        self.get_hash_by_height(BlockHeight::genesis())
    }

    /// Get total difficulty at a block
    pub fn get_total_difficulty(&self, hash: &Hash256) -> StorageResult<Option<u128>> {
        self.get_block_meta(hash)
            .map(|opt| opt.map(|m| m.total_difficulty))
    }
}

/// Block metadata stored separately
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct BlockMeta {
    pow_hash: Hash256,
    total_difficulty: u128,
    is_canonical: bool,
}

/// Transaction location in a block
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxLocation {
    pub block_hash: Hash256,
    pub block_height: u64,
    pub tx_index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::address::Address;
    use frychain_core::block::BlockBody;
    use frychain_core::types::Difficulty;
    use tempfile::tempdir;

    #[test]
    fn test_store_and_retrieve_block() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let store = ChainStore::new(db);

        let miner = Address::from_public_key(&[1u8; 64]);
        let block = Block::genesis(miner, Difficulty::INITIAL);
        let stored = StoredBlock::new(block.clone(), block.hash(), 1000);

        store.put_block(&stored).unwrap();

        let retrieved = store.get_block(&block.hash()).unwrap().unwrap();
        assert_eq!(retrieved.height(), block.height());
        assert_eq!(retrieved.hash(), block.hash());
    }

    #[test]
    fn test_block_by_height() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let store = ChainStore::new(db);

        let miner = Address::from_public_key(&[1u8; 64]);
        let block = Block::genesis(miner, Difficulty::INITIAL);
        let stored = StoredBlock::new(block.clone(), block.hash(), 1000);

        store.put_block(&stored).unwrap();

        let hash = store.get_hash_by_height(BlockHeight::genesis()).unwrap();
        assert_eq!(hash, Some(block.hash()));

        let retrieved = store
            .get_block_by_height(BlockHeight::genesis())
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.hash(), block.hash());
    }
}
