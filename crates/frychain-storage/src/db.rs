//! RocksDB database wrapper

use crate::{StorageError, StorageResult};
use parking_lot::RwLock;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;

/// Column family names
pub mod cf {
    /// Block headers
    pub const HEADERS: &str = "headers";
    /// Block bodies
    pub const BODIES: &str = "bodies";
    /// Block hashes by height
    pub const HEIGHT_TO_HASH: &str = "height_to_hash";
    /// Transactions
    pub const TRANSACTIONS: &str = "transactions";
    /// Transaction receipts
    pub const RECEIPTS: &str = "receipts";
    /// Account state
    pub const ACCOUNTS: &str = "accounts";
    /// Contract code
    pub const CODE: &str = "code";
    /// Contract storage
    pub const STORAGE: &str = "storage";
    /// Chain metadata
    pub const META: &str = "meta";
    /// DePIN device registry
    pub const DEVICES: &str = "devices";
}

/// All column families
pub const ALL_CFS: &[&str] = &[
    cf::HEADERS,
    cf::BODIES,
    cf::HEIGHT_TO_HASH,
    cf::TRANSACTIONS,
    cf::RECEIPTS,
    cf::ACCOUNTS,
    cf::CODE,
    cf::STORAGE,
    cf::META,
    cf::DEVICES,
];

/// Database configuration
#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    /// Create if missing
    pub create_if_missing: bool,
    /// Max open files
    pub max_open_files: i32,
    /// Write buffer size (per column family)
    pub write_buffer_size: usize,
    /// Max write buffers
    pub max_write_buffer_number: i32,
    /// Enable compression
    pub compression: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            create_if_missing: true,
            max_open_files: 512,
            write_buffer_size: 64 * 1024 * 1024, // 64 MB
            max_write_buffer_number: 3,
            compression: true,
        }
    }
}

/// RocksDB wrapper
pub struct Database {
    db: Arc<RwLock<DB>>,
}

impl Database {
    /// Open database at the given path
    pub fn open<P: AsRef<Path>>(path: P, config: DatabaseConfig) -> StorageResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(config.max_open_files);

        let cf_opts = Options::default();
        let cfs: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, cf_opts.clone()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))?;

        Ok(Self {
            db: Arc::new(RwLock::new(db)),
        })
    }

    /// Open database with default configuration
    pub fn open_default<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        Self::open(path, DatabaseConfig::default())
    }

    /// Get a value from a column family
    pub fn get(&self, cf_name: &str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let db = self.db.read();
        let cf = db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::DatabaseError(format!("CF not found: {}", cf_name)))?;

        db.get_cf(cf, key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Put a value into a column family
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let db = self.db.read();
        let cf = db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::DatabaseError(format!("CF not found: {}", cf_name)))?;

        db.put_cf(cf, key, value)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Delete a value from a column family
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> StorageResult<()> {
        let db = self.db.read();
        let cf = db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::DatabaseError(format!("CF not found: {}", cf_name)))?;

        db.delete_cf(cf, key)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Check if a key exists
    pub fn contains(&self, cf_name: &str, key: &[u8]) -> StorageResult<bool> {
        Ok(self.get(cf_name, key)?.is_some())
    }

    /// Write a batch of operations atomically
    pub fn write_batch(&self, batch: StorageBatch) -> StorageResult<()> {
        let db = self.db.read();
        let mut write_batch = WriteBatch::default();

        for op in batch.operations {
            let cf = db.cf_handle(&op.cf_name).ok_or_else(|| {
                StorageError::DatabaseError(format!("CF not found: {}", op.cf_name))
            })?;

            match op.op_type {
                BatchOpType::Put => {
                    write_batch.put_cf(cf, &op.key, op.value.as_ref().unwrap());
                }
                BatchOpType::Delete => {
                    write_batch.delete_cf(cf, &op.key);
                }
            }
        }

        db.write(write_batch)
            .map_err(|e| StorageError::DatabaseError(e.to_string()))
    }

    /// Iterate over all entries in a column family
    pub fn iter(&self, cf_name: &str) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let db = self.db.read();
        let cf = db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::DatabaseError(format!("CF not found: {}", cf_name)))?;

        let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();

        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::DatabaseError(e.to_string()))?;
            results.push((key.to_vec(), value.to_vec()));
        }

        Ok(results)
    }

    /// Get database statistics
    pub fn stats(&self) -> String {
        let db = self.db.read();
        db.property_value("rocksdb.stats")
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Clone the Arc for sharing
    pub fn clone_arc(&self) -> Arc<RwLock<DB>> {
        Arc::clone(&self.db)
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
        }
    }
}

/// Batch operation type
#[derive(Clone, Debug)]
pub enum BatchOpType {
    Put,
    Delete,
}

/// Single batch operation
#[derive(Clone, Debug)]
pub struct BatchOp {
    cf_name: String,
    op_type: BatchOpType,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

/// Storage batch for atomic writes
#[derive(Clone, Debug, Default)]
pub struct StorageBatch {
    operations: Vec<BatchOp>,
}

impl StorageBatch {
    /// Create a new batch
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a put operation
    pub fn put(&mut self, cf_name: &str, key: Vec<u8>, value: Vec<u8>) {
        self.operations.push(BatchOp {
            cf_name: cf_name.to_string(),
            op_type: BatchOpType::Put,
            key,
            value: Some(value),
        });
    }

    /// Add a delete operation
    pub fn delete(&mut self, cf_name: &str, key: Vec<u8>) {
        self.operations.push(BatchOp {
            cf_name: cf_name.to_string(),
            op_type: BatchOpType::Delete,
            key,
            value: None,
        });
    }

    /// Get the number of operations
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_open_close() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        drop(db);
    }

    #[test]
    fn test_put_get_delete() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();

        db.put(cf::META, b"test_key", b"test_value").unwrap();

        let value = db.get(cf::META, b"test_key").unwrap();
        assert_eq!(value, Some(b"test_value".to_vec()));

        db.delete(cf::META, b"test_key").unwrap();

        let value = db.get(cf::META, b"test_key").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_batch_write() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();

        let mut batch = StorageBatch::new();
        batch.put(cf::META, b"key1".to_vec(), b"value1".to_vec());
        batch.put(cf::META, b"key2".to_vec(), b"value2".to_vec());

        db.write_batch(batch).unwrap();

        assert_eq!(db.get(cf::META, b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(db.get(cf::META, b"key2").unwrap(), Some(b"value2".to_vec()));
    }
}
