//! State storage for accounts and contracts

use crate::db::{cf, Database, StorageBatch};
use crate::{StorageError, StorageResult};
use frychain_core::address::Address;
use frychain_core::state::{Account, StateChanges};
use frychain_core::types::Hash256;

/// State storage for accounts, code, and contract storage
#[derive(Clone)]
pub struct StateStore {
    db: Database,
}

impl StateStore {
    /// Create a new state store
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ========== Account Operations ==========

    /// Get an account by address
    pub fn get_account(&self, address: &Address) -> StorageResult<Option<Account>> {
        let bytes = match self.db.get(cf::ACCOUNTS, address.as_bytes())? {
            Some(b) => b,
            None => return Ok(None),
        };

        let account = bincode::deserialize(&bytes)
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;

        Ok(Some(account))
    }

    /// Store an account
    pub fn put_account(&self, account: &Account) -> StorageResult<()> {
        let bytes = bincode::serialize(account)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        self.db.put(cf::ACCOUNTS, account.address.as_bytes(), &bytes)
    }

    /// Delete an account
    pub fn delete_account(&self, address: &Address) -> StorageResult<()> {
        self.db.delete(cf::ACCOUNTS, address.as_bytes())
    }

    /// Check if an account exists
    pub fn has_account(&self, address: &Address) -> StorageResult<bool> {
        self.db.contains(cf::ACCOUNTS, address.as_bytes())
    }

    // ========== Contract Code Operations ==========

    /// Get contract code by address
    pub fn get_code(&self, address: &Address) -> StorageResult<Option<Vec<u8>>> {
        self.db.get(cf::CODE, address.as_bytes())
    }

    /// Store contract code
    pub fn put_code(&self, address: &Address, code: &[u8]) -> StorageResult<()> {
        self.db.put(cf::CODE, address.as_bytes(), code)
    }

    /// Get code hash for an address
    pub fn get_code_hash(&self, address: &Address) -> StorageResult<Option<Hash256>> {
        match self.get_account(address)? {
            Some(account) if !account.code_hash.is_zero() => Ok(Some(account.code_hash)),
            _ => Ok(None),
        }
    }

    // ========== Contract Storage Operations ==========

    /// Get a storage value
    pub fn get_storage(&self, address: &Address, key: &Hash256) -> StorageResult<Option<Hash256>> {
        let storage_key = storage_key(address, key);
        let bytes = match self.db.get(cf::STORAGE, &storage_key)? {
            Some(b) => b,
            None => return Ok(None),
        };

        if bytes.len() != 32 {
            return Err(StorageError::DeserializationError(
                "Invalid storage value length".to_string(),
            ));
        }

        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes);
        Ok(Some(Hash256(value)))
    }

    /// Set a storage value
    pub fn put_storage(&self, address: &Address, key: &Hash256, value: &Hash256) -> StorageResult<()> {
        let storage_key = storage_key(address, key);
        self.db.put(cf::STORAGE, &storage_key, value.as_bytes())
    }

    /// Delete a storage value
    pub fn delete_storage(&self, address: &Address, key: &Hash256) -> StorageResult<()> {
        let storage_key = storage_key(address, key);
        self.db.delete(cf::STORAGE, &storage_key)
    }

    // ========== Batch Operations ==========

    /// Apply state changes atomically
    pub fn apply_changes(&self, changes: &StateChanges) -> StorageResult<()> {
        let mut batch = StorageBatch::new();

        // Modified accounts
        for (_, account) in &changes.modified_accounts {
            let bytes = bincode::serialize(account)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            batch.put(cf::ACCOUNTS, account.address.as_bytes().to_vec(), bytes);
        }

        // Deleted accounts
        for address in &changes.deleted_accounts {
            batch.delete(cf::ACCOUNTS, address.as_bytes().to_vec());
        }

        // Created contracts
        for (address, code) in &changes.created_contracts {
            batch.put(cf::CODE, address.as_bytes().to_vec(), code.clone());
        }

        // Storage changes
        for (address, storage) in &changes.storage_changes {
            for (key, value) in storage {
                let storage_key = storage_key(address, key);
                if value.is_zero() {
                    batch.delete(cf::STORAGE, storage_key);
                } else {
                    batch.put(cf::STORAGE, storage_key, value.as_bytes().to_vec());
                }
            }
        }

        self.db.write_batch(batch)
    }

    // ========== State Root Operations ==========

    /// Get the current state root
    pub fn get_state_root(&self) -> StorageResult<Option<Hash256>> {
        let bytes = match self.db.get(cf::META, b"state_root")? {
            Some(b) => b,
            None => return Ok(None),
        };

        if bytes.len() != 32 {
            return Err(StorageError::DeserializationError(
                "Invalid state root length".to_string(),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Some(Hash256(hash)))
    }

    /// Set the current state root
    pub fn set_state_root(&self, root: &Hash256) -> StorageResult<()> {
        self.db.put(cf::META, b"state_root", root.as_bytes())
    }

    // ========== Iteration ==========

    /// Get all accounts (for debugging/testing)
    pub fn get_all_accounts(&self) -> StorageResult<Vec<Account>> {
        let entries = self.db.iter(cf::ACCOUNTS)?;
        let mut accounts = Vec::new();

        for (_, value) in entries {
            let account: Account = bincode::deserialize(&value)
                .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
            accounts.push(account);
        }

        Ok(accounts)
    }

    /// Get account count
    pub fn account_count(&self) -> StorageResult<usize> {
        Ok(self.db.iter(cf::ACCOUNTS)?.len())
    }
}

/// Create a storage key from address and slot
fn storage_key(address: &Address, key: &Hash256) -> Vec<u8> {
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(address.as_bytes());
    result.extend_from_slice(key.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::types::TokenAmount;
    use tempfile::tempdir;

    #[test]
    fn test_account_storage() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let store = StateStore::new(db);

        let address = Address::from_public_key(&[1u8; 64]);
        let account = Account::with_balance(address, TokenAmount::from_fry(100));

        store.put_account(&account).unwrap();

        let retrieved = store.get_account(&address).unwrap().unwrap();
        assert_eq!(retrieved.balance, account.balance);
        assert_eq!(retrieved.address, account.address);
    }

    #[test]
    fn test_contract_storage() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let store = StateStore::new(db);

        let address = Address::from_public_key(&[1u8; 64]);
        let key = Hash256::new([1u8; 32]);
        let value = Hash256::new([2u8; 32]);

        store.put_storage(&address, &key, &value).unwrap();

        let retrieved = store.get_storage(&address, &key).unwrap().unwrap();
        assert_eq!(retrieved, value);
    }

    #[test]
    fn test_apply_changes() {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let store = StateStore::new(db);

        let address = Address::from_public_key(&[1u8; 64]);
        let account = Account::with_balance(address, TokenAmount::from_fry(50));

        let mut changes = StateChanges::new();
        changes.modify_account(account.clone());

        store.apply_changes(&changes).unwrap();

        let retrieved = store.get_account(&address).unwrap().unwrap();
        assert_eq!(retrieved.balance, account.balance);
    }
}
