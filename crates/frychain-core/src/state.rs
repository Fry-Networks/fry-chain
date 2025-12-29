//! Account state management for FryChain

use crate::address::Address;
use crate::types::{Hash256, Nonce, TokenAmount};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Account state
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Account address
    pub address: Address,
    /// Token balance
    pub balance: TokenAmount,
    /// Transaction nonce (number of transactions sent)
    pub nonce: Nonce,
    /// Code hash (for contracts, zero for regular accounts)
    pub code_hash: Hash256,
    /// Storage root (Merkle root of account storage)
    pub storage_root: Hash256,
    /// Staked amount (for validators/delegators)
    pub staked: TokenAmount,
    /// DePIN device metadata hash (for device accounts)
    pub device_metadata_hash: Option<Hash256>,
}

impl Account {
    /// Create a new empty account
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: TokenAmount::ZERO,
            nonce: Nonce::new(0),
            code_hash: Hash256::zero(),
            storage_root: Hash256::zero(),
            staked: TokenAmount::ZERO,
            device_metadata_hash: None,
        }
    }

    /// Create a new account with initial balance
    pub fn with_balance(address: Address, balance: TokenAmount) -> Self {
        Self {
            address,
            balance,
            nonce: Nonce::new(0),
            code_hash: Hash256::zero(),
            storage_root: Hash256::zero(),
            staked: TokenAmount::ZERO,
            device_metadata_hash: None,
        }
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        !self.code_hash.is_zero()
    }

    /// Check if this is a DePIN device account
    pub fn is_device(&self) -> bool {
        self.device_metadata_hash.is_some()
    }

    /// Check if the account is empty (can be pruned)
    pub fn is_empty(&self) -> bool {
        self.balance.0 == 0
            && self.nonce.0 == 0
            && self.code_hash.is_zero()
            && self.staked.0 == 0
            && self.device_metadata_hash.is_none()
    }

    /// Get the hash of this account state
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(self.address.as_bytes());
        hasher.update(&self.balance.0.to_le_bytes());
        hasher.update(&self.nonce.0.to_le_bytes());
        hasher.update(self.code_hash.as_bytes());
        hasher.update(self.storage_root.as_bytes());
        hasher.update(&self.staked.0.to_le_bytes());
        if let Some(ref hash) = self.device_metadata_hash {
            hasher.update(hash.as_bytes());
        }

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Hash256(bytes)
    }

    /// Add balance (checked)
    pub fn add_balance(&mut self, amount: TokenAmount) -> Result<(), &'static str> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or("Balance overflow")?;
        Ok(())
    }

    /// Subtract balance (checked)
    pub fn sub_balance(&mut self, amount: TokenAmount) -> Result<(), &'static str> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or("Insufficient balance")?;
        Ok(())
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self) {
        self.nonce.increment();
    }
}

/// State root hash representing the entire world state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StateRoot(pub Hash256);

impl StateRoot {
    pub fn new(hash: Hash256) -> Self {
        Self(hash)
    }

    pub fn zero() -> Self {
        Self(Hash256::zero())
    }

    pub fn as_hash(&self) -> &Hash256 {
        &self.0
    }
}

/// Account state changes from a transaction
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateChanges {
    /// Modified accounts
    pub modified_accounts: HashMap<Address, Account>,
    /// Deleted accounts
    pub deleted_accounts: Vec<Address>,
    /// Created contracts
    pub created_contracts: Vec<(Address, Vec<u8>)>,
    /// Storage changes (contract address -> (key, value))
    pub storage_changes: HashMap<Address, HashMap<Hash256, Hash256>>,
}

impl StateChanges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an account modification
    pub fn modify_account(&mut self, account: Account) {
        self.modified_accounts.insert(account.address, account);
    }

    /// Mark an account for deletion
    pub fn delete_account(&mut self, address: Address) {
        self.deleted_accounts.push(address);
        self.modified_accounts.remove(&address);
    }

    /// Add a contract creation
    pub fn create_contract(&mut self, address: Address, code: Vec<u8>) {
        self.created_contracts.push((address, code));
    }

    /// Add a storage change
    pub fn set_storage(&mut self, contract: Address, key: Hash256, value: Hash256) {
        self.storage_changes
            .entry(contract)
            .or_default()
            .insert(key, value);
    }

    /// Merge another StateChanges into this one
    pub fn merge(&mut self, other: StateChanges) {
        for (addr, account) in other.modified_accounts {
            self.modified_accounts.insert(addr, account);
        }
        self.deleted_accounts.extend(other.deleted_accounts);
        self.created_contracts.extend(other.created_contracts);
        for (addr, changes) in other.storage_changes {
            self.storage_changes
                .entry(addr)
                .or_default()
                .extend(changes);
        }
    }

    /// Check if there are any changes
    pub fn is_empty(&self) -> bool {
        self.modified_accounts.is_empty()
            && self.deleted_accounts.is_empty()
            && self.created_contracts.is_empty()
            && self.storage_changes.is_empty()
    }
}

/// In-memory account state (for testing and simple nodes)
#[derive(Clone, Debug, Default)]
pub struct AccountState {
    /// All accounts
    accounts: HashMap<Address, Account>,
    /// Contract code
    contract_code: HashMap<Address, Vec<u8>>,
    /// Contract storage
    contract_storage: HashMap<Address, HashMap<Hash256, Hash256>>,
}

impl AccountState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an account (creates empty if not exists)
    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts
            .get(address)
            .cloned()
            .unwrap_or_else(|| Account::new(*address))
    }

    /// Get an account if it exists
    pub fn get_account_opt(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Set an account
    pub fn set_account(&mut self, account: Account) {
        if account.is_empty() {
            self.accounts.remove(&account.address);
        } else {
            self.accounts.insert(account.address, account);
        }
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> TokenAmount {
        self.get_account(address).balance
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> Nonce {
        self.get_account(address).nonce
    }

    /// Transfer tokens between accounts
    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: TokenAmount,
    ) -> Result<(), &'static str> {
        if from == to {
            return Ok(());
        }

        let mut from_account = self.get_account(from);
        let mut to_account = self.get_account(to);

        from_account.sub_balance(amount)?;
        to_account.add_balance(amount)?;

        self.set_account(from_account);
        self.set_account(to_account);

        Ok(())
    }

    /// Set contract code
    pub fn set_code(&mut self, address: &Address, code: Vec<u8>) {
        let code_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(&code);
            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash);
            Hash256(bytes)
        };

        let mut account = self.get_account(address);
        account.code_hash = code_hash;
        self.set_account(account);
        self.contract_code.insert(*address, code);
    }

    /// Get contract code
    pub fn get_code(&self, address: &Address) -> Option<&Vec<u8>> {
        self.contract_code.get(address)
    }

    /// Set storage value
    pub fn set_storage(&mut self, address: &Address, key: Hash256, value: Hash256) {
        self.contract_storage
            .entry(*address)
            .or_default()
            .insert(key, value);
    }

    /// Get storage value
    pub fn get_storage(&self, address: &Address, key: &Hash256) -> Hash256 {
        self.contract_storage
            .get(address)
            .and_then(|storage| storage.get(key))
            .cloned()
            .unwrap_or_default()
    }

    /// Apply state changes
    pub fn apply_changes(&mut self, changes: StateChanges) {
        for (addr, account) in changes.modified_accounts {
            self.set_account(account);
        }

        for addr in changes.deleted_accounts {
            self.accounts.remove(&addr);
            self.contract_code.remove(&addr);
            self.contract_storage.remove(&addr);
        }

        for (addr, code) in changes.created_contracts {
            self.set_code(&addr, code);
        }

        for (addr, storage) in changes.storage_changes {
            for (key, value) in storage {
                self.set_storage(&addr, key, value);
            }
        }
    }

    /// Calculate state root hash
    pub fn calculate_root(&self) -> StateRoot {
        let mut hasher = Sha3_256::new();

        // Sort accounts by address for deterministic hashing
        let mut addresses: Vec<_> = self.accounts.keys().collect();
        addresses.sort_by_key(|a| a.as_bytes());

        for addr in addresses {
            if let Some(account) = self.accounts.get(addr) {
                hasher.update(account.hash().as_bytes());
            }
        }

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        StateRoot(Hash256(bytes))
    }

    /// Get total number of accounts
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Iterate over all accounts
    pub fn iter_accounts(&self) -> impl Iterator<Item = (&Address, &Account)> {
        self.accounts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_balance_operations() {
        let addr = Address::from_public_key(&[1u8; 64]);
        let mut account = Account::with_balance(addr, TokenAmount::from_fry(100));

        account.add_balance(TokenAmount::from_fry(50)).unwrap();
        assert_eq!(account.balance.to_fry(), 150.0);

        account.sub_balance(TokenAmount::from_fry(30)).unwrap();
        assert_eq!(account.balance.to_fry(), 120.0);

        // Should fail - insufficient balance
        assert!(account.sub_balance(TokenAmount::from_fry(200)).is_err());
    }

    #[test]
    fn test_state_transfer() {
        let mut state = AccountState::new();

        let alice = Address::from_public_key(&[1u8; 64]);
        let bob = Address::from_public_key(&[2u8; 64]);

        state.set_account(Account::with_balance(alice, TokenAmount::from_fry(100)));

        state
            .transfer(&alice, &bob, TokenAmount::from_fry(30))
            .unwrap();

        assert!((state.get_balance(&alice).to_fry() - 70.0).abs() < 0.001);
        assert!((state.get_balance(&bob).to_fry() - 30.0).abs() < 0.001);
    }

    #[test]
    fn test_state_root_deterministic() {
        let mut state = AccountState::new();

        let addr = Address::from_public_key(&[1u8; 64]);
        state.set_account(Account::with_balance(addr, TokenAmount::from_fry(100)));

        let root1 = state.calculate_root();
        let root2 = state.calculate_root();
        assert_eq!(root1, root2);
    }
}
