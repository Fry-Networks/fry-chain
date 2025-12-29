//! Blockchain management

use crate::difficulty::DifficultyAdjuster;
use crate::validation::BlockValidator;
use crate::{ConsensusError, ConsensusResult};
use dashmap::DashMap;
use frychain_core::block::{Block, StoredBlock};
use frychain_core::config::ChainConfig;
use frychain_core::state::AccountState;
use frychain_core::types::{BlockHeight, Difficulty, Hash256, TokenAmount};
use frychain_storage::{ChainStore, StateStore};
use parking_lot::RwLock;
use std::sync::Arc;

/// The blockchain - manages chain state and block processing
pub struct Blockchain {
    /// Chain configuration
    config: ChainConfig,
    /// Block storage
    chain_store: ChainStore,
    /// State storage
    state_store: StateStore,
    /// Block validator
    validator: BlockValidator,
    /// Difficulty adjuster
    difficulty_adjuster: DifficultyAdjuster,
    /// Current chain head
    head: RwLock<Option<StoredBlock>>,
    /// Pending blocks (orphans waiting for parent)
    pending_blocks: DashMap<Hash256, Block>,
    /// Known block hashes
    known_blocks: DashMap<Hash256, ()>,
    /// In-memory state (for quick access)
    state: RwLock<AccountState>,
}

impl Blockchain {
    /// Create a new blockchain
    pub fn new(
        config: ChainConfig,
        chain_store: ChainStore,
        state_store: StateStore,
    ) -> ConsensusResult<Self> {
        let validator = BlockValidator::new(config.clone());
        let difficulty_adjuster = DifficultyAdjuster::new(
            config.target_block_time,
            config.difficulty_adjustment_interval,
        );

        let blockchain = Self {
            config,
            chain_store,
            state_store,
            validator,
            difficulty_adjuster,
            head: RwLock::new(None),
            pending_blocks: DashMap::new(),
            known_blocks: DashMap::new(),
            state: RwLock::new(AccountState::new()),
        };

        // Load chain head from storage
        blockchain.load_head()?;

        Ok(blockchain)
    }

    /// Load the chain head from storage
    fn load_head(&self) -> ConsensusResult<()> {
        if let Some(height) = self.chain_store.get_latest_height()? {
            if let Some(hash) = self.chain_store.get_hash_by_height(height)? {
                if let Some(stored_block) = self.chain_store.get_stored_block(&hash)? {
                    *self.head.write() = Some(stored_block);
                }
            }
        }
        Ok(())
    }

    /// Initialize with genesis block
    pub fn init_genesis(&self, miner: frychain_core::address::Address) -> ConsensusResult<Block> {
        // Check if genesis already exists
        if self.chain_store.get_genesis_hash()?.is_some() {
            return Err(ConsensusError::InvalidBlock(
                "Genesis already exists".to_string(),
            ));
        }

        // Create genesis block
        let genesis = Block::genesis(miner, self.config.initial_difficulty);

        // Apply genesis allocations
        let mut state = self.state.write();
        for alloc in &self.config.genesis_allocations {
            let account = frychain_core::state::Account::with_balance(alloc.address, alloc.balance);
            state.set_account(account);

            if let Some(code) = &alloc.code {
                state.set_code(&alloc.address, code.clone());
            }
        }

        // Store genesis block
        let pow_hash = genesis.hash(); // Genesis has trivial PoW
        let stored = StoredBlock::new(genesis.clone(), pow_hash, self.config.initial_difficulty.0);
        self.chain_store.put_block(&stored)?;
        self.chain_store.set_latest_height(BlockHeight::genesis())?;

        *self.head.write() = Some(stored);

        Ok(genesis)
    }

    /// Get the current chain head
    pub fn head(&self) -> Option<StoredBlock> {
        self.head.read().clone()
    }

    /// Get the current height
    pub fn height(&self) -> BlockHeight {
        self.head
            .read()
            .as_ref()
            .map(|h| h.block.height())
            .unwrap_or(BlockHeight::genesis())
    }

    /// Get current difficulty
    pub fn difficulty(&self) -> Difficulty {
        self.head
            .read()
            .as_ref()
            .map(|h| h.block.difficulty())
            .unwrap_or(self.config.initial_difficulty)
    }

    /// Get total difficulty
    pub fn total_difficulty(&self) -> u128 {
        self.head
            .read()
            .as_ref()
            .map(|h| h.total_difficulty)
            .unwrap_or(0)
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &Hash256) -> ConsensusResult<Option<Block>> {
        Ok(self.chain_store.get_block(hash)?)
    }

    /// Get a block by height
    pub fn get_block_by_height(&self, height: BlockHeight) -> ConsensusResult<Option<Block>> {
        Ok(self.chain_store.get_block_by_height(height)?)
    }

    /// Check if a block is known
    pub fn has_block(&self, hash: &Hash256) -> bool {
        self.known_blocks.contains_key(hash) || self.chain_store.has_block(hash).unwrap_or(false)
    }

    /// Import a new block
    pub fn import_block(&self, block: Block, pow_hash: Hash256) -> ConsensusResult<()> {
        let block_hash = block.hash();

        // Check if already known
        if self.has_block(&block_hash) {
            return Ok(());
        }

        // Get parent block
        let parent = match self.get_block(&block.parent_hash())? {
            Some(p) => p,
            None => {
                // Store as pending/orphan
                self.pending_blocks.insert(block.parent_hash(), block);
                return Ok(());
            }
        };

        // Validate block
        self.validator.validate_block(&block, Some(&parent))?;

        // Verify PoW
        if !block.header.verify_pow(&pow_hash) {
            return Err(ConsensusError::InvalidProofOfWork);
        }

        // Calculate total difficulty
        let parent_td = self
            .chain_store
            .get_total_difficulty(&parent.hash())?
            .unwrap_or(0);
        let total_difficulty = parent_td + block.difficulty().0;

        // Store block
        let stored = StoredBlock::new(block.clone(), pow_hash, total_difficulty);
        self.chain_store.put_block(&stored)?;
        self.known_blocks.insert(block_hash, ());

        // Check if this becomes the new head
        let current_td = self.total_difficulty();
        if total_difficulty > current_td {
            self.set_head(stored)?;
        }

        // Process any pending blocks that depend on this one
        self.process_pending_blocks(&block_hash)?;

        Ok(())
    }

    /// Set a new chain head
    fn set_head(&self, stored: StoredBlock) -> ConsensusResult<()> {
        let height = stored.block.height();
        self.chain_store.set_latest_height(height)?;
        *self.head.write() = Some(stored);
        Ok(())
    }

    /// Process pending blocks that may now be valid
    fn process_pending_blocks(&self, parent_hash: &Hash256) -> ConsensusResult<()> {
        if let Some((_, block)) = self.pending_blocks.remove(parent_hash) {
            // Re-verify PoW for the pending block
            let pow_hash = crate::pow::verify_pow(&block.header)?;
            self.import_block(block, pow_hash)?;
        }
        Ok(())
    }

    /// Get the next block difficulty
    pub fn next_difficulty(&self) -> Difficulty {
        let head = self.head.read();
        if head.is_none() {
            return self.config.initial_difficulty;
        }

        let head = head.as_ref().unwrap();
        let next_height = head.block.height().next();

        if !self.difficulty_adjuster.should_adjust(next_height) {
            return head.block.difficulty();
        }

        // Get blocks for adjustment window
        let window_start = next_height
            .0
            .saturating_sub(self.config.difficulty_adjustment_interval);

        let first_block = self
            .get_block_by_height(BlockHeight::new(window_start))
            .ok()
            .flatten();
        let last_block = self
            .get_block_by_height(head.block.height())
            .ok()
            .flatten();

        match (first_block, last_block) {
            (Some(first), Some(last)) => self.difficulty_adjuster.calculate_new_difficulty(
                head.block.difficulty(),
                first.timestamp(),
                last.timestamp(),
            ),
            _ => head.block.difficulty(),
        }
    }

    /// Get current block reward
    pub fn block_reward(&self) -> TokenAmount {
        let height = self.height();
        self.config.block_reward_at_height(height)
    }

    /// Get account state
    pub fn get_state(&self) -> AccountState {
        self.state.read().clone()
    }

    /// Get configuration
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::address::Address;
    use frychain_storage::Database;
    use tempfile::tempdir;

    fn create_blockchain() -> (Blockchain, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let chain_store = ChainStore::new(db.clone());
        let state_store = StateStore::new(db);
        let config = ChainConfig::devnet();

        let blockchain = Blockchain::new(config, chain_store, state_store).unwrap();
        (blockchain, dir)
    }

    #[test]
    fn test_genesis_initialization() {
        let (blockchain, _dir) = create_blockchain();
        let miner = Address::from_public_key(&[1u8; 64]);

        let genesis = blockchain.init_genesis(miner).unwrap();

        assert_eq!(genesis.height().0, 0);
        assert!(genesis.parent_hash().is_zero());
        assert_eq!(blockchain.height().0, 0);
    }

    #[test]
    fn test_no_double_genesis() {
        let (blockchain, _dir) = create_blockchain();
        let miner = Address::from_public_key(&[1u8; 64]);

        blockchain.init_genesis(miner).unwrap();

        // Second genesis should fail
        assert!(blockchain.init_genesis(miner).is_err());
    }
}
