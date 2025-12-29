//! Block and transaction validation

use crate::{ConsensusError, ConsensusResult};
use frychain_core::block::{Block, BlockHeader};
use frychain_core::config::ChainConfig;
use frychain_core::transaction::SignedTransaction;
use frychain_core::types::{BlockHeight, Hash256};

/// Maximum allowed timestamp drift into the future (seconds)
const MAX_FUTURE_TIMESTAMP: u64 = 15 * 60; // 15 minutes

/// Block validator
pub struct BlockValidator {
    config: ChainConfig,
}

impl BlockValidator {
    /// Create a new block validator
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }

    /// Validate a block header against its parent
    pub fn validate_header(
        &self,
        header: &BlockHeader,
        parent_header: Option<&BlockHeader>,
    ) -> ConsensusResult<()> {
        // Genesis block validation
        if header.height.0 == 0 {
            if parent_header.is_some() {
                return Err(ConsensusError::InvalidParent);
            }
            // Genesis specific checks
            if !header.parent_hash.is_zero() {
                return Err(ConsensusError::InvalidBlock(
                    "Genesis parent hash must be zero".to_string(),
                ));
            }
            return Ok(());
        }

        // Non-genesis blocks must have parent
        let parent = parent_header.ok_or(ConsensusError::InvalidParent)?;

        // Check height is sequential
        if header.height.0 != parent.height.0 + 1 {
            return Err(ConsensusError::InvalidBlock(format!(
                "Invalid height: expected {}, got {}",
                parent.height.0 + 1,
                header.height.0
            )));
        }

        // Check parent hash matches
        if header.parent_hash != parent.hash() {
            return Err(ConsensusError::InvalidParent);
        }

        // Check timestamp is not too far in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if header.timestamp > now + MAX_FUTURE_TIMESTAMP {
            return Err(ConsensusError::BlockFromFuture);
        }

        // Check timestamp is not before parent
        if header.timestamp < parent.timestamp {
            return Err(ConsensusError::BlockTooOld);
        }

        // Check gas limit is valid
        if header.gas_limit == 0 {
            return Err(ConsensusError::InvalidBlock("Gas limit cannot be zero".to_string()));
        }

        // Check gas used doesn't exceed limit
        if header.gas_used > header.gas_limit {
            return Err(ConsensusError::InvalidBlock(
                "Gas used exceeds gas limit".to_string(),
            ));
        }

        // Check extra data size
        if header.extra_data.len() > 32 {
            return Err(ConsensusError::InvalidBlock(
                "Extra data too long".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate a complete block
    pub fn validate_block(
        &self,
        block: &Block,
        parent: Option<&Block>,
    ) -> ConsensusResult<()> {
        // Validate header
        self.validate_header(&block.header, parent.map(|p| &p.header))?;

        // Check block structure
        block
            .verify_structure()
            .map_err(|e| ConsensusError::InvalidBlock(e.to_string()))?;

        // Check block size
        if block.size() > frychain_core::MAX_BLOCK_SIZE {
            return Err(ConsensusError::InvalidBlock(format!(
                "Block too large: {} bytes",
                block.size()
            )));
        }

        // Check transaction count
        if block.tx_count() > frychain_core::MAX_TXS_PER_BLOCK {
            return Err(ConsensusError::InvalidBlock(format!(
                "Too many transactions: {}",
                block.tx_count()
            )));
        }

        // Validate each transaction
        for tx in block.transactions() {
            self.validate_transaction(tx)?;
        }

        // Check transactions root matches
        let calculated_root = block.body.calculate_transactions_root();
        if calculated_root != block.header.transactions_root {
            return Err(ConsensusError::InvalidBlock(
                "Transactions root mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate a signed transaction
    pub fn validate_transaction(&self, tx: &SignedTransaction) -> ConsensusResult<()> {
        // Check chain ID
        if tx.transaction.chain_id != self.config.chain_id {
            return Err(ConsensusError::InvalidBlock(format!(
                "Invalid chain ID: expected {}, got {}",
                self.config.chain_id, tx.transaction.chain_id
            )));
        }

        // Check gas price meets minimum
        if tx.gas_price().0 < self.config.min_gas_price {
            return Err(ConsensusError::InvalidBlock(format!(
                "Gas price too low: minimum {}",
                self.config.min_gas_price
            )));
        }

        // Check gas limit is reasonable
        if tx.gas_limit().0 == 0 {
            return Err(ConsensusError::InvalidBlock(
                "Gas limit cannot be zero".to_string(),
            ));
        }

        // Verify signature
        let tx_hash = tx.transaction.hash();
        if !frychain_crypto::keys::verify_signature(&tx.signature, tx_hash.as_bytes()) {
            return Err(ConsensusError::InvalidBlock(
                "Invalid transaction signature".to_string(),
            ));
        }

        // Check post-quantum requirement if enabled
        if self.config.post_quantum_only
            && !frychain_crypto::keys::is_signature_post_quantum(&tx.signature)
        {
            return Err(ConsensusError::InvalidBlock(
                "Non-post-quantum signature not allowed".to_string(),
            ));
        }

        Ok(())
    }

    /// Calculate expected block reward at height
    pub fn block_reward(&self, height: BlockHeight) -> u128 {
        self.config.block_reward_at_height(height).0
    }
}

/// Validate that a hash meets the difficulty target
pub fn validate_pow_hash(pow_hash: &Hash256, target: &Hash256) -> bool {
    pow_hash.meets_difficulty(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::address::Address;
    use frychain_core::block::{BlockBody, BlockHeader};
    use frychain_core::types::Difficulty;

    fn make_header(height: u64, parent_hash: Hash256) -> BlockHeader {
        let miner = Address::from_public_key(&[1u8; 64]);
        BlockHeader::new(
            BlockHeight::new(height),
            parent_hash,
            miner,
            Difficulty::INITIAL,
        )
    }

    #[test]
    fn test_validate_genesis() {
        let validator = BlockValidator::new(ChainConfig::devnet());
        let header = make_header(0, Hash256::zero());

        assert!(validator.validate_header(&header, None).is_ok());
    }

    #[test]
    fn test_validate_sequential_headers() {
        let validator = BlockValidator::new(ChainConfig::devnet());

        let genesis = make_header(0, Hash256::zero());
        let block1 = make_header(1, genesis.hash());

        assert!(validator.validate_header(&block1, Some(&genesis)).is_ok());
    }

    #[test]
    fn test_reject_wrong_parent() {
        let validator = BlockValidator::new(ChainConfig::devnet());

        let genesis = make_header(0, Hash256::zero());
        let block1 = make_header(1, Hash256::new([1u8; 32])); // Wrong parent

        assert!(validator.validate_header(&block1, Some(&genesis)).is_err());
    }

    #[test]
    fn test_reject_wrong_height() {
        let validator = BlockValidator::new(ChainConfig::devnet());

        let genesis = make_header(0, Hash256::zero());
        let mut block1 = make_header(1, genesis.hash());
        block1.height = BlockHeight::new(5); // Wrong height

        assert!(validator.validate_header(&block1, Some(&genesis)).is_err());
    }
}
