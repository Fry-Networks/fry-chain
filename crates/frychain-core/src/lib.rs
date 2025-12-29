//! FryChain Core - Fundamental blockchain primitives
//!
//! This crate provides the core data structures and types for FryChain:
//! - Addresses and account management
//! - Block and transaction structures
//! - State management with Merkle trees
//! - Hash types and utilities

pub mod address;
pub mod block;
pub mod transaction;
pub mod state;
pub mod merkle;
pub mod types;
pub mod error;
pub mod config;

pub use address::{Address, AddressType};
pub use block::{Block, BlockHeader, BlockBody};
pub use transaction::{Transaction, TransactionType, SignedTransaction};
pub use state::{Account, AccountState, StateRoot};
pub use merkle::{MerkleTree, MerkleProof};
pub use types::{Hash256, Hash512, Nonce, Difficulty, BlockHeight, TokenAmount};
pub use error::{CoreError, CoreResult};
pub use config::{ChainConfig, NetworkId};

/// FryChain token denomination - 1 FRY = 10^18 base units (like ETH wei)
pub const FRY_DECIMALS: u8 = 18;
pub const UNITS_PER_FRY: u128 = 1_000_000_000_000_000_000;

/// Block time target in seconds
pub const TARGET_BLOCK_TIME_SECS: u64 = 60; // 1 minute blocks

/// Maximum block size in bytes
pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// Maximum transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 10_000;

/// Initial block reward
pub const INITIAL_BLOCK_REWARD: u128 = 50 * UNITS_PER_FRY; // 50 FRY

/// Halving interval (blocks)
pub const HALVING_INTERVAL: u64 = 2_100_000; // ~4 years at 1 min blocks

/// Difficulty adjustment interval (blocks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Maximum supply
pub const MAX_SUPPLY: u128 = 210_000_000 * UNITS_PER_FRY; // 210 million FRY
