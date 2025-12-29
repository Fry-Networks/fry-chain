//! Chain configuration for FryChain

use crate::address::Address;
use crate::types::{BlockHeight, Difficulty, TokenAmount};
use serde::{Deserialize, Serialize};

/// Network identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkId {
    /// Main network
    Mainnet = 1,
    /// Test network
    Testnet = 2,
    /// Development network
    Devnet = 3,
    /// Local development
    Local = 1337,
}

impl NetworkId {
    pub fn chain_id(&self) -> u64 {
        *self as u64
    }

    pub fn from_chain_id(id: u64) -> Option<Self> {
        match id {
            1 => Some(NetworkId::Mainnet),
            2 => Some(NetworkId::Testnet),
            3 => Some(NetworkId::Devnet),
            1337 => Some(NetworkId::Local),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "mainnet",
            NetworkId::Testnet => "testnet",
            NetworkId::Devnet => "devnet",
            NetworkId::Local => "local",
        }
    }
}

/// Genesis allocation for an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Address to receive allocation
    pub address: Address,
    /// Initial balance
    pub balance: TokenAmount,
    /// Optional contract code
    pub code: Option<Vec<u8>>,
    /// Is this a DePIN device registration
    pub is_device: bool,
}

/// Chain configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Network identifier
    pub network_id: NetworkId,
    /// Chain ID for transaction signing
    pub chain_id: u64,
    /// Human-readable chain name
    pub chain_name: String,
    /// Native token symbol
    pub token_symbol: String,
    /// Native token decimals
    pub token_decimals: u8,
    /// Genesis timestamp (Unix timestamp)
    pub genesis_timestamp: u64,
    /// Initial difficulty
    pub initial_difficulty: Difficulty,
    /// Target block time in seconds
    pub target_block_time: u64,
    /// Difficulty adjustment interval (blocks)
    pub difficulty_adjustment_interval: u64,
    /// Initial block reward
    pub initial_block_reward: TokenAmount,
    /// Block reward halving interval
    pub halving_interval: u64,
    /// Maximum supply
    pub max_supply: TokenAmount,
    /// Genesis allocations
    pub genesis_allocations: Vec<GenesisAllocation>,
    /// Precompiled contracts
    pub precompiles: Vec<Address>,
    /// Enable post-quantum signatures only
    pub post_quantum_only: bool,
    /// Enable DePIN features
    pub depin_enabled: bool,
    /// Minimum gas price
    pub min_gas_price: u128,
    /// Block gas limit
    pub block_gas_limit: u64,
}

impl ChainConfig {
    /// Create mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            network_id: NetworkId::Mainnet,
            chain_id: 1,
            chain_name: "FryChain Mainnet".to_string(),
            token_symbol: "FRY".to_string(),
            token_decimals: 18,
            genesis_timestamp: 1704067200, // 2024-01-01 00:00:00 UTC
            initial_difficulty: Difficulty::INITIAL,
            target_block_time: 60, // 1 minute
            difficulty_adjustment_interval: 2016,
            initial_block_reward: TokenAmount::from_fry(50),
            halving_interval: 2_100_000,
            max_supply: TokenAmount::new(210_000_000 * crate::UNITS_PER_FRY),
            genesis_allocations: Vec::new(),
            precompiles: Vec::new(),
            post_quantum_only: true,
            depin_enabled: true,
            min_gas_price: 1_000_000_000, // 1 Gwei
            block_gas_limit: 30_000_000,
        }
    }

    /// Create testnet configuration
    pub fn testnet() -> Self {
        Self {
            network_id: NetworkId::Testnet,
            chain_id: 2,
            chain_name: "FryChain Testnet".to_string(),
            token_symbol: "tFRY".to_string(),
            token_decimals: 18,
            genesis_timestamp: 1704067200,
            initial_difficulty: Difficulty::new(0x0000_0FFF_FFFF_FFFF), // Lower difficulty
            target_block_time: 30, // 30 seconds
            difficulty_adjustment_interval: 100,
            initial_block_reward: TokenAmount::from_fry(100),
            halving_interval: 100_000,
            max_supply: TokenAmount::new(1_000_000_000 * crate::UNITS_PER_FRY),
            genesis_allocations: Vec::new(),
            precompiles: Vec::new(),
            post_quantum_only: false, // Allow classical signatures for testing
            depin_enabled: true,
            min_gas_price: 1_000_000, // Lower min gas
            block_gas_limit: 50_000_000,
        }
    }

    /// Create devnet configuration (for local development)
    pub fn devnet() -> Self {
        Self {
            network_id: NetworkId::Devnet,
            chain_id: 3,
            chain_name: "FryChain Devnet".to_string(),
            token_symbol: "dFRY".to_string(),
            token_decimals: 18,
            genesis_timestamp: 0, // Start immediately
            initial_difficulty: Difficulty::new(1), // Minimum difficulty
            target_block_time: 5, // 5 seconds
            difficulty_adjustment_interval: 10,
            initial_block_reward: TokenAmount::from_fry(1000),
            halving_interval: 1000,
            max_supply: TokenAmount::new(u128::MAX),
            genesis_allocations: Vec::new(),
            precompiles: Vec::new(),
            post_quantum_only: false,
            depin_enabled: true,
            min_gas_price: 1,
            block_gas_limit: 100_000_000,
        }
    }

    /// Add a genesis allocation
    pub fn add_allocation(&mut self, address: Address, balance: TokenAmount) {
        self.genesis_allocations.push(GenesisAllocation {
            address,
            balance,
            code: None,
            is_device: false,
        });
    }

    /// Calculate block reward at a given height
    pub fn block_reward_at_height(&self, height: BlockHeight) -> TokenAmount {
        let halvings = height.0 / self.halving_interval;
        if halvings >= 64 {
            return TokenAmount::ZERO;
        }
        TokenAmount::new(self.initial_block_reward.0 >> halvings)
    }

    /// Check if this is a mainnet configuration
    pub fn is_mainnet(&self) -> bool {
        self.network_id == NetworkId::Mainnet
    }

    /// Get the expected difficulty at a given height
    pub fn should_adjust_difficulty(&self, height: BlockHeight) -> bool {
        height.0 > 0 && height.0 % self.difficulty_adjustment_interval == 0
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

/// Node configuration (runtime settings)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Chain configuration
    pub chain: ChainConfig,
    /// Data directory
    pub data_dir: String,
    /// P2P listen address
    pub p2p_listen: String,
    /// P2P port
    pub p2p_port: u16,
    /// RPC listen address
    pub rpc_listen: String,
    /// RPC port
    pub rpc_port: u16,
    /// Enable mining
    pub mining_enabled: bool,
    /// Miner address (coinbase)
    pub miner_address: Option<Address>,
    /// Mining threads
    pub mining_threads: usize,
    /// Maximum peers
    pub max_peers: usize,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Enable metrics
    pub metrics_enabled: bool,
    /// Metrics port
    pub metrics_port: u16,
    /// Log level
    pub log_level: String,
}

impl NodeConfig {
    /// Create default node configuration
    pub fn default_for(chain: ChainConfig) -> Self {
        Self {
            chain,
            data_dir: "./frychain-data".to_string(),
            p2p_listen: "0.0.0.0".to_string(),
            p2p_port: 30303,
            rpc_listen: "127.0.0.1".to_string(),
            rpc_port: 8545,
            mining_enabled: false,
            miner_address: None,
            mining_threads: 1,
            max_peers: 50,
            bootstrap_nodes: Vec::new(),
            metrics_enabled: false,
            metrics_port: 9090,
            log_level: "info".to_string(),
        }
    }

    /// Create for local development
    pub fn local_dev() -> Self {
        Self::default_for(ChainConfig::devnet())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_reward_halving() {
        let config = ChainConfig::mainnet();

        let reward_0 = config.block_reward_at_height(BlockHeight::new(0));
        let reward_half = config.block_reward_at_height(BlockHeight::new(config.halving_interval));
        let reward_double =
            config.block_reward_at_height(BlockHeight::new(config.halving_interval * 2));

        assert_eq!(reward_0.0, config.initial_block_reward.0);
        assert_eq!(reward_half.0, config.initial_block_reward.0 / 2);
        assert_eq!(reward_double.0, config.initial_block_reward.0 / 4);
    }

    #[test]
    fn test_config_serialization() {
        let config = ChainConfig::mainnet();
        let json = config.to_json();
        let parsed = ChainConfig::from_json(&json).unwrap();

        assert_eq!(config.chain_id, parsed.chain_id);
        assert_eq!(config.token_symbol, parsed.token_symbol);
    }

    #[test]
    fn test_network_id() {
        assert_eq!(NetworkId::Mainnet.chain_id(), 1);
        assert_eq!(NetworkId::from_chain_id(1), Some(NetworkId::Mainnet));
        assert_eq!(NetworkId::from_chain_id(999), None);
    }
}
