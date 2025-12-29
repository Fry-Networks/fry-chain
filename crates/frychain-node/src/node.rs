//! Full node implementation

use frychain_consensus::chain::Blockchain;
use frychain_core::address::Address;
use frychain_core::config::{ChainConfig, NodeConfig};
use frychain_network::peer::PeerManager;
use frychain_storage::{ChainStore, Database, StateStore};
use std::path::Path;
use std::sync::Arc;

/// FryChain full node
pub struct FryChainNode {
    /// Node configuration
    pub config: NodeConfig,
    /// Blockchain
    pub blockchain: Arc<Blockchain>,
    /// Peer manager
    pub peers: Arc<PeerManager>,
    /// Running state
    running: bool,
}

impl FryChainNode {
    /// Create a new node
    pub fn new(config: NodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Open database
        let db_path = Path::new(&config.data_dir).join("db");
        std::fs::create_dir_all(&db_path)?;
        let db = Database::open_default(&db_path)?;

        // Create stores
        let chain_store = ChainStore::new(db.clone());
        let state_store = StateStore::new(db);

        // Create blockchain
        let blockchain = Arc::new(Blockchain::new(
            config.chain.clone(),
            chain_store,
            state_store,
        )?);

        // Create peer manager
        let peers = Arc::new(PeerManager::new(config.max_peers));

        Ok(Self {
            config,
            blockchain,
            peers,
            running: false,
        })
    }

    /// Initialize the node with genesis block if needed
    pub fn init(&self, miner: Address) -> Result<(), Box<dyn std::error::Error>> {
        if self.blockchain.height().0 == 0 {
            tracing::info!("Initializing genesis block...");
            self.blockchain.init_genesis(miner)?;
        }
        Ok(())
    }

    /// Start the node
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting FryChain node...");
        self.running = true;

        tracing::info!("Chain height: {}", self.blockchain.height());
        tracing::info!("Total difficulty: {}", self.blockchain.total_difficulty());

        // In a full implementation:
        // 1. Start P2P networking
        // 2. Start RPC server
        // 3. Start sync manager
        // 4. Start miner (if enabled)

        Ok(())
    }

    /// Stop the node
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Stopping FryChain node...");
        self.running = false;
        Ok(())
    }

    /// Check if node is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get chain config
    pub fn chain_config(&self) -> &ChainConfig {
        self.blockchain.config()
    }
}
