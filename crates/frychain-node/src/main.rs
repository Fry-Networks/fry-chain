//! FryChain Full Node

use clap::Parser;
use frychain_core::address::Address;
use frychain_core::config::{ChainConfig, NodeConfig};
use frychain_crypto::keys::{Keypair, KeypairType};
use frychain_node::FryChainNode;
use std::sync::Arc;
use tokio::signal;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "frychain-node")]
#[command(about = "FryChain Full Node")]
#[command(version)]
struct Args {
    /// Data directory
    #[arg(short, long, default_value = "./frychain-data")]
    data_dir: String,

    /// Network (mainnet, testnet, devnet)
    #[arg(short, long, default_value = "devnet")]
    network: String,

    /// P2P listen port
    #[arg(long, default_value = "30303")]
    p2p_port: u16,

    /// RPC listen port
    #[arg(long, default_value = "8545")]
    rpc_port: u16,

    /// RPC listen address
    #[arg(long, default_value = "127.0.0.1")]
    rpc_addr: String,

    /// Enable mining
    #[arg(long)]
    mine: bool,

    /// Miner address
    #[arg(long)]
    miner: Option<String>,

    /// Mining threads
    #[arg(long, default_value = "1")]
    mining_threads: usize,

    /// Bootstrap nodes (comma-separated)
    #[arg(long)]
    bootnodes: Option<String>,

    /// Maximum peers
    #[arg(long, default_value = "50")]
    max_peers: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!(r#"
 _____ ____   __ __  ____  _   _    __    ____  _   _
|  ___||  _ \ \ \ \ / /\ \/ / / \  | |_ / ___|| | | |
| |_   | |_) | \ V /  \  / / _ \ | | | | |   | |_| |
|  _|  |  _ <   | |   / / / ___ \| |_| | |___|  _  |
|_|    |_| \_\  |_|  /_/ /_/   \_\____/ \____|_| |_|

        Post-Quantum PoW Blockchain Node v0.1.0
    "#);

    // Get chain config
    let chain_config = match args.network.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "testnet" => ChainConfig::testnet(),
        _ => ChainConfig::devnet(),
    };

    // Parse bootstrap nodes
    let bootstrap_nodes: Vec<String> = args
        .bootnodes
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_default();

    // Create node config
    let node_config = NodeConfig {
        chain: chain_config,
        data_dir: args.data_dir.clone(),
        p2p_listen: "0.0.0.0".to_string(),
        p2p_port: args.p2p_port,
        rpc_listen: args.rpc_addr.clone(),
        rpc_port: args.rpc_port,
        mining_enabled: args.mine,
        miner_address: args.miner.as_ref().map(|s| Address::from_string(s).ok()).flatten(),
        mining_threads: args.mining_threads,
        max_peers: args.max_peers,
        bootstrap_nodes,
        metrics_enabled: false,
        metrics_port: 9090,
        log_level: "info".to_string(),
    };

    info!("Network: {}", args.network);
    info!("Data directory: {}", args.data_dir);
    info!("P2P port: {}", args.p2p_port);
    info!("RPC: {}:{}", args.rpc_addr, args.rpc_port);

    // Create node
    let mut node = FryChainNode::new(node_config)?;

    // Initialize with genesis if needed
    let genesis_miner = if let Some(miner_addr) = args.miner {
        Address::from_string(&miner_addr)?
    } else {
        // Generate a temporary address for genesis
        let keypair = Keypair::generate(KeypairType::Dilithium)?;
        keypair.address()
    };

    node.init(genesis_miner)?;

    // Start node
    node.start().await?;

    info!("Node started successfully");
    info!("Press Ctrl+C to stop");

    // Wait for shutdown signal
    signal::ctrl_c().await?;

    // Stop node
    node.stop().await?;

    info!("Node stopped");
    Ok(())
}
