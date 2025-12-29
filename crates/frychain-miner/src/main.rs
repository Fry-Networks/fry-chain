//! FryChain Miner
//!
//! CryptoNight-STC proof-of-work miner for FryChain

use clap::Parser;
use frychain_consensus::pow::{mine_block_parallel, MiningResult};
use frychain_core::address::Address;
use frychain_core::block::{Block, BlockHeader};
use frychain_core::config::ChainConfig;
use frychain_core::types::{BlockHeight, Difficulty, Hash256};
use frychain_crypto::keys::{Keypair, KeypairType};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "frychain-miner")]
#[command(about = "FryChain CryptoNight-STC Miner")]
#[command(version)]
struct Args {
    /// Miner address (will generate new keypair if not provided)
    #[arg(short, long)]
    address: Option<String>,

    /// Number of mining threads (defaults to number of CPUs)
    #[arg(short, long)]
    threads: Option<usize>,

    /// RPC endpoint to connect to
    #[arg(short, long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Network (mainnet, testnet, devnet)
    #[arg(short, long, default_value = "devnet")]
    network: String,

    /// Solo mining mode (no pool)
    #[arg(long, default_value = "true")]
    solo: bool,

    /// Benchmark mode - run for specified seconds and exit
    #[arg(long)]
    benchmark: Option<u64>,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!(r#"
 _____ ____   __ __  ____  _   _    __    ____  _   _
|  ___||  _ \ \ \ \ / /\ \/ / / \  | |_ / ___|| | | |
| |_   | |_) | \ V /  \  / / _ \ | | | | |   | |_| |
|  _|  |  _ <   | |   / / / ___ \| |_| | |___|  _  |
|_|    |_| \_\  |_|  /_/ /_/   \_\____/ \____|_| |_|

        Post-Quantum PoW Mining Software v0.1.0
    "#);

    // Determine miner address
    let miner_address = if let Some(addr_str) = args.address {
        Address::from_string(&addr_str).expect("Invalid address")
    } else {
        // Generate new keypair
        info!("Generating new post-quantum keypair...");
        let keypair = Keypair::generate(KeypairType::Dilithium).expect("Failed to generate keypair");
        let address = keypair.address();
        println!("Generated miner address: {}", address);
        println!("WARNING: Save your private key! This is a temporary keypair.");
        address
    };

    let num_threads = args.threads.unwrap_or_else(num_cpus::get);
    info!("Using {} mining threads", num_threads);

    // Get chain config
    let config = match args.network.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "testnet" => ChainConfig::testnet(),
        _ => ChainConfig::devnet(),
    };

    // Benchmark mode
    if let Some(duration) = args.benchmark {
        println!("\nRunning benchmark for {} seconds...", duration);
        run_benchmark(num_threads, duration);
        return;
    }

    // Mining loop
    println!("\nStarting mining...");
    println!("Miner address: {}", miner_address);
    println!("Network: {}", args.network);
    println!("Threads: {}", num_threads);
    println!();

    let stop_signal = Arc::new(AtomicBool::new(false));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let blocks_found = Arc::new(AtomicU64::new(0));

    // Handle Ctrl+C
    let stop = Arc::clone(&stop_signal);
    ctrlc::set_handler(move || {
        println!("\nShutting down miner...");
        stop.store(true, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    // Mining loop
    let mut height = 1u64;
    let mut parent_hash = Hash256::zero();
    let mut difficulty = config.initial_difficulty;

    while !stop_signal.load(Ordering::Relaxed) {
        // Create block template
        let mut header = BlockHeader::new(
            BlockHeight::new(height),
            parent_hash,
            miner_address,
            difficulty,
        );

        println!("Mining block {} at difficulty {:?}...", height, difficulty.0);

        // Mine the block
        let result = mine_block_parallel(&header, num_threads, Arc::clone(&stop_signal));

        if let Some(mining_result) = result {
            blocks_found.fetch_add(1, Ordering::Relaxed);
            total_hashes.fetch_add(mining_result.hashes, Ordering::Relaxed);

            println!(
                "Block {} found! Nonce: {}, Hash: {}, Hashrate: {:.2} H/s",
                height,
                mining_result.nonce.0,
                mining_result.pow_hash,
                mining_result.hashrate()
            );

            // Update for next block
            header.nonce = mining_result.nonce;
            parent_hash = header.hash();
            height += 1;

            // Simulate difficulty adjustment
            if height % 10 == 0 {
                difficulty = Difficulty::new(difficulty.0 + difficulty.0 / 10);
                println!("Difficulty adjusted to {:?}", difficulty.0);
            }
        }
    }

    let total = total_hashes.load(Ordering::Relaxed);
    let found = blocks_found.load(Ordering::Relaxed);
    println!("\nMining summary:");
    println!("  Total hashes: {}", total);
    println!("  Blocks found: {}", found);
}

fn run_benchmark(threads: usize, duration_secs: u64) {
    use std::time::{Duration, Instant};

    let stop_signal = Arc::new(AtomicBool::new(false));
    let miner = Address::from_public_key(&[0u8; 64]);

    // Easy difficulty for benchmarking
    let header = BlockHeader::new(
        BlockHeight::new(1),
        Hash256::zero(),
        miner,
        Difficulty::new(u128::MAX), // Very hard - won't find solution
    );

    let stop = Arc::clone(&stop_signal);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(duration_secs));
        stop.store(true, Ordering::Relaxed);
    });

    let start = Instant::now();

    // Run mining until stopped
    let _ = mine_block_parallel(&header, threads, stop_signal);

    let elapsed = start.elapsed().as_secs_f64();

    // Use CryptoNight benchmark
    println!("Running CryptoNight-STC benchmark...");
    let hashrate = frychain_crypto::cryptonight::benchmark_hashrate(duration_secs.min(10));

    println!("\nBenchmark Results:");
    println!("  Threads: {}", threads);
    println!("  Duration: {:.2} seconds", elapsed);
    println!("  Hashrate: {:.2} H/s", hashrate);
    println!("  Estimated daily earnings at current difficulty: TBD");
}
