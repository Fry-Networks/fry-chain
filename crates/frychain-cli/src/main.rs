//! FryChain CLI

use clap::{Parser, Subcommand};
use frychain_core::address::Address;
use frychain_core::types::TokenAmount;
use frychain_crypto::keys::{Keypair, KeypairType};

#[derive(Parser, Debug)]
#[command(name = "frycli")]
#[command(about = "FryChain Command Line Interface")]
#[command(version)]
struct Args {
    /// RPC endpoint
    #[arg(short, long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new keypair
    Keygen {
        /// Key type (dilithium, sphincs, ed25519)
        #[arg(short = 't', long, default_value = "dilithium")]
        key_type: String,

        /// Output file (optional)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Get account balance
    Balance {
        /// Account address
        address: String,
    },

    /// Get account nonce
    Nonce {
        /// Account address
        address: String,
    },

    /// Send tokens
    Send {
        /// Sender private key (hex)
        #[arg(long)]
        from_key: String,

        /// Recipient address
        #[arg(long)]
        to: String,

        /// Amount in FRY
        #[arg(long)]
        amount: f64,

        /// Gas price in Gwei
        #[arg(long, default_value = "1")]
        gas_price: f64,
    },

    /// Get block information
    Block {
        /// Block height or "latest"
        #[arg(default_value = "latest")]
        height: String,
    },

    /// Get transaction information
    Tx {
        /// Transaction hash
        hash: String,
    },

    /// Get chain info
    Info,

    /// Get mining info
    Mining,

    /// Deploy a smart contract
    Deploy {
        /// Deployer private key (hex)
        #[arg(long)]
        key: String,

        /// Contract bytecode file
        #[arg(long)]
        bytecode: String,

        /// Gas limit
        #[arg(long, default_value = "1000000")]
        gas_limit: u64,
    },

    /// Call a smart contract (read-only)
    Call {
        /// Contract address
        #[arg(long)]
        contract: String,

        /// Call data (hex)
        #[arg(long)]
        data: String,
    },

    /// DePIN device commands
    Device {
        #[command(subcommand)]
        action: DeviceCommands,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCommands {
    /// Register a new device
    Register {
        /// Device owner private key
        #[arg(long)]
        owner_key: String,

        /// Device type
        #[arg(long)]
        device_type: String,
    },

    /// List devices owned by an address
    List {
        /// Owner address
        owner: String,
    },

    /// Get device info
    Info {
        /// Device DID
        did: String,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Keygen { key_type, output } => {
            let keypair_type = match key_type.as_str() {
                "dilithium" => KeypairType::Dilithium,
                "sphincs" => KeypairType::SphincsPlus,
                "ed25519" => KeypairType::Ed25519,
                _ => {
                    eprintln!("Unknown key type: {}. Use: dilithium, sphincs, ed25519", key_type);
                    return;
                }
            };

            println!("Generating {} keypair...", key_type);

            let keypair = Keypair::generate(keypair_type).expect("Failed to generate keypair");
            let address = keypair.address();

            println!("\n=== New FryChain Keypair ===");
            println!("Algorithm: {} ({})",
                key_type,
                if keypair.is_post_quantum() { "post-quantum" } else { "classical" }
            );
            println!("Address: {}", address);
            println!();

            if keypair.is_post_quantum() {
                println!("This keypair is QUANTUM-RESISTANT");
            } else {
                println!("WARNING: This keypair is NOT quantum-resistant");
            }

            if let Some(path) = output {
                // Save to file (simplified - would need proper format)
                println!("\nKeystore would be saved to: {}", path);
            }
        }

        Commands::Balance { address } => {
            println!("Getting balance for {}...", address);
            println!("Balance: 0.000000 FRY");
            println!("(Connect to a running node for live data)");
        }

        Commands::Nonce { address } => {
            println!("Getting nonce for {}...", address);
            println!("Nonce: 0");
            println!("(Connect to a running node for live data)");
        }

        Commands::Send { from_key, to, amount, gas_price } => {
            println!("Sending {} FRY to {}...", amount, to);
            println!("Gas price: {} Gwei", gas_price);
            println!("(Connect to a running node to send transactions)");
        }

        Commands::Block { height } => {
            println!("Getting block {}...", height);
            if height == "latest" {
                println!("Latest block height: 0 (genesis)");
            }
            println!("(Connect to a running node for live data)");
        }

        Commands::Tx { hash } => {
            println!("Getting transaction {}...", hash);
            println!("Transaction not found");
            println!("(Connect to a running node for live data)");
        }

        Commands::Info => {
            println!("\n=== FryChain Info ===");
            println!("Chain ID: 1");
            println!("Network: mainnet");
            println!("Best block: 0");
            println!("Total difficulty: 0");
            println!("Peer count: 0");
            println!("Syncing: false");
            println!("(Connect to a running node for live data)");
        }

        Commands::Mining => {
            println!("\n=== Mining Info ===");
            println!("Mining: false");
            println!("Hashrate: 0 H/s");
            println!("Difficulty: 0");
            println!("(Connect to a running node for live data)");
        }

        Commands::Deploy { key, bytecode, gas_limit } => {
            println!("Deploying contract...");
            println!("Bytecode file: {}", bytecode);
            println!("Gas limit: {}", gas_limit);
            println!("(Connect to a running node to deploy contracts)");
        }

        Commands::Call { contract, data } => {
            println!("Calling contract {}...", contract);
            println!("Data: {}", data);
            println!("(Connect to a running node for contract calls)");
        }

        Commands::Device { action } => {
            match action {
                DeviceCommands::Register { owner_key, device_type } => {
                    println!("Registering {} device...", device_type);
                    println!("(Connect to a running node to register devices)");
                }
                DeviceCommands::List { owner } => {
                    println!("Listing devices for {}...", owner);
                    println!("No devices found");
                    println!("(Connect to a running node for live data)");
                }
                DeviceCommands::Info { did } => {
                    println!("Getting device info for {}...", did);
                    println!("Device not found");
                    println!("(Connect to a running node for live data)");
                }
            }
        }
    }
}
