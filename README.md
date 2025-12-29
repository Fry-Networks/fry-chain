# FryChain

**Post-Quantum Proof-of-Work Blockchain with DePIN Integration**

FryChain is a next-generation blockchain featuring:
- **CryptoNight-STC** memory-hard Proof-of-Work algorithm
- **Post-quantum resistant** cryptography (CRYSTALS-Dilithium, SPHINCS+)
- **Dual Smart Contract VMs** supporting both Solana-style (sBPF) and Algorand-style (AVM/TEAL) contracts
- **DePIN features** including device identity (DIDs), M2M transactions, and data marketplace

## Features

### Proof-of-Work Mining
- CryptoNight-STC algorithm (2MB scratchpad, memory-hard)
- ASIC-resistant design favoring CPU/GPU mining
- Dynamic difficulty adjustment (720-block window)
- Block reward: 50 FRY, halving every 2.1M blocks
- Target block time: 60 seconds
- Maximum supply: 210,000,000 FRY

### Post-Quantum Cryptography
- **CRYSTALS-Dilithium**: Default signature algorithm (NIST standard)
- **SPHINCS+**: Alternative hash-based signatures
- **Ed25519**: Classical fallback for compatibility
- Addresses encode algorithm type for future-proofing

### Smart Contracts
- **Solana-style (SBF)**: Register-based eBPF VM for high-performance contracts
- **Algorand-style (AVM)**: Stack-based TEAL interpreter for simple, auditable contracts
- Gas metering for both VMs
- Cross-VM interoperability

### DePIN (Decentralized Physical Infrastructure)
- Device Identity (DID): `did:fry:<address>` format
- Device registry with attestation and metadata
- Machine-to-Machine (M2M) transactions
- Data marketplace for IoT data monetization

## Building

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- RocksDB development libraries
- OpenSSL development libraries (for cryptography)

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y build-essential cmake librocksdb-dev libssl-dev pkg-config
```

#### macOS
```bash
brew install rocksdb openssl cmake
```

#### Fedora/RHEL
```bash
sudo dnf install -y rocksdb-devel openssl-devel cmake gcc gcc-c++
```

### Build All Components

```bash
# Clone the repository
git clone https://github.com/Fry-Foundation/fry-chain.git
cd fry-chain

# Build in release mode (recommended for mining)
cargo build --release

# Or build in debug mode for development
cargo build
```

### Individual Components

```bash
# Full node
cargo build --release -p frychain-node

# Miner
cargo build --release -p frychain-miner

# CLI
cargo build --release -p frychain-cli
```

## Quick Start

### 1. Generate a Keypair

```bash
# Generate a post-quantum Dilithium keypair
./target/release/frycli keygen --key-type dilithium

# Or generate classical Ed25519 (faster, but not quantum-resistant)
./target/release/frycli keygen --key-type ed25519

# Or SPHINCS+ (larger signatures, hash-based security)
./target/release/frycli keygen --key-type sphincs
```

### 2. Start a Node

```bash
# Start a devnet node with mining enabled
./target/release/frychain-node --network devnet --mine

# Start a mainnet node
./target/release/frychain-node --network mainnet --data-dir ./mainnet-data

# See all options
./target/release/frychain-node --help
```

### 3. Start Mining

```bash
# Start miner (connects to local node)
./target/release/frychain-miner --address <your-address>

# Use specific number of threads
./target/release/frychain-miner --address <your-address> --threads 4

# Run benchmark
./target/release/frychain-miner --benchmark 30

# See all options
./target/release/frychain-miner --help
```

### 4. Use the CLI

```bash
# Check chain info
./target/release/frycli info

# Check balance
./target/release/frycli balance <address>

# Send tokens
./target/release/frycli send --from-key <private-key> --to <address> --amount 10

# Deploy contract
./target/release/frycli deploy --key <private-key> --bytecode contract.bin

# DePIN device registration
./target/release/frycli device register --owner-key <key> --device-type sensor
```

## Using Launch Scripts

```bash
# Setup and start a local devnet
./scripts/setup-devnet.sh

# Launch a node with custom options
./scripts/launch-node.sh --network testnet --mine --miner <address>

# Launch a miner
./scripts/launch-miner.sh --address <address> --threads 8

# Run benchmarks
./scripts/benchmark.sh 30 8  # 30 seconds, 8 threads
```

## Network Configuration

### Mainnet (Chain ID: 1)
- P2P Port: 30303
- RPC Port: 8545
- Target Block Time: 60s
- Initial Difficulty: 0x100000

### Testnet (Chain ID: 2)
- P2P Port: 30304
- RPC Port: 8546
- Target Block Time: 30s
- Initial Difficulty: 0x10000

### Devnet (Chain ID: 255)
- P2P Port: 30305
- RPC Port: 8547
- Target Block Time: 5s
- Initial Difficulty: 0x1000

## Project Structure

```
fry-chain/
├── crates/
│   ├── frychain-core/       # Core types, blocks, transactions, state
│   ├── frychain-crypto/     # CryptoNight-STC, post-quantum signatures
│   ├── frychain-consensus/  # PoW consensus, difficulty adjustment
│   ├── frychain-vm/         # Dual VM (SBF + AVM)
│   ├── frychain-depin/      # DePIN features (DID, M2M, marketplace)
│   ├── frychain-network/    # P2P networking (libp2p)
│   ├── frychain-storage/    # RocksDB storage layer
│   ├── frychain-rpc/        # JSON-RPC API
│   ├── frychain-node/       # Full node binary
│   ├── frychain-miner/      # Mining binary
│   └── frychain-cli/        # CLI binary
├── genesis/                  # Genesis configurations
│   ├── mainnet.json
│   ├── testnet.json
│   └── devnet.json
└── scripts/                  # Launch and utility scripts
```

## Smart Contract Development

### Solana-style Contracts (SBF)

FryChain supports Solana's sBPF instruction set. Contracts can be written in Rust and compiled to sBPF:

```rust
// Example: Simple counter contract
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Your contract logic here
    Ok(())
}
```

### Algorand-style Contracts (AVM/TEAL)

FryChain also supports TEAL-like contracts:

```teal
// Example: Simple approval program
#pragma version 8
txn TypeEnum
int pay
==
txn Amount
int 1000000
>=
&&
return
```

## RPC API

The node exposes a JSON-RPC API compatible with common blockchain tooling:

```bash
# Get chain info
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"fry_chainId","params":[],"id":1}'

# Get balance
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"fry_getBalance","params":["fry1..."],"id":1}'

# Get block
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"fry_getBlockByNumber","params":["latest"],"id":1}'
```

## DePIN Integration

### Device Registration

```bash
# Register a new IoT device
./target/release/frycli device register \
  --owner-key <your-key> \
  --device-type sensor

# List your devices
./target/release/frycli device list <your-address>

# Get device info
./target/release/frycli device info did:fry:<device-address>
```

### M2M Transactions

Devices can transact directly with each other for:
- Data purchases
- Service payments
- Resource sharing

## Security

### Post-Quantum Resistance
FryChain uses NIST-standardized post-quantum algorithms:
- **CRYSTALS-Dilithium** (ML-DSA): Lattice-based signatures
- **SPHINCS+** (SLH-DSA): Hash-based signatures

Both algorithms are believed to be secure against quantum computer attacks.

### Mining Security
CryptoNight-STC is memory-hard, requiring 2MB of scratchpad memory per hash:
- Resistant to ASIC mining
- Promotes decentralization
- Fair mining for consumer hardware

## Economics

| Parameter | Value |
|-----------|-------|
| Total Supply | 210,000,000 FRY |
| Block Reward | 50 FRY (initial) |
| Halving Interval | 2,100,000 blocks |
| Target Block Time | 60 seconds |
| Decimals | 18 |

### Emission Schedule
- Year 1: ~26.3M FRY
- Years 1-4: ~105M FRY (50% of supply)
- Full emission: ~40 years

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

MIT License - see LICENSE file for details.

## Links

- Website: https://frychain.io
- Documentation: https://docs.frychain.io
- Explorer: https://explorer.frychain.io
- Discord: https://discord.gg/frychain

---

**FryChain** - Building the post-quantum future of decentralized infrastructure.
