#!/bin/bash
# FryChain Development Network Setup Script

set -e

echo "======================================"
echo "   FryChain DevNet Setup Script"
echo "======================================"
echo ""

# Create directories
echo "Creating directories..."
mkdir -p ./devnet/node1
mkdir -p ./devnet/node2
mkdir -p ./devnet/miner

# Build all binaries
echo "Building FryChain binaries..."
cargo build --release

echo ""
echo "DevNet setup complete!"
echo ""
echo "To start a local development network:"
echo ""
echo "1. Start node 1 (seed node):"
echo "   ./target/release/frychain-node --network devnet --data-dir ./devnet/node1 --p2p-port 30305 --rpc-port 8547 --mine"
echo ""
echo "2. Start node 2 (connects to node 1):"
echo "   ./target/release/frychain-node --network devnet --data-dir ./devnet/node2 --p2p-port 30306 --rpc-port 8548 --bootnodes 127.0.0.1:30305"
echo ""
echo "3. Start standalone miner:"
echo "   ./target/release/frychain-miner --network devnet --rpc http://127.0.0.1:8547"
echo ""
echo "4. Use CLI to interact:"
echo "   ./target/release/frycli --rpc http://127.0.0.1:8547 info"
echo "   ./target/release/frycli keygen --key-type dilithium"
echo "   ./target/release/frycli balance <address>"
echo ""
echo "For more options, run any binary with --help"
