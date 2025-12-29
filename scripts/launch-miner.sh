#!/bin/bash
# FryChain Miner Launch Script

set -e

# Default values
NETWORK="${NETWORK:-devnet}"
RPC="${RPC:-http://127.0.0.1:8545}"
THREADS="${THREADS:-}"
ADDRESS="${ADDRESS:-}"
BENCHMARK="${BENCHMARK:-}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --rpc)
            RPC="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --address)
            ADDRESS="$2"
            shift 2
            ;;
        --benchmark)
            BENCHMARK="$2"
            shift 2
            ;;
        --help)
            echo "FryChain Miner Launch Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --network <network>   Network to mine on (mainnet, testnet, devnet)"
            echo "  --rpc <url>           RPC endpoint to connect to"
            echo "  --threads <num>       Number of mining threads (default: auto)"
            echo "  --address <addr>      Miner address for rewards"
            echo "  --benchmark <secs>    Run benchmark for specified seconds"
            echo "  --help                Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build the miner if not already built
if [ ! -f "./target/release/frychain-miner" ]; then
    echo "Building FryChain miner..."
    cargo build --release -p frychain-miner
fi

# Construct command
CMD="./target/release/frychain-miner"
CMD="$CMD --network $NETWORK"
CMD="$CMD --rpc $RPC"

if [ -n "$THREADS" ]; then
    CMD="$CMD --threads $THREADS"
fi

if [ -n "$ADDRESS" ]; then
    CMD="$CMD --address $ADDRESS"
fi

if [ -n "$BENCHMARK" ]; then
    CMD="$CMD --benchmark $BENCHMARK"
fi

echo "Starting FryChain miner..."
echo "Network: $NETWORK"
echo "RPC endpoint: $RPC"
if [ -n "$THREADS" ]; then
    echo "Mining threads: $THREADS"
else
    echo "Mining threads: auto (all CPUs)"
fi
if [ -n "$ADDRESS" ]; then
    echo "Miner address: $ADDRESS"
else
    echo "Miner address: will generate new keypair"
fi
echo ""

exec $CMD
