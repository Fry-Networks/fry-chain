#!/bin/bash
# FryChain Node Launch Script

set -e

# Default values
NETWORK="${NETWORK:-devnet}"
DATA_DIR="${DATA_DIR:-./frychain-data}"
P2P_PORT="${P2P_PORT:-30303}"
RPC_PORT="${RPC_PORT:-8545}"
RPC_ADDR="${RPC_ADDR:-127.0.0.1}"
MAX_PEERS="${MAX_PEERS:-50}"
MINE="${MINE:-false}"
MINER_ADDR="${MINER_ADDR:-}"
MINING_THREADS="${MINING_THREADS:-1}"
BOOTNODES="${BOOTNODES:-}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --p2p-port)
            P2P_PORT="$2"
            shift 2
            ;;
        --rpc-port)
            RPC_PORT="$2"
            shift 2
            ;;
        --rpc-addr)
            RPC_ADDR="$2"
            shift 2
            ;;
        --max-peers)
            MAX_PEERS="$2"
            shift 2
            ;;
        --mine)
            MINE="true"
            shift
            ;;
        --miner)
            MINER_ADDR="$2"
            shift 2
            ;;
        --mining-threads)
            MINING_THREADS="$2"
            shift 2
            ;;
        --bootnodes)
            BOOTNODES="$2"
            shift 2
            ;;
        --help)
            echo "FryChain Node Launch Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --network <network>      Network to connect to (mainnet, testnet, devnet)"
            echo "  --data-dir <path>        Data directory for blockchain data"
            echo "  --p2p-port <port>        P2P listen port (default: 30303)"
            echo "  --rpc-port <port>        RPC listen port (default: 8545)"
            echo "  --rpc-addr <addr>        RPC listen address (default: 127.0.0.1)"
            echo "  --max-peers <num>        Maximum peer connections (default: 50)"
            echo "  --mine                   Enable mining"
            echo "  --miner <address>        Miner address for block rewards"
            echo "  --mining-threads <num>   Number of mining threads (default: 1)"
            echo "  --bootnodes <nodes>      Comma-separated list of bootstrap nodes"
            echo "  --help                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build the node if not already built
if [ ! -f "./target/release/frychain-node" ]; then
    echo "Building FryChain node..."
    cargo build --release -p frychain-node
fi

# Construct command
CMD="./target/release/frychain-node"
CMD="$CMD --network $NETWORK"
CMD="$CMD --data-dir $DATA_DIR"
CMD="$CMD --p2p-port $P2P_PORT"
CMD="$CMD --rpc-port $RPC_PORT"
CMD="$CMD --rpc-addr $RPC_ADDR"
CMD="$CMD --max-peers $MAX_PEERS"

if [ "$MINE" = "true" ]; then
    CMD="$CMD --mine"
fi

if [ -n "$MINER_ADDR" ]; then
    CMD="$CMD --miner $MINER_ADDR"
fi

if [ -n "$MINING_THREADS" ] && [ "$MINING_THREADS" -gt 0 ]; then
    CMD="$CMD --mining-threads $MINING_THREADS"
fi

if [ -n "$BOOTNODES" ]; then
    CMD="$CMD --bootnodes $BOOTNODES"
fi

echo "Starting FryChain node..."
echo "Network: $NETWORK"
echo "Data directory: $DATA_DIR"
echo "P2P port: $P2P_PORT"
echo "RPC: $RPC_ADDR:$RPC_PORT"
echo ""

exec $CMD
