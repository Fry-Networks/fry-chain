#!/bin/bash
# FryChain Benchmark Script

set -e

echo "======================================"
echo "   FryChain Benchmark Suite"
echo "======================================"
echo ""

# Build in release mode
echo "Building in release mode..."
cargo build --release

# Parse arguments
DURATION="${1:-10}"
THREADS="${2:-$(nproc)}"

echo ""
echo "Running benchmarks with:"
echo "  Duration: ${DURATION} seconds"
echo "  Threads: ${THREADS}"
echo ""

# Run mining benchmark
echo "======================================"
echo "  CryptoNight-STC Mining Benchmark"
echo "======================================"
./target/release/frychain-miner --benchmark "$DURATION" --threads "$THREADS"

echo ""
echo "======================================"
echo "  Benchmark Complete!"
echo "======================================"
