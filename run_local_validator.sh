#!/bin/bash

# BSC Local Validator Setup Script
# This script sets up a single validator for local testing

set -e

# Configuration
VALIDATOR_KEY="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DATADIR="./.local_data/local_validator"
HTTP_PORT="8545"
P2P_PORT="30303"

echo "🚀 Starting BSC Local Validator..."
echo "📋 Configuration:"
echo "   Validator Key: ${VALIDATOR_KEY:0:10}... (address auto-derived)"
echo "   Data Directory: $DATADIR"
echo "   HTTP Port: $HTTP_PORT"
echo "   P2P Port: $P2P_PORT"
echo "   Chain: Local BSC (ID: 1337)"
echo "   Hardforks: Progressive (single validator compatible)"
echo "   Block Interval: 3s initially, then 750ms after block 20000"
echo ""

# Build if needed
if [ ! -f "./target/release/reth-bsc" ]; then
    echo "🔨 Building BSC Reth..."
    cargo build --release
fi

# Create data directory
mkdir -p "$DATADIR"

# Start the validator
echo "✅ Starting validator..."
./target/release/reth-bsc node \
    --chain=bsc-local \
    --datadir="$DATADIR" \
    --http \
    --http.addr=0.0.0.0 \
    --http.port="$HTTP_PORT" \
    --port="$P2P_PORT" \
    --discovery.port="$P2P_PORT" \
    --mining.enabled \
    --mining.private-key="$VALIDATOR_KEY" \
    -vvv

echo ""
echo "🛑 Validator stopped."
