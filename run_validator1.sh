#!/bin/bash

# BSC Local Validator 1 - Primary validator from Target 1
# Private Key: ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

echo "🚀 Starting BSC Local Validator 1..."
echo "📋 Configuration:"
echo "   Validator Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
echo "   Data Directory: ./.local_data/validator1"
echo "   HTTP Port: 8545"
echo "   P2P Port: 30303"
echo "   Mining: Enabled"
echo ""

# Clean up any existing data
rm -rf ./.local_data/validator1

# Mining configuration
export RUST_LOG="info,reth_bsc=info"
export BSC_MINING_ENABLED="true"
export BSC_PRIVATE_KEY="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "✅ Starting validator 1 (Bootstrap Node)..."
./target/release/reth-bsc node \
    --chain bsc-local \
    --datadir ./.local_data/validator1 \
    --http \
    --http.port 8545 \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --http.api "admin,debug,web3,eth,net,txpool" \
    --ws \
    --ws.addr 0.0.0.0 \
    --ws.port 8546 \
    --authrpc.addr 127.0.0.1 \
    --authrpc.port 8551 \
    --port 30303 \
    --discovery.port 30303 \
    --discovery.addr 0.0.0.0 \
    --nat extip:127.0.0.1 \
    --mining.enabled \
    --mining.private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --log.file.filter warn \
    --log.stdout.filter info \
    -vvv \
    2>&1

echo "🛑 Validator 1 stopped."
