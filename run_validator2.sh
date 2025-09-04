#!/bin/bash

# BSC Local Validator 2 - Second validator for turn-taking
# Private Key: 59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d  
# Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

echo "🚀 Starting BSC Local Validator 2..."
echo "📋 Configuration:"
echo "   Validator Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
echo "   Data Directory: ./.local_data/validator2"
echo "   HTTP Port: 8547"
echo "   P2P Port: 30304"
echo "   Mining: Enabled"
echo ""

# Clean up any existing data
rm -rf ./.local_data/validator2

# Mining configuration
export RUST_LOG="info,reth_bsc=info"
export BSC_MINING_ENABLED="true"
export BSC_PRIVATE_KEY="59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

echo "✅ Starting validator 2..."
./target/release/reth-bsc node \
    --chain bsc-local \
    --datadir ./.local_data/validator2 \
    --http \
    --http.port 8547 \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --http.api "admin,debug,web3,eth,net,txpool" \
    --ws \
    --ws.addr 0.0.0.0 \
    --ws.port 8548 \
    --authrpc.addr 127.0.0.1 \
    --authrpc.port 8552 \
    --port 30304 \
    --discovery.port 30304 \
    --discovery.addr 0.0.0.0 \
    --nat extip:127.0.0.1 \
    --log.file.filter warn \
    --log.stdout.filter info \
    -vvv \
    2>&1

echo "🛑 Validator 2 stopped."
