#!/bin/bash

# BSC Local Validator 3 - Third validator for rotation testing
# Private Key: 5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
# Address: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

echo "🚀 Starting BSC Local Validator 3..."
echo "📋 Configuration:"
echo "   Validator Address: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
echo "   Data Directory: ./.local_data/validator3"
echo "   HTTP Port: 8549"
echo "   P2P Port: 30305"
echo "   Mining: Enabled"
echo ""

# Clean up any existing data
rm -rf ./.local_data/validator3

# Mining configuration
export RUST_LOG="info,reth_bsc=info"
export BSC_MINING_ENABLED="true"
export BSC_PRIVATE_KEY="5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

echo "✅ Starting validator 3..."
./target/release/reth-bsc node \
    --chain bsc-local \
    --datadir ./.local_data/validator3 \
    --http \
    --http.port 8549 \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --http.api "admin,debug,web3,eth,net,txpool" \
    --ws \
    --ws.addr 0.0.0.0 \
    --ws.port 8550 \
    --authrpc.addr 127.0.0.1 \
    --authrpc.port 8553 \
    --port 30305 \
    --discovery.port 30305 \
    --discovery.addr 0.0.0.0 \
    --nat extip:127.0.0.1 \
    --bootnodes "enode://9acc9b94f3f5b1cc2b25566c6fd0363f194a491e13fa1fca70402e322b8bb6ac8117ad0a8b1e95009d462f11ad7a082a4a80c59ebf1757ba6d8fdfb42c683dad@18.162.231.39:30303" \
    --trusted-peers "enode://9acc9b94f3f5b1cc2b25566c6fd0363f194a491e13fa1fca70402e322b8bb6ac8117ad0a8b1e95009d462f11ad7a082a4a80c59ebf1757ba6d8fdfb42c683dad@18.162.231.39:30303" \
    --mining.enabled \
    --mining.private-key 5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a \
    --log.file.filter warn \
    --log.stdout.filter info \
    -vvv \
    2>&1

echo "🛑 Validator 3 stopped."
