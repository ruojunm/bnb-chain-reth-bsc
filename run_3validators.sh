#!/bin/bash

# BSC Local 3-Validator Network - Target 2 Implementation
# Runs 3 validators that take turns mining blocks in Parlia PoA consensus

echo "🎯 Starting BSC Local 3-Validator Network (Target 2)"
echo "==============================================="
echo ""
echo "📋 Validator Configuration:"
echo "   Validator 1: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (HTTP: 8545, P2P: 30303)"
echo "   Validator 2: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (HTTP: 8547, P2P: 30304)" 
echo "   Validator 3: 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC (HTTP: 8549, P2P: 30305)"
echo ""
echo "🔄 Expected Behavior:"
echo "   - Each validator takes turns mining blocks (turn_length=1)"
echo "   - Block 1: Validator 1, Block 2: Validator 2, Block 3: Validator 3, Block 4: Validator 1..."
echo "   - All validators share the same blockchain state"
echo "   - RPC API available on all ports with parlia_eth_getBlockByNumber"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping all validators..."
    pkill -f "reth-bsc node"
    pkill -f "run_validator"
    echo "✅ All validators stopped."
    exit 0
}

# Set trap to cleanup on Ctrl+C
trap cleanup SIGINT SIGTERM

# Make scripts executable
chmod +x run_validator1.sh run_validator2.sh run_validator3.sh

# Function to get enode from a running validator
get_enode() {
    local port=$1
    local retries=0
    local max_retries=10
    
    while [ $retries -lt $max_retries ]; do
        enode=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
            "http://localhost:$port" 2>/dev/null | \
            jq -r '.result.enode // empty' 2>/dev/null)
        
        if [ ! -z "$enode" ] && [ "$enode" != "null" ] && [ "$enode" != "empty" ]; then
            echo "$enode"
            return 0
        fi
        
        retries=$((retries + 1))
        sleep 1
    done
    
    return 1
}

# Function to add peer manually
add_peer() {
    local port=$1
    local enode=$2
    
    curl -s -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"admin_addPeer\",\"params\":[\"$enode\"],\"id\":1}" \
        "http://localhost:$port" >/dev/null 2>&1
}

# Function to check if RPC server is ready
check_rpc_ready() {
    local port=$1
    local retries=0
    local max_retries=20
    
    while [ $retries -lt $max_retries ]; do
        if curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"parlia_getLocalHead","params":[],"id":1}' \
            "http://localhost:$port" >/dev/null 2>&1; then
            return 0
        fi
        retries=$((retries + 1))
        sleep 1
    done
    return 1
}

# Start validator 1 first (primary/bootstrap node)
echo "🚀 Starting Validator 1 (Bootstrap)..."
./run_validator1.sh > ./.local_data/validator1.log 2>&1 &
VALIDATOR1_PID=$!

echo "⏳ Waiting for Validator 1 RPC server to be ready..."
if check_rpc_ready 8545; then
    echo "✅ Validator 1 RPC server ready"
else
    echo "❌ Validator 1 RPC server failed to start"
    cleanup
fi

# Try to get Validator 1's enode for manual peer connections
VALIDATOR1_ENODE=$(get_enode 8545)
if [ ! -z "$VALIDATOR1_ENODE" ]; then
    echo "✅ Got Validator 1 enode: ${VALIDATOR1_ENODE:0:50}..."
fi

# Start validator 2 (connects to validator 1)
echo "🚀 Starting Validator 2..."
./run_validator2.sh > ./.local_data/validator2.log 2>&1 &
VALIDATOR2_PID=$!

echo "⏳ Waiting for Validator 2 RPC server to be ready..."
if check_rpc_ready 8547; then
    echo "✅ Validator 2 RPC server ready"
else
    echo "❌ Validator 2 RPC server failed to start"
    cleanup
fi

# Start validator 3 (connects to validator 1)
echo "🚀 Starting Validator 3..."
./run_validator3.sh > ./.local_data/validator3.log 2>&1 &
VALIDATOR3_PID=$!

echo "⏳ Waiting for Validator 3 RPC server to be ready..."
if check_rpc_ready 8549; then
    echo "✅ Validator 3 RPC server ready"
else
    echo "❌ Validator 3 RPC server failed to start"
    cleanup
fi

# Manual peer connections if enode is available
if [ ! -z "$VALIDATOR1_ENODE" ]; then
    echo "🔗 Setting up manual P2P connections..."
    add_peer 8547 "$VALIDATOR1_ENODE"
    add_peer 8549 "$VALIDATOR1_ENODE"
    echo "✅ P2P connections initiated"
fi

echo "⏱️ All validators ready - mining will begin in 15 seconds (startup delay)..."
echo ""
echo "✅ All 3 validators started successfully and coordinated!"
echo ""
echo "📊 Network Status:"
echo "   Validator 1 PID: $VALIDATOR1_PID (Primary RPC: http://localhost:8545)"
echo "   Validator 2 PID: $VALIDATOR2_PID (Alt RPC: http://localhost:8547)"
echo "   Validator 3 PID: $VALIDATOR3_PID (Alt RPC: http://localhost:8549)"
echo ""
echo "🧪 Test Commands:"
echo "   curl -X POST -H \"Content-Type: application/json\" --data '{\"jsonrpc\":\"2.0\",\"method\":\"parlia_getLocalHead\",\"params\":[],\"id\":1}' http://localhost:8545"
echo "   curl -X POST -H \"Content-Type: application/json\" --data '{\"jsonrpc\":\"2.0\",\"method\":\"parlia_eth_getBlockByNumber\",\"params\":[\"latest\", false],\"id\":1}' http://localhost:8545"
echo ""
echo "📄 Logs:"
echo "   tail -f ./.local_data/validator1.log"
echo "   tail -f ./.local_data/validator2.log" 
echo "   tail -f ./.local_data/validator3.log"
echo ""
echo "Press Ctrl+C to stop all validators..."

# Keep script running and monitor validators
while true; do
    # Check if all validators are still running
    if ! kill -0 $VALIDATOR1_PID 2>/dev/null; then
        echo "❌ Validator 1 stopped unexpectedly!"
        cleanup
    fi
    if ! kill -0 $VALIDATOR2_PID 2>/dev/null; then
        echo "❌ Validator 2 stopped unexpectedly!"
        cleanup
    fi
    if ! kill -0 $VALIDATOR3_PID 2>/dev/null; then
        echo "❌ Validator 3 stopped unexpectedly!"
        cleanup
    fi
    
    sleep 5
done
