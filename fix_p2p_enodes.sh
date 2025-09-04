#!/bin/bash

echo "🔧 BSC P2P Connectivity Fix"
echo "========================================="
echo ""

# Function to get enode from a running validator
get_enode() {
    local port=$1
    local retries=0
    local max_retries=10
    
    while [ $retries -lt $max_retries ]; do
        enode=$(curl -s -X POST -H "Content-Type: application/json" \
            --data '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
            "http://localhost:$port" | jq -r '.result.enode // empty' 2>/dev/null)
        
        if [ ! -z "$enode" ] && [ "$enode" != "null" ]; then
            echo "$enode"
            return 0
        fi
        
        retries=$((retries + 1))
        sleep 1
    done
    
    echo ""
    return 1
}

# Start validator 1 temporarily to get its enode
echo "🚀 Starting Validator 1 temporarily to get enode..."
./run_validator1.sh > ./.local_data/temp_validator1.log 2>&1 &
VALIDATOR1_PID=$!

echo "⏳ Waiting for Validator 1 to start..."
sleep 10

echo "🔍 Getting Validator 1 enode..."
VALIDATOR1_ENODE=$(get_enode 8545)

if [ -z "$VALIDATOR1_ENODE" ]; then
    echo "❌ Failed to get Validator 1 enode"
    kill $VALIDATOR1_PID 2>/dev/null
    exit 1
fi

echo "✅ Validator 1 enode: $VALIDATOR1_ENODE"

# Stop validator 1
echo "🛑 Stopping temporary Validator 1..."
kill $VALIDATOR1_PID 2>/dev/null
sleep 3

# Update validator scripts with correct enode
echo "📝 Updating validator scripts with correct bootnode..."

# Update validator 2
sed -i.bak "s|--bootnodes \"enode://.*\"|--bootnodes \"$VALIDATOR1_ENODE\"|" run_validator2.sh
sed -i.bak "s|--trusted-peers \"enode://.*\"|--trusted-peers \"$VALIDATOR1_ENODE\"|" run_validator2.sh

# Update validator 3  
sed -i.bak "s|--bootnodes \"enode://.*\"|--bootnodes \"$VALIDATOR1_ENODE\"|" run_validator3.sh
sed -i.bak "s|--trusted-peers \"enode://.*\"|--trusted-peers \"$VALIDATOR1_ENODE\"|" run_validator3.sh

echo "✅ P2P configuration updated!"
echo ""
echo "🎯 Updated bootnode enode: $VALIDATOR1_ENODE"
echo ""
echo "🚀 Ready to start 3-validator network with proper P2P connectivity!"
