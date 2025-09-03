# BSC Local Chain Setup Guide

## 🎯 **Local Chain Configuration**

### **Chain Specifications:**
- **Chain ID**: 1337 (dev standard)
- **Consensus**: Parlia PoA
- **Block Interval**: 750ms (Maxwell hardfork)
- **Epoch Length**: 1000 blocks
- **Validators**: 3 minimal validators

### **Validators Configuration:**

| Validator | Address | Role |
|-----------|---------|------|
| Validator 1 | `0x1000000000000000000000000000000000000001` | Primary |
| Validator 2 | `0x2000000000000000000000000000000000000002` | Secondary |
| Validator 3 | `0x3000000000000000000000000000000000000003` | Tertiary |

## 🔧 **Setup Steps**

### **1. Generate Validator Keys**

You'll need private keys for the validators. For testing, you can use:

```bash
# Generate or use test private keys
VALIDATOR1_KEY="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # Standard test key
VALIDATOR2_KEY="59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # Standard test key  
VALIDATOR3_KEY="5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # Standard test key
```

### **2. Run Local Chain**

```bash
# Build the project
cargo build --release

# Start validator 1 (primary)
./target/release/reth-bsc node \
    --chain=bsc-local \
    --datadir ./.local_data/validator1 \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --mining.enabled \
    --mining.private-key ${VALIDATOR1_KEY} \
    -vvv

# Start validator 2 (in another terminal)
./target/release/reth-bsc node \
    --chain=bsc-local \
    --datadir ./.local_data/validator2 \
    --port 30304 \
    --discovery.port 30304 \
    --http.port 8546 \
    --mining.enabled \
    --mining.private-key ${VALIDATOR2_KEY} \
    -vvv \
    --bootnodes enode://...  # Connect to validator1

# Start validator 3 (in another terminal)  
./target/release/reth-bsc node \
    --chain=bsc-local \
    --datadir ./.local_data/validator3 \
    --port 30305 \
    --discovery.port 30305 \
    --http.port 8547 \
    --mining.enabled \
    --mining.private-key ${VALIDATOR3_KEY} \
    -vvv \
    --bootnodes enode://...  # Connect to validator1
```

## ⚙️ **Command Line Arguments**

### **Correct Mining Arguments**
- ✅ `--mining.enabled` - Enable validator mining
- ✅ `--mining.private-key <HEX>` - Private key (validator address auto-derived)
- ✅ `--mining.dev` - Auto-generate development keys
- ❌ ~~`--mining`~~ - **This doesn't exist!**
- ❌ ~~`--mining.validator-address`~~ - **Not needed (auto-derived)**

### **Chain Arguments**
- ✅ `--chain=bsc-local` - Local development chain (ID 1337)
- ✅ `--chain=bsc-testnet` - BSC Chapel testnet (ID 97) 
- ✅ `--chain=bsc` - BSC mainnet (ID 56)

### **Logging Arguments**
- ✅ `-v` - Errors only
- ✅ `-vv` - Warnings + Errors  
- ✅ `-vvv` - Info + Warnings + Errors
- ✅ `-vvvv` - Debug + Info + Warnings + Errors
- ✅ `-vvvvv` - Traces (very verbose!)
- ✅ `--log.file.filter <LEVEL>` - File logging level (debug, info, warn, error)
- ❌ ~~`--log.file.verbosity`~~ - **This doesn't exist!**

## 🔬 **Testing the Chain**

### **Check Block Production**
```bash
# Check latest block
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545

# Check validator snapshot
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"parlia_getSnapshot","params":["latest"],"id":1}' \
  http://localhost:8545
```

### **Monitor Performance**
- **Expected Block Time**: ~750ms
- **Validator Rotation**: Every 1000 blocks
- **Gas Limit**: ~4.7M per block

## 🎛️ **Minimal Validator Requirements**

### **Hardware (Local Testing)**
- **CPU**: 2+ cores
- **Memory**: 4GB+ RAM  
- **Storage**: 10GB+ SSD
- **Network**: Local (no internet required)

### **Software**
- Rust 1.75+
- BSC Reth (current build)
- 3 validator private keys

## 🚀 **Next Steps**

1. **Start with 1 validator** for basic testing
2. **Add validators incrementally** 
3. **Test block sealing** and validation
4. **Verify consensus** and turn rotation
5. **Add transaction inclusion** later

This gives you a **minimal but complete BSC testnet** for validator development!
