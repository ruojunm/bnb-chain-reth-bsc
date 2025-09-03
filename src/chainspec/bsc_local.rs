//! Local BSC chain specification for development and testing
use crate::hardforks::bsc::BscHardfork;
use alloy_primitives::{Address, BlockHash, B256, U256};
use reth_chainspec::{
    make_genesis_header, BaseFeeParams, BaseFeeParamsKind, Chain, ChainSpec, ForkCondition, Head,
};
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, Hardfork};
use reth_primitives::SealedHeader;
use std::str::FromStr;

/// Local BSC chain ID for development (using 1337 like Hardhat)
pub const BSC_LOCAL_CHAIN_ID: u64 = 1337;

/// Create local BSC chain specification with Maxwell hardfork active from genesis
pub fn bsc_local() -> ChainSpec {
    let genesis = serde_json::from_str(include_str!("genesis_local.json"))
        .expect("Can't deserialize BSC Local genesis json");
    let hardforks = local_hardforks();
    ChainSpec {
        chain: Chain::from_id(BSC_LOCAL_CHAIN_ID),
        genesis: serde_json::from_str(include_str!("genesis_local.json"))
            .expect("Can't deserialize BSC Local genesis json"),
        paris_block_and_final_difficulty: Some((0, U256::from(0))),
        hardforks,
        deposit_contract: None,
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::new(1, 1)),
        prune_delete_limit: 10000,
        genesis_header: SealedHeader::new(
            make_genesis_header(&genesis, &local_hardforks()),
            BlockHash::from_str(
                // This will be calculated based on the actual genesis
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
        ),
        ..Default::default()
    }
}

/// Local hardforks configuration - Maxwell active from genesis for latest features
fn local_hardforks() -> ChainHardforks {
    ChainHardforks::new(vec![
        // All Ethereum hardforks from genesis for full compatibility
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::MuirGlacier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Shanghai.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Cancun.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Prague.boxed(), ForkCondition::Block(0)),
        
        // All BSC hardforks from genesis for testing
        (BscHardfork::Ramanujan.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Niels.boxed(), ForkCondition::Block(0)),
        (BscHardfork::MirrorSync.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Bruno.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Euler.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Nano.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Moran.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Gibbs.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Planck.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Luban.boxed(), ForkCondition::Block(25000)),
        (BscHardfork::Plato.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Hertz.boxed(), ForkCondition::Block(0)),
        (BscHardfork::HertzFix.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Kepler.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Feynman.boxed(), ForkCondition::Block(0)),
        (BscHardfork::FeynmanFix.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Cancun.boxed(), ForkCondition::Block(0)),
        (BscHardfork::Haber.boxed(), ForkCondition::Block(0)),
        (BscHardfork::HaberFix.boxed(), ForkCondition::Block(0)),
        // Bohr hardfork disabled for single validator development (strict signing rules)
        // (BscHardfork::Bohr.boxed(), ForkCondition::Block(0)),
        // Later hardforks activated after sufficient blocks for multi-validator testing
        (BscHardfork::Tycho.boxed(), ForkCondition::Block(5000)),
        (BscHardfork::Pascal.boxed(), ForkCondition::Block(10000)),
        (BscHardfork::Lorentz.boxed(), ForkCondition::Block(15000)),
        // Maxwell activated later to test all features with multiple validators
        (BscHardfork::Maxwell.boxed(), ForkCondition::Block(20000)),
    ])
}

/// Local development head (genesis block)
pub fn head() -> Head {
    Head {
        number: 0,
        hash: B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap(),
        difficulty: U256::from(2), // In-turn difficulty for PoA
        total_difficulty: U256::from(0),
        timestamp: 0, // Will be set when chain starts
    }
}

/// Generate validator addresses for local testing
pub fn local_validators() -> Vec<Address> {
    vec![
        // Validator 1 - Standard test account (matches private key in script)
        Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
        // Validator 2 - for multi-validator testing
        Address::from_str("0x2000000000000000000000000000000000000002").unwrap(),
        // Validator 3 - minimum viable set
        Address::from_str("0x3000000000000000000000000000000000000003").unwrap(),
    ]
}
