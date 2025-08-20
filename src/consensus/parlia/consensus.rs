use alloy_rlp::Decodable;
use super::{
    ParliaHeaderValidator, SnapshotProvider, BscConsensusValidator, Snapshot, TransactionSplitter, SplitTransactions, VoteAttestation, ParliaConsensusError, 
    constants::*,
};
use alloy_consensus::{Header, TxReceipt, Transaction, BlockHeader};
use alloy_primitives::{map::foldhash::{HashSet, HashSetExt}, Address, Bytes, B256};
use rand::Rng;
use reth_primitives_traits::{GotExpected, SignerRecoverable};
use crate::{
    consensus::parlia::{VoteAddress, VoteData, VoteEnvelope, VoteSignature}, hardforks::BscHardforks, node::primitives::BscBlock, BscPrimitives
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use reth::consensus::{Consensus, FullConsensus, ConsensusError, HeaderValidator};
use reth_primitives_traits::{Block, SealedBlock, SealedHeader, RecoveredBlock};
use reth_chainspec::EthChainSpec;
use std::sync::Arc;
use std::time::SystemTime;
use lazy_static::lazy_static;
use std::sync::RwLock;

use schnellru::LruMap;
use schnellru::ByLength;
use alloy_primitives::{Address, B256};
use secp256k1::{SECP256K1, Message, ecdsa::{RecoveryId, RecoverableSignature}};
use super::{
    VoteAttestation, ParliaConsensusError, VoteAddress,
    constants::*,
    hash_with_chain_id,
    provider::ValidatorsInfo
};
use std::collections::HashMap;
use blst::min_pk::{AggregateSignature, Signature as blsSignature};

const RECOVERED_PROPOSER_CACHE_NUM: usize = 4096;
const ADDRESS_LENGTH: usize = 20; // Ethereum address length in bytes

lazy_static! {
    // recovered proposer cache map by block_number: proposer_address
    static ref RECOVERED_PROPOSER_CACHE: RwLock<LruMap<B256, Address, ByLength>> = RwLock::new(LruMap::new(ByLength::new(RECOVERED_PROPOSER_CACHE_NUM as u32)));
}

#[derive(Debug)]
pub struct Parlia<ChainSpec> {
    pub spec: Arc<ChainSpec>,
    pub epoch: u64, // The epoch number
    // period: u64, // The period of block proposal
}

type SignFnPtr = fn(Address, &str, &[u8]) -> Result<[u8; 65], ConsensusError>;
// type SignTxFnPtr = fn(Address, &mut dyn SignableTransaction<Signature>, u64) -> Result<Box<dyn SignableTransaction<Signature>>, ConsensusError>;

impl<ChainSpec> Parlia<ChainSpec> 
where ChainSpec: EthChainSpec + BscHardforks + 'static, 
{
    pub fn new(chain_spec: Arc<ChainSpec>, epoch: u64) -> Self {
        Self { spec: chain_spec, epoch }
    }

    /// Get chain spec
    pub fn chain_spec(&self) -> &ChainSpec {
        &self.spec
    }

    /// Get epoch length from header
    pub fn get_epoch_length(&self, header: &Header) -> u64 {
        if self.spec.is_maxwell_active_at_timestamp(header.timestamp()) {
            return crate::consensus::parlia::snapshot::MAXWELL_EPOCH_LENGTH;
        }
        if self.spec.is_lorentz_active_at_timestamp(header.timestamp()) {
            return crate::consensus::parlia::snapshot::LORENTZ_EPOCH_LENGTH;
        }
        self.epoch
    }

    /// Get validator bytes from header extra data
    pub fn get_validator_bytes_from_header(&self, header: &Header) -> Option<Vec<u8>> {
        let extra_len = header.extra_data.len();
        if extra_len <= EXTRA_VANITY + EXTRA_SEAL {
            return None;
        }

        let is_luban_active = self.spec.is_luban_active_at_block(header.number);
        let is_epoch = header.number % self.get_epoch_length(header) == 0;

        if is_luban_active {
            if !is_epoch {
                return None;
            }

            let count = header.extra_data[EXTRA_VANITY] as usize;
            let start = EXTRA_VANITY+VALIDATOR_NUMBER_SIZE;
            let end = start + count * VALIDATOR_BYTES_LEN_AFTER_LUBAN;

            let mut extra_min_len = end + EXTRA_SEAL;
            let is_bohr_active = self.spec.is_bohr_active_at_timestamp(header.timestamp);
            if is_bohr_active {
                extra_min_len += TURN_LENGTH_SIZE;
            }
            if count == 0 || extra_len < extra_min_len {
                return None
            }
            Some(header.extra_data[start..end].to_vec())
        } else {
            if is_epoch &&
                (extra_len - EXTRA_VANITY - EXTRA_SEAL) %
                VALIDATOR_BYTES_LEN_BEFORE_LUBAN !=
                    0
            {
                return None;
            }

            Some(header.extra_data[EXTRA_VANITY..extra_len - EXTRA_SEAL].to_vec())
        }
    }

    /// Get turn length from header
    pub fn get_turn_length_from_header(&self, header: &Header) -> Result<Option<u8>, ParliaConsensusError> {
        if header.number % self.get_epoch_length(header) != 0 ||
            !self.spec.is_bohr_active_at_timestamp(header.timestamp)
        {
            return Ok(None);
        }

        if header.extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
            return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                header_extra_len: header.extra_data.len() as u64,
            });
        }

        let num = header.extra_data[EXTRA_VANITY] as usize;
        let pos = EXTRA_VANITY + 1 + num * VALIDATOR_BYTES_LEN_AFTER_LUBAN;

        if header.extra_data.len() <= pos {
            return Err(ParliaConsensusError::ExtraInvalidTurnLength);
        }

        let turn_length = header.extra_data[pos];
        Ok(Some(turn_length))
    }

    /// Get vote attestation from header
    pub fn get_vote_attestation_from_header(&self, header: &Header) -> Result<Option<VoteAttestation>, ParliaConsensusError> {
        let extra_len = header.extra_data.len();
        if extra_len <= EXTRA_VANITY + EXTRA_SEAL {
            return Ok(None);
        }

        if !self.spec.is_luban_active_at_block(header.number()) {
            return Ok(None);
        }

        let mut raw_attestation_data = if header.number() % self.get_epoch_length(header) != 0 {
            &header.extra_data[EXTRA_VANITY..extra_len - EXTRA_SEAL]
        } else {
            let validator_count =
                header.extra_data[EXTRA_VANITY + VALIDATOR_NUMBER_SIZE - 1] as usize;
            let mut start =
                EXTRA_VANITY + VALIDATOR_NUMBER_SIZE + validator_count * VALIDATOR_BYTES_LEN_AFTER_LUBAN;
            let is_bohr_active = self.spec.is_bohr_active_at_timestamp(header.timestamp);
            if is_bohr_active {
                start += TURN_LENGTH_SIZE;
            }
            let end = extra_len - EXTRA_SEAL;
            if end <= start {
                return Ok(None)
            }
            &header.extra_data[start..end]
        };
        if raw_attestation_data.is_empty() {
            return Ok(None);
        }

        Ok(Some(
            Decodable::decode(&mut raw_attestation_data)
                .map_err(|_| ParliaConsensusError::ABIDecodeInnerError)?,
        ))
    }

    pub fn recover_proposer(&self, header: &Header) -> Result<Address, ParliaConsensusError> {
        let hash = header.hash_slow();
        
        { // Check cache first
            let mut cache = RECOVERED_PROPOSER_CACHE.write().unwrap();
            if let Some(proposer) = cache.get(&hash) {
                return Ok(*proposer);
            }
        }

        let extra_data = &header.extra_data;
        if extra_data.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(ParliaConsensusError::ExtraSignatureMissing);
        }

        let signature_offset = extra_data.len() - EXTRA_SEAL;
        let recovery_byte = extra_data[signature_offset + EXTRA_SEAL - 1] as i32;
        let signature_bytes = &extra_data[signature_offset..signature_offset + EXTRA_SEAL - 1];

        let recovery_id = RecoveryId::try_from(recovery_byte)
            .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;
        let signature = RecoverableSignature::from_compact(signature_bytes, recovery_id)
            .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;

        let message = Message::from_digest_slice(
                            hash_with_chain_id(header, self.spec.chain().id()).as_slice(),
        )
        .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;
        let public = &SECP256K1
            .recover_ecdsa(&message, &signature)
            .map_err(|_| ParliaConsensusError::RecoverECDSAInnerError)?;

        let proposer =
            Address::from_slice(&alloy_primitives::keccak256(&public.serialize_uncompressed()[1..])[12..]);
        
        { // Update cache
            let mut cache = RECOVERED_PROPOSER_CACHE.write().unwrap();
            cache.insert(hash, proposer);
        }
        
        Ok(proposer)
    }
    
    pub fn present_timestamp(&self) -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }

    fn get_validator_len_from_header(
        &self,
        header: &Header,
    ) -> Result<usize, ParliaConsensusError> {
        if header.number % self.get_epoch_length(header) != 0 {
            return Ok(0);
        }

        let extra_len = header.extra_data.len();

        if !self.spec.is_luban_active_at_block(header.number) {
            return Ok(extra_len - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN);
        }

        let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
        Ok(count * EXTRA_VALIDATOR_LEN)
    }

    fn check_header_extra_len(&self, header: &Header) -> Result<(), ParliaConsensusError> {
        let extra_len = header.extra_data.len();
        if extra_len < EXTRA_VANITY_LEN {
            return Err(ParliaConsensusError::ExtraVanityMissing);
        }
        if extra_len < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
            return Err(ParliaConsensusError::ExtraSignatureMissing);
        }

        if header.number % self.get_epoch_length(header) != 0 {
            return Ok(());
        }

        if self.spec.is_luban_active_at_block(header.number) {
            let count = header.extra_data[EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM - 1] as usize;
            let expect =
                EXTRA_VANITY_LEN_WITH_VALIDATOR_NUM + EXTRA_SEAL_LEN + count * EXTRA_VALIDATOR_LEN;
            if count == 0 || extra_len < expect {
                tracing::warn!("Invalid header extra len, block_number: {}, extra_len: {}, expect: {}, count: {}, epoch_length: {}", 
                    header.number, extra_len, expect, count, self.get_epoch_length(header));
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                });
            }
        } else {
            let validator_bytes_len = extra_len - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN;
            if validator_bytes_len / EXTRA_VALIDATOR_LEN_BEFORE_LUBAN == 0 ||
                validator_bytes_len % EXTRA_VALIDATOR_LEN_BEFORE_LUBAN != 0
            {
                return Err(ParliaConsensusError::InvalidHeaderExtraLen {
                    header_extra_len: extra_len as u64,
                });
            }
        }

        Ok(())
    }

    pub fn check_header_extra(&self, header: &Header) -> Result<(), ParliaConsensusError> {
        self.check_header_extra_len(header)?;

        let is_epoch = header.number % self.get_epoch_length(header) == 0;
        let validator_bytes_len = self.get_validator_len_from_header(header)?;
        if (!is_epoch && validator_bytes_len != 0) || (is_epoch && validator_bytes_len == 0) {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch,
                validator_bytes_len,
            });
        }

        Ok(())
    }

    pub fn parse_validators_from_header(
        &self,
        header: &Header,
    ) -> Result<ValidatorsInfo, ParliaConsensusError> {
        let val_bytes = self.get_validator_bytes_from_header(header).ok_or_else(|| {
            ParliaConsensusError::InvalidHeaderExtraLen {
                header_extra_len: header.extra_data.len() as u64,
            }
        })?;

        if val_bytes.is_empty() {
            return Err(ParliaConsensusError::InvalidHeaderExtraValidatorBytesLen {
                is_epoch: true,
                validator_bytes_len: 0,
            })
        }

        if self.spec.is_luban_active_at_block(header.number) {
            self.parse_validators_after_luban(&val_bytes)
        } else {
            self.parse_validators_before_luban(&val_bytes)
        }
    }

    fn parse_validators_after_luban(
        &self,
        validator_bytes: &[u8],
    ) -> Result<ValidatorsInfo, ParliaConsensusError> {
        let count = validator_bytes.len() / EXTRA_VALIDATOR_LEN;
        let mut consensus_addrs = Vec::with_capacity(count);
        let mut vote_addrs = Vec::with_capacity(count);

        for i in 0..count {
            let consensus_start = i * EXTRA_VALIDATOR_LEN;
            let consensus_end = consensus_start + ADDRESS_LENGTH;
            let consensus_address =
                Address::from_slice(&validator_bytes[consensus_start..consensus_end]);
            consensus_addrs.push(consensus_address);

            let vote_start = consensus_start + ADDRESS_LENGTH;
            let vote_end = consensus_start + EXTRA_VALIDATOR_LEN;
            let vote_address = VoteAddress::from_slice(&validator_bytes[vote_start..vote_end]);
            vote_addrs.push(vote_address);
        }

        Ok(ValidatorsInfo { consensus_addrs, vote_addrs: Some(vote_addrs) })
    }

    fn parse_validators_before_luban(
        &self,
        validator_bytes: &[u8],
    ) -> Result<ValidatorsInfo, ParliaConsensusError> {
        let count = validator_bytes.len() / EXTRA_VALIDATOR_LEN_BEFORE_LUBAN;
        let mut consensus_addrs = Vec::with_capacity(count);

        for i in 0..count {
            let start = i * EXTRA_VALIDATOR_LEN_BEFORE_LUBAN;
            let end = start + EXTRA_VALIDATOR_LEN_BEFORE_LUBAN;
            let address = Address::from_slice(&validator_bytes[start..end]);
            consensus_addrs.push(address);
        }

        Ok(ValidatorsInfo { consensus_addrs, vote_addrs: None })
    }
} 


impl<ChainSpec, P> ParliaConsensus<ChainSpec, P>
where
    ChainSpec: EthChainSpec + BscHardforks + Send + Sync + 'static,
    P: SnapshotProvider + std::fmt::Debug + Send + Sync + 'static,
{
    #[allow(unused_variables)]
    pub fn seal(self,
        block: &BscBlock,
        results_sender: std::sync::mpsc::Sender<reth_primitives_traits::SealedBlock<BscBlock>>,
        stop_receiver: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), ConsensusError> {
        let header = block.header();
        if header.number == 0 {
            return Err(ConsensusError::Other("Unknown block (genesis sealing not supported)".into()));
        }

        let val     = self.validator_address;
        let sign_fn = self.sign_fn;

        let parent_number = header.number - 1;
        let parent_hash   = header.parent_hash;
        let snap = self.snapshot_provider.snapshot(parent_number)
            .ok_or_else(|| ConsensusError::Other("Snapshot not found".into()))?;

        if !snap.validators.contains(&val) {
            return Err(ConsensusError::Other(format!("Unauthorized validator: {val}").into()));
        }

        if snap.sign_recently(val) {
            tracing::info!("Signed recently, must wait for others");
            return Ok(());
        }

        let delay = self.delay_for_ramanujan_fork(&snap, header);
        tracing::info!(
            target: "parlia::seal",
            "Sealing block {} (delay {:?}, difficulty {:?})",
            header.number,
            delay,
            header.difficulty
        );

        let block = block.clone();

        std::thread::spawn(move || {
            if let Ok(()) = stop_receiver.try_recv() {
                return;
            } else {
                std::thread::sleep(delay);
            }

            let mut header = block.header().clone();
            if let Err(e) = self.assemble_vote_attestation_stub(&mut header) {
                tracing::error!(target: "parlia::seal", "Assemble vote attestation failed: {e}");
            }

            match sign_fn(val, "mimetype/parlia", &[]) {
                Ok(sig) => {
                    let mut extra = header.extra_data.to_vec();
                    if extra.len() >= EXTRA_SEAL {
                        let start = extra.len() - EXTRA_SEAL;
                        extra[start..].copy_from_slice(&sig);
                        header.extra_data = Bytes::from(extra);
                    } else {
                        tracing::error!(target: "parlia::seal", "extra_data too short to insert seal");
                    }
                }
                Err(e) => tracing::debug!(target: "parlia::seal", "Sign for the block header failed when sealing, err {e}"),
            }

            // TODO
            // if p.shouldWaitForCurrentBlockProcess(chain, header, snap) {
            if !true {
                let gas_used = 0;
                let wait_process_estimate = (gas_used as f64 / 100_000_000f64).ceil();
                tracing::info!(target: "parlia::seal", "Waiting for received in turn block to process waitProcessEstimate(Seconds) {wait_process_estimate}");
                std::thread::sleep(Duration::from_secs(wait_process_estimate as u64));
                if let Ok(()) = stop_receiver.try_recv() {
                    tracing::info!(target: "parlia::seal", "Received block process finished, abort block seal");
                    return;
                }
                //TODO:
                let currend_header = 0;
                if currend_header >= header.number() {
                    tracing::info!(target: "parlia::seal", "Process backoff time exhausted, and current header has updated to abort this seal");
                    return;
                } else {
                    tracing::info!(target: "parlia::seal", "Process backoff time exhausted, start to seal block");
                }
            }

            let _ = results_sender.send(BscBlock::new_sealed(SealedHeader::new_unhashed(header), block.body));
        });

        Ok(())
    }

    fn delay_for_ramanujan_fork(&self, snapshot: &Snapshot, header: &Header) -> std::time::Duration {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut delay = Duration::from_secs((header.timestamp as u64).saturating_sub(now_secs));

        if self.chain_spec.is_ramanujan_active_at_block(header.number) {
            return delay;
        }

        if header.difficulty == DIFF_NOTURN {
            const FIXED_BACKOFF_TIME_BEFORE_FORK: Duration = Duration::from_millis(200);
            const WIGGLE_TIME_BEFORE_FORK: u64 = 500 * 1000 * 1000; // 500 ms

            let validators = snapshot.validators.len();
            let rand_wiggle = rand::thread_rng().gen_range(0..(WIGGLE_TIME_BEFORE_FORK * (validators / 2 + 1) as u64));

            delay += FIXED_BACKOFF_TIME_BEFORE_FORK + Duration::from_nanos(rand_wiggle);
        }

        delay
    }


    fn assemble_vote_attestation_stub(&self, header: & mut alloy_consensus::Header) -> Result<(), ConsensusError> {
        if !self.chain_spec.is_luban_active_at_block(header.number()) || header.number() < 2 {
         return Ok(());
        }

        let parent = self.snapshot_provider.get_header_by_hash(&header.parent_hash)
        .ok_or_else(|| ConsensusError::Other("parent not found".into()))?;
        let snap = self.snapshot_provider.snapshot(parent.number-1)
        .ok_or_else(|| ConsensusError::Other("Snapshot not found".into()))?;

        //TODO
        // votes := p.VotePool.FetchVoteByBlockHash(parent.Hash())
        // if len(votes) < cmath.CeilDiv(len(snap.Validators)*2, 3) {
        //     return nil
        // }
        let votes: Vec<VoteEnvelope> = Vec::new();

        let (justifiedBlockNumber, justifiedBlockHash) = match self.get_justified_number_and_hash(&parent) {
            Ok((a, b)) => (a, b),
            Err(err) => return Err(err),
        };

        let mut attestation = VoteAttestation::new_with_vote_data(
            VoteData{
                source_hash: justifiedBlockHash,
                source_number: justifiedBlockNumber,
                target_hash: parent.mix_hash,
                target_number: parent.number,
        });

        for vote in votes.iter() {
            if vote.data.hash() != attestation.data.hash() {
                return Err(ConsensusError::Other(
                    format!(
                        "vote check error, expected: {:?}, real: {:?}",
                        attestation.data,
                        vote.data,
                ).into(),
                ));
            }
        }

        let mut vote_addr_set: HashSet<VoteAddress> = HashSet::new();
        let mut signatures: Vec<VoteSignature> = Vec::new();

        for vote in votes.iter() {
            vote_addr_set.insert(vote.vote_address);
            signatures.push(vote.signature);
        }

        let sigs: Vec<blsSignature> = signatures.iter().map(
                    |raw| blsSignature::from_bytes(raw.as_slice())
                    .map_err(|e| ConsensusError::Other(format!("BLS sig decode error: {:?}", e).into()))
                ).collect::<Result<_, _>>()?;
        let sigs_ref: Vec<&blsSignature> = sigs.iter().collect();
        attestation.agg_signature.copy_from_slice(
            &AggregateSignature::aggregate(&sigs_ref, false)
                .expect("aggregate failed")
                .to_signature()
                .to_bytes(),
        );

        for (_, val_info) in snap.validators_map.iter() {
            if vote_addr_set.contains(&val_info.vote_addr) {
                attestation.vote_address_set |= 1 << (val_info.index-1)
            }
        }

        if attestation.vote_address_set.count_ones() as usize != signatures.len() {
            tracing::warn!(
                "assembleVoteAttestation, check VoteAddress Set failed, expected: {:?}, real: {:?}",
                signatures.len(), attestation.vote_address_set.count_ones());
            return Err(ConsensusError::Other("invalid attestation, check VoteAddress Set failed".into()));
        }

        let buf = alloy_rlp::encode(&attestation);
        let extra_seal_start = header.extra_data.len() - EXTRA_SEAL;
        let extra_seal_bytes = &header.extra_data[extra_seal_start..];


        let mut new_extra = Vec::with_capacity(extra_seal_start + buf.len() + EXTRA_SEAL);
        new_extra.extend_from_slice(&header.extra_data[..extra_seal_start]);
        new_extra.extend_from_slice(buf.as_ref());
        new_extra.extend_from_slice(extra_seal_bytes);

        header.extra_data = Bytes::from(new_extra);

        Ok(())
    }

    fn get_justified_number_and_hash(&self, header: &alloy_consensus::Header) -> Result<(u64, B256), ConsensusError> {
        let snap = self.snapshot_provider.snapshot(header.number-1)
        .ok_or_else(|| ConsensusError::Other("Snapshot not found".into()))?;
        Ok((snap.vote_data.target_number, snap.vote_data.target_hash))
    }

}
