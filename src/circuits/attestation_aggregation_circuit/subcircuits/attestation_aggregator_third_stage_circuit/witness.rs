use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::circuits::validators_state_circuit::ValidatorsStateProof;
use crate::participation::empty_participation_sub_root;
use crate::{field_hash_two, Config, Field, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, AGGREGATION_STAGE3_SIZE, D};
use crate::circuits::Proof;
use super::{AttAgg3Targets, AttestationAggregatorSecondStageProof};

#[derive(Clone)]
pub struct AttestationAggregatorThirdStageData {
    pub block_slot: usize,
    pub validators_state_proof: ValidatorsStateProof,
    pub agg2_data: Vec<AttestationAggregatorThirdStageAgg2Data>,
}

#[derive(Clone)]
pub struct AttestationAggregatorThirdStageAgg2Data {
    pub validators_sub_root: [Field; 4],
    pub agg2_proof: Option<AttestationAggregatorSecondStageProof>,
}

pub fn generate_partial_witness(
    targets: &AttAgg3Targets, 
    data: &AttestationAggregatorThirdStageData, 
    atts_agg2_verifier: &VerifierOnlyCircuitData<Config, D>, 
    validators_state_verifier: &VerifierOnlyCircuitData<Config, D>
) -> Result<PartialWitness<Field>> {
    if data.agg2_data.len() != AGGREGATION_STAGE3_SIZE {
        return Err(anyhow!("Must include {} datas in attestation aggregation third pass", AGGREGATION_STAGE3_SIZE));
    }

    //find a proof to use as a dummy proof
    let mut dummy_proof: Option<AttestationAggregatorSecondStageProof> = None;
    for d in &data.agg2_data {
        if d.agg2_proof.is_some() {
            dummy_proof = d.agg2_proof.clone();
            break;
        }
    }
    if dummy_proof.is_none() {
        return Err(anyhow!("Must include at least one valid proof in attestation aggregation third pass"));
    }
    let dummy_proof = dummy_proof.unwrap();

    //create partial witness
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Field::from_canonical_u64(data.block_slot as u64));

    pw.set_verifier_data_target(&targets.validators_state_verifier, validators_state_verifier);
    pw.set_proof_with_pis_target(&targets.validators_state_proof, data.validators_state_proof.proof());

    pw.set_verifier_data_target(&targets.atts_agg2_verifier, atts_agg2_verifier);
    for (t, v) in targets.atts_agg2_data.iter().zip(data.agg2_data.clone()) {
        let validators_sub_root: HashOut<Field> = HashOut::<Field> { elements: v.validators_sub_root };
        pw.set_hash_target(t.validators_sub_root, validators_sub_root);
        match v.agg2_proof {
            Some(proof) => {
                pw.set_bool_target(t.has_participation, true);
                pw.set_proof_with_pis_target(&t.proof, proof.proof());
            },
            None => {
                pw.set_bool_target(t.has_participation, false);
                pw.set_proof_with_pis_target(&t.proof, dummy_proof.proof());
            },
        }
    }

    Ok(pw)
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AttestationAggregatorThirdStageProofData {
    pub validators_inputs_hash: [u8; 32],
    pub total_staked: u64,
    pub block_slot: u32,
    pub participation_root: [Field; 4],
    pub participation_count: u32,
    pub attestations_stake: u64,
}

pub fn generate_proof_data(data: &AttestationAggregatorThirdStageData) -> AttestationAggregatorThirdStageProofData {
    let mut attestations_stake = 0;
    let mut participation_count = 0;
    for agg2_data in &data.agg2_data {
        if let Some(proof) = &agg2_data.agg2_proof {
            attestations_stake += proof.attestations_stake();
            participation_count += proof.participation_count();
        }
    }

    let empty_participation_sub_root = empty_participation_sub_root(AGGREGATION_STAGE2_SUB_TREE_HEIGHT);
    let mut nodes: Vec<[Field; 4]> = data.agg2_data.iter().map(|d| {
        match &d.agg2_proof {
            Some(proof) => proof.participation_sub_root(),
            None => empty_participation_sub_root,
        }
    }).collect();
    while nodes.len() > 1 {
        let new_nodes = nodes.chunks(2).map(|c| {
            field_hash_two(c[0], c[1])
        }).collect();
        nodes = new_nodes;
    }
    
    AttestationAggregatorThirdStageProofData {
        validators_inputs_hash: data.validators_state_proof.inputs_hash(),
        total_staked: data.validators_state_proof.total_staked(),
        block_slot: data.block_slot as u32,
        participation_root: nodes[0],
        participation_count: participation_count as u32,
        attestations_stake,
    }
}

#[inline]
pub fn write_proof_data(buffer: &mut Vec<u8>, data: &AttestationAggregatorThirdStageProofData) -> IoResult<()> {
    buffer.write_all(&data.validators_inputs_hash)?;
    buffer.write_usize(data.total_staked as usize)?;
    buffer.write_u32(data.block_slot)?;
    buffer.write_usize(data.participation_root[0].to_canonical_u64() as usize)?;
    buffer.write_usize(data.participation_root[1].to_canonical_u64() as usize)?;
    buffer.write_usize(data.participation_root[2].to_canonical_u64() as usize)?;
    buffer.write_usize(data.participation_root[3].to_canonical_u64() as usize)?;
    buffer.write_u32(data.participation_count)?;
    buffer.write_usize(data.attestations_stake as usize)?;

    Ok(())
}

#[inline]
pub fn read_proof_data(buffer: &mut Buffer) -> IoResult<AttestationAggregatorThirdStageProofData> {
    let mut validators_inputs_hash = [0u8; 32];
    let mut participation_root = [Field::ZERO; 4];

    buffer.read_exact(&mut validators_inputs_hash)?;
    let total_staked = buffer.read_usize()? as u64;
    let block_slot = buffer.read_u32()?;
    participation_root[0] = Field::from_canonical_usize(buffer.read_usize()?);
    participation_root[1] = Field::from_canonical_usize(buffer.read_usize()?);
    participation_root[2] = Field::from_canonical_usize(buffer.read_usize()?);
    participation_root[3] = Field::from_canonical_usize(buffer.read_usize()?);
    let participation_count = buffer.read_u32()?;
    let attestations_stake = buffer.read_usize()? as u64;

    Ok(AttestationAggregatorThirdStageProofData {
        validators_inputs_hash,
        total_staked,
        block_slot,
        participation_root,
        participation_count,
        attestations_stake,
    })
}
