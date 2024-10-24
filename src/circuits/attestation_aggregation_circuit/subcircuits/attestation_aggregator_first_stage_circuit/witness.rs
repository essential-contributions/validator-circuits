use anyhow::{anyhow, Result};
use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};

use crate::circuits::extensions::PartialWitnessExtended;
use crate::commitment::empty_commitment;
use crate::participation::leaf_fields;
use crate::{Field, AGGREGATION_STAGE1_SIZE};

use super::AttAgg1Targets;

#[derive(Clone)]
pub struct AttestationAggregatorFirstStageData {
    pub block_slot: usize,
    pub validators: Vec<AttestationAggregatorFirstStageValidatorData>,
}

#[derive(Clone)]
pub struct AttestationAggregatorFirstStageValidatorData {
    pub stake: u32,
    pub commitment_root: [Field; 4],
    pub reveal: Option<AttestationAggregatorFirstStageRevealData>,
}

#[derive(Clone)]
pub struct AttestationAggregatorFirstStageRevealData {
    pub reveal: [Field; 4],
    pub reveal_proof: Vec<[Field; 4]>,
}

pub fn generate_partial_witness(
    targets: &AttAgg1Targets,
    data: &AttestationAggregatorFirstStageData,
) -> Result<PartialWitness<Field>> {
    if data.validators.len() != AGGREGATION_STAGE1_SIZE {
        return Err(anyhow!(
            "Must include {} validators in attestation aggregation first pass",
            AGGREGATION_STAGE1_SIZE
        ));
    }

    //identify non-participating validators to skip (null reveal)
    let empty_commit = empty_commitment();
    let mut validators = data.validators.clone();
    let mut validator_participation: Vec<bool> = Vec::new();
    for validator in validators.iter_mut() {
        match validator.reveal {
            Some(_) => validator_participation.push(true),
            None => {
                validator_participation.push(false);
                validator.reveal = Some(AttestationAggregatorFirstStageRevealData {
                    reveal: empty_commit.reveal.clone(),
                    reveal_proof: empty_commit.proof.clone(),
                });
            }
        }
    }

    //create partial witness
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Field::from_canonical_u64(data.block_slot as u64));

    for (t, v) in targets.validators.iter().zip(validators.iter()) {
        pw.set_target(t.stake, Field::from_canonical_u32(v.stake));
        pw.set_hash_target(
            t.commitment_root,
            HashOut::<Field> {
                elements: v.commitment_root,
            },
        );
        pw.set_target_arr(&t.reveal, &v.reveal.clone().unwrap().reveal);
        pw.set_merkle_proof_target(t.reveal_proof.clone(), &v.reveal.clone().unwrap().reveal_proof);
    }

    let participation_bits_fields = leaf_fields(validator_participation);
    for (t, v) in targets
        .participation_bits_fields
        .iter()
        .zip(participation_bits_fields.iter())
    {
        pw.set_target(*t, *v);
    }

    Ok(pw)
}
