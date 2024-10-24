use anyhow::{anyhow, Result};
use plonky2::field::types::{Field as Plonky2_Field, Field64};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::circuits::extensions::PartialWitnessExtended;
use crate::circuits::validators_state_circuit::ValidatorsStateProof;
use crate::circuits::Proof;
use crate::participation::participation_merkle_data;
use crate::validators::empty_validators_tree_proof;
use crate::{Config, Field, AGGREGATION_STAGE1_SIZE, D, MAX_VALIDATORS, PARTICIPATION_ROUNDS_PER_STATE_EPOCH};

use super::{ValidatorParticipationAggCircuitTargets, ValidatorParticipationAggProof};

#[derive(Clone)]
pub struct ValidatorParticipationAggCircuitData {
    pub validator: Option<ValidatorParticipationValidatorData>,
    pub account_validator_proof: Vec<[Field; 4]>,
    pub validators_state_proof: ValidatorsStateProof,
    pub validator_epochs_proof: Vec<[Field; 4]>,

    pub participation_rounds: Vec<ValidatorPartAggRoundData>,

    pub previous_data: ValidatorPartAggPrevData,
}
#[derive(Clone)]
pub struct ValidatorParticipationValidatorData {
    pub index: usize,
    pub stake: u32,
    pub commitment: [Field; 4],
    pub proof: Vec<[Field; 4]>,
}
#[derive(Clone)]
pub struct ValidatorPartAggRoundData {
    pub participation_root: [Field; 4],
    pub participation_count: u32,
    pub participation_round_proof: Vec<[Field; 4]>,

    pub participation_bits: Option<Vec<u8>>,
}
#[derive(Clone)]
pub struct ValidatorPartAggStartData {
    pub val_epochs_tree_root: [Field; 4],
    pub pr_tree_root: [Field; 4],
    pub account: [u8; 20],
    pub epoch: u32,
    pub param_rf: u32,
    pub param_st: u32,
}
#[derive(Clone)]
pub enum ValidatorPartAggPrevData {
    Start(ValidatorPartAggStartData),
    Continue(ValidatorParticipationAggProof),
}

pub fn generate_partial_witness(
    targets: &ValidatorParticipationAggCircuitTargets,
    data: &ValidatorParticipationAggCircuitData,
    circuit_data: &CircuitData<Field, Config, D>,
    validators_state_verifier: &VerifierOnlyCircuitData<Config, D>,
) -> Result<PartialWitness<Field>> {
    let validator_index = match &data.validator {
        Some(v) => Some(v.index),
        None => None,
    };
    if validator_index.is_some_and(|i| i >= MAX_VALIDATORS) {
        return Err(anyhow!("Invalid validator index (max: {})", MAX_VALIDATORS));
    }
    if data.participation_rounds.len() != PARTICIPATION_ROUNDS_PER_STATE_EPOCH {
        return Err(anyhow!(
            "Incorrect number of rounds data (expected: {})",
            PARTICIPATION_ROUNDS_PER_STATE_EPOCH
        ));
    }
    let mut pw = PartialWitness::new();

    //validators state proof
    pw.set_verifier_data_target(&targets.validators_state_verifier, validators_state_verifier);
    pw.set_proof_with_pis_target(&targets.validators_state_proof, data.validators_state_proof.proof());
    pw.set_merkle_proof_target(targets.validator_epochs_proof.clone(), &data.validator_epochs_proof);

    //account validator index
    match &data.validator {
        Some(validator) => {
            let validator_field_index = validator.index / AGGREGATION_STAGE1_SIZE;
            let validator_bit_index = validator.index % AGGREGATION_STAGE1_SIZE;
            pw.set_target(targets.validator_index, Field::from_canonical_usize(validator.index));
            pw.set_target(
                targets.validator_field_index,
                Field::from_canonical_usize(validator_field_index),
            );
            pw.set_target(
                targets.validator_bit_index,
                Field::from_canonical_usize(validator_bit_index),
            );
            pw.set_target(targets.validator_stake, Field::from_canonical_u32(validator.stake));
            pw.set_hash_target(
                targets.validator_commitment,
                HashOut::<Field> {
                    elements: validator.commitment,
                },
            );
            pw.set_merkle_proof_target(targets.validator_stake_proof.clone(), &validator.proof);
        }
        None => {
            //fill in with null data
            pw.set_target(targets.validator_index, Field::ZERO.sub_one());
            pw.set_target(targets.validator_field_index, Field::ZERO);
            pw.set_target(targets.validator_bit_index, Field::ZERO);
            pw.set_target(targets.validator_stake, Field::ZERO);
            pw.set_hash_target(
                targets.validator_commitment,
                HashOut::<Field> {
                    elements: [Field::ZERO; 4],
                },
            );
            pw.set_merkle_proof_target(targets.validator_stake_proof.clone(), &empty_validators_tree_proof());
        }
    }
    pw.set_merkle_proof_target(targets.account_validator_proof.clone(), &data.account_validator_proof);

    //participation round issuance
    let (rf, st) = match &data.previous_data {
        ValidatorPartAggPrevData::Start(start_data) => (start_data.param_rf as u64, start_data.param_st as u64),
        ValidatorPartAggPrevData::Continue(previous_proof) => {
            (previous_proof.param_rf() as u64, previous_proof.param_st() as u64)
        }
    };
    let validator_stake = match &data.validator {
        Some(validator) => validator.stake as u64,
        None => 0,
    };
    let total_staked = data.validators_state_proof.total_staked() as u64;
    let mut gamma = 0;
    let mut lambda = 0;
    let mut round_issuance = 0;
    if total_staked > 0 {
        gamma = integer_sqrt(total_staked * 1000000); //`sqrt(total_staked * 1000000)` rounded down
        lambda = (rf * st * validator_stake * 1000000) / gamma; //`(rf * st * stake * 1000000) / gamma` rounded down
        round_issuance = (lambda * 1000000) / (total_staked + (st * 1000000)); //`(lambda * 1000000) / (total_staked + (st * 1000000))` rounded down
    }
    pw.set_target(targets.gamma, Field::from_canonical_u64(gamma));
    pw.set_target(targets.lambda, Field::from_canonical_u64(lambda));
    pw.set_target(targets.round_issuance, Field::from_canonical_u64(round_issuance));

    //participation rounds targets
    for (t, d) in targets
        .participation_rounds_targets
        .iter()
        .zip(data.participation_rounds.clone())
    {
        pw.set_hash_target(
            t.participation_root,
            HashOut::<Field> {
                elements: d.participation_root,
            },
        );
        pw.set_target(t.participation_count, Field::from_canonical_u32(d.participation_count));
        pw.set_merkle_proof_target(t.participation_round_proof.clone(), &d.participation_round_proof);

        if validator_index.is_some() && d.participation_bits.is_some() {
            let validator_index = validator_index.unwrap();
            let participation_bits = d.participation_bits.unwrap();
            let participation_merkle_data = participation_merkle_data(&participation_bits, validator_index);
            if participation_merkle_data.root != d.participation_root {
                return Err(anyhow!(
                    "Root caluclated from participation bits is different from given root"
                ));
            }
            pw.set_bool_target(t.skip_participation, false);
            pw.set_target_arr(&t.participation_bits_fields, &participation_merkle_data.leaf_fields);
            pw.set_merkle_proof_target(t.participation_proof.clone(), &participation_merkle_data.proof);
        } else {
            //fill in with empty participation data
            let participation_merkle_data = participation_merkle_data(&vec![], 0);
            pw.set_bool_target(t.skip_participation, true);
            pw.set_target_arr(&t.participation_bits_fields, &participation_merkle_data.leaf_fields);
            pw.set_merkle_proof_target(t.participation_proof.clone(), &participation_merkle_data.proof);
        }
    }

    //previous data to build off of
    match &data.previous_data {
        ValidatorPartAggPrevData::Start(start_data) => {
            pw.set_hash_target(
                targets.init_val_epochs_tree_root,
                HashOut::<Field> {
                    elements: start_data.val_epochs_tree_root,
                },
            );
            pw.set_hash_target(
                targets.init_pr_tree_root,
                HashOut::<Field> {
                    elements: start_data.pr_tree_root,
                },
            );
            pw.set_target_arr(&targets.init_account_address, &account_to_fields(start_data.account));
            pw.set_target(targets.init_epoch, Field::from_canonical_u32(start_data.epoch));
            pw.set_target(targets.init_param_rf, Field::from_canonical_u32(start_data.param_rf));
            pw.set_target(targets.init_param_st, Field::from_canonical_u32(start_data.param_st));

            //create starter proof initial state (no previous proof)
            let base_proof = initial_proof(circuit_data, start_data);
            pw.set_bool_target(targets.init_zero, false);
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
        }
        ValidatorPartAggPrevData::Continue(previous_proof) => {
            pw.set_bool_target(targets.init_zero, true);
            pw.set_proof_with_pis_target(&targets.previous_proof, previous_proof.proof());

            //blank out init data
            pw.set_hash_target(
                targets.init_val_epochs_tree_root,
                HashOut::<Field> {
                    elements: [Field::ZERO; 4],
                },
            );
            pw.set_hash_target(
                targets.init_pr_tree_root,
                HashOut::<Field> {
                    elements: [Field::ZERO; 4],
                },
            );
            pw.set_target_arr(&targets.init_account_address, &[Field::ZERO; 5]);
            pw.set_target(targets.init_epoch, Field::ZERO);
            pw.set_target(targets.init_param_rf, Field::ZERO);
            pw.set_target(targets.init_param_st, Field::ZERO);
        }
    }
    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);

    Ok(pw)
}

fn initial_proof(
    circuit_data: &CircuitData<Field, Config, D>,
    init_data: &ValidatorPartAggStartData,
) -> ProofWithPublicInputs<Field, Config, D> {
    let initial_public_inputs = [
        &init_data.val_epochs_tree_root[..],
        &init_data.pr_tree_root[..],
        &account_to_fields(init_data.account)[..],
        &[Field::from_canonical_u32(init_data.epoch)],
        &[Field::from_canonical_u32(init_data.epoch)],
        &[Field::ZERO],
        &[Field::ZERO],
        &[Field::from_canonical_u32(init_data.param_rf)],
        &[Field::from_canonical_u32(init_data.param_st)],
    ]
    .concat();
    cyclic_base_proof(
        &circuit_data.common,
        &circuit_data.verifier_only,
        initial_public_inputs.into_iter().enumerate().collect(),
    )
}

fn account_to_fields(account: [u8; 20]) -> [Field; 5] {
    let mut account_fields = [Field::ZERO; 5];
    account.chunks(4).enumerate().for_each(|(i, c)| {
        account_fields[i] = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    });
    account_fields
}

fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }

    let mut left: u64 = 1;
    let mut right: u64 = n;
    let mut result: u64 = 0;

    while left <= right {
        let mid = left + (right - left) / 2;
        if mid * mid <= n {
            result = mid;
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    result
}
