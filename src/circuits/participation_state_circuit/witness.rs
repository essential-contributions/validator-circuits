use anyhow::Result;
use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::circuits::extensions::PartialWitnessExtended;
use crate::epochs::{initial_validator_epochs_tree, initial_validator_epochs_tree_root};
use crate::participation::{
    initial_participation_rounds_tree, initial_participation_rounds_tree_root,
};
use crate::{Config, Field, D, PARTICIPATION_ROUNDS_PER_STATE_EPOCH};

use super::proof::ParticipationStateProof;
use super::{ParticipationStateCircuitTargets, Proof};

#[derive(Clone)]
pub struct ParticipationStateCircuitData {
    pub round_num: usize,
    pub val_state_inputs_hash: [u8; 32],
    pub participation_root: [Field; 4],
    pub participation_count: u32,

    pub current_val_state_inputs_hash: [u8; 32],
    pub validator_epoch_proof: Vec<[Field; 4]>,
    pub current_participation_root: [Field; 4],
    pub current_participation_count: u32,
    pub participation_round_proof: Vec<[Field; 4]>,

    pub previous_proof: Option<ParticipationStateProof>,
}

pub fn generate_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>,
    targets: &ParticipationStateCircuitTargets,
    data: &ParticipationStateCircuitData,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    pw.set_target(
        targets.epoch_num,
        Field::from_canonical_usize(data.round_num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH),
    );
    data.val_state_inputs_hash
        .chunks(4)
        .enumerate()
        .for_each(|(i, c)| {
            let value = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
            pw.set_target(targets.val_state_inputs_hash[i], value);
        });
    pw.set_target(
        targets.round_num,
        Field::from_canonical_usize(data.round_num),
    );
    pw.set_hash_target(
        targets.participation_root,
        HashOut::<Field> {
            elements: data.participation_root,
        },
    );
    pw.set_target(
        targets.participation_count,
        Field::from_canonical_u32(data.participation_count),
    );

    data.current_val_state_inputs_hash
        .chunks(4)
        .enumerate()
        .for_each(|(i, c)| {
            let value = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
            pw.set_target(targets.current_val_state_inputs_hash[i], value);
        });
    pw.set_merkle_proof_target(
        targets.validator_epoch_proof.clone(),
        &data.validator_epoch_proof,
    );
    pw.set_hash_target(
        targets.current_participation_root,
        HashOut::<Field> {
            elements: data.current_participation_root,
        },
    );
    pw.set_target(
        targets.current_participation_count,
        Field::from_canonical_u32(data.current_participation_count),
    );
    pw.set_merkle_proof_target(
        targets.participation_round_proof.clone(),
        &data.participation_round_proof,
    );

    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);
    match &data.previous_proof {
        Some(previous_proof) => {
            pw.set_bool_target(targets.init_zero, true);
            pw.set_proof_with_pis_target(&targets.previous_proof, &previous_proof.proof());
        }
        None => {
            //setup for using initial state (no previous proof)
            let base_proof = initial_proof(circuit_data);
            pw.set_bool_target(targets.init_zero, false);
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
        }
    };
    Ok(pw)
}

pub fn generate_initial_data() -> ParticipationStateCircuitData {
    let validator_epochs_tree = initial_validator_epochs_tree();
    let participation_rounds_tree = initial_participation_rounds_tree();

    let round_num = 32;
    let epoch_num = round_num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round_num);
    ParticipationStateCircuitData {
        round_num,
        val_state_inputs_hash: [0u8; 32],
        participation_root: [Field::ZERO; 4],
        participation_count: 0,
        current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
        validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
        current_participation_root: current_round_data.participation_root,
        current_participation_count: current_round_data.participation_count,
        participation_round_proof: participation_rounds_tree.merkle_proof(round_num),
        previous_proof: None,
    }
}

fn initial_proof(
    circuit_data: &CircuitData<Field, Config, D>,
) -> ProofWithPublicInputs<Field, Config, D> {
    let initial_inputs_hash = [Field::ZERO; 8];
    let initial_validator_epochs_tree_root = initial_validator_epochs_tree_root();
    let initial_participation_rounds_tree_root = initial_participation_rounds_tree_root();
    let initial_public_inputs = [
        &initial_inputs_hash[..],
        &initial_validator_epochs_tree_root[..],
        &initial_participation_rounds_tree_root[..],
    ]
    .concat();
    cyclic_base_proof(
        &circuit_data.common,
        &circuit_data.verifier_only,
        initial_public_inputs.into_iter().enumerate().collect(),
    )
}
