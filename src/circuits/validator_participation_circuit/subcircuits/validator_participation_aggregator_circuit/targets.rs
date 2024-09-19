use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::D;

pub struct ValidatorParticipationAggCircuitTargets {
    pub init_val_epochs_tree_root: HashOutTarget,
    pub init_pr_tree_root: HashOutTarget,
    pub init_account_address: Vec<Target>,
    pub init_epoch: Target,
    pub init_param_rf: Target,
    pub init_param_st: Target,

    pub validators_state_verifier: VerifierCircuitTarget,
    pub validators_state_proof: ProofWithPublicInputsTarget<D>,
    pub validator_epochs_proof: MerkleProofTarget,

    pub validator_index: Target,
    pub validator_bit_index: Target,
    pub validator_field_index: Target,
    pub validator_stake: Target,
    pub validator_commitment: HashOutTarget,
    pub validator_stake_proof: MerkleProofTarget,
    pub account_validator_proof: MerkleProofTarget,

    pub gamma: Target,
    pub lambda: Target,
    pub round_issuance: Target,
    pub participation_rounds_targets: Vec<ValidatorParticipationRoundTargets>,

    pub init_zero: BoolTarget,
    pub verifier: VerifierCircuitTarget,
    pub previous_proof: ProofWithPublicInputsTarget<D>,
}

pub struct ValidatorParticipationRoundTargets {
    pub participation_root: HashOutTarget,
    pub participation_count: Target,
    pub participation_round_proof: MerkleProofTarget,

    pub skip_participation: BoolTarget,
    pub participation_bits_fields: Vec<Target>,
    pub participation_proof: MerkleProofTarget,
}

#[inline]
pub fn write_targets(
    buffer: &mut Vec<u8>,
    targets: &ValidatorParticipationAggCircuitTargets,
) -> IoResult<()> {
    buffer.write_target_hash(&targets.init_val_epochs_tree_root)?;
    buffer.write_target_hash(&targets.init_pr_tree_root)?;
    buffer.write_target_vec(&targets.init_account_address)?;
    buffer.write_target(targets.init_epoch)?;
    buffer.write_target(targets.init_param_rf)?;
    buffer.write_target(targets.init_param_st)?;

    buffer.write_target_verifier_circuit(&targets.validators_state_verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.validators_state_proof)?;
    buffer.write_target_merkle_proof(&targets.validator_epochs_proof)?;

    buffer.write_target(targets.validator_index)?;
    buffer.write_target(targets.validator_bit_index)?;
    buffer.write_target(targets.validator_field_index)?;
    buffer.write_target(targets.validator_stake)?;
    buffer.write_target_hash(&targets.validator_commitment)?;
    buffer.write_target_merkle_proof(&targets.validator_stake_proof)?;
    buffer.write_target_merkle_proof(&targets.account_validator_proof)?;

    buffer.write_target(targets.gamma)?;
    buffer.write_target(targets.lambda)?;
    buffer.write_target(targets.round_issuance)?;
    buffer.write_usize(targets.participation_rounds_targets.len())?;
    for d in &targets.participation_rounds_targets {
        buffer.write_target_hash(&d.participation_root)?;
        buffer.write_target(d.participation_count)?;
        buffer.write_target_merkle_proof(&d.participation_round_proof)?;

        buffer.write_target_bool(d.skip_participation)?;
        buffer.write_target_vec(&d.participation_bits_fields)?;
        buffer.write_target_merkle_proof(&d.participation_proof)?;
    }

    buffer.write_target_bool(targets.init_zero)?;
    buffer.write_target_verifier_circuit(&targets.verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.previous_proof)?;

    Ok(())
}

#[inline]
pub fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggCircuitTargets> {
    let init_val_epochs_tree_root = buffer.read_target_hash()?;
    let init_pr_tree_root = buffer.read_target_hash()?;
    let init_account_address = buffer.read_target_vec()?;
    let init_epoch = buffer.read_target()?;
    let init_param_rf = buffer.read_target()?;
    let init_param_st = buffer.read_target()?;

    let validators_state_verifier = buffer.read_target_verifier_circuit()?;
    let validators_state_proof = buffer.read_target_proof_with_public_inputs()?;
    let validator_epochs_proof = buffer.read_target_merkle_proof()?;

    let validator_index = buffer.read_target()?;
    let validator_bit_index = buffer.read_target()?;
    let validator_field_index = buffer.read_target()?;
    let validator_stake = buffer.read_target()?;
    let validator_commitment = buffer.read_target_hash()?;
    let validator_stake_proof = buffer.read_target_merkle_proof()?;
    let account_validator_proof = buffer.read_target_merkle_proof()?;

    let gamma = buffer.read_target()?;
    let lambda = buffer.read_target()?;
    let round_issuance = buffer.read_target()?;
    let mut participation_rounds_targets: Vec<ValidatorParticipationRoundTargets> = Vec::new();
    let participation_rounds_targets_length = buffer.read_usize()?;
    for _ in 0..participation_rounds_targets_length {
        let participation_root = buffer.read_target_hash()?;
        let participation_count = buffer.read_target()?;
        let participation_round_proof = buffer.read_target_merkle_proof()?;

        let skip_participation = buffer.read_target_bool()?;
        let participation_bits_fields = buffer.read_target_vec()?;
        let participation_proof = buffer.read_target_merkle_proof()?;

        participation_rounds_targets.push(ValidatorParticipationRoundTargets {
            participation_root,
            participation_count,
            participation_round_proof,
            skip_participation,
            participation_bits_fields,
            participation_proof,
        });
    }

    let init_zero = buffer.read_target_bool()?;
    let verifier = buffer.read_target_verifier_circuit()?;
    let previous_proof = buffer.read_target_proof_with_public_inputs()?;

    Ok(ValidatorParticipationAggCircuitTargets {
        init_val_epochs_tree_root,
        init_pr_tree_root,
        init_account_address,
        init_epoch,
        init_param_rf,
        init_param_st,
        validators_state_verifier,
        validators_state_proof,
        validator_epochs_proof,
        validator_index,
        validator_bit_index,
        validator_field_index,
        validator_stake,
        validator_commitment,
        validator_stake_proof,
        account_validator_proof,
        gamma,
        lambda,
        round_issuance,
        participation_rounds_targets,
        init_zero,
        verifier,
        previous_proof,
    })
}
