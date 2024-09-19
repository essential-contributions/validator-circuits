use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::D;

pub struct ParticipationStateCircuitTargets {
    pub epoch_num: Target,
    pub val_state_inputs_hash: Vec<Target>,
    pub round_num: Target,
    pub participation_root: HashOutTarget,
    pub participation_count: Target,

    pub current_val_state_inputs_hash: Vec<Target>,
    pub validator_epoch_proof: MerkleProofTarget,
    pub current_participation_root: HashOutTarget,
    pub current_participation_count: Target,
    pub participation_round_proof: MerkleProofTarget,

    pub init_zero: BoolTarget,
    pub verifier: VerifierCircuitTarget,
    pub previous_proof: ProofWithPublicInputsTarget<D>,
}

#[inline]
pub fn write_targets(
    buffer: &mut Vec<u8>,
    targets: &ParticipationStateCircuitTargets,
) -> IoResult<()> {
    buffer.write_target(targets.epoch_num)?;
    buffer.write_target_vec(&targets.val_state_inputs_hash)?;
    buffer.write_target(targets.round_num)?;
    buffer.write_target_hash(&targets.participation_root)?;
    buffer.write_target(targets.participation_count)?;

    buffer.write_target_vec(&targets.current_val_state_inputs_hash)?;
    buffer.write_target_merkle_proof(&targets.validator_epoch_proof)?;
    buffer.write_target_hash(&targets.current_participation_root)?;
    buffer.write_target(targets.current_participation_count)?;
    buffer.write_target_merkle_proof(&targets.participation_round_proof)?;

    buffer.write_target_bool(targets.init_zero)?;
    buffer.write_target_verifier_circuit(&targets.verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.previous_proof)?;

    Ok(())
}

#[inline]
pub fn read_targets(buffer: &mut Buffer) -> IoResult<ParticipationStateCircuitTargets> {
    let epoch_num = buffer.read_target()?;
    let val_state_inputs_hash = buffer.read_target_vec()?;
    let round_num = buffer.read_target()?;
    let participation_root = buffer.read_target_hash()?;
    let participation_count = buffer.read_target()?;

    let current_val_state_inputs_hash = buffer.read_target_vec()?;
    let validator_epoch_proof = buffer.read_target_merkle_proof()?;
    let current_participation_root = buffer.read_target_hash()?;
    let current_participation_count = buffer.read_target()?;
    let participation_round_proof = buffer.read_target_merkle_proof()?;

    let init_zero = buffer.read_target_bool()?;
    let verifier = buffer.read_target_verifier_circuit()?;
    let previous_proof = buffer.read_target_proof_with_public_inputs()?;

    Ok(ParticipationStateCircuitTargets {
        epoch_num,
        val_state_inputs_hash,
        round_num,
        participation_root,
        participation_count,
        current_val_state_inputs_hash,
        validator_epoch_proof,
        current_participation_root,
        current_participation_count,
        participation_round_proof,
        init_zero,
        verifier,
        previous_proof,
    })
}
