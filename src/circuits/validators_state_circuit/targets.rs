use plonky2::{hash::{hash_types::HashOutTarget, merkle_proofs::MerkleProofTarget}, iop::target::{BoolTarget, Target}, plonk::{circuit_data::VerifierCircuitTarget, proof::ProofWithPublicInputsTarget}};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::D;

pub struct ValidatorsStateCircuitTargets {
    pub index: Target,
    pub stake: Target,
    pub commitment: HashOutTarget,
    pub account: Vec<Target>,
    
    pub validator_index: Target,
    pub validator_stake: Target,
    pub validator_commitment: HashOutTarget,
    pub validator_proof: MerkleProofTarget,
    pub from_account: Vec<Target>,
    pub from_acc_index: Target,
    pub from_acc_proof: MerkleProofTarget,
    pub to_account: Vec<Target>,
    pub to_acc_index: Target,
    pub to_acc_proof: MerkleProofTarget,
    
    pub init_zero: BoolTarget,
    pub verifier: VerifierCircuitTarget,
    pub previous_proof: ProofWithPublicInputsTarget<D>,
}

#[inline]
pub fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorsStateCircuitTargets) -> IoResult<()> {
    buffer.write_target(targets.index)?;
    buffer.write_target(targets.stake)?;
    buffer.write_target_hash(&targets.commitment)?;
    buffer.write_target_vec(&targets.account)?;
    
    buffer.write_target(targets.validator_index)?;
    buffer.write_target(targets.validator_stake)?;
    buffer.write_target_hash(&targets.validator_commitment)?;
    buffer.write_target_merkle_proof(&targets.validator_proof)?;

    buffer.write_target_vec(&targets.from_account)?;
    buffer.write_target(targets.from_acc_index)?;
    buffer.write_target_merkle_proof(&targets.from_acc_proof)?;

    buffer.write_target_vec(&targets.to_account)?;
    buffer.write_target(targets.to_acc_index)?;
    buffer.write_target_merkle_proof(&targets.to_acc_proof)?;

    buffer.write_target_bool(targets.init_zero)?;
    buffer.write_target_verifier_circuit(&targets.verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.previous_proof)?;

    Ok(())
}

#[inline]
pub fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorsStateCircuitTargets> {
    let index = buffer.read_target()?;
    let stake = buffer.read_target()?;
    let commitment = buffer.read_target_hash()?;
    let account = buffer.read_target_vec()?;
    
    let validator_index = buffer.read_target()?;
    let validator_stake = buffer.read_target()?;
    let validator_commitment = buffer.read_target_hash()?;
    let validator_proof = buffer.read_target_merkle_proof()?;

    let from_account = buffer.read_target_vec()?;
    let from_acc_index = buffer.read_target()?;
    let from_acc_proof = buffer.read_target_merkle_proof()?;

    let to_account = buffer.read_target_vec()?;
    let to_acc_index = buffer.read_target()?;
    let to_acc_proof = buffer.read_target_merkle_proof()?;
    
    let init_zero = buffer.read_target_bool()?;
    let verifier = buffer.read_target_verifier_circuit()?;
    let previous_proof = buffer.read_target_proof_with_public_inputs()?;

    Ok(ValidatorsStateCircuitTargets {
        index,
        stake,
        commitment,
        account,
        validator_index,
        validator_stake,
        validator_commitment,
        validator_proof,
        from_account,
        from_acc_index,
        from_acc_proof,
        to_account,
        to_acc_index,
        to_acc_proof,
        init_zero,
        verifier,
        previous_proof,
    })
}
