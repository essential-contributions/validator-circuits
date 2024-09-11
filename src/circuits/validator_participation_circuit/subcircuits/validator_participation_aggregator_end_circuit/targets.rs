use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::D;

pub struct ValidatorParticipationAggEndCircuitTargets {
    pub participation_agg_proof: ProofWithPublicInputsTarget<D>,
    pub participation_agg_verifier: VerifierCircuitTarget,

    pub participation_state_proof: ProofWithPublicInputsTarget<D>,
    pub participation_state_verifier: VerifierCircuitTarget,
}

#[inline]
pub fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorParticipationAggEndCircuitTargets) -> IoResult<()> {
    buffer.write_target_proof_with_public_inputs(&targets.participation_agg_proof)?;
    buffer.write_target_verifier_circuit(&targets.participation_agg_verifier)?;

    buffer.write_target_proof_with_public_inputs(&targets.participation_state_proof)?;
    buffer.write_target_verifier_circuit(&targets.participation_state_verifier)?;

    Ok(())
}

#[inline]
pub fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggEndCircuitTargets> {
    let participation_agg_proof = buffer.read_target_proof_with_public_inputs()?;
    let participation_agg_verifier = buffer.read_target_verifier_circuit()?;

    let participation_state_proof = buffer.read_target_proof_with_public_inputs()?;
    let participation_state_verifier = buffer.read_target_verifier_circuit()?;

    Ok(ValidatorParticipationAggEndCircuitTargets {
        participation_agg_proof,
        participation_agg_verifier,
        participation_state_proof,
        participation_state_verifier,
    })
}
