use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::D;

pub struct AttAgg2Targets {
    pub block_slot: Target,
    pub atts_agg1_verifier: VerifierCircuitTarget,
    pub atts_agg1_data: Vec<AttAgg2Agg1Targets>,
}

pub struct AttAgg2Agg1Targets {
    pub validators_sub_root: HashOutTarget,
    pub has_participation: BoolTarget,
    pub proof: ProofWithPublicInputsTarget<D>,
}

#[inline]
pub fn write_targets(buffer: &mut Vec<u8>, targets: &AttAgg2Targets) -> IoResult<()> {
    buffer.write_target(targets.block_slot)?;
    buffer.write_target_verifier_circuit(&targets.atts_agg1_verifier)?;
    buffer.write_usize(targets.atts_agg1_data.len())?;
    for d in &targets.atts_agg1_data {
        buffer.write_target_hash(&d.validators_sub_root)?;
        buffer.write_target_bool(d.has_participation)?;
        buffer.write_target_proof_with_public_inputs(&d.proof)?;
    }

    Ok(())
}

#[inline]
pub fn read_targets(buffer: &mut Buffer) -> IoResult<AttAgg2Targets> {
    let block_slot = buffer.read_target()?;
    let atts_agg1_verifier = buffer.read_target_verifier_circuit()?;
    let mut atts_agg1_data: Vec<AttAgg2Agg1Targets> = Vec::new();
    let atts_agg1_data_length = buffer.read_usize()?;
    for _ in 0..atts_agg1_data_length {
        let validators_sub_root = buffer.read_target_hash()?;
        let has_participation = buffer.read_target_bool()?;
        let proof = buffer.read_target_proof_with_public_inputs()?;
        atts_agg1_data.push(AttAgg2Agg1Targets {
            validators_sub_root,
            has_participation,
            proof,
        });
    }

    Ok(AttAgg2Targets {
        block_slot,
        atts_agg1_verifier,
        atts_agg1_data,
    })
}
