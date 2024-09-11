use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::Target;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

pub struct AttAgg1Targets {
    pub block_slot: Target,
    pub validators: Vec<AttAgg1ValidatorTargets>,
    pub participation_bits_fields: Vec<Target>,
}

pub struct AttAgg1ValidatorTargets {
    pub stake: Target,
    pub commitment_root: HashOutTarget,
    pub reveal: Vec<Target>,
    pub reveal_proof: MerkleProofTarget,
}

#[inline]
pub fn write_targets(buffer: &mut Vec<u8>, targets: &AttAgg1Targets) -> IoResult<()> {
    buffer.write_target(targets.block_slot)?;
    buffer.write_usize(targets.validators.len())?;
    for v in &targets.validators {
        buffer.write_target(v.stake)?;
        buffer.write_target_hash(&v.commitment_root)?;
        buffer.write_target_vec(&v.reveal)?;
        buffer.write_target_merkle_proof(&v.reveal_proof)?;
    }
    buffer.write_target_vec(&targets.participation_bits_fields)?;

    Ok(())
}

#[inline]
pub fn read_targets(buffer: &mut Buffer) -> IoResult<AttAgg1Targets> {
    let block_slot = buffer.read_target()?;
    let mut validators: Vec<AttAgg1ValidatorTargets> = Vec::new();
    let validators_length = buffer.read_usize()?;
    for _ in 0..validators_length {
        let stake = buffer.read_target()?;
        let commitment_root = buffer.read_target_hash()?;
        let reveal = buffer.read_target_vec()?;
        let reveal_proof = buffer.read_target_merkle_proof()?;
        validators.push(AttAgg1ValidatorTargets {
            stake,
            commitment_root,
            reveal,
            reveal_proof,
        });
    }
    let participation_bits_fields = buffer.read_target_vec()?;

    Ok(AttAgg1Targets {
        block_slot,
        validators,
        participation_bits_fields,
    })
}
