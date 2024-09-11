use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::circuits::participation_state_circuit::ParticipationStateProof;
use crate::circuits::Proof;
use crate::{Config, Field, D};

use super::{ValidatorParticipationAggEndCircuitTargets, ValidatorParticipationAggProof};

#[derive(Clone)]
pub struct ValidatorParticipationAggEndCircuitData {
    pub participation_agg_proof: ValidatorParticipationAggProof,
    pub participation_state_proof: ParticipationStateProof,
}

pub fn generate_partial_witness(
    targets: &ValidatorParticipationAggEndCircuitTargets,
    data: &ValidatorParticipationAggEndCircuitData,
    participation_agg_verifier: &VerifierOnlyCircuitData<Config, D>,
    participation_state_verifier: &VerifierOnlyCircuitData<Config, D>,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    //participation agg proof
    pw.set_verifier_data_target(&targets.participation_agg_verifier, participation_agg_verifier);
    pw.set_proof_with_pis_target(&targets.participation_agg_proof, data.participation_agg_proof.proof());

    //participation state proof
    pw.set_verifier_data_target(&targets.participation_state_verifier, participation_state_verifier);
    pw.set_proof_with_pis_target(&targets.participation_state_proof, data.participation_state_proof.proof());

    Ok(pw)
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorParticipationAggEndProofData {
    pub participation_inputs_hash: [u8; 32],
    pub account_address: [u8; 20],
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub withdraw_max: u64,
    pub withdraw_unearned: u64,
    pub param_rf: u32,
    pub param_st: u32,
}

pub fn generate_proof_data(data: &ValidatorParticipationAggEndCircuitData) -> ValidatorParticipationAggEndProofData {
    ValidatorParticipationAggEndProofData {
        participation_inputs_hash: data.participation_state_proof.inputs_hash(),
        account_address: data.participation_agg_proof.account_address(),
        from_epoch: data.participation_agg_proof.from_epoch(),
        to_epoch: data.participation_agg_proof.to_epoch(),
        withdraw_max: data.participation_agg_proof.withdraw_max(),
        withdraw_unearned: data.participation_agg_proof.withdraw_unearned(),
        param_rf: data.participation_agg_proof.param_rf(),
        param_st: data.participation_agg_proof.param_st(),
    }
}

#[inline]
pub fn write_proof_data(buffer: &mut Vec<u8>, data: &ValidatorParticipationAggEndProofData) -> IoResult<()> {
    buffer.write_all(&data.participation_inputs_hash)?;
    buffer.write_all(&data.account_address)?;
    buffer.write_u32(data.from_epoch)?;
    buffer.write_u32(data.to_epoch)?;
    buffer.write_usize(data.withdraw_max as usize)?;
    buffer.write_usize(data.withdraw_unearned as usize)?;
    buffer.write_u32(data.param_rf)?;
    buffer.write_u32(data.param_st)?;

    Ok(())
}

#[inline]
pub fn read_proof_data(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggEndProofData> {
    let mut participation_inputs_hash = [0u8; 32];
    let mut account_address = [0u8; 20];
    buffer.read_exact(&mut participation_inputs_hash)?;
    buffer.read_exact(&mut account_address)?;
    let from_epoch = buffer.read_u32()?;
    let to_epoch = buffer.read_u32()?;
    let withdraw_max = buffer.read_usize()? as u64;
    let withdraw_unearned = buffer.read_usize()? as u64;
    let param_rf = buffer.read_u32()?;
    let param_st = buffer.read_u32()?;

    Ok(ValidatorParticipationAggEndProofData {
        participation_inputs_hash,
        account_address,
        from_epoch,
        to_epoch,
        withdraw_max,
        withdraw_unearned,
        param_rf,
        param_st,
    })
}
