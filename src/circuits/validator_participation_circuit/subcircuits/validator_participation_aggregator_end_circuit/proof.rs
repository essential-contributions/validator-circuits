use anyhow::{anyhow, Result};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::Write;
use serde::{Deserialize, Serialize};

use crate::circuits::Proof;
use crate::{Config, Field, D};

use super::{write_proof_data, ValidatorParticipationAggEndProofData};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorParticipationAggEndProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
    data: ValidatorParticipationAggEndProofData,
}

impl ValidatorParticipationAggEndProof {
    pub fn new(proof: ProofWithPublicInputs<Field, Config, D>, data: ValidatorParticipationAggEndProofData) -> Self {
        ValidatorParticipationAggEndProof { proof, data }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        if write_proof_data(&mut buffer, &self.data).is_err() {
            return Err(anyhow!("Failed to serialize proof data"));
        }
        if buffer.write_all(&self.proof().to_bytes()).is_err() {
            return Err(anyhow!("Failed to serialize proof"));
        }
        Ok(buffer)
    }

    pub fn public_inputs_hash(&self) -> [Field; 4] {
        [
            self.proof.public_inputs[0],
            self.proof.public_inputs[1],
            self.proof.public_inputs[2],
            self.proof.public_inputs[3],
        ]
    }

    pub fn participation_inputs_hash(&self) -> [u8; 32] {
        self.data.participation_inputs_hash
    }

    pub fn account_address(&self) -> [u8; 20] {
        self.data.account_address
    }

    pub fn from_epoch(&self) -> u32 {
        self.data.from_epoch
    }

    pub fn to_epoch(&self) -> u32 {
        self.data.to_epoch
    }

    pub fn withdraw_max(&self) -> u64 {
        self.data.withdraw_max
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.data.withdraw_unearned
    }

    pub fn param_rf(&self) -> u32 {
        self.data.param_rf
    }

    pub fn param_st(&self) -> u32 {
        self.data.param_st
    }
}

impl Proof for ValidatorParticipationAggEndProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}
