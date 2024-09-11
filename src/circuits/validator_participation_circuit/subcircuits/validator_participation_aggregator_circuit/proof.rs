use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use serde::{Deserialize, Serialize};

use crate::{circuits::Proof, Config, Field, D};

pub const PIS_AGG_EPOCHS_TREE_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_AGG_PR_TREE_ROOT: [usize; 4] = [4, 5, 6, 7];
pub const PIS_AGG_ACCOUNT_ADDRESS: [usize; 5] = [8, 9, 10, 11, 12];
pub const PIS_AGG_FROM_EPOCH: usize = 13;
pub const PIS_AGG_TO_EPOCH: usize = 14;
pub const PIS_AGG_WITHDRAW_MAX: usize = 15;
pub const PIS_AGG_WITHDRAW_UNEARNED: usize = 16;
pub const PIS_AGG_PARAM_RF: usize = 17;
pub const PIS_AGG_PARAM_ST: usize = 18;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorParticipationAggProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl ValidatorParticipationAggProof {
    pub fn new(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        ValidatorParticipationAggProof { proof }
    }

    pub fn account_address(&self) -> [u8; 20] {
        let mut hash = [0u8; 20];
        for i in 0..5 {
            let bytes = (self.proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn from_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_FROM_EPOCH].to_canonical_u64() as u32
    }

    pub fn to_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_TO_EPOCH].to_canonical_u64() as u32
    }

    pub fn withdraw_max(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG_WITHDRAW_MAX].to_canonical_u64()
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG_WITHDRAW_UNEARNED].to_canonical_u64()
    }

    pub fn param_rf(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_PARAM_RF].to_canonical_u64() as u32
    }

    pub fn param_st(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_PARAM_ST].to_canonical_u64() as u32
    }
}

impl Proof for ValidatorParticipationAggProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}
