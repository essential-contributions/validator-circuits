use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};

use crate::{Config, Field, D};
use crate::circuits::Proof;

pub const PIS_AGG1_VALIDATORS_SUB_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_AGG1_PARTICIPATION_SUB_ROOT: [usize; 4] = [4, 5, 6, 7];
pub const PIS_AGG1_PARTICIPATION_COUNT: usize = 8;
pub const PIS_AGG1_ATTESTATIONS_STAKE: usize = 9;
pub const PIS_AGG1_BLOCK_SLOT: usize = 10;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AttestationAggregatorFirstStageProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl AttestationAggregatorFirstStageProof {
    pub fn new(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        AttestationAggregatorFirstStageProof { proof }
    }

    pub fn validators_sub_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[3]]]
    }

    pub fn participation_sub_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[3]]]
    }

    pub fn participation_count(&self) -> usize{
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_COUNT].to_canonical_u64() as usize
    }

    pub fn attestations_stake(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG1_ATTESTATIONS_STAKE].to_canonical_u64()
    }

    pub fn block_slot(&self) -> usize{
        self.proof.public_inputs[PIS_AGG1_BLOCK_SLOT].to_canonical_u64() as usize
    }
}

impl Proof for AttestationAggregatorFirstStageProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}
