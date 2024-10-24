use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use serde::{Deserialize, Serialize};

use crate::{circuits::Proof, Config, Field, D};

pub const PIS_VALIDATORS_STATE_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_VALIDATORS_STATE_TOTAL_STAKED: usize = 8;
pub const PIS_VALIDATORS_STATE_TOTAL_VALIDATORS: usize = 9;
pub const PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT: [usize; 4] = [10, 11, 12, 13];
pub const PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT: [usize; 4] = [14, 15, 16, 17];

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorsStateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl ValidatorsStateProof {
    pub fn new(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        ValidatorsStateProof { proof }
    }

    pub fn inputs_hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes =
                (self.proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn total_staked(&self) -> u64 {
        self.proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_STAKED].to_canonical_u64()
    }

    pub fn total_validators(&self) -> u32 {
        self.proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_VALIDATORS].to_canonical_u64() as u32
    }

    pub fn validators_tree_root(&self) -> [Field; 4] {
        [
            self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[0]],
            self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[1]],
            self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[2]],
            self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[3]],
        ]
    }

    pub fn accounts_tree_root(&self) -> [Field; 4] {
        [
            self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[0]],
            self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[1]],
            self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[2]],
            self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[3]],
        ]
    }
}

impl Proof for ValidatorsStateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}
