use plonky2::field::types::PrimeField64;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};

use crate::{Config, Field, D};

use super::Proof;

pub const PIS_PARTICIPATION_STATE_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_VALIDATOR_EPOCHS_TREE_ROOT: [usize; 4] = [8, 9, 10, 11];
pub const PIS_PARTICIPATION_ROUNDS_TREE_ROOT: [usize; 4] = [12, 13, 14, 15];

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationStateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl ParticipationStateProof {
    pub fn new(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        ParticipationStateProof { proof }
    }

    pub fn inputs_hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes = (self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[i]].to_canonical_u64() as u32)
                .to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn validator_epochs_tree_root(&self) -> [Field; 4] {
        [
            self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[0]],
            self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[1]],
            self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[2]],
            self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[3]],
        ]
    }

    pub fn participation_rounds_tree_root(&self) -> [Field; 4] {
        [
            self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[0]],
            self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[1]],
            self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[2]],
            self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[3]],
        ]
    }
}

impl Proof for ParticipationStateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}
