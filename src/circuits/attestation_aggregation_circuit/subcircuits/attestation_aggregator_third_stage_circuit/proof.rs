use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::Write;
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::{Config, Field, D};
use crate::circuits::Proof;
use super::{write_proof_data, AttestationAggregatorThirdStageProofData};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AttestationAggregatorThirdStageProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
    data: AttestationAggregatorThirdStageProofData,
}

impl AttestationAggregatorThirdStageProof {
    pub fn new(proof: ProofWithPublicInputs<Field, Config, D>, data: AttestationAggregatorThirdStageProofData) -> Self {
        AttestationAggregatorThirdStageProof { proof, data }
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
        [self.proof.public_inputs[0], 
        self.proof.public_inputs[1], 
        self.proof.public_inputs[2], 
        self.proof.public_inputs[3]]
    }

    pub fn validators_inputs_hash(&self) -> [u8; 32] {
        self.data.validators_inputs_hash
    }

    pub fn total_staked(&self) -> u64 {
        self.data.total_staked
    }

    pub fn block_slot(&self) -> usize {
        self.data.block_slot as usize
    }

    pub fn participation_root(&self) -> [Field; 4] {
        self.data.participation_root
    }

    pub fn participation_count(&self) -> usize {
        self.data.participation_count as usize
    }

    pub fn attestations_stake(&self) -> u64 {
        self.data.attestations_stake
    }
}

impl Proof for AttestationAggregatorThirdStageProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}
