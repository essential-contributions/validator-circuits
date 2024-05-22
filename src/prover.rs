use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use serde::{Deserialize, Serialize};
use anyhow::*;

use crate::{AttestationsAggregator1Data, AttestationsAggregator1RevealData, AttestationsAggregator1ValidatorData, AttestationsAggregator2Agg1Data, AttestationsAggregator2Data, AttestationsAggregator3Agg2Data, AttestationsAggregator3Data, AttestationsAggregator3Proof, ValidatorCircuits, AGGREGATION_PASS1_SIZE, AGGREGATION_PASS1_SUB_TREE_HEIGHT, AGGREGATION_PASS2_SUB_TREE_HEIGHT, ATTESTATION_AGGREGATION_PASS1_SIZE, ATTESTATION_AGGREGATION_PASS2_SIZE, ATTESTATION_AGGREGATION_PASS3_SIZE, VALIDATORS_TREE_HEIGHT};
use crate::Field;
use crate::Hash;

//TODO: implement multi-threading for tree construction and proof generation

const AGG1_BINS_LEN: usize = ATTESTATION_AGGREGATION_PASS2_SIZE * ATTESTATION_AGGREGATION_PASS3_SIZE;

pub struct Validator {
    pub commitment_root: [Field; 4],
    pub stake: u64,
}

pub struct ValidatorSet {
    circuits: ValidatorCircuits,
    validators: Vec<Validator>,
    nodes: Vec<[Field; 4]>,
    height: u32,
}

impl ValidatorSet {
    pub fn new(circuits: ValidatorCircuits, validators: Vec<Validator>) -> Self {
        let height = VALIDATORS_TREE_HEIGHT as u32;
        let num_nodes = (1 << (height + 1)) - 1;
        let nodes: Vec<[Field; 4]> = vec![[Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO]; num_nodes];
        let mut validator_set = Self { circuits, validators, nodes, height };
        validator_set.fill_nodes();

        validator_set
    }

    pub fn root(&self) -> &[Field; 4] {
        &self.nodes[0]
    }

    pub fn sub_root(&self, height: usize, index: usize) -> &[Field; 4] {
        let start = (2u32.pow(self.height - (height as u32)) - 1) as usize;
        &self.nodes[start + index]
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn validator(&self, index: usize) -> &Validator {
        &self.validators[index]
    }

    pub fn prove_attestations(&self, reveals: Vec<CommitmentReveal>) -> Result<AttestationsAggregator3Proof> {
        let max_attestations = ATTESTATION_AGGREGATION_PASS1_SIZE * ATTESTATION_AGGREGATION_PASS2_SIZE * ATTESTATION_AGGREGATION_PASS3_SIZE;
        if reveals.len() == 0 {
            return Err(anyhow!("At least one reveal must be provided for the attestations proof"));
        }
        if reveals.len() > max_attestations {
            return Err(anyhow!("Only {} reveals can be proven per attestations proof", max_attestations));
        }

        //verify all are for the same slot
        let block_slot = reveals[0].block_slot;
        for reveal in reveals.iter() {
            if reveal.block_slot != block_slot {
                return Err(anyhow!("All reveals do not have the same block_slot"));
            }
        }

        //sort each reveal into bins that must be proven
        let mut agg1_bins: Vec<Vec<CommitmentReveal>> = Vec::new();
        for _ in 0..AGG1_BINS_LEN {
            agg1_bins.push(Vec::new());
        }
        for reveal in reveals.iter() {
            agg1_bins[reveal.validator_index / AGGREGATION_PASS1_SIZE].push(reveal.clone());
        }

        //generate proofs for each bin
        //TODO: parallelize
        let mut agg1_datas: Vec<AttestationsAggregator2Agg1Data> = Vec::new();
        for (index, bin) in agg1_bins.iter().enumerate() {
            if bin.len() > 0 {
                //create complete validator list
                let starting_index = index * AGGREGATION_PASS1_SIZE;
                let mut validators: Vec<AttestationsAggregator1ValidatorData> = (0..AGGREGATION_PASS1_SIZE).map(|i| {
                    let validator = self.validator(starting_index + i);
                    AttestationsAggregator1ValidatorData {
                        stake: validator.stake,
                        commitment_root: validator.commitment_root,
                        reveal: None,
                    }
                }).collect();

                //add reveal data to the complete list
                for reveal in reveals.iter() {
                    validators[reveal.validator_index - starting_index].reveal = Some(AttestationsAggregator1RevealData {
                        reveal: reveal.reveal,
                        reveal_proof: reveal.proof.clone(),
                    });
                }

                //generate proof
                let proof = self.circuits.generate_attestations_aggregator1_proof(&AttestationsAggregator1Data {
                    block_slot,
                    validators,
                })?;
                agg1_datas.push(AttestationsAggregator2Agg1Data {
                    validators_sub_root: self.sub_root(AGGREGATION_PASS1_SUB_TREE_HEIGHT, index).clone(),
                    agg1_proof: Some(proof),
                });

            } else {
                agg1_datas.push(AttestationsAggregator2Agg1Data {
                    validators_sub_root: self.sub_root(AGGREGATION_PASS1_SUB_TREE_HEIGHT, index).clone(),
                    agg1_proof: None,
                });
            }
        }
        
        //generate second pass aggregate proofs
        let mut agg2_datas: Vec<AttestationsAggregator3Agg2Data> = Vec::new();
        for (index, agg1_data) in agg1_datas.chunks(ATTESTATION_AGGREGATION_PASS2_SIZE).enumerate() {
            let mut has_proofs = false;
            for data in agg1_data {
                if data.agg1_proof.is_some() {
                    has_proofs = true;
                    break;
                }
            }
            if has_proofs {                
                //generate proof
                let proof = self.circuits.generate_attestations_aggregator2_proof(&AttestationsAggregator2Data {
                    block_slot,
                    agg1_data: agg1_data.to_vec(),
                })?;
                agg2_datas.push(AttestationsAggregator3Agg2Data {
                    validators_sub_root: proof.validators_sub_root(),
                    agg2_proof: Some(proof),
                });
            } else {
                agg2_datas.push(AttestationsAggregator3Agg2Data {
                    validators_sub_root: self.sub_root(AGGREGATION_PASS1_SUB_TREE_HEIGHT + AGGREGATION_PASS2_SUB_TREE_HEIGHT, index).clone(),
                    agg2_proof: None,
                });
            }
        }
        
        //generate third pass aggregate proof
        let proof = self.circuits.generate_attestations_aggregator3_proof(&AttestationsAggregator3Data {
            block_slot,
            agg2_data: agg2_datas,
        })?;

        Ok(proof)
    }

    pub fn prove_update(&self) {
        todo!();
    }

    pub fn verify_attestations(&self, reveals: Vec<CommitmentReveal>) -> Result<bool> {
        if reveals.len() == 0 {
            return Err(anyhow!("At least one reveal must be provided for the batch"));
        }
        if reveals.len() > ATTESTATION_AGGREGATION_PASS1_SIZE {
            return Err(anyhow!("Only {} reveals can be proven per batch", ATTESTATION_AGGREGATION_PASS1_SIZE));
        }

        //verify all are for the same slot
        let block_slot = reveals[0].block_slot;
        for reveal in reveals.iter() {
            if reveal.block_slot != block_slot {
                return Err(anyhow!("All reveals do not have the same block_slot"));
            }
        }

        //TODO: check each commitment in parallel
        todo!();
    }

    pub fn verify_attestations_proof(&self, proof: &AttestationsAggregator3Proof) -> Result<()> {
        if &proof.validators_root() != self.root() {
            return Err(anyhow!("Incorrect validators root"));
        }
        self.circuits.verify_attestations_aggregator3_proof(proof)
    }

    pub fn set_validator(&mut self, validator: Validator, index: usize) {
        self.validators[index] = validator;
        self.fill_nodes();
    }

    pub fn validator_merkle_proof(&self, index: usize) -> Vec<[Field; 4]> {
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; self.height as usize];
        let mut node_index: usize = 0;
        let mut idx = index;
        for i in (0..self.height).rev() {
            let start = (2u32.pow(i + 1) - 1) as usize;
            if (idx & 1) == 0 {
                 nodes[node_index] = self.nodes[start + idx + 1];
            } else {
                nodes[node_index] = self.nodes[start + idx - 1];
            }
            idx = idx / 2;
            node_index = node_index + 1;
        }
        nodes
    }

    pub fn circuits(&self) -> &ValidatorCircuits {
        &self.circuits
    }

    fn fill_nodes(&mut self) {
        //fill in leave digests first
        let leave_digests_start = self.validators.len() - 1;
        for i in 0..self.validators.len() {
            let mut elements = self.validators[i].commitment_root.to_vec();
            elements.push(Plonky2_Field::from_canonical_u64(self.validators[i].stake));
            self.nodes[leave_digests_start + i] = field_hash(&elements);
        }
    
        //fill in the rest of the tree
        for i in (0..self.height).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            for j in start..end {
                self.nodes[j] = field_hash_two(self.nodes[(j * 2) + 1], self.nodes[(j * 2) + 2]);
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CommitmentReveal {
    pub validator_index: usize,
    pub block_slot: usize,
    pub reveal: [Field; 4],
    pub proof: Vec<[Field; 4]>,
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}
