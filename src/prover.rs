use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use serde::{Deserialize, Serialize};
use anyhow::*;

use crate::{BatchCircuitData, BatchCircuitValidatorData, BatchProof, Commitment, ValidatorCircuits, REVEAL_BATCH_MAX_SIZE, VALIDATORS_TREE_DEPTH};
use crate::Field;
use crate::Hash;

//TODO: implement multi-threading for tree construction

pub struct Validator {
    pub commitment_root: [Field; 4],
    pub stake: u64,
}

pub struct ValidatorSet {
    circuits: ValidatorCircuits,
    validators: Vec<Validator>,
    nodes: Vec<[Field; 4]>,
    depth: u32,
}

impl ValidatorSet {
    pub fn new(circuits: ValidatorCircuits, mut validators: Vec<Validator>) -> Self {
        let depth = VALIDATORS_TREE_DEPTH as u32;

        //the 0 validator is always empty
        validators[0] = Validator {
            commitment_root: Commitment::zero_root(),
            stake: 0,
        };

        let num_nodes = (1 << (depth + 1)) - 1;
        let nodes: Vec<[Field; 4]> = vec![[Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO]; num_nodes];
        let mut validator_set = Self { circuits, validators, nodes, depth };
        validator_set.fill_nodes();

        validator_set
    }

    pub fn root(&self) -> &[Field; 4] {
        &self.nodes[0]
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn validator(&self, index: usize) -> &Validator {
        &self.validators[index]
    }

    pub fn prove_full(&self, batches: Vec<BatchProof>) {
        todo!();
    }

    pub fn prove_batch(&self, reveals: Vec<CommitmentReveal>) -> Result<BatchProof> {
        if reveals.len() == 0 {
            return Err(anyhow!("At least one reveal must be provided for the batch"));
        }

        //verify all are for the same slot
        let block_slot = reveals[0].block_slot;
        for reveal in reveals.iter() {
            if reveal.block_slot != block_slot {
                return Err(anyhow!("All reveals do not have the same block_slot"));
            }
        }

        //convert to data for circuit and sort
        let mut validators: Vec<BatchCircuitValidatorData> = vec![];
        for reveal in &reveals {
            let validator = self.validator(reveal.validator_index);
            validators.push(BatchCircuitValidatorData {
                index: reveal.validator_index,
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                validator_proof: self.proof(reveal.validator_index),
                block_slot,
                reveal: reveal.reveal,
                reveal_proof: reveal.proof.clone(),
            });
        }

        //sort and add the zero validator for padding
        validators.sort_by(|a, b| {
            a.index.cmp(&b.index)
        });
        if validators.len() < REVEAL_BATCH_MAX_SIZE {
            let commitment_root = Commitment::zero_root();
            let validator_proof = self.proof(0);
            let reveal = Commitment::zero_reveal();
            let reveal_proof = Commitment::zero_proof();
            while validators.len() < REVEAL_BATCH_MAX_SIZE {
                validators.insert(0, BatchCircuitValidatorData {
                    index: 0,
                    stake: 0,
                    commitment_root,
                    validator_proof: validator_proof.clone(),
                    block_slot,
                    reveal,
                    reveal_proof: reveal_proof.clone(),
                });
            }
        }

        //prove
        let batch_proof = self.circuits.batch_circuit.generate_proof(&BatchCircuitData {
            block_slot,
            validators_root: self.root().clone(),
            validators,
        })?;

        Ok(batch_proof)
    }

    pub fn prove_update(&self) {
        todo!();
    }

    pub fn verify_full(&self, batches: Vec<BatchProof>) {
        todo!();
    }

    pub fn verify_batch(&self, proof: &BatchProof) -> Result<()> {
        if &proof.validators_root() != self.root() {
            return Err(anyhow!("Incorrect validators root"));
        }
        self.circuits.batch_circuit.verify_proof(proof)
    }

    pub fn verify_update(&self) {
        todo!();
    }

    pub fn set_validator(&mut self, validator: Validator, index: usize) {
        self.validators[index] = validator;
        self.fill_nodes();
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
        for i in (0..self.depth).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            for j in start..end {
                self.nodes[j] = field_hash_two(self.nodes[(j * 2) + 1], self.nodes[(j * 2) + 2]);
            }
        }
    }

    fn proof(&self, index: usize) -> Vec<[Field; 4]> {
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; self.depth as usize];
        let mut node_index: usize = 0;
        let mut idx = index;
        for i in (0..self.depth).rev() {
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
