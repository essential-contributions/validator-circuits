use plonky2::field::types::Field as Plonky2_Field;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;
use anyhow::{anyhow, Result};

use crate::{field_hash, field_hash_two, AGGREGATION_STAGE1_SIZE, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT};
use crate::Field;

//TODO: support from_bytes, to_bytes and save/load (see commitment)
//TODO: need to be able to track historical state of validators at specific epochs (see todo in validator_participation_circuit)
// (alternatively manage historic data in a new data structure completely that combines the validators_state_roots in the participation tree)
//TODO: implement multi-threading for manual reveal verification

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Validator {
    pub commitment_root: [Field; 4],
    pub stake: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorCommitmentReveal {
    pub validator_index: usize,
    pub block_slot: usize,
    pub reveal: [Field; 4],
    pub proof: Vec<[Field; 4]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorsTree {
    validators: Vec<Validator>,
    nodes: Vec<[Field; 4]>,
}

impl ValidatorsTree {
    pub fn new() -> Self {
        let mut validators: Vec<Validator> = Vec::new();
        for _ in 0..MAX_VALIDATORS {
            validators.push(Validator {
                commitment_root: [Field::ZERO; 4],
                stake: 0,
            });
        }
        Self::from_validators(&validators)
    }

    pub fn from_validators(validators: &[Validator]) -> Self {
        let num_nodes = (1 << (VALIDATORS_TREE_HEIGHT + 1)) - 1;
        let nodes: Vec<[Field; 4]> = vec![[Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO]; num_nodes];
        let mut validator_set = Self { validators: validators.to_vec(), nodes };
        validator_set.fill_nodes();

        validator_set
    }

    pub fn root(&self) -> [Field; 4] {
        self.nodes[0].clone()
    }

    pub fn sub_root(&self, height: usize, index: usize) -> [Field; 4] {
        let start = (2u32.pow((VALIDATORS_TREE_HEIGHT - height) as u32) - 1) as usize;
        self.nodes[start + index].clone()
    }

    pub fn height(&self) -> usize {
        VALIDATORS_TREE_HEIGHT
    }

    pub fn validator(&self, index: usize) -> Validator {
        self.validators[index].clone()
    }

    pub fn validators(&self) -> Vec<Validator> {
        self.validators.clone()
    }

    pub fn verify_attestations(&self, reveals: Vec<ValidatorCommitmentReveal>) -> Result<bool> {
        if reveals.len() == 0 {
            return Err(anyhow!("At least one reveal must be provided for the batch"));
        }
        if reveals.len() > AGGREGATION_STAGE1_SIZE {
            return Err(anyhow!("Only {} reveals can be proven per batch", AGGREGATION_STAGE1_SIZE));
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

    pub fn set_validator(&mut self, index: usize, validator: Validator) {
        self.validators[index] = validator;
        self.fill_nodes();
    }

    pub fn merkle_proof(&self, index: usize) -> Vec<[Field; 4]> {
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; VALIDATORS_TREE_HEIGHT];
        let mut node_index: usize = 0;
        let mut idx = index;
        for i in (0..VALIDATORS_TREE_HEIGHT).rev() {
            let start = (2u32.pow((i + 1) as u32) - 1) as usize;
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

    pub fn verify_merkle_proof(&self, validator: Validator, index: usize, proof: &[[Field; 4]]) -> Result<bool> {
        if proof.len() != VALIDATORS_TREE_HEIGHT {
            return Err(anyhow!("Invalid proof length."));
        }

        let mut idx = index;
        let mut hash = Self::hash_validator(validator);
        for sibling in proof {
            if (idx & 1) == 0 {
                hash = field_hash_two(hash, *sibling);
            } else {
                hash = field_hash_two(*sibling, hash);
            }
            idx = idx >> 1;
        }

        if hash != self.root() {
            return Err(anyhow!("Invalid proof"));
        }
        Ok(true)
    }

    fn fill_nodes(&mut self) {
        //fill in leave digests first
        {
            let leave_digests: Vec<[Field; 4]> = (0..self.validators.len()).into_par_iter().map(|i| {
                Self::hash_validator(self.validators[i].clone())
            }).collect();
            let leave_digests_start = self.validators.len() - 1;
            leave_digests.iter().enumerate().for_each(|(i, d)| {
                self.nodes[leave_digests_start + i] = d.clone();
            });
        }
    
        //fill in the rest of the tree
        for i in (0..VALIDATORS_TREE_HEIGHT).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            let hashes: Vec<[Field; 4]> = (start..end).into_par_iter().map(|j| {
                field_hash_two(self.nodes[(j * 2) + 1], self.nodes[(j * 2) + 2])
            }).collect();
            hashes.iter().enumerate().for_each(|(j, h)| {
                self.nodes[j + start] = h.clone();
            });
        }
    }

    fn hash_validator(validator: Validator) -> [Field; 4] {
        let mut elements = validator.commitment_root.to_vec();
        elements.push(Field::from_canonical_u32(validator.stake));
        field_hash(&elements)
    }
}

pub fn initial_validators_tree_root() -> [Field; 4] {
    let validators_tree = ValidatorsTree::new();
    validators_tree.root()
}

pub fn empty_validators_tree_root() -> [Field; 4] {
    let mut node = field_hash(&[Field::ZERO; 5]);
    for _ in 0..VALIDATORS_TREE_HEIGHT {
        node = field_hash_two(node.clone(), node.clone());
    }
    node
}

pub fn empty_validators_tree_proof() -> Vec<[Field; 4]> {
    let mut proof = Vec::new();
    let mut node = field_hash(&[Field::ZERO; 5]);
    for _ in 0..VALIDATORS_TREE_HEIGHT {
        proof.push(node);
        node = field_hash_two(node.clone(), node.clone());
    }
    proof
}
