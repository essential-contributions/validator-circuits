use anyhow::{anyhow, Result};
use plonky2::field::types::Field as Plonky2_Field;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::commitment::{verify_commitment_reveal, CommitmentReveal};
use crate::{
    bytes_to_fields, field_hash, field_hash_two, load_from_file, save_to_file, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT,
};
use crate::{fields_to_bytes, Field};

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
        Self::from_validators(&[])
    }

    pub fn from_validators(validators: &[Validator]) -> Self {
        let mut validators = validators.to_vec();
        for _ in validators.len()..MAX_VALIDATORS {
            validators.push(Validator {
                commitment_root: [Field::ZERO; 4],
                stake: 0,
            });
        }

        let num_nodes = (1 << (VALIDATORS_TREE_HEIGHT + 1)) - 1;
        let nodes: Vec<[Field; 4]> = vec![[Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO]; num_nodes];
        let mut validator_set = Self { validators, nodes };
        validator_set.fill_nodes();

        validator_set
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let num_validators = MAX_VALIDATORS;
        let num_validators_bytes = (32 + 4) * num_validators;
        if bytes.len() != num_validators_bytes {
            return Err(anyhow!("Invalid bytes"));
        }

        let mut validators = Vec::new();
        for i in 0..MAX_VALIDATORS {
            let j = i * (32 + 4);
            let commitment_root = bytes_to_fields(&bytes[j..(j + 32)]);
            let mut stake = [0u8; 4];
            stake
                .iter_mut()
                .enumerate()
                .for_each(|(j, b)| *b = bytes[(i * (20 + 4)) + 20 + j]);
            validators.push(Validator {
                commitment_root,
                stake: u32::from_be_bytes(stake),
            });
        }

        Ok(Self::from_validators(&validators))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let num_validators_bytes = (32 + 4) * MAX_VALIDATORS;
        let mut bytes: Vec<u8> = vec![0; num_validators_bytes];

        self.validators.iter().enumerate().for_each(|(i, v)| {
            let cr = fields_to_bytes(&v.commitment_root);
            cr.iter().enumerate().for_each(|(j, b)| {
                bytes[i * (32 + 4) + j] = *b;
            });
            v.stake.to_be_bytes().iter().enumerate().for_each(|(j, b)| {
                bytes[(i * (32 + 4)) + 32 + j] = *b;
            });
        });

        Ok(bytes)
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

    pub fn verify_attestations(&self, reveals: Vec<ValidatorCommitmentReveal>) -> Result<()> {
        if reveals.len() > 0 {
            //verify all are for the same slot
            let block_slot = reveals[0].block_slot;
            for reveal in reveals.iter() {
                if reveal.block_slot != block_slot {
                    return Err(anyhow!("All reveals do not have the same block_slot"));
                }
            }

            //check each reveal in parallel
            let results: Vec<bool> = reveals
                .par_iter()
                .map(|reveal| {
                    let validator = self.validator(reveal.validator_index);
                    let commitment_reveal = CommitmentReveal {
                        reveal: reveal.reveal,
                        proof: reveal.proof.clone(),
                    };
                    verify_commitment_reveal(validator.commitment_root, &commitment_reveal, reveal.block_slot).is_ok()
                })
                .collect();
            for i in 0..results.len() {
                if !results[i] {
                    return Err(anyhow!("Invalid proof for reveal {}", i));
                }
            }
        }

        Ok(())
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

    pub fn verify_merkle_proof(&self, validator: Validator, index: usize, proof: &[[Field; 4]]) -> Result<()> {
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
        Ok(())
    }

    fn fill_nodes(&mut self) {
        //fill in leave digests first
        {
            let leave_digests: Vec<[Field; 4]> = (0..self.validators.len())
                .into_par_iter()
                .map(|i| Self::hash_validator(self.validators[i].clone()))
                .collect();
            let leave_digests_start = self.validators.len() - 1;
            leave_digests.iter().enumerate().for_each(|(i, d)| {
                self.nodes[leave_digests_start + i] = d.clone();
            });
        }

        //fill in the rest of the tree
        for i in (0..VALIDATORS_TREE_HEIGHT).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            let hashes: Vec<[Field; 4]> = (start..end)
                .into_par_iter()
                .map(|j| field_hash_two(self.nodes[(j * 2) + 1], self.nodes[(j * 2) + 2]))
                .collect();
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

// Generate the initial validators tree
pub fn initial_validators_tree() -> ValidatorsTree {
    ValidatorsTree::new()
}

// Generate the initial validators tree root
pub fn initial_validators_tree_root() -> [Field; 4] {
    //equivalent to initial_validators_tree().root()
    let mut node = field_hash(&[Field::ZERO; 5]);
    for _ in 0..VALIDATORS_TREE_HEIGHT {
        node = field_hash_two(node.clone(), node.clone());
    }
    node
}

// Generate a proof for any of the validators in the initial validators tree
pub fn initial_validators_tree_proof() -> Vec<[Field; 4]> {
    //equivalent to initial_validators_tree().merkle_proof(0)
    let mut proof = Vec::new();
    let mut node = field_hash(&[Field::ZERO; 5]);
    for _ in 0..VALIDATORS_TREE_HEIGHT {
        proof.push(node);
        node = field_hash_two(node.clone(), node.clone());
    }
    proof
}

// Saves all validator data to a file
pub fn save_validators(validators_tree: &ValidatorsTree, path: &[&str], filename: &str) -> Result<()> {
    let bytes = validators_tree.to_bytes()?;
    save_to_file(&bytes, path, filename)
}

// Loads all validator data from a file
pub fn load_validators(path: &[&str], filename: &str) -> Result<ValidatorsTree> {
    let bytes = load_from_file(path, filename)?;
    Ok(ValidatorsTree::from_bytes(&bytes)?)
}
