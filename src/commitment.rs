use blake3::Hasher as Blake3_Hasher;
use plonky2::{field::types::Field as Plonky2_Field, hash::hash_types::HashOut};
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::{Field, Hash, VALIDATOR_COMMITMENT_TREE_HEIGHT};

const COMMITMENT_COMPUTED_TREE_HEIGHT: usize = 14;
const COMMITMENT_MEMORY_TREE_HEIGHT: usize = VALIDATOR_COMMITMENT_TREE_HEIGHT - COMMITMENT_COMPUTED_TREE_HEIGHT;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct CommitmentReveal {
    pub reveal: [Field; 4],
    pub proof: Vec<[Field; 4]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Commitment {
    seed: [u8; 32],
    nodes: Vec<[Field; 4]>,
}

impl Commitment {
    pub fn from_seed(seed: [u8; 32]) -> Self {

        //build memory tree nodes
        let num_nodes = (1 << (COMMITMENT_MEMORY_TREE_HEIGHT + 1)) - 1;
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; num_nodes];

        //fill in computed tree roots first
        {
            let num_computed_trees = 1 << COMMITMENT_MEMORY_TREE_HEIGHT;
            let computed_roots: Vec<[Field; 4]> = (0..num_computed_trees).into_par_iter().map(|i| {
                computed_root(seed, i)
            }).collect();
            let comp_roots_start = num_computed_trees - 1;
            computed_roots.iter().enumerate().for_each(|(i, r)| {
                nodes[comp_roots_start + i] = r.clone();
            });
        }
        
        //fill in the rest of the tree
        for i in (0..COMMITMENT_MEMORY_TREE_HEIGHT).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            for j in start..end {
                nodes[j] = field_hash_two(nodes[(j * 2) + 1], nodes[(j * 2) + 2]);
            }
        }

        Self { seed, nodes }
    }

    pub fn from_rnd() -> Self {
        let mut seed: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut seed);

        Self::from_seed(seed)
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let num_nodes = (1 << (COMMITMENT_MEMORY_TREE_HEIGHT + 1)) - 1;
        if bytes.len() != 32 + (32 * num_nodes) {
            return Err(anyhow!("Invalid bytes"));
        }

        let mut seed = [0u8; 32];
        seed.iter_mut().enumerate().for_each(|(i, b)| *b = bytes[i]);
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; num_nodes];
        nodes.iter_mut().enumerate().for_each(|(i, n)| {
            *n = bytes_to_fields(&bytes[(32 + i * 32)..(64 + i * 32)]);
        });

        Ok(Self { seed, nodes })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let num_nodes = (1 << (COMMITMENT_MEMORY_TREE_HEIGHT + 1)) - 1;
        let mut bytes: Vec<u8> = vec![0; 32 + (32 * num_nodes)];

        self.seed.iter().enumerate().for_each(|(i, b)| bytes[i] = *b);
        self.nodes.iter().enumerate().for_each(|(i, n)| {
            fields_to_bytes(n).iter().enumerate().for_each(|(j, b)| {
                bytes[32 + i * 32 + j] = *b;
            });
        });

        Ok(bytes)
    }

    pub fn root(&self) -> &[Field; 4] {
        &self.nodes[0]
    }

    pub fn height(&self) -> u32 {
        VALIDATOR_COMMITMENT_TREE_HEIGHT as u32
    }

    pub fn reveal(&self, index: usize) -> CommitmentReveal {
        let secret = computed_secret(self.seed, index);
        let computed_tree_index = index / (1 << COMMITMENT_COMPUTED_TREE_HEIGHT);
        let computed_nodes = computed_nodes(self.seed, computed_tree_index);

        let mut proof: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; VALIDATOR_COMMITMENT_TREE_HEIGHT];
        let mut proof_index: usize = 0;

        //start proof with computed nodes
        let mut idx = index % (1 << COMMITMENT_COMPUTED_TREE_HEIGHT);
        for i in (0..COMMITMENT_COMPUTED_TREE_HEIGHT).rev() {
            let start = (1 << (i + 1)) - 1;
            if (idx & 1) == 0 {
                proof[proof_index] = computed_nodes[start + idx + 1];
            } else {
                proof[proof_index] = computed_nodes[start + idx - 1];
            }
            idx = idx / 2;
            proof_index = proof_index + 1;
        }
        
        //continue proof with the memory nodes
        let mut idx = computed_tree_index;
        for i in (0..COMMITMENT_MEMORY_TREE_HEIGHT).rev() {
            let start = (1 << (i + 1)) - 1;
            if (idx & 1) == 0 {
                proof[proof_index] = self.nodes[start + idx + 1];
            } else {
                proof[proof_index] = self.nodes[start + idx - 1];
            }
            idx = idx / 2;
            proof_index = proof_index + 1;
        }

        CommitmentReveal {
            reveal: secret,
            proof,
        }
    }
}

fn computed_root(seed: [u8; 32], offset: usize) -> [Field; 4] {
    let seed_offset = (1 << COMMITMENT_COMPUTED_TREE_HEIGHT) * offset;

    let mut nodes = [[Field::ZERO; 4]; COMMITMENT_COMPUTED_TREE_HEIGHT + 1];
    for i in 0..(1 << COMMITMENT_COMPUTED_TREE_HEIGHT) {
        let secret = computed_secret(seed, i + seed_offset);
        let secret_hash = field_hash(&secret);

        for h in (0..(COMMITMENT_COMPUTED_TREE_HEIGHT + 1)).rev() {
            let p = 1 << h;
            if i % p == p - 1 {
                nodes[h] = secret_hash;
                for r in 0..h {
                    nodes[h] = field_hash_two(nodes[r], nodes[h]);
                }
                break;
            }
        }
    }

    nodes[COMMITMENT_COMPUTED_TREE_HEIGHT]
}

fn computed_nodes(seed: [u8; 32], offset: usize) -> Vec<[Field; 4]> {
    let seed_offset = (1 << COMMITMENT_COMPUTED_TREE_HEIGHT) * offset;

    //fill in secrets hashes
    let num_nodes = (1 << (COMMITMENT_COMPUTED_TREE_HEIGHT + 1)) - 1;
    let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; num_nodes];
    {
        let num_secrets = 1 << COMMITMENT_COMPUTED_TREE_HEIGHT;
        let secrets_hashes: Vec<[Field; 4]> = (0..num_secrets).into_par_iter().map(|i| {
            let secret = computed_secret(seed, i + seed_offset);
            field_hash(&secret)
        }).collect();

        let secrets_hashes_start = num_secrets - 1;
        secrets_hashes.iter().enumerate().for_each(|(i, s)| {
            nodes[secrets_hashes_start + i] = s.clone();
        });
    }
    
    //fill in the rest of the nodes
    for i in (0..COMMITMENT_COMPUTED_TREE_HEIGHT).rev() {
        let start = ((1 << i) - 1) as usize;
        let end = (start * 2) + 1;
        let hashes: Vec<[Field; 4]> = (start..end).into_par_iter().map(|j| {
            field_hash_two(nodes[(j * 2) + 1], nodes[(j * 2) + 2])
        }).collect();
        hashes.iter().enumerate().for_each(|(j, h)| {
            nodes[j + start] = h.clone();
        });
    }

    nodes
}

fn computed_secret(seed: [u8; 32], index: usize) -> [Field; 4] {
    let index_bytes: [u8; 4] = (index as u32).to_le_bytes();
    let mut seed_bytes = seed.to_vec();
    seed_bytes.append(&mut index_bytes.to_vec());

    bytes_to_fields(&blake3_hash(seed_bytes.as_slice()))
}

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3_Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}

fn bytes_to_fields(bytes: &[u8]) -> [Field; 4] {
    let mut chunk0: [u8; 8] = [0u8; 8];
    chunk0.copy_from_slice(&bytes[0..8]);
    let mut chunk1: [u8; 8] = [0u8; 8];
    chunk1.copy_from_slice(&bytes[8..16]);
    let mut chunk2: [u8; 8] = [0u8; 8];
    chunk2.copy_from_slice(&bytes[16..24]);
    let mut chunk3: [u8; 8] = [0u8; 8];
    chunk3.copy_from_slice(&bytes[24..32]);
    
    [
        Plonky2_Field::from_canonical_u64(u64::from_le_bytes(chunk0)),
        Plonky2_Field::from_canonical_u64(u64::from_le_bytes(chunk1)),
        Plonky2_Field::from_canonical_u64(u64::from_le_bytes(chunk2)),
        Plonky2_Field::from_canonical_u64(u64::from_le_bytes(chunk3)),
    ]
}

fn fields_to_bytes(fields: &[Field; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fields[0].0.to_le_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[i] = *b;
    });
    fields[1].0.to_le_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[8 + i] = *b;
    });
    fields[2].0.to_le_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[16 + i] = *b;
    });
    fields[3].0.to_le_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[24 + i] = *b;
    });

    bytes
}
