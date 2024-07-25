use std::fs::{create_dir_all, File};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;

use blake3::Hasher as Blake3_Hasher;
use plonky2::field::types::Field as Plonky2_Field;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::{bytes_to_fields, field_hash, field_hash_two, fields_to_bytes, Field, VALIDATOR_COMMITMENT_TREE_HEIGHT};

const COMMITMENT_COMPUTED_TREE_HEIGHT: usize = 14;
const COMMITMENT_MEMORY_TREE_HEIGHT: usize = VALIDATOR_COMMITMENT_TREE_HEIGHT - COMMITMENT_COMPUTED_TREE_HEIGHT;

const COMMITMENT_OUTPUT_FOLDER: &str = "data";
const COMMITMENT_OUTPUT_FILE: &str = "secret.bin";

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

    pub fn root(&self) -> [Field; 4] {
        self.nodes[0].clone()
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
    let index_bytes: [u8; 4] = (index as u32).to_be_bytes();
    let mut seed_bytes = seed.to_vec();
    seed_bytes.append(&mut index_bytes.to_vec());

    bytes_to_fields(&blake3_hash(seed_bytes.as_slice()))
}

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3_Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

// The max number of unique commitments when generating examples (index is always modulo this value)
pub const EXAMPLE_COMMITMENTS_REPEAT: usize = 2000;

// Creates an example commitment root
pub fn example_commitment_root(validator_index: usize) -> [Field; 4] {
    let secret = generate_secret_from_seed(validator_index);
    let mut node = field_hash(&secret);
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        node = field_hash_two(node, node);
    }
    node
}

// Creates an example commitment proof (same for every index)
pub fn example_commitment_proof(validator_index: usize) -> CommitmentReveal {
    let reveal = generate_secret_from_seed(validator_index);
    let mut node = field_hash(&reveal);
    let mut proof: Vec<[Field; 4]> = vec![];
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        proof.push(node);
        node = field_hash_two(node, node);
    }
    CommitmentReveal {reveal, proof }
}

// Generates an empty commitment proof
pub fn empty_commitment() -> CommitmentReveal {
    let reveal = [
        Field::from_canonical_usize(0),
        Field::from_canonical_usize(0),
        Field::from_canonical_usize(0),
        Field::from_canonical_usize(0),
    ];
    let mut node = field_hash(&reveal);
    let mut proof: Vec<[Field; 4]> = vec![];
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        proof.push(node);
        node = field_hash_two(node, node);
    }

    CommitmentReveal {reveal, proof }
}

// Generates an empty commitment root
pub fn empty_commitment_root() -> [Field; 4] {
    let reveal = [
        Field::from_canonical_usize(0),
        Field::from_canonical_usize(0),
        Field::from_canonical_usize(0),
        Field::from_canonical_usize(0),
    ];
    let mut node = field_hash(&reveal);
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        node = field_hash_two(node, node);
    }
    node
}

fn generate_secret_from_seed(seed: usize) -> [Field; 4] {
    let seed = seed % EXAMPLE_COMMITMENTS_REPEAT;
    [
        Field::from_canonical_usize(seed + 10),
        Field::from_canonical_usize(seed + 11),
        Field::from_canonical_usize(seed + 12),
        Field::from_canonical_usize(seed + 13),
    ]
}

pub fn save_commitment(commitment: &Commitment) -> Result<()> {
    let bytes = commitment.to_bytes()?;

    let mut path = PathBuf::from(COMMITMENT_OUTPUT_FOLDER);
    path.push(COMMITMENT_OUTPUT_FILE);

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&path)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
}

pub fn load_commitment() -> Result<Commitment> {
    let mut path = PathBuf::from(COMMITMENT_OUTPUT_FOLDER);
    path.push(COMMITMENT_OUTPUT_FILE);

    let file = File::open(&path)?;
    let mut reader = BufReader::with_capacity(32 * 1024, file);
    let mut bytes: Vec<u8> = Vec::new();
    reader.read_to_end(&mut bytes)?;
    
    Ok(Commitment::from_bytes(&bytes)?)
}
