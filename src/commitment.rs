use blake3::Hasher as Blake3_Hasher;
use plonky2::{field::types::Field as Plonky2_Field, hash::hash_types::HashOut};
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{Field, Hash, COMMITMENT_TREE_DEPTH};

//TODO: implement multi-threading


#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Commitment {
    leaves: Vec<[Field; 4]>,
    nodes: Vec<[Field; 4]>,
    depth: u32,
}

impl Commitment {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let depth = COMMITMENT_TREE_DEPTH as u32;

        //generate leaves based on the seed and blake3 hash
        let mut leaf = seed;
        let leaves: Vec<[Field; 4]> = (0..(1 << depth)).map(|_| {
            leaf = blake3_hash(&leaf);
            bytes_to_fields(leaf)
        }).collect();

        let num_nodes = (1 << (depth + 1)) - 1;
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO]; num_nodes];

        //fill in leave digests first
        let leave_digests_start = leaves.len() - 1;
        for i in 0..leaves.len() {
            nodes[leave_digests_start + i] = field_hash(&leaves[i]);
        }

        //fill in the rest of the tree
        for i in (0..depth).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            for j in start..end {
                nodes[j] = field_hash_two(nodes[(j * 2) + 1], nodes[(j * 2) + 2]);
            }
        }

        Self { leaves, nodes, depth }
    }

    pub fn from_rnd() -> Self {
        let mut seed: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut seed);

        Self::from_seed(seed)
    }

    pub fn root(&self) -> &[Field; 4] {
        &self.nodes[0]
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn leaf(&self, index: usize) -> &[Field; 4] {
        &self.leaves[index]
    }

    pub fn leaves(&self) -> &[[Field; 4]] {
        &self.leaves
    }

    pub fn reveal(&self, index: usize) -> Vec<[Field; 4]> {
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

    pub fn zero_root() -> [Field; 4] {
        let mut node = field_hash(&Self::zero_reveal());
        for _ in 0..COMMITMENT_TREE_DEPTH {
            node = field_hash_two(node, node);
        }
        node
    }

    pub fn zero_proof() -> Vec<[Field; 4]> {
        let mut node = field_hash(&Self::zero_reveal());
        let mut proof: Vec<[Field; 4]> = vec![];
        for _ in 0..COMMITMENT_TREE_DEPTH {
            proof.push(node);
            node = field_hash_two(node, node);
        }
        proof
    }

    pub fn zero_reveal() -> [Field; 4] {
        [Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO]
    }
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

fn bytes_to_fields(hash: [u8; 32]) -> [Field; 4] {
    let mut chunk0: [u8; 8] = [0u8; 8];
    chunk0.copy_from_slice(&hash[0..8]);
    let mut chunk1: [u8; 8] = [0u8; 8];
    chunk1.copy_from_slice(&hash[8..16]);
    let mut chunk2: [u8; 8] = [0u8; 8];
    chunk2.copy_from_slice(&hash[16..24]);
    let mut chunk3: [u8; 8] = [0u8; 8];
    chunk3.copy_from_slice(&hash[24..32]);
    
    [
        Plonky2_Field::from_canonical_u64(u64::from_be_bytes(chunk0)),
        Plonky2_Field::from_canonical_u64(u64::from_be_bytes(chunk1)),
        Plonky2_Field::from_canonical_u64(u64::from_be_bytes(chunk2)),
        Plonky2_Field::from_canonical_u64(u64::from_be_bytes(chunk3)),
    ]
}
