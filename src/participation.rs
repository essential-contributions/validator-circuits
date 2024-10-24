use std::collections::HashMap;

use anyhow::{anyhow, Result};
use plonky2::field::types::Field as Plonky2_Field;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::Field;
use crate::{
    field_hash, field_hash_two, AGGREGATION_STAGE1_SIZE, AGGREGATION_STAGE2_SIZE, AGGREGATION_STAGE2_SUB_TREE_HEIGHT,
    AGGREGATION_STAGE3_SIZE, AGGREGATION_STAGE3_SUB_TREE_HEIGHT, PARTICIPATION_ROUNDS_TREE_HEIGHT,
};

pub const PARTICIPATION_TREE_SIZE: usize = AGGREGATION_STAGE2_SIZE * AGGREGATION_STAGE3_SIZE;
pub const PARTICIPATION_TREE_HEIGHT: usize = AGGREGATION_STAGE2_SUB_TREE_HEIGHT + AGGREGATION_STAGE3_SUB_TREE_HEIGHT;

pub const PARTICIPANTS_PER_FIELD: usize = 62;
pub const PARTICIPATION_FIELDS_PER_LEAF: usize = div_ceil(AGGREGATION_STAGE1_SIZE, PARTICIPANTS_PER_FIELD);
pub const PARTICIPATION_BITS_BYTE_SIZE: usize =
    (AGGREGATION_STAGE1_SIZE * AGGREGATION_STAGE2_SIZE * AGGREGATION_STAGE3_SIZE) / 8;

//TODO: support from_bytes, to_bytes and save/load (see commitment)
//TODO: store participation_bits in disk rather than memory

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationRound {
    pub num: usize,
    pub participation_root: [Field; 4],
    pub participation_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct ParticipationRoundData {
    pub participation_root: [Field; 4],
    pub participation_count: u32,
    pub participation_bits: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ParticipationRoundsTree {
    rounds: HashMap<usize, ParticipationRoundData>,
    default_round_data: ParticipationRoundData,
}

impl ParticipationRoundsTree {
    pub fn new() -> Self {
        let default_round_data = ParticipationRoundData {
            participation_root: empty_participation_root(),
            participation_count: 0,
            participation_bits: None,
        };
        Self {
            rounds: HashMap::new(),
            default_round_data,
        }
    }

    pub fn root(&self) -> [Field; 4] {
        let (mut intermediary_nodes, mut default_node) = self.compute_first_level_intermediary_nodes();
        for _ in 0..PARTICIPATION_ROUNDS_TREE_HEIGHT {
            (intermediary_nodes, default_node) = Self::compute_intermediary_nodes(&intermediary_nodes, default_node);
        }

        match intermediary_nodes.get(0) {
            Some(node) => node.1,
            None => default_node,
        }
    }

    pub fn height(&self) -> usize {
        PARTICIPATION_ROUNDS_TREE_HEIGHT
    }

    pub fn merkle_proof(&self, num: usize) -> Vec<[Field; 4]> {
        //compute initial intermediary nodes
        let (mut intermediary_nodes, mut default_node) = self.compute_first_level_intermediary_nodes();

        //build the merkle proof for each level in the tree
        let mut proof: Vec<[Field; 4]> = Vec::new();
        let mut idx = num;
        for _ in 0..PARTICIPATION_ROUNDS_TREE_HEIGHT {
            //add sibling to proof
            let sibling_idx = if (idx % 2) == 0 { idx + 1 } else { idx - 1 };
            let sibling = match intermediary_nodes.iter().find(|x| x.0 == sibling_idx) {
                Some(node) => node.1,
                None => default_node,
            };
            proof.push(sibling);
            idx = idx >> 1;

            //compute the next level intermediary nodes
            (intermediary_nodes, default_node) = Self::compute_intermediary_nodes(&intermediary_nodes, default_node);
        }

        proof
    }

    pub fn verify_merkle_proof(&self, round: ParticipationRound, proof: &[[Field; 4]]) -> Result<bool> {
        if proof.len() != PARTICIPATION_ROUNDS_TREE_HEIGHT {
            return Err(anyhow!("Invalid proof length."));
        }

        let mut idx = round.num;
        let mut hash = Self::hash_round(round);
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

    pub fn round(&self, num: usize) -> ParticipationRound {
        match self.rounds.get(&num) {
            Some(round) => ParticipationRound {
                num,
                participation_root: round.participation_root,
                participation_count: round.participation_count,
            },
            None => ParticipationRound {
                num,
                participation_root: self.default_round_data.participation_root,
                participation_count: self.default_round_data.participation_count,
            },
        }
    }

    pub fn round_participation_bits(&self, num: usize) -> Option<Vec<u8>> {
        match self.rounds.get(&num) {
            Some(round) => round.participation_bits.clone(),
            None => None,
        }
    }

    pub fn update_round(&mut self, round: ParticipationRound, participation_bits: Option<Vec<u8>>) {
        let current_round = self.round(round.num);
        if round.participation_count >= current_round.participation_count {
            self.rounds.insert(
                round.num,
                ParticipationRoundData {
                    participation_root: round.participation_root,
                    participation_count: round.participation_count,
                    participation_bits,
                },
            );
        }
    }

    fn hash_round(round: ParticipationRound) -> [Field; 4] {
        let fields_to_hash = [
            round.participation_root.to_vec(),
            vec![Field::from_canonical_u32(round.participation_count)],
        ]
        .concat();
        field_hash(&fields_to_hash)
    }

    fn compute_first_level_intermediary_nodes(&self) -> (Vec<(usize, [Field; 4])>, [Field; 4]) {
        let mut round_numbers: Vec<usize> = self.rounds.iter().map(|(k, _)| *k).collect();
        round_numbers.sort();
        let intermediary_nodes: Vec<(usize, [Field; 4])> = round_numbers
            .par_iter()
            .map(|num| (*num, Self::hash_round(self.round(*num))))
            .collect();

        let default_node = Self::hash_round(ParticipationRound {
            num: 0,
            participation_root: self.default_round_data.participation_root,
            participation_count: self.default_round_data.participation_count,
        });

        (intermediary_nodes, default_node)
    }

    fn compute_intermediary_nodes(
        intermediary_nodes: &[(usize, [Field; 4])],
        default_node: [Field; 4],
    ) -> (Vec<(usize, [Field; 4])>, [Field; 4]) {
        //arrange intermediary nodes into pairs (left, right)
        let mut intermediary_node_pairs: Vec<(usize, (Option<usize>, Option<usize>))> = Vec::new();
        let mut i = 0;
        while i < intermediary_nodes.len() {
            let node = intermediary_nodes[i];
            let mut pair = (None, None);
            if (node.0 % 2) == 0 {
                pair.0 = Some(i);
                if (i + 1) < intermediary_nodes.len() {
                    let next_node = intermediary_nodes[i + 1];
                    if next_node.0 == node.0 + 1 {
                        pair.1 = Some(i + 1);
                        i += 1; //skip the next node as it is part of the current pair
                    }
                }
            } else {
                pair.1 = Some(i);
            }
            intermediary_node_pairs.push((node.0 >> 1, pair));
            i += 1;
        }

        //compute the next level intermediary nodes in parallel
        let next_level_intermediary_nodes = intermediary_node_pairs
            .par_iter()
            .map(|(addr, (left, right))| {
                let left_sibling = match *left {
                    Some(left) => intermediary_nodes[left].1,
                    None => default_node,
                };
                let right_sibling = match *right {
                    Some(right) => intermediary_nodes[right].1,
                    None => default_node,
                };
                (*addr, (field_hash_two(left_sibling, right_sibling)))
            })
            .collect();

        let next_default_node = field_hash_two(default_node, default_node);
        (next_level_intermediary_nodes, next_default_node)
    }
}

pub fn initial_participation_rounds_tree() -> ParticipationRoundsTree {
    ParticipationRoundsTree::new()
}

pub fn initial_participation_rounds_tree_root() -> [Field; 4] {
    initial_participation_rounds_tree().root()
}

pub fn empty_participation_sub_root(height: usize) -> [Field; 4] {
    let mut node = field_hash(&[Field::ZERO; PARTICIPATION_FIELDS_PER_LEAF]);
    for _ in 0..height {
        node = field_hash_two(node.clone(), node.clone());
    }
    node
}

pub fn empty_participation_root() -> [Field; 4] {
    empty_participation_sub_root(PARTICIPATION_TREE_HEIGHT)
}

pub fn leaf_fields(participation: Vec<bool>) -> Vec<Field> {
    let mut b = 0;
    let mut participation_bits_u64: Vec<u64> = Vec::new();
    for _ in 0..PARTICIPATION_FIELDS_PER_LEAF {
        let mut field_u64: u64 = 0;
        for _ in 0..PARTICIPANTS_PER_FIELD {
            if b < AGGREGATION_STAGE1_SIZE {
                field_u64 = field_u64 << 1;
                if participation[b] {
                    field_u64 += 1;
                }
            }
            b += 1;
        }
        participation_bits_u64.push(field_u64);
    }
    let fields: Vec<Field> = participation_bits_u64
        .iter()
        .map(|f| Field::from_canonical_u64(*f))
        .collect();
    fields
}

pub fn participation_root(participation_bits: &Vec<u8>) -> [Field; 4] {
    participation_merkle_data(participation_bits, 0).root
}

pub struct ParticipationMerkleData {
    pub root: [Field; 4],
    pub leaf_fields: Vec<Field>,
    pub proof: Vec<[Field; 4]>,
}

pub fn participation_merkle_data(participation_bits: &Vec<u8>, validator_index: usize) -> ParticipationMerkleData {
    let participation_root_index = validator_index / AGGREGATION_STAGE1_SIZE;
    let mut leaf_fields = Vec::new();

    let mut nodes: Vec<[Field; 4]> = Vec::new();
    for i in 0..PARTICIPATION_TREE_SIZE {
        let fields = participation_fields(participation_bits, i);
        if i == participation_root_index {
            leaf_fields = fields.clone();
        }
        nodes.push(field_hash(fields.as_slice()));
    }

    for h in (0..PARTICIPATION_TREE_HEIGHT).rev() {
        let start = nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            nodes.push(field_hash_two(nodes[start + (i * 2)], nodes[start + (i * 2) + 1]));
        }
    }
    let root = *nodes.last().unwrap();

    let mut proof: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; PARTICIPATION_TREE_HEIGHT];
    let mut start: usize = 0;
    let mut jump: usize = PARTICIPATION_TREE_SIZE;
    let mut idx = participation_root_index;
    for i in 0..PARTICIPATION_TREE_HEIGHT {
        if (idx & 1) == 0 {
            proof[i] = nodes[start + idx + 1];
        } else {
            proof[i] = nodes[start + idx - 1];
        }
        start = start + jump;
        jump = jump / 2;
        idx = idx / 2;
    }

    ParticipationMerkleData {
        root,
        leaf_fields,
        proof,
    }
}

fn participation_fields(participation_bits: &Vec<u8>, group_index: usize) -> Vec<Field> {
    let mut b = group_index * AGGREGATION_STAGE1_SIZE;
    let mut participation_bits_u64: Vec<u64> = Vec::new();
    for _ in 0..PARTICIPATION_FIELDS_PER_LEAF {
        let mut field_u64: u64 = 0;
        for _ in 0..PARTICIPANTS_PER_FIELD {
            if b < (group_index + 1) * AGGREGATION_STAGE1_SIZE {
                field_u64 = field_u64 << 1;
                if bit_from_field(participation_bits, b) {
                    field_u64 += 1;
                }
            }
            b += 1;
        }
        participation_bits_u64.push(field_u64);
    }
    let fields: Vec<Field> = participation_bits_u64
        .iter()
        .map(|f| Field::from_canonical_u64(*f))
        .collect();
    fields
}

fn bit_from_field(participation_bits: &Vec<u8>, index: usize) -> bool {
    match participation_bits.get(index / 8) {
        Some(byte) => byte & (128u8 >> (index % 8)) > 0,
        None => false,
    }
}

const fn div_ceil(x: usize, y: usize) -> usize {
    if x == 0 {
        return 0;
    }

    let div = x / y;
    if y * div == x {
        return div;
    }
    div + 1
}
