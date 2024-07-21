use std::collections::HashMap;

use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{AGGREGATION_PASS1_SIZE, AGGREGATION_PASS2_SIZE, AGGREGATION_PASS2_SUB_TREE_HEIGHT, AGGREGATION_PASS3_SIZE, AGGREGATION_PASS3_SUB_TREE_HEIGHT, PARTICIPATION_ROUNDS_PER_STATE_EPOCH, PARTICIPATION_ROUNDS_TREE_HEIGHT};
use crate::Field;
use crate::Hash;

pub const PARTICIPATION_TREE_SIZE: usize = AGGREGATION_PASS2_SIZE * AGGREGATION_PASS3_SIZE;
pub const PARTICIPATION_TREE_HEIGHT: usize = AGGREGATION_PASS2_SUB_TREE_HEIGHT + AGGREGATION_PASS3_SUB_TREE_HEIGHT;

pub const PARTICIPANTS_PER_FIELD: usize = 62;
pub const PARTICIPATION_FIELDS_PER_LEAF: usize = div_ceil(AGGREGATION_PASS1_SIZE, PARTICIPANTS_PER_FIELD);
pub const PARTICIPATION_BITS_BYTE_SIZE: usize = (AGGREGATION_PASS1_SIZE * AGGREGATION_PASS2_SIZE * AGGREGATION_PASS3_SIZE) / 8;


//TODO: support from_bytes, to_bytes and save/load (see commitment)
//TODO: store ParticipationBits in disk rather than memory
//TODO: root and merkle proof generation can add more parallelism

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationBits {
    pub bit_flags: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationRound {
    pub num: usize,
    pub state_inputs_hash: [u64; 4],
    pub participation_root: [Field; 4],
    pub participation_count: u32,
    pub participation_bits: ParticipationBits,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationRoundData {
    pub participation_root: [Field; 4],
    pub participation_count: u32,
    pub participation_bits: ParticipationBits,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationRoundsTree {
    state_inputs_hashes: HashMap<usize, [u64; 4]>,
    rounds: HashMap<usize, ParticipationRoundData>,
}

impl ParticipationRoundsTree {
    pub fn new() -> Self {
        Self::from_rounds(Vec::<ParticipationRound>::new())
    }

    pub fn from_rounds(rounds: Vec<ParticipationRound>) -> Self {
        let mut rounds_tree = Self { state_inputs_hashes: HashMap::new(), rounds: HashMap::new() };
        for round in rounds {
            rounds_tree.update_round(round);
        }
        rounds_tree
    }

    pub fn root(&self) -> [Field; 4] {
        //compute initial intermediary nodes
        let mut round_numbers: Vec<usize> = self.rounds.iter().map(|(k, _)| *k).collect();
        round_numbers.sort();
        let mut intermediary_nodes: Vec<(usize, [Field; 4])> = round_numbers.par_iter().map(|num| {
            (*num, Self::hash_round(self.round(*num)))
        }).collect();

        //compute the initial default node
        let mut default_node = Self::hash_round(ParticipationRound {
            num: 0,
            state_inputs_hash: [0u64; 4],
            participation_root: empty_participation_root(),
            participation_count: 0,
            participation_bits: ParticipationBits {
                bit_flags: Vec::<u8>::new(),
            },
        });

        //compute intermediary nodes for each level of the tree
        for _ in 0..PARTICIPATION_ROUNDS_TREE_HEIGHT {
            let mut next_level_intermediary_nodes: Vec<(usize, [Field; 4])> = Vec::new();
            let mut skip_next = false;
            for i in 0..intermediary_nodes.len() {
                if skip_next {
                    skip_next = false;
                    continue;
                }

                let node = intermediary_nodes[i];
                let mut parent_node = (node.0 >> 1, [Field::ZERO; 4]);
                if (node.0 % 2) == 0 {
                    if (i + 1) < intermediary_nodes.len() {
                        let next_node = intermediary_nodes[i + 1];
                        if next_node.0 == node.0 + 1 {
                            parent_node.1 = field_hash_two(node.1, next_node.1);
                            skip_next = true;
                        } else {
                            parent_node.1 = field_hash_two(node.1, default_node);
                        }
                    } else {
                        parent_node.1 = field_hash_two(node.1, default_node);
                    }
                } else {
                    parent_node.1 = field_hash_two(default_node, node.1);
                }
                next_level_intermediary_nodes.push(parent_node);
            }

            //move everything forward for next loop iteration
            intermediary_nodes = next_level_intermediary_nodes;
            default_node = field_hash_two(default_node, default_node);
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
        let mut round_numbers: Vec<usize> = self.rounds.iter().map(|(k, _)| *k).collect();
        round_numbers.sort();
        let mut intermediary_nodes: Vec<(usize, [Field; 4])> = round_numbers.par_iter().map(|num| {
            (*num, Self::hash_round(self.round(*num)))
        }).collect();

        //compute the initial default node
        let mut default_node = Self::hash_round(ParticipationRound {
            num: 0,
            state_inputs_hash: [0u64; 4],
            participation_root: empty_participation_root(),
            participation_count: 0,
            participation_bits: ParticipationBits {
                bit_flags: Vec::<u8>::new(),
            },
        });

        //build the merkle proof for each level in the tree
        let mut proof: Vec<[Field; 4]> = Vec::new();
        let mut idx = num;
        for _ in 0..PARTICIPATION_ROUNDS_TREE_HEIGHT {
            //add sibling to proof
            let sibling_idx = if (idx % 2) == 0 { idx + 1 } else { idx - 1 };
            let sibling = match intermediary_nodes.iter().find(|x| x.0 == sibling_idx ) {
                Some(node) => node.1,
                None => default_node,
            };
            proof.push(sibling);
            idx = idx >> 1;

            //compute intermediary nodes for next level 
            let mut next_level_intermediary_nodes: Vec<(usize, [Field; 4])> = Vec::new();
            let mut skip_next = false;
            for i in 0..intermediary_nodes.len() {
                if skip_next {
                    skip_next = false;
                    continue;
                }

                let node = intermediary_nodes[i];
                let mut parent_node = (node.0 >> 1, [Field::ZERO; 4]);
                if (node.0 % 2) == 0 {
                    if (i + 1) < intermediary_nodes.len() {
                        let next_node = intermediary_nodes[i + 1];
                        if next_node.0 == node.0 + 1 {
                            parent_node.1 = field_hash_two(node.1, next_node.1);
                            skip_next = true;
                        } else {
                            parent_node.1 = field_hash_two(node.1, default_node);
                        }
                    } else {
                        parent_node.1 = field_hash_two(node.1, default_node);
                    }
                } else {
                    parent_node.1 = field_hash_two(default_node, node.1);
                }
                next_level_intermediary_nodes.push(parent_node);
            }

            //move everything forward for next loop iteration
            intermediary_nodes = next_level_intermediary_nodes;
            default_node = field_hash_two(default_node, default_node);
        }

        proof
    }

    pub fn round(&self, num: usize) -> ParticipationRound {
        let state_epoch = num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
        match self.rounds.get(&num) {
            Some(round) => ParticipationRound {
                num,
                state_inputs_hash: match self.state_inputs_hashes.get(&state_epoch) {
                    Some(state_inputs_hash) => state_inputs_hash.clone(),
                    None => [0u64; 4],
                },
                participation_root: round.participation_root,
                participation_count: round.participation_count,
                participation_bits: round.participation_bits.clone(),
            },
            None => ParticipationRound {
                num,
                state_inputs_hash: [0u64; 4],
                participation_root: empty_participation_root(),
                participation_count: 0,
                participation_bits: ParticipationBits {
                    bit_flags: Vec::<u8>::new(),
                }
            },
        }
    }

    pub fn update_round(&mut self, round: ParticipationRound) {
        let state_epoch = round.num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
        match self.state_inputs_hashes.get(&state_epoch) {
            Some(inputs_hash) => {
                assert_eq!(
                    inputs_hash.clone(), 
                    round.state_inputs_hash, 
                    "round update must have the same state_inputs_hash as previous updates within the same epoch"
                );
            },
            _ => {},
        }

        let current_round = self.round(round.num);
        if round.participation_count >= current_round.participation_count {
            self.state_inputs_hashes.insert(state_epoch, round.state_inputs_hash);
            self.rounds.insert(round.num, ParticipationRoundData {
                participation_root: round.participation_root,
                participation_count: round.participation_count,
                participation_bits: round.participation_bits,
            });
        }
    }
    
    fn hash_round(round: ParticipationRound) -> [Field; 4] {
        let mut state_inputs_hash_as_fields = Vec::new();
        for e in round.state_inputs_hash {
            state_inputs_hash_as_fields.push(Field::from_canonical_u64(e >> 32));
            state_inputs_hash_as_fields.push(Field::from_canonical_u32(e as u32));
        }
        let fields_to_hash = [
            state_inputs_hash_as_fields,
            round.participation_root.to_vec(),
            vec!(Field::from_canonical_u32(round.participation_count)),
        ].concat();
        field_hash(&fields_to_hash)
    }
}

pub fn initial_participation_rounds_root() -> [Field; 4] {
    let participation_rounds_tree = ParticipationRoundsTree::new();
    participation_rounds_tree.root()
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
            if b < AGGREGATION_PASS1_SIZE {
                field_u64 = field_u64 << 1;
                if participation[b] {
                    field_u64 += 1;
                }
            }
            b += 1;
        }
        participation_bits_u64.push(field_u64);
    }
    let fields: Vec<Field> = participation_bits_u64.iter().map(|f| Plonky2_Field::from_canonical_u64(*f)).collect();
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
    let participation_root_index = validator_index / AGGREGATION_PASS1_SIZE;
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

    ParticipationMerkleData { root, leaf_fields, proof }
}

fn participation_fields(participation_bits: &Vec<u8>, group_index: usize) -> Vec<Field> {
    let mut b = group_index * AGGREGATION_PASS1_SIZE;
    let mut participation_bits_u64: Vec<u64> = Vec::new();
    for _ in 0..PARTICIPATION_FIELDS_PER_LEAF {
        let mut field_u64: u64 = 0;
        for _ in 0..PARTICIPANTS_PER_FIELD {
            if b < (group_index + 1) * AGGREGATION_PASS1_SIZE {
                field_u64 = field_u64 << 1;
                if bit_from_field(participation_bits, b) {
                    field_u64 += 1;
                }
            }
            b += 1;
        }
        participation_bits_u64.push(field_u64);
    }
    let fields: Vec<Field> = participation_bits_u64.iter().map(|f| Plonky2_Field::from_canonical_u64(*f)).collect();
    fields
}

fn bit_from_field(participation_bits: &Vec<u8>, index: usize) -> bool {
    match participation_bits.get(index / 8) {
        Some(byte) => byte & (128u8 >> (index % 8)) > 0,
        None => false,
    }
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
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
