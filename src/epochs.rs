use std::collections::HashMap;

use plonky2::field::types::Field as Plonky2_Field;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::accounts::AccountsTree;
use crate::circuits::validators_state_circuit::ValidatorsStateProof;
use crate::validators::ValidatorsTree;
use crate::{field_hash, field_hash_two, VALIDATOR_EPOCHS_TREE_HEIGHT};
use crate::Field;

//TODO: support from_bytes, to_bytes and save/load (see commitment)
//TODO: store validators_state_proof, validators_tree and accounts_tree in disk rather than memory (will need an efficient compression strategy)

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorEpoch {
    pub num: u32,
    pub validators_state_inputs_hash: [u8; 32],
    pub total_staked: u64,
    pub total_validators: u32,
    pub validators_tree_root: [Field; 4],
    pub accounts_tree_root: [Field; 4],
}

#[derive(Clone, Serialize, Deserialize)]
struct ValidatorEpochData {
    pub validators_state_proof: ValidatorsStateProof,
    pub validators_tree: ValidatorsTree,
    pub accounts_tree: AccountsTree,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorEpochsTree {
    epochs: HashMap<usize, ValidatorEpochData>,
}

impl ValidatorEpochsTree {
    pub fn new() -> Self {
        Self { epochs: HashMap::new() }
    }

    pub fn root(&self) -> [Field; 4] {
        let (mut intermediary_nodes, mut default_node) = self.compute_first_level_intermediary_nodes();
        for _ in 0..VALIDATOR_EPOCHS_TREE_HEIGHT {
            (intermediary_nodes, default_node) = Self::compute_intermediary_nodes(&intermediary_nodes, default_node);
        }

        match intermediary_nodes.get(0) {
            Some(node) => node.1,
            None => default_node,
        }
    }

    pub fn height(&self) -> usize {
        VALIDATOR_EPOCHS_TREE_HEIGHT
    }

    pub fn merkle_proof(&self, num: usize) -> Vec<[Field; 4]> {
        //compute initial intermediary nodes
        let (mut intermediary_nodes, mut default_node) = self.compute_first_level_intermediary_nodes();

        //build the merkle proof for each level in the tree
        let mut proof: Vec<[Field; 4]> = Vec::new();
        let mut idx = num;
        for _ in 0..VALIDATOR_EPOCHS_TREE_HEIGHT {
            //add sibling to proof
            let sibling_idx = if (idx % 2) == 0 { idx + 1 } else { idx - 1 };
            let sibling = match intermediary_nodes.iter().find(|x| x.0 == sibling_idx ) {
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

    pub fn verify_merkle_proof(&self, epoch: ValidatorEpoch, proof: &[[Field; 4]]) -> Result<bool> {
        if proof.len() != VALIDATOR_EPOCHS_TREE_HEIGHT {
            return Err(anyhow!("Invalid proof length."));
        }

        let mut idx = epoch.num;
        let mut hash = Self::hash_epoch(epoch);
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

    pub fn epoch(&self, num: usize) -> ValidatorEpoch {
        match self.epochs.get(&num) {
            Some(epoch) => ValidatorEpoch {
                num: num as u32,
                validators_state_inputs_hash: epoch.validators_state_proof.inputs_hash(),
                total_staked: epoch.validators_state_proof.total_staked(),
                total_validators: epoch.validators_state_proof.total_validators(),
                validators_tree_root: epoch.validators_state_proof.validators_tree_root(),
                accounts_tree_root: epoch.validators_state_proof.accounts_tree_root(),
            },
            None => ValidatorEpoch {
                num: num as u32,
                validators_state_inputs_hash: [0u8; 32],
                total_staked: 0,
                total_validators: 0,
                validators_tree_root: [Field::ZERO; 4],
                accounts_tree_root: [Field::ZERO; 4],
            },
        }
    }

    pub fn epoch_validators_state_proof(&self, num: usize) -> Option<ValidatorsStateProof> {
        match self.epochs.get(&num) {
            Some(epoch) => Some(epoch.validators_state_proof.clone()),
            None => None,
        }
    }

    pub fn epoch_validators_tree(&self, num: usize) -> Option<ValidatorsTree> {
        match self.epochs.get(&num) {
            Some(epoch) => Some(epoch.validators_tree.clone()),
            None => None,
        }
    }

    pub fn epoch_accounts_tree(&self, num: usize) -> Option<AccountsTree> {
        match self.epochs.get(&num) {
            Some(epoch) => Some(epoch.accounts_tree.clone()),
            None => None,
        }
    }

    pub fn update_epoch(&mut self, epoch_num: usize, validators_state_proof: &ValidatorsStateProof, validators_tree: &ValidatorsTree, accounts_tree: &AccountsTree) {
        self.epochs.insert(epoch_num, ValidatorEpochData {
            validators_state_proof: validators_state_proof.clone(),
            validators_tree: validators_tree.clone(),
            accounts_tree: accounts_tree.clone(),
        });
    }
    
    fn hash_epoch(epoch: ValidatorEpoch) -> [Field; 4] {
        let validators_state_inputs_hash: Vec<Field> = epoch.validators_state_inputs_hash.chunks(4).into_iter().map(|c| {
            Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        }).collect();
        field_hash(&validators_state_inputs_hash)
    }

    fn compute_first_level_intermediary_nodes(&self) -> (Vec<(usize, [Field; 4])>, [Field; 4]) {
        let mut round_numbers: Vec<usize> = self.epochs.iter().map(|(k, _)| *k).collect();
        round_numbers.sort();
        let intermediary_nodes: Vec<(usize, [Field; 4])> = round_numbers.par_iter().map(|num| {
            (*num, Self::hash_epoch(self.epoch(*num)))
        }).collect();

        let default_node = Self::hash_epoch(ValidatorEpoch {
            num: 0,
            validators_state_inputs_hash: [0u8; 32],
            total_staked: 0,
            total_validators: 0,
            validators_tree_root: [Field::ZERO; 4],
            accounts_tree_root: [Field::ZERO; 4],
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
        let next_level_intermediary_nodes = intermediary_node_pairs.par_iter().map(|(addr, (left, right))| {
            let left_sibling = match *left {
                Some(left) => intermediary_nodes[left].1,
                None => default_node,
            };
            let right_sibling = match *right {
                Some(right) => intermediary_nodes[right].1,
                None => default_node,
            };
            (*addr, (field_hash_two(left_sibling, right_sibling)))
        }).collect();

        let next_default_node = field_hash_two(default_node, default_node);
        (next_level_intermediary_nodes, next_default_node)
    }
}

pub fn initial_validator_epochs_root() -> [Field; 4] {
    let validator_epochs_tree = ValidatorEpochsTree::new();
    validator_epochs_tree.root()
}
