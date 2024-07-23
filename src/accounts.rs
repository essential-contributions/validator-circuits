use std::collections::HashMap;

use plonky2::field::types::{Field as Plonky2_Field, Field64};
use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher as Plonky2_Hasher};
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{Field, MAX_VALIDATORS};
use crate::Hash;

const SPARSE_ACCOUNTS_TREE_HEIGHT: usize = 160;
const ACCOUNTS_NULL_FIELD: u64 = 0xffffffff00000000;

//TODO: support from_bytes, to_bytes and save/load (see commitment)
//TODO: root and merkle proof generation can add more parallelism

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Account {
    pub address: [u8; 20],
    pub validator_index: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AccountsTree {
    accounts: HashMap<[u8; 20], Account>,
}

impl AccountsTree {
    pub fn new() -> Self {
        //create the default accounts
        let mut accounts = HashMap::new();
        for i in 0..(MAX_VALIDATORS as u32) {
            let mut address = [0u8; 20];
            address[16..20].copy_from_slice(&i.to_be_bytes());
            accounts.insert(address, Account {
                address,
                validator_index: Some(i),
            });
        }

        Self { accounts }
    }

    pub fn from_accounts(accounts: &[Account]) -> Self {
        let mut accounts_tree = Self::new();
        for account in accounts {
            accounts_tree.set_account(account.clone());
        }
        accounts_tree
    }

    pub fn root(&self) -> [Field; 4] {
        //compute initial intermediary nodes
        let mut account_addresses: Vec<[u8; 20]> = self.accounts.iter().map(|(k, _)| *k).collect();
        account_addresses.sort();
        let mut intermediary_nodes: Vec<([u8; 20], [Field; 4])> = account_addresses.par_iter().map(|address| {
            (*address, Self::hash_account(self.account(*address)))
        }).collect();

        //compute the initial default node
        let mut default_node = Self::hash_account(Account { address: [0u8; 20], validator_index: None });

        //compute intermediary nodes for each level of the tree
        for _ in 0..SPARSE_ACCOUNTS_TREE_HEIGHT {
            let mut next_level_intermediary_nodes: Vec<([u8; 20], [Field; 4])> = Vec::new();
            let mut skip_next = false;
            for i in 0..intermediary_nodes.len() {
                if skip_next {
                    skip_next = false;
                    continue;
                }

                let node = intermediary_nodes[i];
                let mut parent_node = (address_shr(node.0, 1), [Field::ZERO; 4]);
                if (node.0[19] % 2) == 0 {
                    if (i + 1) < intermediary_nodes.len() {
                        let next_node = intermediary_nodes[i + 1];
                        if next_node.0 == address_add(node.0, 1) {
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
        SPARSE_ACCOUNTS_TREE_HEIGHT
    }

    pub fn merkle_proof(&self, address: [u8; 20]) -> Vec<[Field; 4]> {
        //compute initial intermediary nodes
        let mut account_addresses: Vec<[u8; 20]> = self.accounts.iter().map(|(k, _)| *k).collect();
        account_addresses.sort();
        let mut intermediary_nodes: Vec<([u8; 20], [Field; 4])> = account_addresses.par_iter().map(|address| {
            (*address, Self::hash_account(self.account(*address)))
        }).collect();

        //compute the initial default node
        let mut default_node = Self::hash_account(Account { address: [0u8; 20], validator_index: None });

        //build the merkle proof for each level in the tree
        let mut proof: Vec<[Field; 4]> = Vec::new();
        let mut idx = address;
        for _ in 0..SPARSE_ACCOUNTS_TREE_HEIGHT {
            //add sibling to proof
            let sibling_idx = if (idx[19] % 2) == 0 { address_add(idx, 1) } else { address_sub(idx, 1) };
            let sibling = match intermediary_nodes.iter().find(|x| x.0 == sibling_idx ) {
                Some(node) => node.1,
                None => default_node,
            };
            proof.push(sibling);
            idx = address_shr(idx, 1);

            //compute intermediary nodes for next level 
            let mut next_level_intermediary_nodes: Vec<([u8; 20], [Field; 4])> = Vec::new();
            let mut skip_next = false;
            for i in 0..intermediary_nodes.len() {
                if skip_next {
                    skip_next = false;
                    continue;
                }

                let node = intermediary_nodes[i];
                let mut parent_node = (address_shr(node.0, 1), [Field::ZERO; 4]);
                if (node.0[19] % 2) == 0 {
                    if (i + 1) < intermediary_nodes.len() {
                        let next_node = intermediary_nodes[i + 1];
                        if next_node.0 == address_add(node.0, 1) {
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

    pub fn account(&self, address: [u8; 20]) -> Account {
        match self.accounts.get(&address) {
            Some(account) => account.clone(),
            None => Account { address, validator_index: None },
        }
    }

    pub fn account_with_index(&self, validator_index: u32) -> Option<Account> {
        let account_entry = self.accounts.iter().find(|(_, v) | {
            if v.validator_index.is_some() {
                return v.validator_index.unwrap() == validator_index;
            }
            return false;
        });
        match account_entry {
            Some((_, account)) => {
                Some(account.clone())
            },
            None => None,
        }
    }

    pub fn set_account(&mut self, account: Account) {
        match account.validator_index {
            Some(validator_index) => {
                match self.account_with_index(validator_index) {
                    Some(account_with_index) => {
                        self.accounts.remove(&account_with_index.address);
                    },
                    None => {},
                }
                self.accounts.insert(account.address, account);
            },
            None => {
                let account_data = self.account(account.address);
                match account_data.validator_index {
                    Some(validator_index) => {
                        let mut null_account_address = [0u8; 20];
                        null_account_address[16..20].copy_from_slice(&validator_index.to_be_bytes());
                        self.accounts.insert(null_account_address, Account {
                            address: null_account_address,
                            validator_index: Some(validator_index),
                        });
                    },
                    None => todo!(),
                }
                self.accounts.remove(&account.address);
            }
        }
    }
    
    fn hash_account(account: Account) -> [Field; 4] {
        let validator_index = match account.validator_index {
            Some(validator_index) => Field::from_canonical_u32(validator_index),
            None => Field::ZERO.sub_one(),
        };
        [validator_index, Field::ZERO, Field::ZERO, Field::ZERO]
    }
}

pub fn initial_accounts_tree_root() -> [Field; 4] {
    let accounts_tree = AccountsTree::new();
    accounts_tree.root()
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}

fn address_add(mut addr: [u8; 20], value: u32) -> [u8; 20] {
    let mut carry = value as u64;
    for byte in addr.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xFF);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
        
        if carry == 0 {
            break;
        }
    }
    addr
}

fn address_sub(mut addr: [u8; 20], value: u32) -> [u8; 20] {
    let mut borrow = value as u64;
    for byte in addr.iter_mut().rev() {
        let sub = *byte as i64 - (borrow & 0xFF) as i64;
        if sub < 0 {
            *byte = (sub + 256) as u8;
            borrow = (borrow >> 8) + 1;
        } else {
            *byte = sub as u8;
            borrow >>= 8;
        }

        if borrow == 0 {
            break;
        }
    }
    addr
}

fn address_shr(mut addr: [u8; 20], shift: usize) -> [u8; 20] {
    if shift == 0 {
        return addr;
    }
    if shift >= 160 {
        return [0u8; 20];
    }

    //first shift full bytes
    let byte_shift = shift / 8;
    if byte_shift > 0 {
        for i in (byte_shift..20).rev() {
            addr[i] = addr[i - byte_shift];
        }
        for i in 0..byte_shift {
            addr[i] = 0;
        }
    }

    //shift bits
    let bit_shift = shift % 8;
    if bit_shift > 0 {
        let mut carry = 0;
        for byte in addr.iter_mut().rev() {
            let new_carry = *byte & ((1 << bit_shift) - 1);
            *byte = (*byte >> bit_shift) | (carry << (8 - bit_shift));
            carry = new_carry;
        }
    }
    addr
}
