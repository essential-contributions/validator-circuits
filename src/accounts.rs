use std::collections::HashMap;

use plonky2::field::types::Field as Plonky2_Field;
use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher as Plonky2_Hasher};
use serde::{Deserialize, Serialize};

use crate::{Field, MAX_VALIDATORS};
use crate::Hash;

const SPARSE_ACCOUNTS_TREE_HEIGHT: usize = 160;
const ACCOUNTS_NULL_FIELD: u64 = 0xffffffff00000000;

//TODO: support from_bytes, to_bytes and save/load (see commitment)

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Account {
    pub address: [u8; 20],
    pub active: bool,
    pub validator_index: Option<u32>,
    pub start_unchecked_participation_epoch: Option<u32>,
    pub end_unchecked_participation_epoch: Option<u32>,
    pub balance: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AccountsTree {
    accounts: HashMap<[u8; 20], Account>,
    intermediary_nodes: Vec<HashMap<[u8; 20], [Field; 4]>>,
    default_nodes: Vec<[Field; 4]>,
    root: [Field; 4],
}

impl AccountsTree {
    pub fn new() -> Self {
        let mut tree = Self::from_accounts(&vec![]);

        //create a default account for each of the validators
        for i in 0..MAX_VALIDATORS as u32 {
            tree.set_account(Account {
                address: address_add([0u8; 20], i),
                active: true,
                validator_index: Some(i),
                start_unchecked_participation_epoch: Some(0),
                end_unchecked_participation_epoch: None,
                balance: 0,
            });
        }
        tree
    }

    pub fn from_accounts(accounts: &Vec<Account>) -> Self {
        //compute the default nodes
        let mut default_nodes: Vec<[Field; 4]> = Vec::new();
        let mut hash = Self::hash_account(Account {
            address: [0u8; 20],
            active: false,
            validator_index: None,
            start_unchecked_participation_epoch: None,
            end_unchecked_participation_epoch: None,
            balance: 0
        });
        for _ in 0..SPARSE_ACCOUNTS_TREE_HEIGHT {
            default_nodes.push(hash);
            hash = field_hash_two(hash, hash);
        }

        //build maps for intermediary nodes
        let mut intermediary_nodes: Vec<HashMap<[u8; 20], [Field; 4]>> = Vec::new();
        for _ in 0..SPARSE_ACCOUNTS_TREE_HEIGHT {
            intermediary_nodes.push(HashMap::new());
        }

        //build tree
        let mut tree = AccountsTree {
            accounts: HashMap::new(),
            intermediary_nodes,
            default_nodes,
            root: hash,
        };

        //add accounts
        for account in accounts {
            tree.set_account(account.clone());
        }

        tree
    }

    pub fn root(&self) -> [Field; 4] {
        self.root
    }

    pub fn set_account(&mut self, account: Account) {
        let mut address = account.address;
        self.accounts.insert(address, account.clone());

        //fill intermediary nodes
        let mut hash = Self::hash_account(account);
        for i in 0..SPARSE_ACCOUNTS_TREE_HEIGHT {
            self.set_node(i, address, hash);
            hash = if (address[19] & 1) == 0 {
                let neighbor = self.get_node(0, address_add(address, 1));
                field_hash_two(hash, neighbor)
            } else {
                let neighbor = self.get_node(0, address_sub(address, 1));
                field_hash_two(neighbor, hash)
            };
            address = address_shr(address, 1);
        }

        //set new root
        self.root = hash;
    }

    pub fn get_account(&self, address: [u8; 20]) -> Account {
        match self.accounts.get(&address) {
            Some(node) => node.clone(),
            None => Account {
                address,
                active: false,
                validator_index: None,
                start_unchecked_participation_epoch: None,
                end_unchecked_participation_epoch: None,
                balance: 0,
            },
        }
    }

    pub fn account_merkle_proof(&self, address: [u8; 20]) -> Vec<[Field; 4]> {
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; SPARSE_ACCOUNTS_TREE_HEIGHT];
        let mut node_index: usize = 0;
        let mut idx = address;
        for i in (0..SPARSE_ACCOUNTS_TREE_HEIGHT).rev() {
            if (idx[19] & 1) == 0 {
                nodes[node_index] = self.get_node(i, address_add(idx, 1));
            } else {
                nodes[node_index] = self.get_node(i, address_sub(idx, 1));
            }
            idx = address_shr(idx, 1);
            node_index = node_index + 1;
        }
        nodes
    }

    fn set_node(&mut self, height: usize, index: [u8; 20], value: [Field; 4]) {
        let map = self.intermediary_nodes.get_mut(height).expect("invalid height");
        let default_node = self.default_nodes.get(height as usize).expect("invalid height");
        if value[0].eq(&default_node[0]) && value[1].eq(&default_node[1]) && value[2].eq(&default_node[2]) && value[3].eq(&default_node[3]) {
            map.remove(&index);
        } else {
            map.insert(index, value);
        }
    }

    fn get_node(&self, height: usize, index: [u8; 20]) -> [Field; 4] {
        let map = self.intermediary_nodes.get(height).expect("invalid height");
        let default_node = self.default_nodes.get(height as usize).expect("invalid height");
        match map.get(&index) {
            Some(node) => node.clone(),
            None => default_node.clone(),
        }
    }

    fn hash_account(account: Account) -> [Field; 4] {
        let validator_index_field = match account.validator_index {
            Some(validator_index) => Field::from_canonical_u32(validator_index),
            None => Field::from_canonical_u64(ACCOUNTS_NULL_FIELD),
        };
        let validator_start_epoch = match account.start_unchecked_participation_epoch {
            Some(start_unchecked_participation_epoch) => Field::from_canonical_u32(start_unchecked_participation_epoch),
            None => Field::from_canonical_u64(ACCOUNTS_NULL_FIELD),
        };
        let validator_end_epoch = match account.end_unchecked_participation_epoch {
            Some(end_unchecked_participation_epoch) => Field::from_canonical_u32(end_unchecked_participation_epoch),
            None => Field::from_canonical_u64(ACCOUNTS_NULL_FIELD),
        };
        let fields = [
            Field::from_bool(account.active),
            validator_index_field,
            validator_start_epoch,
            validator_end_epoch,
            Field::from_canonical_u64(account.balance),
        ];
        field_hash(&fields)
    }
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
