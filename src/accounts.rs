use std::{collections::HashMap, fs::{create_dir_all, File}, io::{BufReader, Read, Write}, path::PathBuf};

use plonky2::field::types::{Field as Plonky2_Field, Field64};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{bytes_to_fields, field_hash_two, fields_to_bytes, Field, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT};

const SPARSE_ACCOUNTS_TREE_HEIGHT: usize = 160;

const SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT: usize = 10;
const SPARSE_ACCOUNTS_COMPUTED_TREE_HEIGHT: usize = SPARSE_ACCOUNTS_TREE_HEIGHT - SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Account {
    pub address: [u8; 20],
    pub validator_index: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AccountData {
    pub address: [u8; 20],
    pub validator_index: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccountsTree {
    nodes: Vec<[Field; 4]>,
    accounts: HashMap<[u8; 20], AccountData>,
}

impl AccountsTree {
    pub fn new() -> Self {
        Self::from_accounts(&Self::default_accounts())
    }

    pub fn from_accounts(accounts: &[Account]) -> Self {
        let mut accounts_map = HashMap::new();
        for account in accounts {
            if account.validator_index.is_some() {
                accounts_map.insert(account.address, AccountData {
                    address: account.address,
                    validator_index: account.validator_index.unwrap(),
                });
            }
        }
        assert_eq!(accounts_map.len(), MAX_VALIDATORS, "An account for every validator index is required when calling from_accounts.");

        //create the tree
        let num_nodes = (1 << (SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT + 1)) - 1;
        let nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; num_nodes];
        let mut tree = Self { nodes, accounts: accounts_map };

        //fill node data
        let default_nodes = Self::compute_default_nodes();
        let num_computed_roots = 1 << SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT;
        let computed_node_roots: Vec<(usize, [Field; 4])> = (0..num_computed_roots).into_par_iter().map(|i| {
            (i, tree.computed_nodes_root(i, &default_nodes))
        }).collect();
        tree.fill_nodes(&computed_node_roots);

        tree
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let num_nodes = (1 << (SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT + 1)) - 1;
        let num_nodes_bytes = 32 * num_nodes;
        let num_accounts_bytes = (20 + 4) * MAX_VALIDATORS;
        if bytes.len() != num_accounts_bytes + num_nodes_bytes {
            return Err(anyhow!("Invalid bytes"));
        }

        let mut accounts_map = HashMap::new();
        for i in 0..MAX_VALIDATORS {
            let mut address = [0u8; 20];
            address.iter_mut().enumerate().for_each(|(j, b)| *b = bytes[(i * (20 + 4)) + j]);
            let mut validator_index_raw = [0u8; 4];
            validator_index_raw.iter_mut().enumerate().for_each(|(j, b)| *b = bytes[(i * (20 + 4)) + 20 + j]);

            accounts_map.insert(address, AccountData {
                address,
                validator_index: u32::from_be_bytes(validator_index_raw) as usize,
            });
        }
        let mut nodes: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; num_nodes];
        nodes.iter_mut().enumerate().for_each(|(i, n)| {
            let j = num_accounts_bytes + (i * 32);
            *n = bytes_to_fields(&bytes[j..(j + 32)]);
        });

        Ok(Self { accounts: accounts_map, nodes })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let num_accounts_bytes = (20 + 4) * MAX_VALIDATORS;
        let num_nodes_bytes = 32 * ((1 << (SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT + 1)) - 1);
        let mut bytes: Vec<u8> = vec![0; num_accounts_bytes + num_nodes_bytes];

        self.accounts.iter().enumerate().for_each(|(i, (_, a))| {
            a.address.iter().enumerate().for_each(|(j, b)| bytes[(i * (20 + 4)) + j] = *b);
            (a.validator_index as u32).to_be_bytes().iter().enumerate().for_each(|(j, b)| {
                bytes[(i * (20 + 4)) + 20 + j] = *b;
            });
        });
        self.nodes.iter().enumerate().for_each(|(i, n)| {
            fields_to_bytes(n).iter().enumerate().for_each(|(j, b)| {
                bytes[num_accounts_bytes + (i * 32) + j] = *b;
            });
        });

        Ok(bytes)
    }

    pub fn root(&self) -> [Field; 4] {
        self.nodes[0].clone()
    }

    pub fn height(&self) -> usize {
        SPARSE_ACCOUNTS_TREE_HEIGHT
    }

    pub fn merkle_proof(&self, address: [u8; 20]) -> Vec<[Field; 4]> {
        //compute initial intermediary nodes
        let memory_leaf_index = Self::address_memory_tree_leaf_index(address);
        let default_nodes = Self::compute_default_nodes();
        let mut intermediary_nodes = self.compute_first_level_intermediary_nodes(memory_leaf_index);

        //build the merkle proof for each level in the tree
        let mut proof: Vec<[Field; 4]> = Vec::new();
        let mut idx = address;
        for i in 0..SPARSE_ACCOUNTS_COMPUTED_TREE_HEIGHT {
            //add sibling to proof
            let sibling_idx = if (idx[19] & 1) == 0 { address_add(idx, 1) } else { address_sub(idx, 1) };
            let sibling = match intermediary_nodes.iter().find(|x| x.0 == sibling_idx ) {
                Some(node) => node.1,
                None => default_nodes[i],
            };
            proof.push(sibling);
            idx = address_shr(idx, 1);

            //compute the next level intermediary nodes
            intermediary_nodes = Self::compute_intermediary_nodes(&intermediary_nodes, default_nodes[i]);
        }

        //continue proof by looping through the nodes in memory
        let mut idx = memory_leaf_index;
        for i in (0..SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT).rev() {
            let start = (1 << (i + 1)) - 1;
            if (idx & 1) == 0 {
                proof.push(self.nodes[start + idx + 1]);
            } else {
                proof.push(self.nodes[start + idx - 1]);
            }
            idx = idx / 2;
        }

        proof
    }

    pub fn verify_merkle_proof(&self, account: Account, proof: &[[Field; 4]]) -> Result<bool> {
        if proof.len() != SPARSE_ACCOUNTS_TREE_HEIGHT {
            return Err(anyhow!("Invalid proof length."));
        }

        let mut idx = account.address;
        let mut hash = Self::hash_account(account);
        for sibling in proof {
            if (idx[19] & 1) == 0 {
                hash = field_hash_two(hash, *sibling);
            } else {
                hash = field_hash_two(*sibling, hash);
            }
            idx = address_shr(idx, 1);
        }

        if hash != self.root() {
            return Err(anyhow!("Invalid proof"));
        }
        Ok(true)
    }

    pub fn account(&self, address: [u8; 20]) -> Account {
        match self.accounts.get(&address) {
            Some(a) => Account { address: a.address, validator_index: Some(a.validator_index) },
            None => Account { address, validator_index: None },
        }
    }

    pub fn account_with_index(&self, validator_index: usize) -> Option<Account> {
        let account_entry = self.accounts.iter().find(|(_, a) | {
            return a.validator_index == validator_index;
        });
        match account_entry {
            Some((_, a)) => {
                Some(Account { address: a.address, validator_index: Some(a.validator_index) })
            },
            None => None,
        }
    }

    pub fn set_account(&mut self, account: Account) {
        let default_nodes = Self::compute_default_nodes();
        let mut computed_node_roots: Vec<(usize, [Field; 4])> = Vec::new();
        match account.validator_index {
            Some(validator_index) => {
                match self.account_with_index(validator_index) {
                    Some(account_with_index) => {
                        //remove the account that currently holds the same validator index
                        self.accounts.remove(&account_with_index.address);
                        let memory_tree_index = Self::address_memory_tree_leaf_index(account_with_index.address);
                        computed_node_roots.push((
                            memory_tree_index,
                            self.computed_nodes_root(memory_tree_index, &default_nodes)
                        ));
                    },
                    None => {},
                }
                //insert the new account
                self.accounts.insert(account.address, AccountData {
                    address: account.address,
                    validator_index: validator_index,
                });
                let memory_tree_index = Self::address_memory_tree_leaf_index(account.address);
                computed_node_roots.push((
                    memory_tree_index,
                    self.computed_nodes_root(memory_tree_index, &default_nodes)
                ));
            },
            None => {
                let account_data = self.account(account.address);
                match account_data.validator_index {
                    Some(validator_index) => {
                        //insert the null account to have ownership of the validator index
                        let null_account_address = null_account_address(validator_index as usize);
                        self.accounts.insert(null_account_address, AccountData {
                            address: null_account_address,
                            validator_index: validator_index,
                        });
                        let memory_tree_index = Self::address_memory_tree_leaf_index(null_account_address);
                        computed_node_roots.push((
                            memory_tree_index,
                            self.computed_nodes_root(memory_tree_index, &default_nodes)
                        ));
                    },
                    None => {},
                }
                //remove the account that no longer holds a validator index
                self.accounts.remove(&account.address);
                let memory_tree_index = Self::address_memory_tree_leaf_index(account.address);
                computed_node_roots.push((
                    memory_tree_index,
                    self.computed_nodes_root(memory_tree_index, &default_nodes)
                ));
            }
        }

        //recompute the nodes in memory
        self.fill_nodes(&computed_node_roots);
    }

    pub fn default_accounts() -> Vec<Account> {
        let mut default_accounts = Vec::new();
        for i in 0..MAX_VALIDATORS {
            default_accounts.push(Account {
                address: null_account_address(i),
                validator_index: Some(i),
            });
        }
        default_accounts
    }

    fn computed_nodes_root(&self, memory_tree_index: usize, default_nodes: &[[Field; 4]]) -> [Field; 4] {
        let mut intermediary_nodes = self.compute_first_level_intermediary_nodes(memory_tree_index);
        for i in 0..SPARSE_ACCOUNTS_COMPUTED_TREE_HEIGHT {
            intermediary_nodes = Self::compute_intermediary_nodes(&intermediary_nodes, default_nodes[i]);
        }

        match intermediary_nodes.get(0) {
            Some(node) => node.1,
            None => default_nodes[SPARSE_ACCOUNTS_COMPUTED_TREE_HEIGHT],
        }
    }

    fn fill_nodes(&mut self, computed_node_roots: &[(usize, [Field; 4])]) {
        //fill in computed node roots
        let computed_node_roots_start = (1 << SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT) - 1;
        for (index, computed_node_root) in computed_node_roots {
            self.nodes[computed_node_roots_start + index] = computed_node_root.clone();
        }
    
        //fill in the rest of the tree
        for i in (0..SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT).rev() {
            let start = ((1 << i) - 1) as usize;
            let end = (start * 2) + 1;
            let hashes: Vec<[Field; 4]> = (start..end).into_par_iter().map(|j| {
                field_hash_two(self.nodes[(j * 2) + 1], self.nodes[(j * 2) + 2])
            }).collect();
            hashes.iter().enumerate().for_each(|(j, h)| {
                self.nodes[start + j] = *h;
            });
        }
    }
    
    fn hash_account(account: Account) -> [Field; 4] {
        let validator_index = match account.validator_index {
            Some(validator_index) => Field::from_canonical_usize(validator_index),
            None => Field::ZERO.sub_one(),
        };
        [validator_index, Field::ZERO, Field::ZERO, Field::ZERO]
    }

    fn compute_default_nodes() -> Vec<[Field; 4]> {
        let mut default_nodes = Vec::new();
        let mut default_node = Self::hash_account(Account { address: [0u8; 20], validator_index: None });
        for _ in 0..SPARSE_ACCOUNTS_TREE_HEIGHT {
            default_nodes.push(default_node);
            default_node = field_hash_two(default_node, default_node);
        }
        default_nodes.push(default_node);
        default_nodes
    }

    fn compute_first_level_intermediary_nodes(&self, memory_tree_index: usize) -> Vec<([u8; 20], [Field; 4])> {
        let mut account_addresses: Vec<[u8; 20]> = Vec::new();
        self.accounts.iter().for_each(|(addr, _)| {
            if Self::address_memory_tree_leaf_index(*addr) == memory_tree_index {
                account_addresses.push(addr.clone());
            }
        });
        account_addresses.sort();
        account_addresses.par_iter().map(|address| {
            (*address, Self::hash_account(self.account(*address)))
        }).collect()
    }

    fn compute_intermediary_nodes(
        intermediary_nodes: &[([u8; 20], [Field; 4])], 
        default_node: [Field; 4],
    ) -> Vec<([u8; 20], [Field; 4])> {
        //arrange intermediary nodes into pairs (left, right)
        let mut intermediary_node_pairs: Vec<([u8; 20], (Option<usize>, Option<usize>))> = Vec::new();
        let mut i = 0;
        while i < intermediary_nodes.len() {
            let node = intermediary_nodes[i];
            let mut pair = (None, None);
            if (node.0[19] & 1) == 0 {
                pair.0 = Some(i);
                if (i + 1) < intermediary_nodes.len() {
                    let next_node = intermediary_nodes[i + 1];
                    if next_node.0 == address_add(node.0, 1) {
                        pair.1 = Some(i + 1);
                        i += 1; //skip the next node as it is part of the current pair
                    }
                }
            } else {
                pair.1 = Some(i);
            }
            intermediary_node_pairs.push((address_shr(node.0, 1), pair));
            i += 1;
        }

        //compute the next level intermediary nodes
        intermediary_node_pairs.par_iter().map(|(addr, (left, right))| {
            let left_sibling = match *left {
                Some(left) => intermediary_nodes[left].1,
                None => default_node,
            };
            let right_sibling = match *right {
                Some(right) => intermediary_nodes[right].1,
                None => default_node,
            };
            (*addr, (field_hash_two(left_sibling, right_sibling)))
        }).collect()
    }

    fn address_memory_tree_leaf_index(addr: [u8; 20]) -> usize {
        let top_u32 = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
        (top_u32 >> ((32 - VALIDATORS_TREE_HEIGHT) + SPARSE_ACCOUNTS_MEMORY_TREE_HEIGHT)) as usize
    }
}

pub fn initial_accounts_tree_root() -> [Field; 4] {
    let accounts = AccountsTree::default_accounts();

    //check that default account length matches what's been hardcoded
    let expected_length = 1048576;
    if accounts.len() != expected_length {
        log::warn!("initial_accounts_tree_root hardcoded value is no longer correct. Please update the code to avoid having to compute manually which can take a while.");
        return AccountsTree::new().root();
    }

    //check that the defaults accounts themselves match what's been hardcoded
    for i in 0..accounts.len() {
        let mut expected_address = [0u8; 20];
        expected_address[0..4].copy_from_slice(&((i as u32) << (32 - VALIDATORS_TREE_HEIGHT)).to_be_bytes());
        if accounts[i].address != expected_address {
            log::warn!("initial_accounts_tree_root hardcoded value is no longer correct. Please update the code to avoid having to compute manually which can take a while.");
            return AccountsTree::new().root();
        }
    }

    //return a hardcoded value to save time
    [
        Field::from_canonical_u64(11170973715345476166),
        Field::from_canonical_u64(2656591256015083907),
        Field::from_canonical_u64(7379642696541209614),
        Field::from_canonical_u64(13886610048497901282),
    ]
}

pub fn null_account_address(validator_index: usize) -> [u8; 20] {
    let validator_index_bytes = ((validator_index as u32) << (32 - VALIDATORS_TREE_HEIGHT)).to_be_bytes();
    let mut address = [0u8; 20];
    address[0..4].copy_from_slice(&validator_index_bytes);
    address
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
        for byte in addr.iter_mut() {
            let new_carry = *byte & ((1 << bit_shift) - 1);
            *byte = (*byte >> bit_shift) | (carry << (8 - bit_shift));
            carry = new_carry;
        }
    }
    addr
}

pub fn save_accounts(accounts_tree: &AccountsTree, path: &[&str], filename: &str) -> Result<()> {
    let bytes = accounts_tree.to_bytes()?;

    let mut path_buf = PathBuf::new();
    for &p in path {
        path_buf.push(p);
    }
    path_buf.push(filename);

    if let Some(parent) = path_buf.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&path_buf)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
}

pub fn load_accounts(path: &[&str], filename: &str) -> Result<AccountsTree> {
    let mut path_buf = PathBuf::new();
    for &p in path {
        path_buf.push(p);
    }
    path_buf.push(filename);

    let file = File::open(&path_buf)?;
    let mut reader = BufReader::with_capacity(32 * 1024, file);
    let mut bytes: Vec<u8> = Vec::new();
    reader.read_to_end(&mut bytes)?;

    Ok(AccountsTree::from_bytes(&bytes)?)
}
