pub mod circuits;
pub mod bn128_wrapper;
pub mod groth16_wrapper;
pub mod validators;
pub mod accounts;
pub mod participation;
pub mod commitment;

use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::PoseidonGoldilocksConfig};

pub const D: usize = 2;
pub type Field = GoldilocksField;
pub type Hash = PoseidonHash;
pub type Config = PoseidonGoldilocksConfig;

pub const VALIDATORS_TREE_HEIGHT: usize = 20; //1048576
pub const VALIDATOR_COMMITMENT_TREE_HEIGHT: usize = 28; //102 years
pub const PARTICIPATION_ROUNDS_TREE_HEIGHT: usize = 21; //102 years
pub const ACCOUNTS_TREE_HEIGHT: usize = 160;
pub const PARTICIPATION_ROUNDS_PER_STATE_EPOCH: usize = 64;
pub const AGGREGATION_PASS1_SIZE: usize = 1024;
pub const AGGREGATION_PASS2_SIZE: usize = 32;
pub const AGGREGATION_PASS3_SIZE: usize = 32;

pub const MAX_VALIDATORS: usize = AGGREGATION_PASS1_SIZE * AGGREGATION_PASS2_SIZE * AGGREGATION_PASS3_SIZE;
pub const AGGREGATION_PASS1_SUB_TREE_HEIGHT: usize = sqrt_usize(AGGREGATION_PASS1_SIZE);
pub const AGGREGATION_PASS2_SUB_TREE_HEIGHT: usize = sqrt_usize(AGGREGATION_PASS2_SIZE);
pub const AGGREGATION_PASS3_SUB_TREE_HEIGHT: usize = sqrt_usize(AGGREGATION_PASS3_SIZE);

pub fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

pub fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}

pub fn bytes_to_fields(bytes: &[u8]) -> [Field; 4] {
    let mut chunk0: [u8; 8] = [0u8; 8];
    chunk0.copy_from_slice(&bytes[0..8]);
    let mut chunk1: [u8; 8] = [0u8; 8];
    chunk1.copy_from_slice(&bytes[8..16]);
    let mut chunk2: [u8; 8] = [0u8; 8];
    chunk2.copy_from_slice(&bytes[16..24]);
    let mut chunk3: [u8; 8] = [0u8; 8];
    chunk3.copy_from_slice(&bytes[24..32]);
    
    [
        Field::from_canonical_u64(u64::from_be_bytes(chunk0)),
        Field::from_canonical_u64(u64::from_be_bytes(chunk1)),
        Field::from_canonical_u64(u64::from_be_bytes(chunk2)),
        Field::from_canonical_u64(u64::from_be_bytes(chunk3)),
    ]
}

pub fn fields_to_bytes(fields: &[Field; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fields[0].0.to_be_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[i] = *b;
    });
    fields[1].0.to_be_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[8 + i] = *b;
    });
    fields[2].0.to_be_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[16 + i] = *b;
    });
    fields[3].0.to_be_bytes().iter().enumerate().for_each(|(i, b)| {
        bytes[24 + i] = *b;
    });

    bytes
}

const fn sqrt_usize(x: usize) -> usize {
    if x == 0 {
        return 0;
    }

    let mut guess = 1;
    while (2 as u64).pow(guess) < (x as u64) && guess < (x / 2) as u32 {
        guess += 1;
    }
    guess as usize
}
