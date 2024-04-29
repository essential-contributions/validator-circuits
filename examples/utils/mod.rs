use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::Hasher as Plonky2_Hasher;

use validator_circuits::{CommitmentReveal, Field, Validator, ValidatorCircuits, ValidatorSet, COMMITMENT_TREE_DEPTH, VALIDATORS_TREE_DEPTH};
use validator_circuits::Hash;


pub fn generate_validator_set(circuits: ValidatorCircuits) -> ValidatorSet {
    let validator_stake_default = 7;
    let validators: Vec<Validator> = (0..(1 << VALIDATORS_TREE_DEPTH)).map(|i| Validator {
        commitment_root: commitment_root(i),
        stake: validator_stake_default,
    }).collect();

    ValidatorSet::new(circuits, validators)
}

pub fn commitment_root(validator_index: usize) -> [Field; 4] {
    let secret = generate_secret_from_index(validator_index);
    let mut node = field_hash(&secret);
    for _ in 0..COMMITMENT_TREE_DEPTH {
        node = field_hash_two(node, node);
    }
    node
}

pub fn commitment_reveal(validator_index: usize, block_slot: usize) -> CommitmentReveal {
    let secret = generate_secret_from_index(validator_index);
    let mut node = field_hash(&secret);
    let mut proof: Vec<[Field; 4]> = vec![];
    for _ in 0..COMMITMENT_TREE_DEPTH {
        proof.push(node);
        node = field_hash_two(node, node);
    }

    CommitmentReveal {
        validator_index,
        block_slot,
        reveal: secret,
        proof,
    }
}

fn generate_secret_from_index(index: usize) -> [Field; 4] {
    [
        Plonky2_Field::from_canonical_usize(index),
        Plonky2_Field::from_canonical_usize(index),
        Plonky2_Field::from_canonical_usize(index),
        Plonky2_Field::from_canonical_usize(index),
    ]
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}
