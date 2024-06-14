use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::config::Hasher as Plonky2_Hasher;
use rayon::prelude::*;

use validator_circuits::{ValidatorCommitmentReveal, Field, Validator, ValidatorCircuits, ValidatorSet, VALIDATOR_COMMITMENT_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT};
use validator_circuits::Hash;

pub const COMMITMENTS_REPEAT: usize = 2000;

pub fn generate_validator_set(circuits: ValidatorCircuits) -> ValidatorSet {
    let commitment_roots: Vec<[Field; 4]> = (0..COMMITMENTS_REPEAT).into_par_iter().map(|i| commitment_root(i)).collect();
    let validator_stake_default = 7;
    let validators: Vec<Validator> = (0..(1 << VALIDATORS_TREE_HEIGHT)).map(|i| Validator {
        commitment_root: commitment_roots[i % COMMITMENTS_REPEAT],
        stake: validator_stake_default,
    }).collect();

    ValidatorSet::new(circuits, validators)
}

pub fn commitment_root(validator_index: usize) -> [Field; 4] {
    let secret = generate_secret_from_index(validator_index);
    let mut node = field_hash(&secret);
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        node = field_hash_two(node, node);
    }
    node
}

pub fn commitment_reveal(validator_index: usize, block_slot: usize) -> ValidatorCommitmentReveal {
    let secret = generate_secret_from_index(validator_index);
    let mut node = field_hash(&secret);
    let mut proof: Vec<[Field; 4]> = vec![];
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        proof.push(node);
        node = field_hash_two(node, node);
    }

    ValidatorCommitmentReveal {
        validator_index,
        block_slot,
        reveal: secret,
        proof,
    }
}

fn generate_secret_from_index(index: usize) -> [Field; 4] {
    let index = index % COMMITMENTS_REPEAT;
    [
        Plonky2_Field::from_canonical_usize(index + 10),
        Plonky2_Field::from_canonical_usize(index + 11),
        Plonky2_Field::from_canonical_usize(index + 12),
        Plonky2_Field::from_canonical_usize(index + 13),
    ]
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}
