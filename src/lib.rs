pub mod circuits;
pub mod bn128_wrapper;
pub mod groth16_wrapper;
pub mod validators;
pub mod accounts;
pub mod participation;
pub mod commitment;

use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::PoseidonGoldilocksConfig};

pub const D: usize = 2;
pub type Field = GoldilocksField;
pub type Hash = PoseidonHash;
pub type Config = PoseidonGoldilocksConfig;

pub const VALIDATORS_TREE_HEIGHT: usize = 20; //1048576
pub const VALIDATOR_COMMITMENT_TREE_HEIGHT: usize = 28; //102 years
pub const PARTICIPATION_ROUNDS_TREE_HEIGHT: usize = 21; //102 years
pub const PARTICIPATION_ROUNDS_PER_STATE_EPOCH: usize = 64;
pub const AGGREGATION_PASS1_SIZE: usize = 1024;
pub const AGGREGATION_PASS2_SIZE: usize = 32;
pub const AGGREGATION_PASS3_SIZE: usize = 32;

pub const MAX_VALIDATORS: usize = AGGREGATION_PASS1_SIZE * AGGREGATION_PASS2_SIZE * AGGREGATION_PASS3_SIZE;
pub const AGGREGATION_PASS1_SUB_TREE_HEIGHT: usize = sqrt_usize(AGGREGATION_PASS1_SIZE);
pub const AGGREGATION_PASS2_SUB_TREE_HEIGHT: usize = sqrt_usize(AGGREGATION_PASS2_SIZE);
pub const AGGREGATION_PASS3_SUB_TREE_HEIGHT: usize = sqrt_usize(AGGREGATION_PASS3_SIZE);

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
