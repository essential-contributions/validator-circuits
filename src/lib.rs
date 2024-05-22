mod circuits;
mod prover;
mod commitment;

pub use prover::*;
pub use circuits::*;
pub use commitment::*;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::PoseidonGoldilocksConfig};

pub const D: usize = 2;
pub type Field = GoldilocksField;
pub type Hash = PoseidonHash;
pub type Config = PoseidonGoldilocksConfig;

pub const VALIDATORS_TREE_HEIGHT: usize = 20; //1048576
pub const VALIDATOR_COMMITMENT_TREE_HEIGHT: usize = 28; //102 years
pub const AGGREGATION_PASS1_SIZE: usize = 1024;
pub const AGGREGATION_PASS2_SIZE: usize = 32;
pub const AGGREGATION_PASS3_SIZE: usize = 32;

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
