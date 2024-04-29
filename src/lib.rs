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

pub const VALIDATORS_TREE_DEPTH: usize = 17; //17 for 128k
pub const COMMITMENT_TREE_DEPTH: usize = 28; //28 for 102 years

pub const BATCH_SIZE: usize = 2048;//2048;
pub const AGGREGATOR_SIZE: usize = 64;//64;
