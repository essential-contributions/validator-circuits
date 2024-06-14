mod wrapper_circuit;

pub use wrapper_circuit::*;

use plonky2::{field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField}, hash::poseidon::PoseidonHash, plonk::config::GenericConfig};
use poseidon_bn128::PoseidonBN128Hash;
use serde::Serialize;

/// Configuration using Poseidon BN128 over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonBN128GoldilocksConfig;
impl GenericConfig<2> for PoseidonBN128GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonBN128Hash;
    type InnerHasher = PoseidonHash;
}
