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
/*
pub fn save_wrapped_proof(proof: &ProofWithPublicInputs<Field, ConfigBN128, D>, dir: &str) {
    let proof_serialized = serde_json::to_string(proof);
    match proof_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            if write_to_dir(&bytes, dir, WRAPPED_PROOF_FILENAME).is_err() {
                println!("Failed to write proof file: {}", dir);
            }
        },
        Err(e) => println!("Failed to serialize proof for {}: {}", dir, e),
    }
}

pub fn load_wrapped_proof(dir: &str) -> Result<ProofWithPublicInputs<Field, ConfigBN128, D>> {
    let bytes = read_from_dir(dir, WRAPPED_PROOF_FILENAME)?;
    let json_str = str::from_utf8(&bytes)?;
    let deserialized: ProofWithPublicInputs<Field, ConfigBN128, D> = serde_json::from_str(&json_str)?;
     
    Ok(deserialized)
}
*/