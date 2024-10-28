pub mod attestation_aggregation_circuit;
pub mod participation_state_circuit;
mod utils;
pub mod validator_participation_circuit;
pub mod validators_state_circuit;
pub mod wrappers;

use anyhow::{anyhow, Result};
use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use std::str;

use crate::{delete_file, file_exists, load_from_file, save_to_file, Config, Field, D};
use utils::*;

pub const CIRCUIT_OUTPUT_FOLDER: &str = "circuits";
pub const CIRCUIT_FILENAME: &str = "circuit.bin";
pub const COMMON_DATA_FILENAME: &str = "common_circuit_data.json";
pub const VERIFIER_ONLY_DATA_FILENAME: &str = "verifier_only_circuit_data.json";
pub const PROOF_FILENAME: &str = "proof_with_public_inputs.json";
const INIT_PROOF_FILENAME: &str = "initial.proof";

pub const VALIDATORS_STATE_CIRCUIT_DIR: &str = "validators_state";
pub const PARTICIPATION_STATE_CIRCUIT_DIR: &str = "participation_state";
pub const VALIDATOR_PARTICIPATION_CIRCUIT_DIR: &str = "validator_participation";
pub const ATTESTATION_AGGREGATION_CIRCUIT_DIR: &str = "attestation_aggregation";

pub trait Circuit {
    type Proof: Proof;

    fn new() -> Self;
    fn verify_proof(&self, proof: &Self::Proof) -> Result<()>;
    fn circuit_data(&self) -> &CircuitData<Field, Config, D>;

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>>;
    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof>;

    fn is_cyclical() -> bool;
    fn cyclical_init_proof(&self) -> Option<Self::Proof>;

    fn is_wrappable() -> bool;
    fn wrappable_example_proof(&self) -> Option<Self::Proof>;
}

pub trait Serializeable {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self>
    where
        Self: Sized;
}

pub trait Proof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D>;
}

pub fn load_or_create_circuit<C>(dir: &str) -> C
where
    C: Circuit + Serializeable,
{
    if circuit_data_exists(dir) {
        let bytes = load_from_file(&[CIRCUIT_OUTPUT_FOLDER, dir], CIRCUIT_FILENAME);
        match bytes {
            Ok(bytes) => {
                let circuit = C::from_bytes(&bytes);
                match circuit {
                    Ok(circuit) => {
                        log::info!("Loaded circuit [/{}]", dir);
                        return circuit;
                    }
                    Err(e) => {
                        log::error!("Failed to deserialize circuit data [/{}]", dir);
                        log::error!("{}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to read circuit data [/{}]", dir);
                log::error!("{}", e);
            }
        };
    }
    let circuit = C::new();
    save_circuit(&circuit, dir);
    circuit
}

pub fn load_or_create_init_proof<C>(dir: &str) -> C::Proof
where
    C: Circuit + Serializeable,
{
    assert!(C::is_cyclical(), "Circuit is not cyclical (no initial proof).");
    let circuit = load_or_create_circuit::<C>(dir);
    if circuit_init_proof_exists(dir) {
        match load_proof(&circuit, &[CIRCUIT_OUTPUT_FOLDER, dir], INIT_PROOF_FILENAME) {
            Ok(proof) => {
                log::info!("Loaded proof [/{}]", dir);
                return proof;
            }
            Err(e) => {
                log::error!("Failed to deserialize proof data [/{}]", dir);
                log::error!("{}", e);
            }
        }
    }
    let proof = circuit.cyclical_init_proof().unwrap();
    if save_proof(&circuit, &proof, &[CIRCUIT_OUTPUT_FOLDER, dir], INIT_PROOF_FILENAME).is_err() {
        log::warn!("Failed to save init proof [/{}]", dir);
    }
    proof
}

pub fn save_circuit<C>(circuit: &C, dir: &str)
where
    C: Circuit + Serializeable,
{
    let circuit_bytes = circuit.to_bytes();
    match circuit_bytes {
        Ok(bytes) => match save_to_file(&bytes, &[CIRCUIT_OUTPUT_FOLDER, dir], CIRCUIT_FILENAME) {
            Ok(_) => log::info!("Saved raw circuit binary [/{}]", dir),
            Err(e) => {
                log::error!("Failed to save circuit [/{}]", dir);
                log::error!("{}", e);
            }
        },
        Err(e) => {
            log::error!("Failed to serialize raw binary [/{}]", dir);
            log::error!("{}", e);
        }
    }

    let circuit = circuit.circuit_data();

    let common_circuit_data_serialized = serde_json::to_string(&circuit.common);
    match common_circuit_data_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            match save_to_file(&bytes, &[CIRCUIT_OUTPUT_FOLDER, dir], COMMON_DATA_FILENAME) {
                Ok(_) => log::info!("Saved common data [/{}]", dir),
                Err(e) => {
                    log::error!("Failed to save common data [/{}]", dir);
                    log::error!("{}", e);
                }
            }
        }
        Err(e) => {
            log::error!("Failed to serialize common data [/{}]", dir);
            log::error!("{}", e);
        }
    }

    let verifier_only_circuit_data_serialized = serde_json::to_string(&circuit.verifier_only);
    match verifier_only_circuit_data_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            match save_to_file(&bytes, &[CIRCUIT_OUTPUT_FOLDER, dir], VERIFIER_ONLY_DATA_FILENAME) {
                Ok(_) => log::info!("Saved verifier only data [/{}]", dir),
                Err(e) => {
                    log::error!("Failed to save verifier only data [/{}]", dir);
                    log::error!("{}", e);
                }
            }
        }
        Err(e) => {
            log::error!("Failed to serialize verifier only data [/{}]", dir);
            log::error!("{}", e);
        }
    }
}

pub fn save_proof<C: Circuit>(circuit: &C, proof: &C::Proof, path: &[&str], filename: &str) -> Result<()> {
    let bytes = circuit.proof_to_bytes(proof)?;
    match save_to_file(&bytes, path, filename) {
        Ok(_) => {
            log::info!("Saved proof [/{}/{}]", path.join("/"), filename);
            Ok(())
        }
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub fn load_proof<C: Circuit>(circuit: &C, path: &[&str], filename: &str) -> Result<C::Proof> {
    match load_from_file(path, filename) {
        Ok(bytes) => {
            let proof = circuit.proof_from_bytes(bytes)?;
            Ok(proof)
        }
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub fn circuit_data_exists(dir: &str) -> bool {
    file_exists(&[CIRCUIT_OUTPUT_FOLDER, dir], CIRCUIT_FILENAME)
        && file_exists(&[CIRCUIT_OUTPUT_FOLDER, dir], COMMON_DATA_FILENAME)
        && file_exists(&[CIRCUIT_OUTPUT_FOLDER, dir], VERIFIER_ONLY_DATA_FILENAME)
}

pub fn circuit_init_proof_exists(dir: &str) -> bool {
    file_exists(&[CIRCUIT_OUTPUT_FOLDER, dir], INIT_PROOF_FILENAME)
}

pub fn clear_data_and_proof(dir: &str) {
    delete_file(&[CIRCUIT_OUTPUT_FOLDER, dir], CIRCUIT_FILENAME);
    delete_file(&[CIRCUIT_OUTPUT_FOLDER, dir], COMMON_DATA_FILENAME);
    delete_file(&[CIRCUIT_OUTPUT_FOLDER, dir], VERIFIER_ONLY_DATA_FILENAME);
    delete_file(&[CIRCUIT_OUTPUT_FOLDER, dir], INIT_PROOF_FILENAME);
}
