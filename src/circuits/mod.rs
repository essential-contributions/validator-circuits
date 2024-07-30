pub mod validators_state_circuit;
pub mod participation_state_circuit;
pub mod attestations_aggregator_circuit;
pub mod validator_participation_circuit;
mod utils;

use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use std::{fs::{self, create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf};
use std::str;
use anyhow::{anyhow, Result};

use crate::{Config, Field, D};
use utils::*;

pub const CIRCUIT_OUTPUT_FOLDER: &str = "circuits";
pub const CIRCUIT_FILENAME: &str = "circuit.bin";
pub const COMMON_DATA_FILENAME: &str = "common_circuit_data.json";
pub const VERIFIER_ONLY_DATA_FILENAME: &str = "verifier_only_circuit_data.json";
pub const PROOF_FILENAME: &str = "proof_with_public_inputs.json";

pub const VALIDATORS_STATE_CIRCUIT_DIR: &str = "validators_state";
pub const PARTICIPATION_STATE_CIRCUIT_DIR: &str = "participation_state";
pub const VALIDATOR_PARTICIPATION_CIRCUIT_DIR: &str = "validator_participation";
pub const ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR: &str = "attestations_aggregator";

pub trait Circuit {
    type Data;
    type Proof: Proof;

    fn new() -> Self;
    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof>;
    fn verify_proof(&self, proof: &Self::Proof) -> Result<()>;
    fn circuit_data(&self) -> &CircuitData<Field, Config, D>;

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
        let bytes = read_from_dir(dir, CIRCUIT_FILENAME);
        match bytes {
            Ok(bytes) => {
                let circuit = C::from_bytes(&bytes);
                match circuit {
                    Ok(circuit) => {
                        log::info!("Loaded circuit [/{}]", dir);
                        return circuit;
                    },
                    Err(e) => {
                        log::error!("Failed to deserialize circuit data [/{}]", dir);
                        log::error!("{}", e);
                    },
                }
            },
            Err(e) => {
                log::error!("Failed to read circuit data [/{}]", dir);
                log::error!("{}", e);
            },
        };
    }
    let circuit = C::new();
    save_circuit(&circuit, dir);
    circuit
}

pub fn load_or_create_example_proof<C>(circuit: &C, dir: &str) -> ProofWithPublicInputs<Field, Config, D> 
where
    C: Circuit,
{
    if circuit_proof_exists(dir) {
        match load_proof(dir) {
            Ok(proof) => {
                log::info!("Loaded proof [/{}]", dir);
                return proof;
            },
            Err(e) => log::error!("{}", e),
        };
    }
    let proof = circuit.wrappable_example_proof().expect("Circuit is not wrappable");
    save_proof(&proof.proof().clone(), dir);
    proof.proof().clone()
}

pub fn save_circuit<C>(circuit: &C, dir: &str) 
where
    C: Circuit + Serializeable,
{
    let circuit_bytes = circuit.to_bytes();
    match circuit_bytes {
        Ok(bytes) => {
            match write_to_dir(&bytes, dir, CIRCUIT_FILENAME) {
                Ok(_) => log::info!("Saved raw circuit binary [/{}]", dir),
                Err(e) => {
                    log::error!("Failed to save circuit [/{}]", dir);
                    log::error!("{}", e);
                },
            }
        },
        Err(e) => {
            log::error!("Failed to serialize raw binary [/{}]", dir);
            log::error!("{}", e);
        },
    }

    let circuit = circuit.circuit_data();

    let common_circuit_data_serialized = serde_json::to_string(&circuit.common);
    match common_circuit_data_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            match write_to_dir(&bytes, dir, COMMON_DATA_FILENAME) {
                Ok(_) => log::info!("Saved common data [/{}]", dir),
                Err(e) => {
                    log::error!("Failed to save common data [/{}]", dir);
                    log::error!("{}", e);
                },
            }
        },
        Err(e) => {
            log::error!("Failed to serialize common data [/{}]", dir);
            log::error!("{}", e);
        },
    }

    let verifier_only_circuit_data_serialized  = serde_json::to_string(&circuit.verifier_only);
    match verifier_only_circuit_data_serialized  {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            match write_to_dir(&bytes, dir, VERIFIER_ONLY_DATA_FILENAME) {
                Ok(_) => log::info!("Saved verifier only data [/{}]", dir),
                Err(e) => {
                    log::error!("Failed to save verifier only data [/{}]", dir);
                    log::error!("{}", e);
                },
            }
        },
        Err(e) => {
            log::error!("Failed to serialize verifier only data [/{}]", dir);
            log::error!("{}", e);
        },
    }
}

pub fn save_proof(proof: &ProofWithPublicInputs<Field, Config, D>, dir: &str) {
    let proof_serialized = serde_json::to_string(proof);
    match proof_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            match write_to_dir(&bytes, dir, PROOF_FILENAME) {
                Ok(_) => log::info!("Saved proof [/{}]", dir),
                Err(e) => {
                    log::error!("Failed to save proof [/{}]", dir);
                    log::error!("{}", e);
                },
            }
        },
        Err(e) => {
            log::error!("Failed to serialize proof [/{}]", dir);
            log::error!("{}", e);
        },
    }
}

pub fn load_proof(dir: &str) -> Result<ProofWithPublicInputs<Field, Config, D>> {
    match read_from_dir(dir, PROOF_FILENAME) {
        Ok(bytes) => {
            match std::str::from_utf8(&bytes) {
                Ok(serialized_str) => {
                    let proof: Result<ProofWithPublicInputs<Field, Config, D>, serde_json::Error> = serde_json::from_str(serialized_str);
                    match proof {
                        Ok(proof) => Ok(proof),
                        Err(_) => {
                            log::error!("Failed to deserialize proof [/{}]", dir);
                            Err(anyhow!("Failed to deserialize proof [/{}]", dir))
                        },
                    }
                },
                Err(_) => {
                    log::error!("Failed to deserialize proof [/{}]", dir);
                    Err(anyhow!("Failed to deserialize proof [/{}]", dir))
                },
            }
        },
        Err(_) => {
            log::error!("Failed to load proof bytes [/{}]", dir);
            Err(anyhow!("Failed to load proof bytes [/{}]", dir))
        },
    }
}

pub fn circuit_data_exists(dir: &str) -> bool {
    file_exists(dir, CIRCUIT_FILENAME) && file_exists(dir, COMMON_DATA_FILENAME) && file_exists(dir, VERIFIER_ONLY_DATA_FILENAME)
}

pub fn circuit_proof_exists(dir: &str) -> bool {
    file_exists(dir, PROOF_FILENAME)
}

pub fn clear_data_and_proof(dir: &str) {
    delete_file(dir, CIRCUIT_FILENAME);
    delete_file(dir, COMMON_DATA_FILENAME);
    delete_file(dir, VERIFIER_ONLY_DATA_FILENAME);
    delete_file(dir, PROOF_FILENAME);
}

#[inline]
fn write_to_dir(bytes: &Vec<u8>, dir: &str, filename: &str) -> io::Result<()> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(filename);

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&path)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
}

#[inline]
fn read_from_dir(dir: &str, filename: &str) -> io::Result<Vec<u8>> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(filename);

    let file = File::open(&path)?;
    let mut reader = BufReader::with_capacity(134217728, file);
    let mut buffer: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)
}

#[inline]
fn file_exists(dir: &str, filename: &str) -> bool {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(filename);
    path.exists()
}

#[inline]
fn delete_file(dir: &str, filename: &str) {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(filename);
    match fs::remove_file(path.clone()) {
        Ok(_) => log::info!("File '{}' deleted.", path.display()),
        Err(e) => log::error!("Failed to delete file '{}': {}", path.display(), e),
    }
}
