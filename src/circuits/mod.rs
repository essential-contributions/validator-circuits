pub mod validators_state_circuit;
pub mod participation_state_circuit;
pub mod attestation_aggregation_circuit;
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
pub const ATTESTATION_AGGREGATION_CIRCUIT_DIR: &str = "attestation_aggregation";

pub trait Circuit {
    type Proof: Proof;

    fn new() -> Self;
    fn verify_proof(&self, proof: &Self::Proof) -> Result<()>;
    fn circuit_data(&self) -> &CircuitData<Field, Config, D>;

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>>;
    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof>;

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
        let bytes = read_file(&[CIRCUIT_OUTPUT_FOLDER, dir], CIRCUIT_FILENAME);
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

pub fn save_circuit<C>(circuit: &C, dir: &str) 
where
    C: Circuit + Serializeable,
{
    let circuit_bytes = circuit.to_bytes();
    match circuit_bytes {
        Ok(bytes) => {
            match write_file(&bytes, &[CIRCUIT_OUTPUT_FOLDER, dir], CIRCUIT_FILENAME) {
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
            match write_file(&bytes, &[CIRCUIT_OUTPUT_FOLDER, dir], COMMON_DATA_FILENAME) {
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
            match write_file(&bytes, &[CIRCUIT_OUTPUT_FOLDER, dir], VERIFIER_ONLY_DATA_FILENAME) {
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

pub fn save_proof<C: Circuit>(circuit: &C, proof: &C::Proof, path: &[&str], filename: &str) -> Result<()> {
    let bytes = circuit.proof_to_bytes(proof)?;
    match write_file(&bytes, path, filename) {
        Ok(_) => {
            log::info!("Saved proof [/{}/{}]", path.join("/"), filename);
            Ok(())
        },
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub fn load_proof<C: Circuit>(circuit: &C, path: &[&str], filename: &str) -> Result<C::Proof> {
    match read_file(path, filename) {
        Ok(bytes) => {
            let proof = circuit.proof_from_bytes(bytes)?;
            Ok(proof)
        },
        Err(e) => Err(anyhow!("{}", e)),
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
fn write_file(bytes: &[u8], path: &[&str], filename: &str) -> io::Result<()> {
    let mut path_buf = PathBuf::new();
    for &p in path {
        path_buf.push(p);
    }
    path_buf.push(filename);

    if let Some(parent) = path_buf.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&path_buf)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
}

#[inline]
fn read_file(path: &[&str], filename: &str) -> io::Result<Vec<u8>> {
    let mut path_buf = PathBuf::new();
    for &p in path {
        path_buf.push(p);
    }
    path_buf.push(filename);

    let file = File::open(&path_buf)?;
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
