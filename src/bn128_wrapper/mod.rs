mod serialization;
mod wrapper_circuit;

use std::{fs::{self, create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf};

pub use wrapper_circuit::*;

use plonky2::{field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField}, hash::poseidon::PoseidonHash, plonk::{circuit_data::CircuitData, config::GenericConfig, proof::ProofWithPublicInputs}};
use poseidon_bn128::PoseidonBN128Hash;
use serde::Serialize;

use crate::{circuits::{CIRCUIT_FILENAME, CIRCUIT_OUTPUT_FOLDER, COMMON_DATA_FILENAME, PROOF_FILENAME, VERIFIER_ONLY_DATA_FILENAME}, Config, Field, D};

pub const BN128_WRAPPER_OUTPUT_FOLDER: &str = "bn128";

/// Configuration using Poseidon BN128 over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonBN128GoldilocksConfig;
impl GenericConfig<2> for PoseidonBN128GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonBN128Hash;
    type InnerHasher = PoseidonHash;
}

pub fn load_or_create_bn128_wrapper_circuit(inner_circuit: &CircuitData<Field, Config, D>, dir: &str) -> BN128WrapperCircuit {
    if bn128_wrapper_circuit_data_exists(dir) {
        let bytes = read_from_dir(dir, CIRCUIT_FILENAME);
        match bytes {
            Ok(bytes) => {
                let circuit = BN128WrapperCircuit::from_bytes(&bytes);
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
    let circuit = BN128WrapperCircuit::new(inner_circuit);
    save_bn128_wrapper_circuit(&circuit, dir);
    circuit
}

pub fn save_bn128_wrapper_circuit(circuit: &BN128WrapperCircuit, dir: &str) {
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

pub fn save_bn128_wrapper_proof(proof: &ProofWithPublicInputs<Field, PoseidonBN128GoldilocksConfig, D>, dir: &str) {
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

pub fn bn128_wrapper_circuit_data_exists(dir: &str) -> bool {
    file_exists(dir, CIRCUIT_FILENAME) && file_exists(dir, COMMON_DATA_FILENAME) && file_exists(dir, VERIFIER_ONLY_DATA_FILENAME)
}

pub fn bn128_wrapper_circuit_proof_exists(dir: &str) -> bool {
    file_exists(dir, PROOF_FILENAME)
}

pub fn bn128_wrapper_clear_data_and_proof(dir: &str) {
    delete_file(dir, CIRCUIT_FILENAME);
    delete_file(dir, COMMON_DATA_FILENAME);
    delete_file(dir, VERIFIER_ONLY_DATA_FILENAME);
    delete_file(dir, PROOF_FILENAME);
}

#[inline]
fn write_to_dir(bytes: &Vec<u8>, dir: &str, filename: &str) -> io::Result<()> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(BN128_WRAPPER_OUTPUT_FOLDER);
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
    path.push(BN128_WRAPPER_OUTPUT_FOLDER);
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
    path.push(BN128_WRAPPER_OUTPUT_FOLDER);
    path.push(filename);
    path.exists()
}

#[inline]
fn delete_file(dir: &str, filename: &str) {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(BN128_WRAPPER_OUTPUT_FOLDER);
    path.push(filename);
    match fs::remove_file(path.clone()) {
        Ok(_) => log::info!("File '{}' deleted.", path.display()),
        Err(e) => log::error!("Failed to delete file '{}': {}", path.display(), e),
    }
}
