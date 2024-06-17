use std::{fs::{create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf};

use plonky2::{field::{extension::quadratic::QuadraticExtension, goldilocks_field::GoldilocksField}, hash::poseidon::PoseidonHash, plonk::config::GenericConfig};
use poseidon_bn128::PoseidonBN128Hash;
use serde::Serialize;

use crate::circuits::{CIRCUIT_FILENAME, CIRCUIT_OUTPUT_FOLDER, COMMON_DATA_FILENAME, PROOF_FILENAME, VERIFIER_ONLY_DATA_FILENAME};

const WRAPPER_OUTPUT_FOLDER: &str = "groth16";

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

pub fn groth16_wrapper_circuit_data_exists(dir: &str) -> bool {
    file_exists(dir, CIRCUIT_FILENAME) && file_exists(dir, COMMON_DATA_FILENAME) && file_exists(dir, VERIFIER_ONLY_DATA_FILENAME)
}

pub fn groth16_wrapper_circuit_proof_exists(dir: &str) -> bool {
    file_exists(dir, PROOF_FILENAME)
}

#[inline]
fn write_to_dir(bytes: &Vec<u8>, dir: &str, filename: &str) -> io::Result<()> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(WRAPPER_OUTPUT_FOLDER);
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
    path.push(WRAPPER_OUTPUT_FOLDER);
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
    path.push(WRAPPER_OUTPUT_FOLDER);
    path.push(filename);
    path.exists()
}
