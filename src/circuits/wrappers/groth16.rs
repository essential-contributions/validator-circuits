mod go;

use anyhow::{anyhow, Result};
use go::{go_build, verify_go};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    process::Command,
};

use crate::circuits::CIRCUIT_OUTPUT_FOLDER;

use super::{bn128_wrapper_circuit_data_exists, bn128_wrapper_circuit_proof_exists, BN128_WRAPPER_OUTPUT_FOLDER};

pub const GROTH16_WRAPPER_OUTPUT_FOLDER: &str = "groth16";
const WRAPPER_GO_PROJECT_PATH: &str = "./groth16-wrapper";
const WRAPPER_GO_PROJECT_BINARY: &str = "groth16-wrapper";

const GROTH16_CIRCUIT_FILENAME: &str = "circuit.bin";
const GROTH16_VERIFYING_KEY_FILENAME: &str = "verifying.key";
const GROTH16_PROVING_KEY_FILENAME: &str = "proving.key";
const GROTH16_SOLIDITY_VERIFIER_FILENAME: &str = "Verifier.sol";
const GROTH16_PROOF_FILENAME: &str = "proof.json";

pub fn create_groth16_wrapper_circuit(dir: &str) {
    if verify_binary() {
        //make sure bn128 wrapper exists
        if bn128_wrapper_circuit_data_exists(dir) && bn128_wrapper_circuit_proof_exists(dir) {
            //run the binary to build circuit and test proof
            let binary_path = format!("{}/{}", WRAPPER_GO_PROJECT_PATH, WRAPPER_GO_PROJECT_BINARY);
            let input_arg = format!(
                "--in=./{}/{}/{}",
                CIRCUIT_OUTPUT_FOLDER, dir, BN128_WRAPPER_OUTPUT_FOLDER
            );
            let output_arg = format!(
                "--out=./{}/{}/{}",
                CIRCUIT_OUTPUT_FOLDER, dir, GROTH16_WRAPPER_OUTPUT_FOLDER
            );
            match Command::new(Path::new(&binary_path))
                .args(&[input_arg, output_arg])
                .output()
            {
                Ok(output) if output.status.success() => {
                    log::info!("Successfully created groth16 wrapper circuit [/{}]", dir);
                }
                Ok(output) => {
                    log::error!("Running Go binary failed: {}", String::from_utf8_lossy(&output.stderr));
                }
                Err(e) => {
                    log::error!("Failed to run Go binary: {}", e);
                }
            }
        } else {
            log::error!("Cannot create groth16 wrapper circuit without bn128 wrapper ciruit");
        }
    }
}

pub fn generate_groth16_wrapper_proof(dir: &str) -> Result<[[u8; 32]; 13]> {
    // make sure bn128 exists
    if !bn128_wrapper_circuit_data_exists(dir) {
        return Err(anyhow!(
            "Cannot generate groth16 wrapped proof until circuits are built"
        ));
    }
    if !bn128_wrapper_circuit_proof_exists(dir) {
        return Err(anyhow!("Proof must be wrapped to bn128 first"));
    }

    // wrap groth16
    if verify_binary() {
        let binary_path = format!("{}/{}", WRAPPER_GO_PROJECT_PATH, WRAPPER_GO_PROJECT_BINARY);
        let input_arg = format!(
            "--in=./{}/{}/{}",
            CIRCUIT_OUTPUT_FOLDER, dir, BN128_WRAPPER_OUTPUT_FOLDER
        );
        let output_arg = format!(
            "--out=./{}/{}/{}",
            CIRCUIT_OUTPUT_FOLDER, dir, GROTH16_WRAPPER_OUTPUT_FOLDER
        );
        match Command::new(Path::new(&binary_path))
            .args(&[input_arg, output_arg])
            .output()
        {
            Ok(output) if output.status.success() => {
                log::info!("Successfully created groth16 proof [/{}]", dir);
            }
            Ok(output) => {
                return Err(anyhow!(
                    "Running Go binary failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
            Err(e) => return Err(anyhow!("Failed to run Go binary: {}", e)),
        }
    } else {
        return Err(anyhow!("Failed to build Go binary"));
    }

    // return json
    match read_from_dir(dir, GROTH16_PROOF_FILENAME) {
        Ok(json_bytes) => {
            let json_str = String::from_utf8_lossy(&json_bytes).to_string();
            Ok(proof_data_from_json(json_str))
        }
        Err(e) => Err(anyhow!("Failed to read proof output: {}", e)),
    }
}

fn verify_binary() -> bool {
    //check if binaries have been built
    if !binary_exists() {
        //check that Go is installed at at minimum spec
        if !verify_go() {
            return false;
        }

        //compile the binaries
        if !go_build(WRAPPER_GO_PROJECT_PATH) {
            return false;
        }
    }
    true
}

pub fn groth16_wrapper_circuit_data_exists(dir: &str) -> bool {
    file_exists(dir, GROTH16_CIRCUIT_FILENAME)
        && file_exists(dir, GROTH16_VERIFYING_KEY_FILENAME)
        && file_exists(dir, GROTH16_PROVING_KEY_FILENAME)
        && file_exists(dir, GROTH16_SOLIDITY_VERIFIER_FILENAME)
}

pub fn groth16_wrapper_circuit_proof_exists(dir: &str) -> bool {
    file_exists(dir, GROTH16_PROOF_FILENAME)
}

pub fn groth16_wrapper_clear_data_and_proof(dir: &str) {
    delete_file(dir, GROTH16_CIRCUIT_FILENAME);
    delete_file(dir, GROTH16_VERIFYING_KEY_FILENAME);
    delete_file(dir, GROTH16_PROVING_KEY_FILENAME);
    delete_file(dir, GROTH16_SOLIDITY_VERIFIER_FILENAME);
    delete_file(dir, GROTH16_PROOF_FILENAME);
}

#[inline]
fn file_exists(dir: &str, filename: &str) -> bool {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(GROTH16_WRAPPER_OUTPUT_FOLDER);
    path.push(filename);
    path.exists()
}

#[inline]
fn binary_exists() -> bool {
    let mut path = PathBuf::from(WRAPPER_GO_PROJECT_PATH);
    path.push(WRAPPER_GO_PROJECT_BINARY);
    path.exists()
}

#[inline]
fn delete_file(dir: &str, filename: &str) {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(GROTH16_WRAPPER_OUTPUT_FOLDER);
    path.push(filename);
    match fs::remove_file(path.clone()) {
        Ok(_) => log::info!("File '{}' deleted.", path.display()),
        Err(e) => log::error!("Failed to delete file '{}': {}", path.display(), e),
    }
}

#[inline]
fn read_from_dir(dir: &str, filename: &str) -> io::Result<Vec<u8>> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(GROTH16_WRAPPER_OUTPUT_FOLDER);
    path.push(filename);

    let file = File::open(&path)?;
    let mut reader = BufReader::with_capacity(134217728, file);
    let mut buffer: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn proof_data_from_json(json_str: String) -> [[u8; 32]; 13] {
    let mut proof_data = [[0u8; 32]; 13];

    //get json elements
    let v: Value = serde_json::from_str(&json_str).expect("JSON was not well-formatted");
    let proof_array = v["proof"].as_array().expect("Expected an array for 'proof'");
    let commitments_array = v["commitments"]
        .as_array()
        .expect("Expected an array for 'commitments'");
    let commitments_pok_array = v["commitmentPok"]
        .as_array()
        .expect("Expected an array for 'commitmentPok'");
    let input_array = v["input"].as_array().expect("Expected an array for 'input'");

    //add proof data
    for (i, data) in proof_array.iter().enumerate() {
        let hex_str = data.as_str().unwrap().to_string();
        proof_data[i] = hex_string_to_u8_array(hex_str);
    }

    //add commitments data
    for (i, data) in commitments_array.iter().enumerate() {
        let hex_str = data.as_str().unwrap().to_string();
        proof_data[8 + i] = hex_string_to_u8_array(hex_str);
    }

    //add commitments pok data
    for (i, data) in commitments_pok_array.iter().enumerate() {
        let hex_str = data.as_str().unwrap().to_string();
        proof_data[10 + i] = hex_string_to_u8_array(hex_str);
    }

    //add inputs data
    let mut input = [0u8; 32];
    for (i, data) in input_array.iter().enumerate() {
        let num = data.as_u64().expect("Invalid number");
        input[(i * 8)..((i + 1) * 8)].copy_from_slice(&num.to_be_bytes());
    }
    proof_data[12] = input;

    proof_data
}

fn hex_string_to_u8_array(hex_str: String) -> [u8; 32] {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
    let hex_str = format!("{:0>64}", hex_str);

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[(i * 2)..((i + 1) * 2)], 16).expect("Invalid hex string");
    }

    bytes
}
