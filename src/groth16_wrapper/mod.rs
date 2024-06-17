mod go;

use go::{go_build, verify_go};
use std::{path::{Path, PathBuf}, process::Command};

use crate::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, bn128_wrapper_circuit_proof_exists, BN128_WRAPPER_OUTPUT_FOLDER}, circuits::CIRCUIT_OUTPUT_FOLDER};

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
            let input_arg = format!("--in=./{}/{}/{}", CIRCUIT_OUTPUT_FOLDER, dir, BN128_WRAPPER_OUTPUT_FOLDER);
            let output_arg = format!("--out=./{}/{}/{}", CIRCUIT_OUTPUT_FOLDER, dir, GROTH16_WRAPPER_OUTPUT_FOLDER);
            match Command::new(Path::new(&binary_path)).args(&[input_arg, output_arg]).output() {
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

pub fn generate_wrapper_proof(dir: &str) {
    // make sure bn128
    // wrap bn128

    // return json
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
    file_exists(dir, GROTH16_CIRCUIT_FILENAME) && file_exists(dir, GROTH16_VERIFYING_KEY_FILENAME) 
        && file_exists(dir, GROTH16_PROVING_KEY_FILENAME) && file_exists(dir, GROTH16_SOLIDITY_VERIFIER_FILENAME)
}

pub fn groth16_wrapper_circuit_proof_exists(dir: &str) -> bool {
    file_exists(dir, GROTH16_PROOF_FILENAME)
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
