mod attestations_aggregator1_circuit;
mod attestations_aggregator2_circuit;
mod attestations_aggregator3_circuit;
mod participation_circuit;
mod validators_update_circuit;
mod serialization;

use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use std::{fs::{create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf};
use std::str;
use anyhow::Result;

pub use attestations_aggregator1_circuit::*;
pub use attestations_aggregator2_circuit::*;
pub use attestations_aggregator3_circuit::*;
pub use participation_circuit::*;
pub use validators_update_circuit::*;

use crate::{Config, ConfigBN128, Field, D};

const CIRCUIT_OUTPUT_FOLDER: &str = "circuits";
const CIRCUIT_FILENAME: &str = "circuit.bin";
const COMMON_DATA_FILENAME: &str = "common_circuit_data.json";
const VERIFIER_ONLY_DATA_FILENAME: &str = "verifier_only_circuit_data.json";
const PROOF_FILENAME: &str = "proof_with_public_inputs.json";
const WRAPPED_PROOF_FILENAME: &str = "wrapped_proof_with_public_inputs.json";

const ATTESTATIONS_AGGREGATOR1_CIRCUIT_DIR: &str = "attestations_aggregator1";
const ATTESTATIONS_AGGREGATOR2_CIRCUIT_DIR: &str = "attestations_aggregator2";
const ATTESTATIONS_AGGREGATOR3_CIRCUIT_DIR: &str = "attestations_aggregator3";
const PARTICIPATION_CIRCUIT_DIR: &str = "participation";
const VALIDATORS_UPDATE_CIRCUIT_DIR: &str = "validators_update";

pub trait Circuit {
    type Data;
    type Proof: Proof;

    fn new() -> Self;
    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof>;
    fn verify_proof(&self, proof: &Self::Proof) -> Result<()>;
    fn circuit_data(&self) -> &CircuitData<Field, Config, D>;
}

pub trait ContinuationCircuit: Circuit {
    type PrevCircuit: Circuit;

    fn new_continuation(prev_circuit: &Self::PrevCircuit) -> Self;
    fn generate_proof_continuation(&self, data: &Self::Data, prev_circuit: &Self::PrevCircuit) -> Result<Self::Proof>;
}

pub trait Proof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D>;
}

pub trait Serializeable {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> 
    where 
        Self: Sized;
}

pub struct ValidatorCircuits {
    attestations_aggregator1: AttestationsAggregator1Circuit,
    attestations_aggregator2: AttestationsAggregator2Circuit,
    attestations_aggregator3: AttestationsAggregator3Circuit,
}

impl ValidatorCircuits {
    pub fn build() -> Self {
        let attestations_aggregator1 = load_or_create_circuit::<AttestationsAggregator1Circuit>(ATTESTATIONS_AGGREGATOR1_CIRCUIT_DIR);
        let attestations_aggregator2 = load_or_create_continuation_circuit::<AttestationsAggregator2Circuit, _>(ATTESTATIONS_AGGREGATOR2_CIRCUIT_DIR, &attestations_aggregator1);
        let attestations_aggregator3 = load_or_create_continuation_circuit::<AttestationsAggregator3Circuit, _>(ATTESTATIONS_AGGREGATOR3_CIRCUIT_DIR, &attestations_aggregator2);
        //let attestations_aggregator1 = AttestationsAggregator1Circuit::new();
        //let attestations_aggregator2 = AttestationsAggregator2Circuit::new_continutation(&attestations_aggregator1);
        //let attestations_aggregator3 = AttestationsAggregator3Circuit::new_continutation(&attestations_aggregator2);

        ValidatorCircuits {
            attestations_aggregator1,
            attestations_aggregator2,
            attestations_aggregator3,
        }
    }

    pub fn generate_attestations_aggregator1_proof(&self, data: &AttestationsAggregator1Data) -> Result<AttestationsAggregator1Proof> {
        self.attestations_aggregator1.generate_proof(data)
    }
    pub fn verify_attestations_aggregator1_proof(&self, proof: &AttestationsAggregator1Proof) -> Result<()> {
        self.attestations_aggregator1.verify_proof(proof)
    }

    pub fn generate_attestations_aggregator2_proof(&self, data: &AttestationsAggregator2Data) -> Result<AttestationsAggregator2Proof> {
        self.attestations_aggregator2.generate_proof_continuation(data, &self.attestations_aggregator1)
    }
    pub fn verify_attestations_aggregator2_proof(&self, proof: &AttestationsAggregator2Proof) -> Result<()> {
        self.attestations_aggregator2.verify_proof(proof)
    }

    pub fn generate_attestations_aggregator3_proof(&self, data: &AttestationsAggregator3Data) -> Result<AttestationsAggregator3Proof> {
        self.attestations_aggregator3.generate_proof_continuation(data, &self.attestations_aggregator2)
    }
    pub fn verify_attestations_aggregator3_proof(&self, proof: &AttestationsAggregator3Proof) -> Result<()> {
        self.attestations_aggregator3.verify_proof(proof)
    }
}

pub fn load_or_create_validators_update_circuit() -> ValidatorsUpdateCircuit {
    load_or_create_circuit::<ValidatorsUpdateCircuit>(VALIDATORS_UPDATE_CIRCUIT_DIR)
}

pub fn load_or_create_participation_circuit() -> ParticipationCircuit {
    load_or_create_circuit::<ParticipationCircuit>(PARTICIPATION_CIRCUIT_DIR)
}

pub fn load_or_create_circuit<C>(dir: &str) -> C 
where
    C: Circuit + Serializeable,
{
    let bytes = read_from_dir(dir, CIRCUIT_FILENAME);
    if bytes.is_ok() {
        let circuit = C::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", dir);
            return circuit.unwrap();
        }
    }
    let circuit = C::new();
    write_circuit(&circuit, dir);
    circuit
}

pub fn load_or_create_continuation_circuit<CC, C>(dir: &str, prev_circuit: &C) -> CC 
where
    C: Circuit,
    CC: ContinuationCircuit<PrevCircuit = C> + Serializeable,
{
    let bytes = read_from_dir(dir, CIRCUIT_FILENAME);
    if bytes.is_ok() {
        let circuit = CC::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", dir);
            return circuit.unwrap();
        }
    }
    let circuit = CC::new_continuation(prev_circuit);
    write_circuit(&circuit, dir);
    circuit
}

pub fn save_circuit(circuit: &CircuitData<Field, ConfigBN128, D>, dir: &str) {
    let common_circuit_data_serialized = serde_json::to_string(&circuit.common);
    match common_circuit_data_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            if write_to_dir(&bytes, dir, COMMON_DATA_FILENAME).is_err() {
                println!("Failed to write common data file: {}", dir);
            }
        },
        Err(e) => println!("Failed to serialize common data for {}: {}", dir, e),
    }

    let verifier_only_circuit_data_serialized  = serde_json::to_string(&circuit.verifier_only);
    match verifier_only_circuit_data_serialized  {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            if write_to_dir(&bytes, dir, VERIFIER_ONLY_DATA_FILENAME).is_err() {
                println!("Failed to write verifier only data file: {}", dir);
            }
        },
        Err(e) => println!("Failed to serialize verifier only data for {}: {}", dir, e),
    }
}

pub fn save_proof(proof: &ProofWithPublicInputs<Field, Config, D>, dir: &str) {
    let proof_serialized = serde_json::to_string(proof);
    match proof_serialized {
        Ok(json) => {
            let bytes = json.as_bytes().to_vec();
            if write_to_dir(&bytes, dir, PROOF_FILENAME).is_err() {
                println!("Failed to write proof file: {}", dir);
            }
        },
        Err(e) => println!("Failed to serialize proof for {}: {}", dir, e),
    }
}

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

#[inline]
fn write_circuit<C>(circuit: &C, dir: &str) 
where
    C: Serializeable,
{
    let circuit_bytes = circuit.to_bytes();
    match circuit_bytes {
        Ok(bytes) => {
            if write_to_dir(&bytes, dir, CIRCUIT_FILENAME).is_err() {
                println!("Failed to write file: {}", dir);
            }
        },
        Err(e) => println!("Failed to serialize for {}: {}", dir, e),
    }
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
