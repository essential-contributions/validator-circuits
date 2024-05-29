mod attestations_aggregator1_circuit;
mod attestations_aggregator2_circuit;
mod attestations_aggregator3_circuit;
mod participation_circuit;
mod validators_update_circuit;
mod serialization;

use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use std::{fs::{create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf};
use anyhow::Result;

pub use attestations_aggregator1_circuit::*;
pub use attestations_aggregator2_circuit::*;
pub use attestations_aggregator3_circuit::*;
pub use participation_circuit::*;
pub use validators_update_circuit::*;

use crate::{Config, Field, D};

const CIRCUIT_OUTPUT_FOLDER: &str = "circuits";
const CIRCUIT_DIRNAME: &str = "circuit.bin";
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
    let bytes = read_from_dir(dir);
    if bytes.is_ok() {
        let circuit = C::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", dir);
            return circuit.unwrap();
        }
    }
    let circuit = C::new();
    write_circuit(circuit.to_bytes(), dir);
    circuit
}

pub fn load_or_create_continuation_circuit<CC, C>(dir: &str, prev_circuit: &C) -> CC 
where
    C: Circuit,
    CC: ContinuationCircuit<PrevCircuit = C> + Serializeable,
{
    let bytes = read_from_dir(dir);
    if bytes.is_ok() {
        let circuit = CC::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", dir);
            return circuit.unwrap();
        }
    }
    let circuit = CC::new_continuation(prev_circuit);
    write_circuit(circuit.to_bytes(), dir);
    circuit
}

#[inline]
fn write_circuit(circuit_bytes: Result<Vec<u8>>, filename: &str) {
    match circuit_bytes {
        Ok(bytes) => {
            if write_to_dir(&bytes, filename).is_err() {
                println!("Failed to write file: {}", filename);
            }
        },
        Err(e) => println!("Failed to serialize for {}: {}", filename, e),
    }
}

#[inline]
fn write_to_dir(bytes: &Vec<u8>, dir: &str) -> io::Result<()> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(CIRCUIT_DIRNAME);

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&path)?;
    file.write_all(&bytes)?;
    file.flush()?;

    Ok(())
}

#[inline]
fn read_from_dir(dir: &str) -> io::Result<Vec<u8>> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(dir);
    path.push(CIRCUIT_DIRNAME);

    let file = File::open(&path)?;
    let mut reader = BufReader::with_capacity(134217728, file);
    let mut buffer: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)
}
