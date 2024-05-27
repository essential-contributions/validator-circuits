mod attestations_aggregator1_circuit;
mod attestations_aggregator2_circuit;
mod attestations_aggregator3_circuit;
mod participation_circuit;
mod validators_update_circuit;
mod serialization;

use std::{fs::{create_dir_all, File}, io::{self, BufReader, Read, Write}, path::PathBuf};
use anyhow::Result;

pub use attestations_aggregator1_circuit::*;
pub use attestations_aggregator2_circuit::*;
pub use attestations_aggregator3_circuit::*;
pub use participation_circuit::*;
pub use validators_update_circuit::*;

const CIRCUIT_OUTPUT_FOLDER: &str = "circuits";
const ATTESTATIONS_AGGREGATOR1_CIRCUIT_FILE: &str = "AttestationsAggregator1Circuit.bin";
const ATTESTATIONS_AGGREGATOR2_CIRCUIT_FILE: &str = "AttestationsAggregator2Circuit.bin";
const ATTESTATIONS_AGGREGATOR3_CIRCUIT_FILE: &str = "AttestationsAggregator3Circuit.bin";

pub struct ValidatorCircuits {
    attestations_aggregator1: AttestationsAggregator1Circuit,
    attestations_aggregator2: AttestationsAggregator2Circuit,
    attestations_aggregator3: AttestationsAggregator3Circuit,
}

impl ValidatorCircuits {
    pub fn build() -> Self {
        let attestations_aggregator1 = attestations_aggregator1_circuit();
        let attestations_aggregator2 = attestations_aggregator2_circuit(&attestations_aggregator1);
        let attestations_aggregator3 = attestations_aggregator3_circuit(&attestations_aggregator2);
        //let attestations_aggregator1 = AttestationsAggregator1Circuit::new();
        //let attestations_aggregator2 = AttestationsAggregator2Circuit::new(&attestations_aggregator1);
        //let attestations_aggregator3 = AttestationsAggregator3Circuit::new(&attestations_aggregator2);

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
        self.attestations_aggregator2.generate_proof(data, &self.attestations_aggregator1)
    }
    pub fn verify_attestations_aggregator2_proof(&self, proof: &AttestationsAggregator2Proof) -> Result<()> {
        self.attestations_aggregator2.verify_proof(proof)
    }

    pub fn generate_attestations_aggregator3_proof(&self, data: &AttestationsAggregator3Data) -> Result<AttestationsAggregator3Proof> {
        self.attestations_aggregator3.generate_proof(data, &self.attestations_aggregator2)
    }
    pub fn verify_attestations_aggregator3_proof(&self, proof: &AttestationsAggregator3Proof) -> Result<()> {
        self.attestations_aggregator3.verify_proof(proof)
    }
}

fn attestations_aggregator1_circuit() -> AttestationsAggregator1Circuit {
    let bytes = read_from_file(ATTESTATIONS_AGGREGATOR1_CIRCUIT_FILE);
    if bytes.is_ok() {
        let circuit = AttestationsAggregator1Circuit::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", ATTESTATIONS_AGGREGATOR1_CIRCUIT_FILE);
            return circuit.unwrap();
        }
    }
    let circuit = AttestationsAggregator1Circuit::new();
    write_circuit(circuit.to_bytes(), ATTESTATIONS_AGGREGATOR1_CIRCUIT_FILE);
    circuit
}

fn attestations_aggregator2_circuit(atts_agg1_circuit: &AttestationsAggregator1Circuit) -> AttestationsAggregator2Circuit {
    let bytes = read_from_file(ATTESTATIONS_AGGREGATOR2_CIRCUIT_FILE);
    if bytes.is_ok() {
        let circuit = AttestationsAggregator2Circuit::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", ATTESTATIONS_AGGREGATOR2_CIRCUIT_FILE);
            return circuit.unwrap();
        }
    }
    let circuit = AttestationsAggregator2Circuit::new(atts_agg1_circuit);
    write_circuit(circuit.to_bytes(), ATTESTATIONS_AGGREGATOR2_CIRCUIT_FILE);
    circuit
}

fn attestations_aggregator3_circuit(atts_agg2_circuit: &AttestationsAggregator2Circuit) -> AttestationsAggregator3Circuit {
    let bytes = read_from_file(ATTESTATIONS_AGGREGATOR3_CIRCUIT_FILE);
    if bytes.is_ok() {
        let circuit = AttestationsAggregator3Circuit::from_bytes(&bytes.unwrap());
        if circuit.is_ok() {
            println!("read circuit from {}", ATTESTATIONS_AGGREGATOR3_CIRCUIT_FILE);
            return circuit.unwrap();
        }
    }
    let circuit = AttestationsAggregator3Circuit::new(atts_agg2_circuit);
    write_circuit(circuit.to_bytes(), ATTESTATIONS_AGGREGATOR3_CIRCUIT_FILE);
    circuit
}

#[inline]
fn write_circuit(circuit_bytes: Result<Vec<u8>>, filename: &str) {
    match circuit_bytes {
        Ok(bytes) => {
            if write_to_file(&bytes, filename).is_err() {
                println!("Failed to write file: {}", filename);
            }
        },
        Err(e) => println!("Failed to serialize for {}: {}", filename, e),
    }
}

#[inline]
fn write_to_file(bytes: &Vec<u8>, filename: &str) -> io::Result<()> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
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
fn read_from_file(filename: &str) -> io::Result<Vec<u8>> {
    let mut path = PathBuf::from(CIRCUIT_OUTPUT_FOLDER);
    path.push(filename);

    let file = File::open(&path)?;
    let mut reader = BufReader::with_capacity(131072, file);
    let mut buffer: Vec<u8> = Vec::new();
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)
}
