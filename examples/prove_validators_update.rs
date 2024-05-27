mod utils;

use validator_circuits::ValidatorCircuits;
use validator_circuits::ValidatorsUpdateCircuit;
use validator_circuits::ValidatorsUpdateCircuitData;
use std::time::Instant;
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use crate::utils::generate_validator_set;

fn main() {
    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    let validators_update_circuit = ValidatorsUpdateCircuit::new();
    println!("(finished in {:?})", start.elapsed());
    println!("");

    //create a quick validator set
    println!("Generating Test Validator Set... ");
    let start = Instant::now();
    let circuits = ValidatorCircuits::build();
    let validators = generate_validator_set(circuits);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //data
    let validator_index = 53;
    let validator = validators.validator(validator_index);


    //prove
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = validators_update_circuit.generate_proof(&ValidatorsUpdateCircuitData {
        validator_index,
        previous_root: validators.root().clone(),
        previous_commitment: validator.commitment_root,
        previous_stake: validator.stake,
        new_root: validators.root().clone(),
        new_commitment: validator.commitment_root,
        new_stake: validator.stake,
        merkle_proof: validators.validator_merkle_proof(validator_index),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if validators_update_circuit.verify_proof(&proof).is_ok() {
        println!("Proved validators update from {:?} to {:?}!", proof.previous_root(), proof.new_root());
    } else {
        println!("Proof failed verification");
    }
}
