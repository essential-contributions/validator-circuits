use std::time::Instant;

use validator_circuits::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, save_proof, validators_update_circuit::ValidatorsUpdateCircuitData, Circuit, Proof, VALIDATORS_UPDATE_CIRCUIT_DIR}, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}, validators::example_validator_set};
use validator_circuits::circuits::validators_update_circuit::ValidatorsUpdateCircuit;

pub fn benchmark_prove_validators_update(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(VALIDATORS_UPDATE_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(VALIDATORS_UPDATE_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            return;
        }
    }

    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    let validators_update_circuit = load_or_create_circuit::<ValidatorsUpdateCircuit>(VALIDATORS_UPDATE_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!("");
    
    //create a quick validator set
    println!("Generating Test Validator Set... ");
    let start = Instant::now();
    let validators = example_validator_set();
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
        log::error!("Proof failed verification.");
        return;
    }
    save_proof(&proof.proof(), VALIDATORS_UPDATE_CIRCUIT_DIR);
    println!();

    if full {
        let inner_circuit = validators_update_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, VALIDATORS_UPDATE_CIRCUIT_DIR);
        println!("(finished in {:?})", start.elapsed());
        println!();

        println!("Generating BN128 Wrapper Proof...");
        let start = Instant::now();
        let proof = bn128_wrapper.generate_proof(inner_circuit, inner_proof).unwrap();
        println!("(finished in {:?})", start.elapsed());
        if bn128_wrapper.verify_proof(&proof).is_ok() {
            println!("Proved with BN128 wrapper!");
        } else {
            log::error!("BN128 wrapped proof failed verification.");
            return;
        }
        save_bn128_wrapper_proof(&proof, VALIDATORS_UPDATE_CIRCUIT_DIR);
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        let proof = generate_groth16_wrapper_proof(VALIDATORS_UPDATE_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
}
