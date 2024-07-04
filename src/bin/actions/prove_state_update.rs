use std::time::Instant;

use validator_circuits::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, save_proof, state_update_circuit::{self, StateUpdateCircuitData}, Circuit, Proof, STATE_UPDATE_CIRCUIT_DIR}, example_validator_set, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}};
use validator_circuits::circuits::state_update_circuit::StateUpdateCircuit;

pub fn benchmark_prove_state_update(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(STATE_UPDATE_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(STATE_UPDATE_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            return;
        }
    }

    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    //let state_update_circuit = load_or_create_circuit::<StateUpdateCircuit>(STATE_UPDATE_CIRCUIT_DIR);
    let state_update_circuit = StateUpdateCircuit::new();
    println!("(finished in {:?})", start.elapsed());
    println!("");
    
    //generate the initial proof
    println!("Generating Initial Proof...");
    let start = Instant::now();
    let proof = state_update_circuit.initial_proof();
    println!("(finished in {:?})", start.elapsed());
    if state_update_circuit.verify_proof(&proof).is_ok() {
        println!("Proved state update {:?} from {:?} to {:?}!", proof.counter(), proof.initial_hash(), proof.hash());
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    println!("");
    
    //generate proof off the last proof
    println!("Generating 1st Round Proof...");
    let start = Instant::now();
    let proof = state_update_circuit.generate_proof(&StateUpdateCircuitData {
        previous_proof: proof,
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if state_update_circuit.verify_proof(&proof).is_ok() {
        println!("Proved state update {:?} from {:?} to {:?}!", proof.counter(), proof.initial_hash(), proof.hash());
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    println!("");
    
    //generate proof off the last proof
    println!("Generating 2nd Round Proof...");
    let start = Instant::now();
    let proof = state_update_circuit.generate_proof(&StateUpdateCircuitData {
        previous_proof: proof,
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if state_update_circuit.verify_proof(&proof).is_ok() {
        println!("Proved state update {:?} from {:?} to {:?}!", proof.counter(), proof.initial_hash(), proof.hash());
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    println!("");





    /*
    save_proof(&proof.proof(), STATE_UPDATE_CIRCUIT_DIR);
    println!();

    if full {
        let inner_circuit = state_update_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, STATE_UPDATE_CIRCUIT_DIR);
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
        save_bn128_wrapper_proof(&proof, STATE_UPDATE_CIRCUIT_DIR);
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        let proof = generate_groth16_wrapper_proof(STATE_UPDATE_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
    */
}
