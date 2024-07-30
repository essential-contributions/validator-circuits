use std::time::Instant;

use validator_circuits::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, save_proof, Circuit, Proof, VALIDATOR_PARTICIPATION_CIRCUIT_DIR}, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}, MAX_VALIDATORS};

pub fn benchmark_validator_prove_participation(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(VALIDATOR_PARTICIPATION_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(VALIDATOR_PARTICIPATION_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            panic!();
        }
    }
/*
    //generate the circuits
    println!("Building Participation Circuit... ");
    let start = Instant::now();
    let participation_circuit = load_or_create_circuit::<ParticipationCircuit>(VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //data
    let validator_index = 53;
    let mut participation_bits = participation_bit_field(0);
    participation_bits[6] = 0x04;

    //prove
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = participation_circuit.generate_proof(&ParticipationCircuitData {
        participation_bits,
        validator_index,
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if participation_circuit.verify_proof(&proof).is_ok() {
        if proof.participated() {
            println!("Proved validator {} participated in root {:?}!", proof.validator_index(), proof.participation_root());
        } else {
            println!("Proved validator {} did not participate in root {:?}!", proof.validator_index(), proof.participation_root());
        }
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    save_proof(&proof.proof(), VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
    println!();

    if full {
        let inner_circuit = participation_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
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
        save_bn128_wrapper_proof(&proof, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        let proof = generate_groth16_wrapper_proof(VALIDATOR_PARTICIPATION_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
    */
}

fn participation_bit_field(to: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0u8; MAX_VALIDATORS / 8];

    let full_bytes = to / 8;
    for i in 0..full_bytes {
        bytes[i] = 0xff;
    }
    if to % 8 > 0 {
        let remainder = to - (full_bytes * 8);
        bytes[full_bytes] = 0xff << (8 - remainder);
    }

    bytes
}
