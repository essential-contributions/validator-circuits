mod utils;

use validator_circuits::load_or_create_participation_circuit;
use validator_circuits::save_circuit;
use validator_circuits::save_proof;
use validator_circuits::wrap::WrapperCircuit;
use validator_circuits::Circuit;
use validator_circuits::ParticipationCircuitData;
use validator_circuits::Proof;
use validator_circuits::MAX_VALIDATORS;
use std::time::Instant;
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    let participation_circuit = load_or_create_participation_circuit();
    println!("(finished in {:?})", start.elapsed());
    println!("");

    //data
    let validator_index = 53;
    let mut participation_bit_field = participation_bit_field(0);
    participation_bit_field[6] = 0x04;

    //prove
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = participation_circuit.generate_proof(&ParticipationCircuitData {
        participation_bit_field,
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
        println!("Proof failed verification");
    }
    println!("");

    //wrap proof
    println!("Building Wrapper Circuit... ");
    let start = Instant::now();
    let inner_circuit = participation_circuit.circuit_data();
    let inner_proof = proof.proof();
    let wrapper = WrapperCircuit::new(inner_circuit);
    println!("(finished in {:?})", start.elapsed());
    println!("");

    println!("Generating Wrapper Proof...");
    let start = Instant::now();
    let proof = wrapper.generate_proof(inner_circuit, inner_proof).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if wrapper.verify_proof(&proof).is_ok() {
        println!("Wrapper successfully verified!");
        save_circuit(wrapper.circuit_data(), "participation");
        save_proof(&proof, "participation");
    } else {
        println!("Wrapper proof failed verification");
    }
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
