mod utils;

use validator_circuits::ParticipationCircuit;
use validator_circuits::ParticipationCircuitData;
use validator_circuits::MAX_VALIDATORS;
use std::time::Instant;
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    let participation_circuit = ParticipationCircuit::new();
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
