mod utils;

use validator_circuits::ParticipationCircuit;
use validator_circuits::ParticipationCircuitData;
use validator_circuits::MAX_PARTICIPANTS;
use std::time::Instant;


fn main() {
    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    let participation_circuit = ParticipationCircuit::new();
    println!("(finished in {:?})", start.elapsed());
    println!("");

    //data
    let validator_index = 0;
    let mut participation_bit_field = participation_bit_field(1000);
    //participation_bit_field[0] = 0xFF;

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
    let mut bytes: Vec<u8> = vec![0u8; MAX_PARTICIPANTS / 8];

    let full_bytes = to / 8;
    for i in 0..full_bytes {
        bytes[i] = 0xff;
    }

    let remainder = to - (full_bytes * 8);
    bytes[full_bytes] = 0xff << (8 - remainder);

    bytes
}
