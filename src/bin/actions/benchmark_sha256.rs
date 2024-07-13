use std::time::Instant;

use validator_circuits::circuits::{sha256_circuit::{Sha256Circuit, Sha256CircuitData}, Circuit};

pub fn benchmark_sha256(_full: bool) {

    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    //let state_update_circuit = load_or_create_circuit::<StateUpdateCircuit>(STATE_UPDATE_CIRCUIT_DIR);
    let state_update_circuit = Sha256Circuit::new();
    println!("(finished in {:?})", start.elapsed());
    println!("");
    
    //generate test proof
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = state_update_circuit.generate_proof(&Sha256CircuitData {
        input: [12u8; 128].to_vec(),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if state_update_circuit.verify_proof(&proof).is_ok() {
        print!("Proved sha256 hash! {:?} -> ", proof.input());
        let hash = proof.hash();
        for byte in hash {
            print!("{:02x}", byte);
        }
        println!();
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    println!("");
    

}
