use std::time::Instant;

use validator_circuits::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, participation_circuit::calculate_participation_root, save_proof, Circuit, Proof, ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR}, example_commitment_proof, example_validator_set, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}, Field, ValidatorCommitmentReveal, EXAMPLE_COMMITMENTS_REPEAT, MAX_VALIDATORS};
use validator_circuits::circuits::attestations_aggregator_circuit::AttestationsAggregatorCircuit;

pub fn benchmark_prove_attestations_aggregation(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            return;
        }
    }

    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    let attestations_circuit = load_or_create_circuit::<AttestationsAggregatorCircuit>(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!("");
    
    //create a quick validator set
    println!("Generating Test Validator Set... ");
    let start = Instant::now();
    let validators = example_validator_set();
    println!("(finished in {:?})", start.elapsed());
    println!();

    //data
    let block_slot = 100;
    let num_attestations = 1000;
    let reveals: Vec<ValidatorCommitmentReveal> = (0..num_attestations).map(|i| {
        let (reveal, proof) = example_commitment_proof(i % EXAMPLE_COMMITMENTS_REPEAT);
        ValidatorCommitmentReveal {
            validator_index: i,
            block_slot,
            reveal,
            proof,
        }
    }).collect();
    
    //prove
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = validators.prove_attestations(&attestations_circuit, &reveals).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if attestations_circuit.verify_proof(&proof).is_ok() {
        println!(
            "Proved a total validation stake of {} from {} validators for slot {} with validator root [{:?}] and participation root [{:?}]!", 
            proof.total_stake(), 
            proof.num_participants(), 
            proof.block_slot(), 
            proof.validators_root(),
            proof.participation_root(),
        );
        println!("expected validator root: {:?}", validators.root());
        println!("expected participation root: {:?}", participation_root(num_attestations));
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    save_proof(&proof.proof(), ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR);
    println!();

    if full {
        let inner_circuit = attestations_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR);
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
        save_bn128_wrapper_proof(&proof, ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR);
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        let proof = generate_groth16_wrapper_proof(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
}

fn participation_root(to: usize) -> [Field; 4] {
    let mut bytes: Vec<u8> = vec![0u8; MAX_VALIDATORS / 8];

    let full_bytes = to / 8;
    for i in 0..full_bytes {
        bytes[i] = 0xff;
    }
    if to % 8 > 0 {
        let remainder = to - (full_bytes * 8);
        bytes[full_bytes] = 0xff << (8 - remainder);
    }

    calculate_participation_root(&bytes)
}
