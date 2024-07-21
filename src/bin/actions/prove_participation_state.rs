use std::time::Instant;

use plonky2::field::types::Field;
use validator_circuits::{bn128_wrapper::bn128_wrapper_circuit_data_exists, circuits::{participation_state_circuit::ParticipationStateCircuitData, Circuit, PARTICIPATION_STATE_CIRCUIT_DIR}, groth16_wrapper::groth16_wrapper_circuit_data_exists, participation::{ParticipationBits, ParticipationRound, ParticipationRoundsTree}};
use validator_circuits::circuits::participation_state_circuit::ParticipationStateCircuit;

pub fn benchmark_prove_participation_state(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(PARTICIPATION_STATE_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(PARTICIPATION_STATE_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            return;
        }
    }

    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    //let participation_state_circuit = load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    let participation_state_circuit = ParticipationStateCircuit::new();
    let mut participation_rounds_tree = ParticipationRoundsTree::new();
    println!("(finished in {:?})", start.elapsed());
    println!("");

    //generate the initial proof
    let round = ParticipationRound {
        num: 32,
        state_inputs_hash: [1, 2, 3, 4],
        participation_root: [Field::ONE; 4],
        participation_count: 100,
        participation_bits: ParticipationBits { bit_flags: vec![7, 8, 9, 10] },
    };
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 1st Proof (from initial state)...");
    let start = Instant::now();
    let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        participation_root: round.participation_root,
        participation_count: round.participation_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_participation_root: current_round_data.participation_root,
        current_participation_count: current_round_data.participation_count,
        participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
        previous_proof: None,
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if participation_state_circuit.verify_proof(&proof).is_ok() {
        print!("Proved participation update to {:?} (inputs hash:", proof.participation_rounds_tree_root());
        for word in proof.inputs_hash() {
            print!("{:16x}", word);
        }
        println!(")");
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    participation_rounds_tree.update_round(round);
    println!("expected root: {:?}", participation_rounds_tree.root());
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 2,
        state_inputs_hash: [1, 2, 3, 4],
        participation_root: [Field::TWO; 4],
        participation_count: 7700,
        participation_bits: ParticipationBits { bit_flags: vec![55, 55, 55, 55] },
    };
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 2nd Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        participation_root: round.participation_root,
        participation_count: round.participation_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_participation_root: current_round_data.participation_root,
        current_participation_count: current_round_data.participation_count,
        participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if participation_state_circuit.verify_proof(&proof).is_ok() {
        print!("Proved participation update to {:?} (inputs hash:", proof.participation_rounds_tree_root());
        for word in proof.inputs_hash() {
            print!("{:16x}", word);
        }
        println!(")");
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    participation_rounds_tree.update_round(round);
    println!("expected root: {:?}", participation_rounds_tree.root());
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 2,
        state_inputs_hash: [1, 2, 3, 4],
        participation_root: [Field::TWO, Field::ONE, Field::TWO, Field::ONE],
        participation_count: 7699,
        participation_bits: ParticipationBits { bit_flags: vec![44, 44, 44, 44] },
    };
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 3rd Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        participation_root: round.participation_root,
        participation_count: round.participation_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_participation_root: current_round_data.participation_root,
        current_participation_count: current_round_data.participation_count,
        participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if participation_state_circuit.verify_proof(&proof).is_ok() {
        print!("Proved participation update to {:?} (inputs hash:", proof.participation_rounds_tree_root());
        for word in proof.inputs_hash() {
            print!("{:16x}", word);
        }
        println!(")");
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    participation_rounds_tree.update_round(round);
    println!("expected root: {:?}", participation_rounds_tree.root());
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 78923,
        state_inputs_hash: [8, 8, 9, 9],
        participation_root: [Field::ZERO, Field::ONE, Field::TWO, Field::ZERO],
        participation_count: 100_000,
        participation_bits: ParticipationBits { bit_flags: vec![123, 99] },
    };
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 4th Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        participation_root: round.participation_root,
        participation_count: round.participation_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_participation_root: current_round_data.participation_root,
        current_participation_count: current_round_data.participation_count,
        participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if participation_state_circuit.verify_proof(&proof).is_ok() {
        print!("Proved participation update to {:?} (inputs hash:", proof.participation_rounds_tree_root());
        for word in proof.inputs_hash() {
            print!("{:16x}", word);
        }
        println!(")");
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    participation_rounds_tree.update_round(round);
    println!("expected root: {:?}", participation_rounds_tree.root());
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 78923,
        state_inputs_hash: [8, 8, 9, 9],
        participation_root: [Field::from_canonical_u64(123); 4],
        participation_count: 100_000,
        participation_bits: ParticipationBits { bit_flags: vec![255, 52, 1] },
    };
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 5th Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        participation_root: round.participation_root,
        participation_count: round.participation_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_participation_root: current_round_data.participation_root,
        current_participation_count: current_round_data.participation_count,
        participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if participation_state_circuit.verify_proof(&proof).is_ok() {
        print!("Proved participation update to {:?} (inputs hash:", proof.participation_rounds_tree_root());
        for word in proof.inputs_hash() {
            print!("{:16x}", word);
        }
        println!(")");
    } else {
        log::error!("Proof failed verification.");
        return;
    }
    participation_rounds_tree.update_round(round);
    println!("expected root: {:?}", participation_rounds_tree.root());
    println!();




    /*
    save_proof(&proof.proof(), PARTICIPATION_STATE_CIRCUIT_DIR);
    println!();

    if full {
        let inner_circuit = participation_state_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, PARTICIPATION_STATE_CIRCUIT_DIR);
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
        save_bn128_wrapper_proof(&proof, PARTICIPATION_STATE_CIRCUIT_DIR);
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        let proof = generate_groth16_wrapper_proof(PARTICIPATION_STATE_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
    */
}
