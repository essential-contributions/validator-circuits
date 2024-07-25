use std::time::Instant;

use plonky2::field::types::{Field, PrimeField64};
use sha2::{Digest, Sha256};
use validator_circuits::{circuits::{participation_state_circuit::ParticipationStateCircuitData, Circuit}, participation::{ParticipationBits, ParticipationRound, ParticipationRoundsTree}};
use validator_circuits::circuits::participation_state_circuit::ParticipationStateCircuit;

pub fn benchmark_prove_participation_state(full: bool) {
    if full {
        log::warn!("Skipping wrapped proof generation as this is an internal proof only (used recursively in other proofs that need to be wrapped for EVM).");
    }

    //generate the circuits
    println!("Building Participation State Circuit... ");
    let start = Instant::now();
    //TODO
    //let participation_state_circuit = load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    let participation_state_circuit = ParticipationStateCircuit::new();
    let mut participation_rounds_tree = ParticipationRoundsTree::new();
    let mut inputs_hash = [0u8; 32];
    println!("(finished in {:?})", start.elapsed());
    println!();

    //generate the initial proof
    let round = ParticipationRound {
        num: 32,
        state_inputs_hash: [1u8; 32],
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
    assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved participation state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    println!("participation_rounds_tree_root - {:?}", proof.participation_rounds_tree_root());
    participation_rounds_tree.update_round(round.clone());
    assert_eq!(proof.participation_rounds_tree_root(), participation_rounds_tree.root(), "Unexpected participation rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 2,
        state_inputs_hash: [1u8; 32],
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
    assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved participation state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    println!("participation_rounds_tree_root - {:?}", proof.participation_rounds_tree_root());
    participation_rounds_tree.update_round(round.clone());
    assert_eq!(proof.participation_rounds_tree_root(), participation_rounds_tree.root(), "Unexpected participation rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 2,
        state_inputs_hash: [1u8; 32],
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
    assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved participation state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    println!("participation_rounds_tree_root - {:?}", proof.participation_rounds_tree_root());
    participation_rounds_tree.update_round(round.clone());
    assert_eq!(proof.participation_rounds_tree_root(), participation_rounds_tree.root(), "Unexpected participation rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 78923,
        state_inputs_hash: [89u8; 32],
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
    assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved participation state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    println!("participation_rounds_tree_root - {:?}", proof.participation_rounds_tree_root());
    participation_rounds_tree.update_round(round.clone());
    assert_eq!(proof.participation_rounds_tree_root(), participation_rounds_tree.root(), "Unexpected participation rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ParticipationRound {
        num: 78923,
        state_inputs_hash: [89u8; 32],
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
    assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved participation state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    println!("participation_rounds_tree_root - {:?}", proof.participation_rounds_tree_root());
    participation_rounds_tree.update_round(round.clone());
    assert_eq!(proof.participation_rounds_tree_root(), participation_rounds_tree.root(), "Unexpected participation rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();

    //TODO
    //save_proof(&proof.proof(), PARTICIPATION_STATE_CIRCUIT_DIR);
}

fn next_inputs_hash(previous_hash: [u8; 32], round_update: ParticipationRound) -> [u8; 32] {
    let mut to_hash = [0u8; 104];
    to_hash[0..32].copy_from_slice(&previous_hash);
    to_hash[32..36].copy_from_slice(&(round_update.num as u32).to_be_bytes());
    to_hash[36..68].copy_from_slice(&round_update.state_inputs_hash);
    to_hash[68..76].copy_from_slice(&round_update.participation_root[0].to_canonical_u64().to_be_bytes());
    to_hash[76..84].copy_from_slice(&round_update.participation_root[1].to_canonical_u64().to_be_bytes());
    to_hash[84..92].copy_from_slice(&round_update.participation_root[2].to_canonical_u64().to_be_bytes());
    to_hash[92..100].copy_from_slice(&round_update.participation_root[3].to_canonical_u64().to_be_bytes());
    to_hash[100..104].copy_from_slice(&(round_update.participation_count as u32).to_be_bytes());
    
    let mut hasher = Sha256::new();
    hasher.update(&to_hash);
    let result = hasher.finalize();
    let hash: [u8; 32] = result.into();
    hash
}

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}