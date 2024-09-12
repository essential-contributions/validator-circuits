use std::time::Instant;

use plonky2::field::types::{Field, PrimeField64};
use sha2::{Digest, Sha256};
use validator_circuits::circuits::participation_state_circuit::ParticipationStateCircuit;
use validator_circuits::{
    circuits::{
        load_or_create_circuit, load_or_create_init_proof,
        participation_state_circuit::ParticipationStateCircuitData,
        validators_state_circuit::ValidatorsStateCircuit, Circuit, PARTICIPATION_STATE_CIRCUIT_DIR,
        VALIDATORS_STATE_CIRCUIT_DIR,
    },
    epochs::initial_validator_epochs_tree,
    participation::{initial_participation_rounds_tree, ParticipationRound},
    PARTICIPATION_ROUNDS_PER_STATE_EPOCH,
};

use crate::actions::build_validators_state;

const VALIDATORS_STATE_OUTPUT_FILE1: &str = "participation_state_validators_state1.proof";
const VALIDATORS_STATE_OUTPUT_FILE2: &str = "participation_state_validators_state2.proof";

pub fn benchmark_prove_participation_state(full: bool) {
    if full {
        log::warn!("Skipping wrapped proof generation as state is an internal proof only (used recursively in other proofs).");
    }

    //generate the circuits
    println!("Building Participation State Circuit... ");
    let start = Instant::now();
    let participation_state_circuit =
        load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    let mut validator_epochs_tree = initial_validator_epochs_tree();
    let mut participation_rounds_tree = initial_participation_rounds_tree();
    let mut inputs_hash = [0u8; 32];
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proofs for validator state
    println!("Building Validators State Data...");
    let start = Instant::now();
    let validators_state_circuit =
        load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let (validators_tree1, accounts_tree1, validators_state_proof1) = build_validators_state(
        &validators_state_circuit,
        &[[1u8; 20]],
        &[1],
        &[32],
        VALIDATORS_STATE_OUTPUT_FILE1,
    );
    let (validators_tree2, accounts_tree2, validators_state_proof2) = build_validators_state(
        &validators_state_circuit,
        &[[2u8; 20]],
        &[2],
        &[64],
        VALIDATORS_STATE_OUTPUT_FILE2,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //generate the initial proof
    println!("Building Initial Proof...");
    let start = Instant::now();
    let proof =
        load_or_create_init_proof::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    assert!(
        participation_state_circuit.verify_proof(&proof).is_ok(),
        "Proof failed verification."
    );
    assert_eq!(
        proof.validator_epochs_tree_root(),
        validator_epochs_tree.root(),
        "Unexpected validator epochs tree root."
    );
    assert_eq!(
        proof.participation_rounds_tree_root(),
        participation_rounds_tree.root(),
        "Unexpected participation rounds tree root."
    );
    assert_eq!(
        proof.inputs_hash(),
        inputs_hash,
        "Unexpected inputs hash from proof."
    );
    println!();

    //generate the first real proof
    let participation_bits = Some(vec![7, 8, 9, 10]);
    let round = ParticipationRound {
        num: 32,
        participation_root: [Field::ONE; 4],
        participation_count: 100,
    };
    let epoch_num = round.num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 1st Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit
        .generate_proof(&ParticipationStateCircuitData {
            round_num: round.num,
            val_state_inputs_hash: validators_state_proof1.inputs_hash(),
            participation_root: round.participation_root,
            participation_count: round.participation_count,
            current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
            validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
            current_participation_root: current_round_data.participation_root,
            current_participation_count: current_round_data.participation_count,
            participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
            previous_proof: Some(proof),
        })
        .unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(
        participation_state_circuit.verify_proof(&proof).is_ok(),
        "Proof failed verification."
    );
    println!(
        "Proved participation state at inputs hash 0x{}",
        to_hex(&proof.inputs_hash())
    );
    println!(
        "validator_epochs_tree_root - {:?}",
        proof.validator_epochs_tree_root()
    );
    println!(
        "participation_rounds_tree_root - {:?}",
        proof.participation_rounds_tree_root()
    );
    validator_epochs_tree.update_epoch(
        epoch_num,
        &validators_state_proof1,
        &validators_tree1,
        &accounts_tree1,
    );
    participation_rounds_tree.update_round(round.clone(), participation_bits);
    assert_eq!(
        proof.validator_epochs_tree_root(),
        validator_epochs_tree.root(),
        "Unexpected validator epochs tree root."
    );
    assert_eq!(
        proof.participation_rounds_tree_root(),
        participation_rounds_tree.root(),
        "Unexpected participation rounds tree root."
    );
    inputs_hash = next_inputs_hash(inputs_hash, round, validators_state_proof1.inputs_hash());
    assert_eq!(
        proof.inputs_hash(),
        inputs_hash,
        "Unexpected inputs hash from proof."
    );
    println!();

    //generate proof off the last proof
    let participation_bits = Some(vec![55, 55, 55, 55]);
    let round = ParticipationRound {
        num: 2,
        participation_root: [Field::TWO; 4],
        participation_count: 7700,
    };
    let epoch_num = round.num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 2nd Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit
        .generate_proof(&ParticipationStateCircuitData {
            round_num: round.num,
            val_state_inputs_hash: validators_state_proof2.inputs_hash(),
            participation_root: round.participation_root,
            participation_count: round.participation_count,
            current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
            validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
            current_participation_root: current_round_data.participation_root,
            current_participation_count: current_round_data.participation_count,
            participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
            previous_proof: Some(proof),
        })
        .unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(
        participation_state_circuit.verify_proof(&proof).is_ok(),
        "Proof failed verification."
    );
    println!(
        "Proved participation state at inputs hash 0x{}",
        to_hex(&proof.inputs_hash())
    );
    println!(
        "validator_epochs_tree_root - {:?}",
        proof.validator_epochs_tree_root()
    );
    println!(
        "participation_rounds_tree_root - {:?}",
        proof.participation_rounds_tree_root()
    );
    validator_epochs_tree.update_epoch(
        epoch_num,
        &validators_state_proof2,
        &validators_tree2,
        &accounts_tree2,
    );
    participation_rounds_tree.update_round(round.clone(), participation_bits);
    assert_eq!(
        proof.validator_epochs_tree_root(),
        validator_epochs_tree.root(),
        "Unexpected validator epochs tree root."
    );
    assert_eq!(
        proof.participation_rounds_tree_root(),
        participation_rounds_tree.root(),
        "Unexpected participation rounds tree root."
    );
    inputs_hash = next_inputs_hash(inputs_hash, round, validators_state_proof2.inputs_hash());
    assert_eq!(
        proof.inputs_hash(),
        inputs_hash,
        "Unexpected inputs hash from proof."
    );
    println!();

    //generate proof off the last proof
    let participation_bits = Some(vec![44, 44, 44, 44]);
    let round = ParticipationRound {
        num: 2,
        participation_root: [Field::TWO, Field::ONE, Field::TWO, Field::ONE],
        participation_count: 7699,
    };
    let epoch_num = round.num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 3rd Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit
        .generate_proof(&ParticipationStateCircuitData {
            round_num: round.num,
            val_state_inputs_hash: validators_state_proof1.inputs_hash(),
            participation_root: round.participation_root,
            participation_count: round.participation_count,
            current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
            validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
            current_participation_root: current_round_data.participation_root,
            current_participation_count: current_round_data.participation_count,
            participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
            previous_proof: Some(proof),
        })
        .unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(
        participation_state_circuit.verify_proof(&proof).is_ok(),
        "Proof failed verification."
    );
    println!(
        "Proved participation state at inputs hash 0x{}",
        to_hex(&proof.inputs_hash())
    );
    println!(
        "validator_epochs_tree_root - {:?}",
        proof.validator_epochs_tree_root()
    );
    println!(
        "participation_rounds_tree_root - {:?}",
        proof.participation_rounds_tree_root()
    );
    validator_epochs_tree.update_epoch(
        epoch_num,
        &validators_state_proof1,
        &validators_tree1,
        &accounts_tree1,
    );
    participation_rounds_tree.update_round(round.clone(), participation_bits);
    assert_eq!(
        proof.validator_epochs_tree_root(),
        validator_epochs_tree.root(),
        "Unexpected validator epochs tree root."
    );
    assert_eq!(
        proof.participation_rounds_tree_root(),
        participation_rounds_tree.root(),
        "Unexpected participation rounds tree root."
    );
    inputs_hash = next_inputs_hash(inputs_hash, round, validators_state_proof1.inputs_hash());
    assert_eq!(
        proof.inputs_hash(),
        inputs_hash,
        "Unexpected inputs hash from proof."
    );
    println!();

    //generate proof off the last proof
    let participation_bits = Some(vec![123, 99]);
    let round = ParticipationRound {
        num: 78923,
        participation_root: [Field::ZERO, Field::ONE, Field::TWO, Field::ZERO],
        participation_count: 100_000,
    };
    let epoch_num = round.num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 4th Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit
        .generate_proof(&ParticipationStateCircuitData {
            round_num: round.num,
            val_state_inputs_hash: validators_state_proof1.inputs_hash(),
            participation_root: round.participation_root,
            participation_count: round.participation_count,
            current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
            validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
            current_participation_root: current_round_data.participation_root,
            current_participation_count: current_round_data.participation_count,
            participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
            previous_proof: Some(proof),
        })
        .unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(
        participation_state_circuit.verify_proof(&proof).is_ok(),
        "Proof failed verification."
    );
    println!(
        "Proved participation state at inputs hash 0x{}",
        to_hex(&proof.inputs_hash())
    );
    println!(
        "validator_epochs_tree_root - {:?}",
        proof.validator_epochs_tree_root()
    );
    println!(
        "participation_rounds_tree_root - {:?}",
        proof.participation_rounds_tree_root()
    );
    validator_epochs_tree.update_epoch(
        epoch_num,
        &validators_state_proof1,
        &validators_tree1,
        &accounts_tree1,
    );
    participation_rounds_tree.update_round(round.clone(), participation_bits);
    assert_eq!(
        proof.validator_epochs_tree_root(),
        validator_epochs_tree.root(),
        "Unexpected validator epochs tree root."
    );
    assert_eq!(
        proof.participation_rounds_tree_root(),
        participation_rounds_tree.root(),
        "Unexpected participation rounds tree root."
    );
    inputs_hash = next_inputs_hash(inputs_hash, round, validators_state_proof1.inputs_hash());
    assert_eq!(
        proof.inputs_hash(),
        inputs_hash,
        "Unexpected inputs hash from proof."
    );
    println!();

    //generate proof off the last proof
    let participation_bits = Some(vec![255, 52, 1]);
    let round = ParticipationRound {
        num: 78923,
        participation_root: [Field::from_canonical_u64(123); 4],
        participation_count: 100_000,
    };
    let epoch_num = round.num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round.num);
    println!("Generating 5th Round Proof...");
    let start = Instant::now();
    let proof = participation_state_circuit
        .generate_proof(&ParticipationStateCircuitData {
            round_num: round.num,
            val_state_inputs_hash: validators_state_proof1.inputs_hash(),
            participation_root: round.participation_root,
            participation_count: round.participation_count,
            current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
            validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
            current_participation_root: current_round_data.participation_root,
            current_participation_count: current_round_data.participation_count,
            participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
            previous_proof: Some(proof),
        })
        .unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(
        participation_state_circuit.verify_proof(&proof).is_ok(),
        "Proof failed verification."
    );
    println!(
        "Proved participation state at inputs hash 0x{}",
        to_hex(&proof.inputs_hash())
    );
    println!(
        "validator_epochs_tree_root - {:?}",
        proof.validator_epochs_tree_root()
    );
    println!(
        "participation_rounds_tree_root - {:?}",
        proof.participation_rounds_tree_root()
    );
    validator_epochs_tree.update_epoch(
        epoch_num,
        &validators_state_proof1,
        &validators_tree1,
        &accounts_tree1,
    );
    participation_rounds_tree.update_round(round.clone(), participation_bits);
    assert_eq!(
        proof.validator_epochs_tree_root(),
        validator_epochs_tree.root(),
        "Unexpected validator epochs tree root."
    );
    assert_eq!(
        proof.participation_rounds_tree_root(),
        participation_rounds_tree.root(),
        "Unexpected participation rounds tree root."
    );
    inputs_hash = next_inputs_hash(inputs_hash, round, validators_state_proof1.inputs_hash());
    assert_eq!(
        proof.inputs_hash(),
        inputs_hash,
        "Unexpected inputs hash from proof."
    );
    println!();
}

fn next_inputs_hash(
    previous_hash: [u8; 32],
    round_update: ParticipationRound,
    val_state_inputs_hash: [u8; 32],
) -> [u8; 32] {
    let mut to_hash = [0u8; 104];
    to_hash[0..32].copy_from_slice(&previous_hash);
    to_hash[32..36].copy_from_slice(&(round_update.num as u32).to_be_bytes());
    to_hash[36..68].copy_from_slice(&val_state_inputs_hash);
    to_hash[68..76].copy_from_slice(
        &round_update.participation_root[0]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[76..84].copy_from_slice(
        &round_update.participation_root[1]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[84..92].copy_from_slice(
        &round_update.participation_root[2]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[92..100].copy_from_slice(
        &round_update.participation_root[3]
            .to_canonical_u64()
            .to_be_bytes(),
    );
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
