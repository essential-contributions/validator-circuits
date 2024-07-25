use std::time::Instant;

use plonky2::field::types::{Field, PrimeField64};
use sha2::{Digest, Sha256};
use validator_circuits::{accounts::{initial_accounts_tree_root, load_accounts, save_accounts, Account, AccountsTree}, circuits::{validators_state_circuit::ValidatorsStateCircuitData, Circuit}, participation::initial_participation_rounds_root, validators::ValidatorsTree};
use validator_circuits::circuits::validators_state_circuit::ValidatorsStateCircuit;

pub fn benchmark_prove_validators_state(full: bool) {
    if full {
        log::warn!("Skipping wrapped proof generation as this is an internal proof only (used recursively in other proofs that need to be wrapped for EVM).");
    }

    //generate the circuits
    println!("Building Circuit... ");
    let start = Instant::now();
    //TODO
    //let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let validators_state_circuit = ValidatorsStateCircuit::new();
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build stake tracking structures
    let mut total_staked = 0;
    let mut total_validators = 0;
    let mut validators_tree = ValidatorsTree::new();
    let mut accounts_tree = match load_accounts() {
        Ok(t) => t,
        Err(_) => {
            let start = Instant::now();
            println!("Building Accounts Tree...");
            let t = AccountsTree::new();
            println!("(finished in {:?})", start.elapsed());
            println!();
            if save_accounts(&t).is_err() {
                log::warn!("Failed to save accounts tree to file.");
            }
            t
        },
    };
    let mut inputs_hash = [0u8; 32];



    //generate the initial proof
    //let round = ValidatorsRound {
    //    num: 32,
    //    state_inputs_hash: [1u8; 32],
    //    validators_root: [Field::ONE; 4],
    //    validators_count: 100,
    //    validators_bits: ValidatorsBits { bit_flags: vec![7, 8, 9, 10] },
    //};
    //let current_round_data = validators_rounds_tree.round(round.num);
    println!("Generating 1st Proof (from initial state)...");
    let start = Instant::now();
    let validator_index = 0;
    let data = ValidatorsStateCircuitData {
        index: validator_index,
        stake: 32,
        commitment: [Field::ONE, Field::TWO, Field::ZERO, Field::TWO],
        account: generate_account_address(12791283791),

        validator_index,
        validator_stake: 0,
        validator_commitment: [Field::ZERO; 4],
        validator_proof: validators_tree.merkle_proof(0),

        from_account: generate_null_account_address(validator_index),
        from_acc_index: Some(validator_index),
        from_acc_proof: accounts_tree.merkle_proof(generate_null_account_address(validator_index)),

        to_account: generate_account_address(12791283791),
        to_acc_index: None,
        to_acc_proof: accounts_tree.merkle_proof(generate_account_address(12791283791)),

        previous_proof: None,
    };
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    //validators_rounds_tree.update_round(round.clone());
    //assert_eq!(proof.validators_rounds_tree_root(), validators_rounds_tree.root(), "Unexpected validators rounds tree root.");
    //inputs_hash = next_inputs_hash(inputs_hash, round);
    //assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    /*
    //generate proof off the last proof
    let round = ValidatorsRound {
        num: 2,
        state_inputs_hash: [1u8; 32],
        validators_root: [Field::TWO; 4],
        validators_count: 7700,
        validators_bits: ValidatorsBits { bit_flags: vec![55, 55, 55, 55] },
    };
    let current_round_data = validators_rounds_tree.round(round.num);
    println!("Generating 2nd Round Proof...");
    let start = Instant::now();
    let proof = validators_state_circuit.generate_proof(&ValidatorsStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        validators_root: round.validators_root,
        validators_count: round.validators_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_validators_root: current_round_data.validators_root,
        current_validators_count: current_round_data.validators_count,
        validators_round_proof: validators_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators update to {:?} (inputs hash: {})", proof.validators_rounds_tree_root(), to_hex(&proof.inputs_hash()));
    validators_rounds_tree.update_round(round.clone());
    assert_eq!(proof.validators_rounds_tree_root(), validators_rounds_tree.root(), "Unexpected validators rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ValidatorsRound {
        num: 2,
        state_inputs_hash: [1u8; 32],
        validators_root: [Field::TWO, Field::ONE, Field::TWO, Field::ONE],
        validators_count: 7699,
        validators_bits: ValidatorsBits { bit_flags: vec![44, 44, 44, 44] },
    };
    let current_round_data = validators_rounds_tree.round(round.num);
    println!("Generating 3rd Round Proof...");
    let start = Instant::now();
    let proof = validators_state_circuit.generate_proof(&ValidatorsStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        validators_root: round.validators_root,
        validators_count: round.validators_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_validators_root: current_round_data.validators_root,
        current_validators_count: current_round_data.validators_count,
        validators_round_proof: validators_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators update to {:?} (inputs hash: {})", proof.validators_rounds_tree_root(), to_hex(&proof.inputs_hash()));
    validators_rounds_tree.update_round(round.clone());
    assert_eq!(proof.validators_rounds_tree_root(), validators_rounds_tree.root(), "Unexpected validators rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ValidatorsRound {
        num: 78923,
        state_inputs_hash: [89u8; 32],
        validators_root: [Field::ZERO, Field::ONE, Field::TWO, Field::ZERO],
        validators_count: 100_000,
        validators_bits: ValidatorsBits { bit_flags: vec![123, 99] },
    };
    let current_round_data = validators_rounds_tree.round(round.num);
    println!("Generating 4th Round Proof...");
    let start = Instant::now();
    let proof = validators_state_circuit.generate_proof(&ValidatorsStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        validators_root: round.validators_root,
        validators_count: round.validators_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_validators_root: current_round_data.validators_root,
        current_validators_count: current_round_data.validators_count,
        validators_round_proof: validators_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators update to {:?} (inputs hash: {})", proof.validators_rounds_tree_root(), to_hex(&proof.inputs_hash()));
    validators_rounds_tree.update_round(round.clone());
    assert_eq!(proof.validators_rounds_tree_root(), validators_rounds_tree.root(), "Unexpected validators rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    
    //generate proof off the last proof
    let round = ValidatorsRound {
        num: 78923,
        state_inputs_hash: [89u8; 32],
        validators_root: [Field::from_canonical_u64(123); 4],
        validators_count: 100_000,
        validators_bits: ValidatorsBits { bit_flags: vec![255, 52, 1] },
    };
    let current_round_data = validators_rounds_tree.round(round.num);
    println!("Generating 5th Round Proof...");
    let start = Instant::now();
    let proof = validators_state_circuit.generate_proof(&ValidatorsStateCircuitData {
        round_num: round.num,
        state_inputs_hash: round.state_inputs_hash,
        validators_root: round.validators_root,
        validators_count: round.validators_count,
        current_state_inputs_hash: current_round_data.state_inputs_hash,
        current_validators_root: current_round_data.validators_root,
        current_validators_count: current_round_data.validators_count,
        validators_round_proof: validators_rounds_tree.merkle_proof(round.num),
        previous_proof: Some(proof),
    }).unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators update to {:?} (inputs hash: {})", proof.validators_rounds_tree_root(), to_hex(&proof.inputs_hash()));
    validators_rounds_tree.update_round(round.clone());
    assert_eq!(proof.validators_rounds_tree_root(), validators_rounds_tree.root(), "Unexpected validators rounds tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, round);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!();
    */

    //TODO
    //save_proof(&proof.proof(), VALIDATORS_STATE_CIRCUIT_DIR);
}

fn generate_account_address(seed: u64) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_be_bytes());
    let result = hasher.finalize();
    let hash: [u8; 32] = result.into();

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[0..20]);
    address
}

fn generate_null_account_address(validator_index: usize) -> [u8; 20] {
    let mut address = [0u8; 20];
    address[16..20].copy_from_slice(&(validator_index as u32).to_be_bytes());
    address
}

fn next_inputs_hash(previous_hash: [u8; 32], data: ValidatorsStateCircuitData) -> [u8; 32] {
    let mut to_hash = [0u8; 104];
    to_hash[0..32].copy_from_slice(&previous_hash);
    to_hash[32..36].copy_from_slice(&(data.index as u32).to_be_bytes());
    to_hash[36..40].copy_from_slice(&(data.stake as u32).to_be_bytes());
    to_hash[40..48].copy_from_slice(&data.commitment[0].to_canonical_u64().to_be_bytes());
    to_hash[48..56].copy_from_slice(&data.commitment[1].to_canonical_u64().to_be_bytes());
    to_hash[56..64].copy_from_slice(&data.commitment[2].to_canonical_u64().to_be_bytes());
    to_hash[64..72].copy_from_slice(&data.commitment[3].to_canonical_u64().to_be_bytes());
    to_hash[72..92].copy_from_slice(&data.account);
    
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