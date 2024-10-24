use std::time::Instant;

use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use sha2::{Digest, Sha256};
use validator_circuits::accounts::AccountsTree;
use validator_circuits::circuits::validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateProof};
use validator_circuits::validators::ValidatorsTree;
use validator_circuits::{
    accounts::{initial_accounts_tree, null_account_address, Account},
    circuits::{
        load_or_create_circuit, load_or_create_init_proof, validators_state_circuit::ValidatorsStateCircuitData,
        Circuit, VALIDATORS_STATE_CIRCUIT_DIR,
    },
    validators::{initial_validators_tree, Validator},
    Field,
};

use crate::actions::compile_data_for_validators_state_circuit;

pub fn benchmark_prove_validators_state(full: bool) {
    if full {
        log::warn!(
            "Skipping wrapped proof generation as state is an internal proof only (used recursively in other proofs)."
        );
    }

    //generate the circuits
    println!("Building Validators State Circuit... ");
    let start = Instant::now();
    let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build stake tracking structures
    println!("Building Accounts Tree...");
    let start = Instant::now();
    let mut total_staked = 0;
    let mut total_validators = 0;
    let mut validators_tree = initial_validators_tree();
    let mut accounts_tree = initial_accounts_tree();
    let mut inputs_hash = [0u8; 32];
    println!("(finished in {:?})", start.elapsed());
    println!();

    //generate the initial proof
    println!("Building Initial Proof...");
    let start = Instant::now();
    let proof = load_or_create_init_proof::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    println!();

    //generate the first real proof
    println!("Generating 1st Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = null_account_address(validator_index);
    let to_account = generate_account_address(12791283791);
    let stake = 64;
    let commitment = [Field::ONE, Field::TWO, Field::ZERO, Field::TWO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    total_staked = total_staked + (stake as u64);
    total_validators = total_validators + 1;
    validators_tree.set_validator(
        validator_index,
        Validator {
            commitment_root: commitment,
            stake,
        },
    );
    accounts_tree.set_account(Account {
        address: to_account,
        validator_index: Some(validator_index),
    });
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (increase stake)
    println!("Generating 2nd Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = generate_account_address(12791283791);
    let to_account = generate_account_address(12791283791);
    let stake = 96;
    let commitment = [Field::ONE, Field::TWO, Field::ZERO, Field::TWO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    total_staked = total_staked + 32;
    validators_tree.set_validator(
        validator_index,
        Validator {
            commitment_root: commitment,
            stake,
        },
    );
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (stake overtake insufficient)
    println!("Generating 3rd Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = generate_account_address(12791283791);
    let to_account = generate_account_address(987645436);
    let stake = 32;
    let commitment = [Field::TWO, Field::TWO, Field::TWO, Field::TWO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (normal)
    println!("Generating 4th Round Proof...");
    let start = Instant::now();
    let validator_index = 110;
    let from_account = null_account_address(validator_index);
    let to_account = generate_account_address(5554443332);
    let stake = 512;
    let commitment = [Field::ONE, Field::ONE, Field::ZERO, Field::ZERO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    total_staked = total_staked + (stake as u64);
    total_validators = total_validators + 1;
    validators_tree.set_validator(
        validator_index,
        Validator {
            commitment_root: commitment,
            stake,
        },
    );
    accounts_tree.set_account(Account {
        address: to_account,
        validator_index: Some(validator_index),
    });
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (stake overtake insufficient because total validators has not maxed yet)
    println!("Generating 5th Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = generate_account_address(12791283791);
    let to_account = generate_account_address(987645436);
    let stake = 128;
    let commitment = [Field::TWO, Field::TWO, Field::TWO, Field::TWO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (already staked)
    println!("Generating 6th Round Proof...");
    let start = Instant::now();
    let validator_index = 555;
    let from_account = null_account_address(validator_index);
    let to_account = generate_account_address(5554443332);
    let stake = 544;
    let commitment = [Field::ZERO, Field::TWO, Field::ZERO, Field::ZERO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (unstake)
    println!("Generating 7th Round Proof...");
    let start = Instant::now();
    let validator_index = 110;
    let from_account = generate_account_address(5554443332);
    let to_account = null_account_address(validator_index);
    let stake = 0;
    let commitment = [Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        from_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    total_staked = total_staked - 512;
    total_validators = total_validators - 1;
    validators_tree.set_validator(
        validator_index,
        Validator {
            commitment_root: commitment,
            stake,
        },
    );
    accounts_tree.set_account(Account {
        address: to_account,
        validator_index: Some(validator_index),
    });
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();

    //generate proof off the last proof (already unstaked)
    println!("Generating 8th Round Proof...");
    let start = Instant::now();
    let validator_index = 0; //can pick anything here for the proof
    let from_account = generate_account_address(5554443332);
    let to_account = null_account_address(validator_index);
    let stake = 0;
    let commitment = [Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO];
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        from_account,
        from_account,
        to_account,
        Some(proof),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    inputs_hash = next_inputs_hash(inputs_hash, data);
    println!("(finished in {:?})", start.elapsed());
    assert_state(
        &validators_state_circuit,
        &proof,
        total_staked,
        total_validators,
        &validators_tree,
        &accounts_tree,
        inputs_hash,
    );
    print_proof(&proof);
    println!();
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

fn next_inputs_hash(previous_hash: [u8; 32], data: ValidatorsStateCircuitData) -> [u8; 32] {
    let mut to_hash = [0u8; 92];
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

fn assert_state(
    circuit: &ValidatorsStateCircuit,
    proof: &ValidatorsStateProof,
    total_staked: u64,
    total_validators: u32,
    validators_tree: &ValidatorsTree,
    accounts_tree: &AccountsTree,
    inputs_hash: [u8; 32],
) {
    assert!(circuit.verify_proof(proof).is_ok(), "Proof failed verification.");
    assert_eq!(
        proof.total_staked(),
        total_staked,
        "Unexpected total staked value from proof."
    );
    assert_eq!(
        proof.total_validators(),
        total_validators,
        "Unexpected total validators value from proof."
    );
    assert_eq!(
        proof.validators_tree_root(),
        validators_tree.root(),
        "Unexpected validators tree root."
    );
    assert_eq!(
        proof.accounts_tree_root(),
        accounts_tree.root(),
        "Unexpected accounts tree root."
    );
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
}

fn print_proof(proof: &ValidatorsStateProof) {
    println!(
        "Proved validators state at inputs hash 0x{}",
        to_hex(&proof.inputs_hash())
    );
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
}

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}
