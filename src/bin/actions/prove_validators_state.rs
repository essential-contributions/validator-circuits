use std::time::Instant;

use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use sha2::{Digest, Sha256};
use validator_circuits::{accounts::{load_accounts, null_account_address, save_accounts, Account, AccountsTree}, circuits::{load_or_create_circuit, save_proof, validators_state_circuit::{ValidatorsStateCircuitData, ValidatorsStateProof}, Circuit, Proof, VALIDATORS_STATE_CIRCUIT_DIR}, validators::{Validator, ValidatorsTree}, Field};
use validator_circuits::circuits::validators_state_circuit::ValidatorsStateCircuit;

const INITIAL_ACCOUNTS_OUTPUT_FILE: &str = "init_accounts.bin";

pub fn benchmark_prove_validators_state(full: bool) {
    if full {
        log::warn!("Skipping wrapped proof generation as state is an internal proof only (used recursively in other proofs).");
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
    let mut accounts_tree = match load_accounts(INITIAL_ACCOUNTS_OUTPUT_FILE) {
        Ok(t) => {
            println!("(loaded from file)");
            t
        },
        Err(_) => {
            let t = AccountsTree::new();
            println!("(finished in {:?})", start.elapsed());
            if save_accounts(&t, INITIAL_ACCOUNTS_OUTPUT_FILE).is_err() {
                log::warn!("Failed to save accounts tree to file.");
            }
            t
        },
    };
    let mut total_staked = 0;
    let mut total_validators = 0;
    let mut validators_tree = ValidatorsTree::new();
    let mut inputs_hash = [0u8; 32];
    println!();

    //generate the initial proof
    println!("Generating 1st Proof (from initial state)...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = null_account_address(validator_index);
    let to_account = generate_account_address(12791283791);
    let stake = 64;
    let commitment = [Field::ONE, Field::TWO, Field::ZERO, Field::TWO];
    let data = compile_data_for_circuit(
        &accounts_tree,
        &validators_tree,
        validator_index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        None,
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    total_staked = total_staked + stake;
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    total_validators = total_validators + 1;
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    validators_tree.set_validator(validator_index, Validator { commitment_root: commitment, stake });
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    accounts_tree.set_account(Account { address: to_account, validator_index: Some(validator_index) });
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();
    
    //generate proof off the last proof (increase stake)
    println!("Generating 2nd Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = generate_account_address(12791283791);
    let to_account = generate_account_address(12791283791);
    let stake = 96;
    let commitment = [Field::ONE, Field::TWO, Field::ZERO, Field::TWO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    total_staked = total_staked + 32;
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    validators_tree.set_validator(validator_index, Validator { commitment_root: commitment, stake });
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();

    //generate proof off the last proof (stake overtake insufficient)
    println!("Generating 3rd Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = generate_account_address(12791283791);
    let to_account = generate_account_address(987645436);
    let stake = 32;
    let commitment = [Field::TWO, Field::TWO, Field::TWO, Field::TWO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();

    //generate proof off the last proof (normal)
    println!("Generating 4th Round Proof...");
    let start = Instant::now();
    let validator_index = 110;
    let from_account = null_account_address(validator_index);
    let to_account = generate_account_address(5554443332);
    let stake = 512;
    let commitment = [Field::ONE, Field::ONE, Field::ZERO, Field::ZERO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    total_staked = total_staked + stake;
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    total_validators = total_validators + 1;
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    validators_tree.set_validator(validator_index, Validator { commitment_root: commitment, stake });
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    accounts_tree.set_account(Account { address: to_account, validator_index: Some(validator_index) });
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();

    //generate proof off the last proof (stake overtake insufficient because total validators has not maxed yet)
    println!("Generating 5th Round Proof...");
    let start = Instant::now();
    let validator_index = 10;
    let from_account = generate_account_address(12791283791);
    let to_account = generate_account_address(987645436);
    let stake = 128;
    let commitment = [Field::TWO, Field::TWO, Field::TWO, Field::TWO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();

    //generate proof off the last proof (already staked)
    println!("Generating 6th Round Proof...");
    let start = Instant::now();
    let validator_index = 555;
    let from_account = null_account_address(validator_index);
    let to_account = generate_account_address(5554443332);
    let stake = 544;
    let commitment = [Field::ZERO, Field::TWO, Field::ZERO, Field::ZERO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();

    //generate proof off the last proof (unstake)
    println!("Generating 7th Round Proof...");
    let start = Instant::now();
    let validator_index = 110;
    let from_account = generate_account_address(5554443332);
    let to_account = null_account_address(validator_index);
    let stake = 0;
    let commitment = [Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    total_staked = total_staked - 512;
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    total_validators = total_validators - 1;
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    validators_tree.set_validator(validator_index, Validator { commitment_root: commitment, stake });
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    accounts_tree.set_account(Account { address: to_account, validator_index: Some(validator_index) });
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();

    //generate proof off the last proof (already unstaked)
    println!("Generating 8th Round Proof...");
    let start = Instant::now();
    let validator_index = 0; //can pick anything here for the proof
    let from_account = generate_account_address(5554443332);
    let to_account = null_account_address(validator_index);
    let stake = 0;
    let commitment = [Field::ZERO, Field::ZERO, Field::ZERO, Field::ZERO];
    let data = compile_data_for_circuit(
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
    assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Proof failed verification.");
    println!("Proved validators state at inputs hash 0x{}", to_hex(&proof.inputs_hash()));
    assert_eq!(proof.total_staked(), total_staked, "Unexpected total staked value from proof.");
    assert_eq!(proof.total_validators(), total_validators, "Unexpected total validators value from proof.");
    assert_eq!(proof.validators_tree_root(), validators_tree.root(), "Unexpected validators tree root.");
    assert_eq!(proof.accounts_tree_root(), accounts_tree.root(), "Unexpected accounts tree root.");
    inputs_hash = next_inputs_hash(inputs_hash, data);
    assert_eq!(proof.inputs_hash(), inputs_hash, "Unexpected inputs hash from proof.");
    println!("(finished in {:?})", start.elapsed());
    println!("total_staked - {:?}", proof.total_staked());
    println!("total_validators - {:?}", proof.total_validators());
    println!("validators_tree_root - {:?}", proof.validators_tree_root());
    println!("accounts_tree_root - {:?}", proof.accounts_tree_root());
    println!();
    
    //save the last round
    save_proof(&proof.proof(), VALIDATORS_STATE_CIRCUIT_DIR);
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

fn compile_data_for_circuit(
    accounts_tree: &AccountsTree,
    validators_tree: &ValidatorsTree,
    index: usize,
    stake: u32,
    commitment: [Field; 4],
    account: [u8; 20],
    from_account: [u8; 20],
    to_account: [u8; 20],
    previous_proof: Option<ValidatorsStateProof>,
) -> ValidatorsStateCircuitData {
    let curr_validator = validators_tree.validator(index);
    ValidatorsStateCircuitData {
        index,
        stake,
        commitment,
        account,

        validator_index: index,
        validator_stake: curr_validator.stake,
        validator_commitment: curr_validator.commitment_root,
        validator_proof: validators_tree.merkle_proof(index),

        from_account,
        from_acc_index: accounts_tree.account(from_account).validator_index,
        from_acc_proof: accounts_tree.merkle_proof(from_account),

        to_account,
        to_acc_index: accounts_tree.account(to_account).validator_index,
        to_acc_proof: accounts_tree.merkle_proof(to_account),

        previous_proof,
    }
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

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}