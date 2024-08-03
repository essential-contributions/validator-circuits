use std::time::Instant;

use validator_circuits::{accounts::{load_accounts, null_account_address, save_accounts, Account, AccountsTree}, bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, load_proof, save_proof, validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateCircuitData, ValidatorsStateProof}, Circuit, Proof, ATTESTATION_AGGREGATION_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR}, commitment::{example_commitment_proof, example_commitment_root}, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}, participation::participation_root, validators::{Validator, ValidatorCommitmentReveal, ValidatorsTree}, Field, MAX_VALIDATORS};
use validator_circuits::circuits::attestation_aggregation_circuit::AttestationAggregationCircuit;

const BENCHMARKING_DATA_DIR: [&str; 2] = ["data", "benchmarking"];
const INITIAL_ACCOUNTS_OUTPUT_FILE: &str = "init_accounts.bin";
const VALIDATORS_STATE_OUTPUT_FILE: &str = "attestation_aggregation_validators_state_proof.json";

pub fn benchmark_prove_attestation_aggregation(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(ATTESTATION_AGGREGATION_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(ATTESTATION_AGGREGATION_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            panic!();
        }
    }

    //generate the circuits
    println!("Building Atestation Aggregation Circuit(s)... ");
    let start = Instant::now();
    let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let attestation_agg_circuit = load_or_create_circuit::<AttestationAggregationCircuit>(ATTESTATION_AGGREGATION_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proof for validator state
    println!("Building Validators State Data...");
    let start = Instant::now();
    let accounts = [[11u8; 20], [22u8; 20], [33u8; 20], [44u8; 20], [55u8; 20], [66u8; 20]];
    let validator_indexes = [21, 22, 23, 24, 25, 26];
    let stakes = [64, 64, 64, 32, 32, 32];
    let (validators_tree, 
        validators_state_proof,
    ) = build_validators_state(
        &validators_state_circuit,
        &accounts,
        &validator_indexes,
        &stakes,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build reveal data
    let block_slot = 100;
    let reveals = validator_indexes.iter().map(|&validator_index| {
        let commitment_proof = example_commitment_proof(validator_index);
        ValidatorCommitmentReveal {
            validator_index,
            block_slot,
            reveal: commitment_proof.reveal,
            proof: commitment_proof.proof,
        }
    }).collect();

    //prove
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = attestation_agg_circuit.generate_proof(&validators_state_proof, &reveals, &validators_tree).unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert_eq!(proof.participation_root(), calculate_participation_root(&validator_indexes), "Unexpected participation root from proof.");
    println!("Proved attestations at inputs hash 0x{}", to_hex(&proof.validator_inputs_hash()));
    println!("participation_root - {:?}", proof.participation_root());
    println!("num_participants - {:?}", proof.num_participants());
    println!("block_slot - {:?}", proof.block_slot());
    println!("total_stake - {:?}", proof.total_stake());
    println!();

    if full {
        let inner_circuit = attestation_agg_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, ATTESTATION_AGGREGATION_CIRCUIT_DIR);
        println!("(finished in {:?})", start.elapsed());
        println!();

        println!("Generating BN128 Wrapper Proof...");
        let start = Instant::now();
        let proof = bn128_wrapper.generate_proof(inner_circuit, inner_proof).unwrap();
        println!("(finished in {:?})", start.elapsed());
        assert!(bn128_wrapper.verify_proof(&proof).is_ok(), "BN128 wrapped proof verification failed.");
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        save_bn128_wrapper_proof(&proof, ATTESTATION_AGGREGATION_CIRCUIT_DIR);
        let proof = generate_groth16_wrapper_proof(ATTESTATION_AGGREGATION_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
}

fn calculate_participation_root(validator_indexes: &[usize]) -> [Field; 4] {
    let mut bytes: Vec<u8> = vec![0u8; MAX_VALIDATORS / 8];
    for validator_index in validator_indexes {
        bytes[validator_index / 8] += 0x80 >> (validator_index % 8);
    }
    participation_root(&bytes)
}

fn build_validators_state(
    validators_state_circuit: &ValidatorsStateCircuit,
    accounts: &[[u8; 20]],
    validator_indexes: &[usize],
    stakes: &[u32],
) -> (
    ValidatorsTree, //validators_tree
    ValidatorsStateProof //validators_state_proof
) {
    let mut validators_tree = ValidatorsTree::new();
    let mut accounts_tree = match load_accounts(&BENCHMARKING_DATA_DIR, INITIAL_ACCOUNTS_OUTPUT_FILE) {
        Ok(tree) => tree,
        Err(_) => {
            println!("  building accounts tree");
            let tree = AccountsTree::new();
            if save_accounts(&tree, &BENCHMARKING_DATA_DIR, INITIAL_ACCOUNTS_OUTPUT_FILE).is_err() {
                log::warn!("Failed to save accounts tree to file.");
            }
            tree
        },
    };

    let validators_state_proof = match load_proof(&BENCHMARKING_DATA_DIR, VALIDATORS_STATE_OUTPUT_FILE) {
        Ok(proof) => {
            for ((&account, &validator_index), &stake) in accounts.iter().zip(validator_indexes).zip(stakes) {
                let commitment_root = example_commitment_root(validator_index);
                validators_tree.set_validator(validator_index, Validator { commitment_root, stake });
                accounts_tree.set_account(Account { address: account, validator_index: Some(validator_index) });
            }
            ValidatorsStateProof::from_proof(proof)
        },
        Err(_) => {
            let mut previous_proof: Option<ValidatorsStateProof> = None;
            for ((&account, &validator_index), &stake) in accounts.iter().zip(validator_indexes).zip(stakes) {
                println!("  building proof");
                let commitment = example_commitment_root(validator_index);
                let data = compile_data_for_validators_state_circuit(
                    &accounts_tree,
                    &validators_tree,
                    validator_index,
                    stake,
                    commitment,
                    account,
                    null_account_address(validator_index),
                    account,
                    previous_proof,
                );
                let proof = validators_state_circuit.generate_proof(&data).unwrap();
                assert!(validators_state_circuit.verify_proof(&proof).is_ok(), "Validators state proof verification failed.");
                validators_tree.set_validator(validator_index, Validator { commitment_root: commitment, stake });
                accounts_tree.set_account(Account { address: account, validator_index: Some(validator_index) });
                previous_proof = Some(proof);
            }
            let proof = previous_proof.unwrap();
            if save_proof(&proof.proof(), &BENCHMARKING_DATA_DIR, VALIDATORS_STATE_OUTPUT_FILE).is_err() {
                log::warn!("Failed to save validators state proof to file.");
            }
            proof
        },
    };
            
    (
        validators_tree, //validators_tree
        validators_state_proof, //validators_state_proof
    )
}

fn compile_data_for_validators_state_circuit(
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

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}
