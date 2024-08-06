use std::time::Instant;

use validator_circuits::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, participation_state_circuit::ParticipationStateCircuit, validator_participation_circuit::{ValidatorParticipationCircuit, ValidatorParticipationCircuitData}, validators_state_circuit::ValidatorsStateCircuit, Circuit, Proof, PARTICIPATION_STATE_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR, VALIDATOR_PARTICIPATION_CIRCUIT_DIR}, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}};

use crate::actions::{build_participation_state, build_validators_state};

const VALIDATORS_STATE_OUTPUT_FILE: &str = "validator_participation_validators_state_proof.json";
const PARTICIPATION_STATE_OUTPUT_FILE: &str = "validator_participation_participation_state_proof.json";

pub fn benchmark_validator_prove_participation(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(VALIDATOR_PARTICIPATION_CIRCUIT_DIR) || !groth16_wrapper_circuit_data_exists(VALIDATOR_PARTICIPATION_CIRCUIT_DIR) {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            panic!();
        }
    }

    //generate the circuits
    println!("Building Validator Participation Circuit...");
    let start = Instant::now();
    let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let participation_state_circuit = load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    let validator_participation_circuit = load_or_create_circuit::<ValidatorParticipationCircuit>(VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proof for validator state
    println!("Building Validators State Data...");
    let start = Instant::now();
    let accounts = [[11u8; 20], [22u8; 20], [66u8; 20]];
    let validator_indexes = [10, 22, 66];
    let stakes = [64, 128, 32];
    let (validators_tree, 
        accounts_tree, 
        validators_state_proof,
    ) = build_validators_state(
        &validators_state_circuit,
        &accounts,
        &validator_indexes,
        &stakes,
        VALIDATORS_STATE_OUTPUT_FILE,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proof for participation state
    println!("Building Participation State Data...");
    let start = Instant::now();
    let (validator_epochs_tree,
        participation_rounds_tree, 
        participation_state_proof,
    ) = build_participation_state(
        &participation_state_circuit,
        &validators_state_proof,
        &validators_tree.validators(),
        &accounts_tree.accounts(),
        &validator_indexes[0..2],
        &[32, 48, 67, 100],
        PARTICIPATION_STATE_OUTPUT_FILE,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proofs for participation
    println!("Generating Proof (account with no participation)...");
    let start: Instant = Instant::now();
    let bad_account = [13u8; 20];
    let proof = validator_participation_circuit.generate_proof(
        &ValidatorParticipationCircuitData {
            account_address: bad_account,
            from_epoch: 0,
            to_epoch: 1,
            rf: 13093,
            st: 84,
            participation_state_proof: participation_state_proof.clone(),
        },
        &validator_epochs_tree,
        &participation_rounds_tree,
    ).unwrap();
    assert!(validator_participation_circuit.verify_proof(&proof).is_ok(), "Validators state proof verification failed.");
    println!("(finished in {:?})", start.elapsed());
    println!("Proved validator participation at inputs hash 0x{}", to_hex(&proof.participation_inputs_hash()));
    println!("account_address - 0x{}", to_hex(&proof.account_address()));
    println!("from_epoch - {:?}", proof.from_epoch());
    println!("to_epoch - {:?}", proof.to_epoch());
    println!("withdraw_max - {:?}", proof.withdraw_max());
    println!("withdraw_unearned - {:?}", proof.withdraw_unearned());
    println!("param_rf - {:?}", proof.param_rf());
    println!("param_st - {:?}", proof.param_st());
    println!();

    //build proofs for participation
    println!("Generating Proof (account with missing participation)...");
    let start: Instant = Instant::now();
    let missing_account = accounts[2];
    let proof = validator_participation_circuit.generate_proof(
        &ValidatorParticipationCircuitData {
            account_address: missing_account,
            from_epoch: 0,
            to_epoch: 1,
            rf: 13093,
            st: 84,
            participation_state_proof: participation_state_proof.clone(),
        },
        &validator_epochs_tree,
        &participation_rounds_tree,
    ).unwrap();
    assert!(validator_participation_circuit.verify_proof(&proof).is_ok(), "Validators state proof verification failed.");
    println!("(finished in {:?})", start.elapsed());
    println!("Proved validator participation at inputs hash 0x{}", to_hex(&proof.participation_inputs_hash()));
    println!("account_address - 0x{}", to_hex(&proof.account_address()));
    println!("from_epoch - {:?}", proof.from_epoch());
    println!("to_epoch - {:?}", proof.to_epoch());
    println!("withdraw_max - {:?}", proof.withdraw_max());
    println!("withdraw_unearned - {:?}", proof.withdraw_unearned());
    println!("param_rf - {:?}", proof.param_rf());
    println!("param_st - {:?}", proof.param_st());
    println!();

    //build proofs for participation
    println!("Generating Proof for Multiple Epochs...");
    let start: Instant = Instant::now();
    let proof = validator_participation_circuit.generate_proof(
        &ValidatorParticipationCircuitData {
            account_address: accounts[0],
            from_epoch: 0,
            to_epoch: 2,
            rf: 13093,
            st: 84,
            participation_state_proof: participation_state_proof.clone(),
        },
        &validator_epochs_tree,
        &participation_rounds_tree,
    ).unwrap();
    assert!(validator_participation_circuit.verify_proof(&proof).is_ok(), "Validators state proof verification failed.");
    println!("(finished in {:?})", start.elapsed());
    println!("Proved validator participation at inputs hash 0x{}", to_hex(&proof.participation_inputs_hash()));
    println!("account_address - 0x{}", to_hex(&proof.account_address()));
    println!("from_epoch - {:?}", proof.from_epoch());
    println!("to_epoch - {:?}", proof.to_epoch());
    println!("withdraw_max - {:?}", proof.withdraw_max());
    println!("withdraw_unearned - {:?}", proof.withdraw_unearned());
    println!("param_rf - {:?}", proof.param_rf());
    println!("param_st - {:?}", proof.param_st());
    println!();
    
    if full {
        let inner_circuit = validator_participation_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(inner_circuit, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
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
        save_bn128_wrapper_proof(&proof, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
        let proof = generate_groth16_wrapper_proof(VALIDATOR_PARTICIPATION_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}
