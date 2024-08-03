use std::time::Instant;

use validator_circuits::{accounts::{load_accounts, null_account_address, save_accounts, Account, AccountsTree}, bn128_wrapper::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, load_proof, participation_state_circuit::{ParticipationStateCircuit, ParticipationStateCircuitData, ParticipationStateProof}, save_proof, validator_participation_circuit::{ValidatorParticipationCircuit, ValidatorParticipationCircuitData}, validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateCircuitData, ValidatorsStateProof}, Circuit, Proof, PARTICIPATION_STATE_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR, VALIDATOR_PARTICIPATION_CIRCUIT_DIR}, commitment::example_commitment_root, groth16_wrapper::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}, participation::{participation_root, ParticipationRound, ParticipationRoundsTree, PARTICIPATION_BITS_BYTE_SIZE}, validators::{Validator, ValidatorsTree}, Field};

const BENCHMARKING_DATA_DIR: [&str; 2] = ["data", "benchmarking"];
const INITIAL_ACCOUNTS_OUTPUT_FILE: &str = "init_accounts.bin";
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
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proof for participation state
    println!("Building Participation State Data...");
    let start = Instant::now();
    let (participation_rounds_tree, 
        participation_state_proof,
    ) = build_participation_state(
        &participation_state_circuit,
        &validator_indexes[0..2],
        validators_state_proof.inputs_hash(),
        &[32, 48, 67, 100],
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
            validators_state_proof: validators_state_proof.clone(),
            participation_state_proof: participation_state_proof.clone(),
        },
        &validators_tree,
        &accounts_tree,
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
            validators_state_proof: validators_state_proof.clone(),
            participation_state_proof: participation_state_proof.clone(),
        },
        &validators_tree,
        &accounts_tree,
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
            validators_state_proof: validators_state_proof.clone(),
            participation_state_proof: participation_state_proof.clone(),
        },
        &validators_tree,
        &accounts_tree,
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
        save_bn128_wrapper_proof(&proof, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        let proof = generate_groth16_wrapper_proof(VALIDATOR_PARTICIPATION_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();
        println!("{}", proof);
    }
}

fn build_validators_state(
    validators_state_circuit: &ValidatorsStateCircuit,
    accounts: &[[u8; 20]],
    validator_indexes: &[usize],
    stakes: &[u32],
) -> (
    ValidatorsTree, //validators_tree
    AccountsTree, //accounts_tree
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
        accounts_tree, //accounts_tree
        validators_state_proof, //validators_state_proof
    )
}

fn build_participation_state(
    participation_state_circuit: &ParticipationStateCircuit,
    validator_indexes: &[usize],
    state_inputs_hash: [u8; 32],
    rounds: &[usize],
) -> (
    ParticipationRoundsTree, //participation_rounds_tree
    ParticipationStateProof //participation_state_proof
) {
    let mut participation_rounds_tree = ParticipationRoundsTree::new();
    let mut bit_flags: Vec<u8> = vec![0u8; PARTICIPATION_BITS_BYTE_SIZE];
    for validator_index in validator_indexes {
        bit_flags[validator_index / 8] += 0x80 >> (validator_index % 8);
    }

    let participation_state_proof = match load_proof(&BENCHMARKING_DATA_DIR, PARTICIPATION_STATE_OUTPUT_FILE) {
        Ok(proof) => {
            for num in rounds {
                participation_rounds_tree.update_round(ParticipationRound {
                    num: *num,
                    state_inputs_hash,
                    participation_root: participation_root(&bit_flags),
                    participation_count: validator_indexes.len() as u32,
                    participation_bits: Some(bit_flags.clone()),
                });
            }
            ParticipationStateProof::from_proof(proof)
        },
        Err(_) => {
            let mut previous_proof: Option<ParticipationStateProof> = None;
            for num in rounds {
                println!("  building proof");
                let round = ParticipationRound {
                    num: *num,
                    state_inputs_hash,
                    participation_root: participation_root(&bit_flags),
                    participation_count: validator_indexes.len() as u32,
                    participation_bits: Some(bit_flags.clone()),
                };
                let current_round_data = participation_rounds_tree.round(round.num);
                let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
                    round_num: round.num,
                    state_inputs_hash: round.state_inputs_hash,
                    participation_root: round.participation_root,
                    participation_count: round.participation_count,
                    current_state_inputs_hash: current_round_data.state_inputs_hash,
                    current_participation_root: current_round_data.participation_root,
                    current_participation_count: current_round_data.participation_count,
                    participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
                    previous_proof,
                }).unwrap();
                assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Participation state proof verification failed.");
                participation_rounds_tree.update_round(round.clone());
                previous_proof = Some(proof);
            }
            let proof = previous_proof.unwrap();
            if save_proof(&proof.proof(), &BENCHMARKING_DATA_DIR, PARTICIPATION_STATE_OUTPUT_FILE).is_err() {
                log::warn!("Failed to save participation state proof to file.");
            }
            proof
        },
    };    
    
    (
        participation_rounds_tree, //accounts_tree
        participation_state_proof, //participation_state_proof
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
