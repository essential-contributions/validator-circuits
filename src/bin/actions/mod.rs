mod commitment_generation;
mod prove_validators_state;
mod prove_participation_state;
mod prove_validator_participation;
mod prove_attestation_aggregation;

pub use commitment_generation::*;
pub use prove_validators_state::*;
pub use prove_participation_state::*;
pub use prove_validator_participation::*;
pub use prove_attestation_aggregation::*;

use validator_circuits::{accounts::{load_accounts, null_account_address, save_accounts, Account, AccountsTree}, circuits::{load_proof, participation_state_circuit::{ParticipationStateCircuit, ParticipationStateCircuitData, ParticipationStateProof}, save_proof, validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateCircuitData, ValidatorsStateProof}, Circuit, Proof}, commitment::example_commitment_root, epochs::ValidatorEpochsTree, participation::{participation_root, ParticipationRound, ParticipationRoundsTree, PARTICIPATION_BITS_BYTE_SIZE}, validators::{Validator, ValidatorsTree}, Field, PARTICIPATION_ROUNDS_PER_STATE_EPOCH};

pub const BENCHMARKING_DATA_DIR: [&str; 2] = ["data", "benchmarking"];
pub const INITIAL_ACCOUNTS_OUTPUT_FILE: &str = "init_accounts.bin";

pub fn build_initial_accounts_tree() -> AccountsTree {
    match load_accounts(&BENCHMARKING_DATA_DIR, INITIAL_ACCOUNTS_OUTPUT_FILE) {
        Ok(tree) => tree,
        Err(_) => {
            println!("  building accounts tree");
            let tree = AccountsTree::new();
            if save_accounts(&tree, &BENCHMARKING_DATA_DIR, INITIAL_ACCOUNTS_OUTPUT_FILE).is_err() {
                log::warn!("Failed to save accounts tree to file.");
            }
            tree
        },
    }
}

pub fn build_validators_state(
    validators_state_circuit: &ValidatorsStateCircuit,
    accounts: &[[u8; 20]],
    validator_indexes: &[usize],
    stakes: &[u32],
    quick_load_filename: &str,
) -> (
    ValidatorsTree, //validators_tree
    AccountsTree, //accounts_tree
    ValidatorsStateProof //validators_state_proof
) {
    let mut validators_tree = ValidatorsTree::new();
    let mut accounts_tree = build_initial_accounts_tree();

    let validators_state_proof = match load_proof(&BENCHMARKING_DATA_DIR, quick_load_filename) {
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
            if save_proof(&proof.proof(), &BENCHMARKING_DATA_DIR, quick_load_filename).is_err() {
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

pub fn build_participation_state(
    participation_state_circuit: &ParticipationStateCircuit,
    validators_state_proof: &ValidatorsStateProof,
    validators: &[Validator],
    accounts: &[Account],
    participating_validator_indexes: &[usize],
    rounds: &[usize],
    quick_load_filename: &str,
) -> (
    ValidatorEpochsTree, //validator_epochs_tree
    ParticipationRoundsTree, //participation_rounds_tree
    ParticipationStateProof //participation_state_proof
) {
    let mut validator_epochs_tree = ValidatorEpochsTree::new();
    let mut participation_rounds_tree = ParticipationRoundsTree::new();

    let mut bit_flags: Vec<u8> = vec![0u8; PARTICIPATION_BITS_BYTE_SIZE];
    for validator_index in participating_validator_indexes {
        bit_flags[validator_index / 8] += 0x80 >> (validator_index % 8);
    }

    let participation_state_proof = match load_proof(&BENCHMARKING_DATA_DIR, quick_load_filename) {
        Ok(proof) => {
            for num in rounds {
                let epoch_num = num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
                validator_epochs_tree.update_epoch(epoch_num, validators_state_proof.clone(), validators, accounts);

                let participation_root = participation_root(&bit_flags);
                participation_rounds_tree.update_round(ParticipationRound {
                    num: *num,
                    participation_root,
                    participation_count: participating_validator_indexes.len() as u32,
                }, Some(bit_flags.clone()));
            }
            ParticipationStateProof::from_proof(proof)
        },
        Err(_) => {
            let mut previous_proof: Option<ParticipationStateProof> = None;
            for num in rounds {
                println!("  building proof");
                let epoch_num = num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
                let round = ParticipationRound {
                    num: *num,
                    participation_root: participation_root(&bit_flags),
                    participation_count: participating_validator_indexes.len() as u32,
                };
                let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
                let current_round_data = participation_rounds_tree.round(round.num);
                let proof = participation_state_circuit.generate_proof(&ParticipationStateCircuitData {
                    round_num: round.num,
                    val_state_inputs_hash: validators_state_proof.inputs_hash(),
                    participation_root: round.participation_root,
                    participation_count: round.participation_count,
                    current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
                    validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
                    current_participation_root: current_round_data.participation_root,
                    current_participation_count: current_round_data.participation_count,
                    participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
                    previous_proof,
                }).unwrap();
                assert!(participation_state_circuit.verify_proof(&proof).is_ok(), "Participation state proof verification failed.");
                validator_epochs_tree.update_epoch(epoch_num, validators_state_proof.clone(), validators, accounts);
                participation_rounds_tree.update_round(round.clone(), Some(bit_flags.clone()));
                previous_proof = Some(proof);
            }
            let proof = previous_proof.unwrap();
            if save_proof(&proof.proof(), &BENCHMARKING_DATA_DIR, quick_load_filename).is_err() {
                log::warn!("Failed to save participation state proof to file.");
            }
            proof
        },
    };    
    
    (
        validator_epochs_tree, //validator_epochs_tree
        participation_rounds_tree, //participation_rounds_tree
        participation_state_proof, //participation_state_proof
    )
}

pub fn compile_data_for_validators_state_circuit(
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
