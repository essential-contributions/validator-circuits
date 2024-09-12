use std::time::Instant;

use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use validator_circuits::circuits::validators_state_circuit::ValidatorsStateCircuit;
use validator_circuits::{
    accounts::{initial_accounts_tree, null_account_address, Account, AccountsTree},
    circuits::wrappers::{
        bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit,
        save_bn128_wrapper_proof, BN128WrapperCircuit,
    },
    circuits::wrappers::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists},
    circuits::{
        attestation_aggregation_circuit::AttestationAggregationCircuit,
        load_or_create_circuit, load_or_create_init_proof,
        participation_state_circuit::{
            ParticipationStateCircuit, ParticipationStateCircuitData, ParticipationStateProof,
        },
        validator_participation_circuit::{
            ValidatorParticipationCircuit, ValidatorParticipationCircuitData,
        },
        validators_state_circuit::ValidatorsStateProof,
        Circuit, Proof, ATTESTATION_AGGREGATION_CIRCUIT_DIR, PARTICIPATION_STATE_CIRCUIT_DIR,
        VALIDATORS_STATE_CIRCUIT_DIR, VALIDATOR_PARTICIPATION_CIRCUIT_DIR,
    },
    commitment::{example_commitment_proof, example_commitment_root},
    epochs::{initial_validator_epochs_tree, ValidatorEpochsTree},
    participation::{
        initial_participation_rounds_tree, ParticipationRound, ParticipationRoundsTree,
        PARTICIPATION_BITS_BYTE_SIZE,
    },
    validators::{initial_validators_tree, Validator, ValidatorCommitmentReveal, ValidatorsTree},
    Field, MAX_VALIDATORS, PARTICIPATION_ROUNDS_PER_STATE_EPOCH,
};

use crate::actions::compile_data_for_validators_state_circuit;

pub const ACCOUNT0: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
pub const ACCOUNT1: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
pub const ACCOUNT2: &str = "0x90F79bf6EB2c4f870365E785982E1f101E93b906";
pub const ACCOUNT3: &str = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";
pub const ACCOUNT4: &str = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc";
pub const ACCOUNT5: &str = "0x976EA74026E726554dB657fA54763abd0C3a0aa9";
pub const ACCOUNT6: &str = "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955";
pub const ACCOUNT7: &str = "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f";

pub fn create_example_proofs() {
    if !bn128_wrapper_circuit_data_exists(VALIDATOR_PARTICIPATION_CIRCUIT_DIR)
        || !groth16_wrapper_circuit_data_exists(VALIDATOR_PARTICIPATION_CIRCUIT_DIR)
        || !bn128_wrapper_circuit_data_exists(ATTESTATION_AGGREGATION_CIRCUIT_DIR)
        || !groth16_wrapper_circuit_data_exists(ATTESTATION_AGGREGATION_CIRCUIT_DIR)
    {
        log::error!("Cannot generate full wrapped proof until circuits are built.");
        log::error!(
            "Please run the build util and try again. [cargo run --release --bin cbuild -- --full]"
        );
        panic!();
    }

    //generate the circuits
    println!("Loading Circuits... ");
    let start = Instant::now();
    let validators_state_circuit =
        load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let participation_state_circuit =
        load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    let attestation_agg_circuit = load_or_create_circuit::<AttestationAggregationCircuit>(
        ATTESTATION_AGGREGATION_CIRCUIT_DIR,
    );
    let attestation_agg_bn128_wrapper = load_or_create_bn128_wrapper_circuit(
        attestation_agg_circuit.circuit_data(),
        ATTESTATION_AGGREGATION_CIRCUIT_DIR,
    );
    let validator_participation_circuit = load_or_create_circuit::<ValidatorParticipationCircuit>(
        VALIDATOR_PARTICIPATION_CIRCUIT_DIR,
    );
    let validator_participation_bn128_wrapper = load_or_create_bn128_wrapper_circuit(
        validator_participation_circuit.circuit_data(),
        VALIDATOR_PARTICIPATION_CIRCUIT_DIR,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build stake tracking structures
    println!("Building State Tracking Structures...");
    let start = Instant::now();
    let mut validators_tree = initial_validators_tree();
    let mut accounts_tree = initial_accounts_tree();
    let mut validator_epochs_tree = initial_validator_epochs_tree();
    let mut participation_rounds_tree = initial_participation_rounds_tree();
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build initial proofs
    println!("Building State Tracking Structures...");
    let start = Instant::now();
    let validators_proof =
        load_or_create_init_proof::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let participation_proof =
        load_or_create_init_proof::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //prove initial stake actions
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT0,
        0,
        16,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT1,
        1,
        16,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT2,
        2,
        128,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT3,
        3,
        128,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT4,
        4,
        128,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT5,
        5,
        16,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    println!();

    //generate fast finality proof
    let participation_proof = action_fast_finality(
        &attestation_agg_circuit,
        &attestation_agg_bn128_wrapper,
        &participation_state_circuit,
        16418,
        &[0, 1, 2, 3, 4, 5],
        &validators_proof,
        Some(participation_proof),
        &validators_tree,
        &accounts_tree,
        &mut validator_epochs_tree,
        &mut participation_rounds_tree,
    );
    println!();

    //generate fast finality proof
    let participation_proof = action_fast_finality(
        &attestation_agg_circuit,
        &attestation_agg_bn128_wrapper,
        &participation_state_circuit,
        16546,
        &[0, 1, 2, 3, 4],
        &validators_proof,
        Some(participation_proof),
        &validators_tree,
        &accounts_tree,
        &mut validator_epochs_tree,
        &mut participation_rounds_tree,
    );
    println!();

    //generate fast finality proof
    let participation_proof = action_fast_finality(
        &attestation_agg_circuit,
        &attestation_agg_bn128_wrapper,
        &participation_state_circuit,
        16674,
        &[0, 1, 2, 3, 4],
        &validators_proof,
        Some(participation_proof),
        &validators_tree,
        &accounts_tree,
        &mut validator_epochs_tree,
        &mut participation_rounds_tree,
    );
    println!();

    //prove two more bad stake action
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT6,
        0,
        8,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_stake(
        &validators_state_circuit,
        ACCOUNT7,
        1,
        32,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    println!();

    //prove unstake actions
    let validators_proof = action_unstake(
        &validators_state_circuit,
        ACCOUNT6,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_unstake(
        &validators_state_circuit,
        ACCOUNT7,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    println!();

    //generate participation proof for invalid assertions
    prove_validator_participation(
        &validator_participation_circuit,
        &validator_participation_bn128_wrapper,
        ACCOUNT3,
        2,
        3,
        &participation_proof,
        &validator_epochs_tree,
        &participation_rounds_tree,
    );
    println!();

    //generate participation proof for inactivity
    prove_validator_participation(
        &validator_participation_circuit,
        &validator_participation_bn128_wrapper,
        ACCOUNT5,
        2,
        4,
        &participation_proof,
        &validator_epochs_tree,
        &participation_rounds_tree,
    );
    println!();

    //inactive validator eviction (unstake)
    let validators_proof = action_unstake(
        &validators_state_circuit,
        ACCOUNT5,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    println!();

    //two unstakes
    let validators_proof = action_unstake(
        &validators_state_circuit,
        ACCOUNT1,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    let validators_proof = action_unstake(
        &validators_state_circuit,
        ACCOUNT2,
        Some(validators_proof),
        &mut validators_tree,
        &mut accounts_tree,
    );
    println!();

    println!(
        "validators_inputs_hash: 0x{})",
        to_hex(&validators_proof.inputs_hash())
    );
    println!(
        "participation_inputs_hash: 0x{})",
        to_hex(&participation_proof.inputs_hash())
    );
}

fn action_stake(
    validators_state_circuit: &ValidatorsStateCircuit,
    account: &str,
    index: usize,
    stake: u32,
    previous_proof: Option<ValidatorsStateProof>,
    validators_tree: &mut ValidatorsTree,
    accounts_tree: &mut AccountsTree,
) -> ValidatorsStateProof {
    let from_account = accounts_tree.account_with_index(index).unwrap().address;
    let to_account = account_address(account);
    let null_account = null_account_address(index);
    let commitment = example_commitment_root(index);
    println!(
        "Computing Stake Action... (commitment 0x{})",
        to_hex_from_fields(&commitment)
    );
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        index,
        stake,
        commitment,
        to_account,
        from_account,
        to_account,
        previous_proof.clone(),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();

    //update tress only if this is a valid stake action
    let stake_increase = stake > validators_tree.validator(index).stake;
    let same_account = from_account == to_account;
    let to_acc_index_is_null = accounts_tree.account(to_account).validator_index.is_none();
    let from_acc_is_null = from_account == null_account;
    let validators_at_max = previous_proof.is_some()
        && previous_proof.unwrap().total_validators() == (MAX_VALIDATORS as u32);
    if stake_increase
        && (same_account || from_acc_is_null || validators_at_max)
        && (same_account || to_acc_index_is_null)
    {
        validators_tree.set_validator(
            index,
            Validator {
                commitment_root: commitment,
                stake,
            },
        );
        accounts_tree.set_account(Account {
            address: to_account,
            validator_index: Some(index),
        });
    }

    proof
}

fn action_unstake(
    validators_state_circuit: &ValidatorsStateCircuit,
    account: &str,
    previous_proof: Option<ValidatorsStateProof>,
    validators_tree: &mut ValidatorsTree,
    accounts_tree: &mut AccountsTree,
) -> ValidatorsStateProof {
    let from_account = account_address(account);
    let index = accounts_tree
        .account(from_account)
        .validator_index
        .unwrap_or(0);
    let to_account = null_account_address(index);
    println!("Computing Unstake Action...");
    let data = compile_data_for_validators_state_circuit(
        &accounts_tree,
        &validators_tree,
        index,
        0,
        [Field::ZERO; 4],
        from_account,
        from_account,
        to_account,
        previous_proof.clone(),
    );
    let proof = validators_state_circuit.generate_proof(&data).unwrap();

    //update tress only if this is a valid unstake action
    let from_acc_index_is_not_null = accounts_tree
        .account(from_account)
        .validator_index
        .is_some();
    if from_acc_index_is_not_null {
        validators_tree.set_validator(
            index,
            Validator {
                commitment_root: [Field::ZERO; 4],
                stake: 0,
            },
        );
        accounts_tree.set_account(Account {
            address: to_account,
            validator_index: Some(index),
        });
    }

    proof
}

fn action_fast_finality(
    attestation_agg_circuit: &AttestationAggregationCircuit,
    attestation_agg_bn128_wrapper: &BN128WrapperCircuit,
    participation_state_circuit: &ParticipationStateCircuit,
    block_slot: usize,
    validator_indexes: &[usize],
    validators_state_proof: &ValidatorsStateProof,
    previous_proof: Option<ParticipationStateProof>,
    validators_tree: &ValidatorsTree,
    accounts_tree: &AccountsTree,
    validator_epochs_tree: &mut ValidatorEpochsTree,
    participation_rounds_tree: &mut ParticipationRoundsTree,
) -> ParticipationStateProof {
    //generate attestation proof all the way to wrapped groth16
    let reveals = validator_indexes
        .iter()
        .map(|&validator_index| {
            let commitment_proof = example_commitment_proof(validator_index);
            ValidatorCommitmentReveal {
                validator_index,
                block_slot,
                reveal: commitment_proof.reveal,
                proof: commitment_proof.proof,
            }
        })
        .collect();
    println!("Aggregating Attestations...");
    let proof = attestation_agg_circuit
        .generate_proof(validators_state_proof, &reveals, &validators_tree)
        .unwrap();
    println!("(wrapping to bn128...)");
    let bn128_proof = attestation_agg_bn128_wrapper
        .generate_proof(attestation_agg_circuit.circuit_data(), proof.proof())
        .unwrap();
    println!("(wrapping to groth16...)");
    save_bn128_wrapper_proof(&bn128_proof, ATTESTATION_AGGREGATION_CIRCUIT_DIR);
    let groth16_proof =
        generate_groth16_wrapper_proof(ATTESTATION_AGGREGATION_CIRCUIT_DIR).unwrap();

    //print the proof
    for i in 0..13 {
        println!("\"0x{}\",", to_hex(&groth16_proof[i]));
    }
    println!(
        "\"validatorInputsHash\": \"0x{}\",",
        to_hex(&proof.validators_inputs_hash())
    );
    println!("\"totalStaked\": {},", proof.total_staked());
    println!("\"blockSlot\": {},", proof.block_slot());
    println!(
        "\"participationRoot\": \"0x{}\",",
        to_hex_from_fields(&proof.participation_root())
    );
    println!("\"participationCount\": {},", proof.participation_count());
    println!("\"attestationsStake\": {},", proof.attestations_stake());
    println!();

    //update the participation state
    println!("Computing Submit Fast Finality Action...");
    let round_num = block_slot / 128;
    let epoch_num = round_num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
    let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
    let current_round_data = participation_rounds_tree.round(round_num);
    let participation_proof = participation_state_circuit
        .generate_proof(&ParticipationStateCircuitData {
            round_num,
            val_state_inputs_hash: validators_state_proof.inputs_hash(),
            participation_root: proof.participation_root(),
            participation_count: proof.participation_count() as u32,
            current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
            validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
            current_participation_root: current_round_data.participation_root,
            current_participation_count: current_round_data.participation_count,
            participation_round_proof: participation_rounds_tree.merkle_proof(round_num),
            previous_proof,
        })
        .unwrap();

    //update tress for participation
    let round = ParticipationRound {
        num: round_num,
        participation_root: proof.participation_root(),
        participation_count: proof.participation_count() as u32,
    };
    let mut participation_bits: Vec<u8> = vec![0u8; PARTICIPATION_BITS_BYTE_SIZE];
    for validator_index in validator_indexes {
        participation_bits[validator_index / 8] += 0x80 >> (validator_index % 8);
    }
    validator_epochs_tree.update_epoch(
        epoch_num,
        &validators_state_proof,
        &validators_tree,
        &accounts_tree,
    );
    participation_rounds_tree.update_round(round.clone(), Some(participation_bits));

    participation_proof
}

fn prove_validator_participation(
    validator_participation_circuit: &ValidatorParticipationCircuit,
    validator_participation_bn128_wrapper: &BN128WrapperCircuit,
    account: &str,
    from_epoch: u32,
    to_epoch: u32,
    participation_state_proof: &ParticipationStateProof,
    validator_epochs_tree: &ValidatorEpochsTree,
    participation_rounds_tree: &ParticipationRoundsTree,
) {
    println!("Proving Validator Participation...");
    let proof = validator_participation_circuit
        .generate_proof(
            &ValidatorParticipationCircuitData {
                account_address: account_address(account),
                from_epoch,
                to_epoch,
                rf: 13093,
                st: 84,
                participation_state_proof: participation_state_proof.clone(),
            },
            validator_epochs_tree,
            participation_rounds_tree,
        )
        .unwrap();
    println!("(wrapping to bn128...)");
    let bn128_proof = validator_participation_bn128_wrapper
        .generate_proof(
            validator_participation_circuit.circuit_data(),
            proof.proof(),
        )
        .unwrap();
    println!("(wrapping to groth16...)");
    save_bn128_wrapper_proof(&bn128_proof, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
    let groth16_proof =
        generate_groth16_wrapper_proof(VALIDATOR_PARTICIPATION_CIRCUIT_DIR).unwrap();

    //print final proof
    for i in 0..13 {
        println!("\"0x{}\",", to_hex(&groth16_proof[i]));
    }
    println!(
        "\"participationInputsHash\": \"0x{}\",",
        to_hex(&proof.participation_inputs_hash())
    );
    println!("\"account\": \"0x{}\",", to_hex(&proof.account_address()));
    println!("\"fromEpoch\": {},", proof.from_epoch());
    println!("\"toEpoch\": {},", proof.to_epoch());
    println!("\"withdrawMax\": {},", proof.withdraw_max());
    println!("\"withdrawUnearned\": {},", proof.withdraw_unearned());
    println!("\"rf\": {},", proof.param_rf());
    println!("\"st\": {},", proof.param_st());
}

fn account_address(address: &str) -> [u8; 20] {
    let hex_str = address.strip_prefix("0x").unwrap_or(&address);
    let hex_str = format!("{:0>40}", hex_str);

    let mut bytes = [0u8; 20];
    for i in 0..20 {
        bytes[i] =
            u8::from_str_radix(&hex_str[(i * 2)..((i + 1) * 2)], 16).expect("Invalid hex string");
    }
    bytes
}

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}

fn to_hex_from_fields(fileds: &[Field]) -> String {
    let hex_string: String = fileds
        .iter()
        .map(|f| format!("{:016x}", f.to_canonical_u64()))
        .collect();
    hex_string
}
