use std::time::Instant;

use plonky2::field::types::PrimeField64;
use sha2::{Digest, Sha256};
use validator_circuits::{circuits::wrappers::{bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{load_or_create_circuit, participation_state_circuit::ParticipationStateCircuit, validator_participation_circuit::{ValidatorParticipationCircuit, ValidatorParticipationCircuitData, ValidatorParticipationProof}, validators_state_circuit::ValidatorsStateCircuit, Circuit, Proof, PARTICIPATION_STATE_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR, VALIDATOR_PARTICIPATION_CIRCUIT_DIR}, circuits::wrappers::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists}};

use crate::actions::{build_participation_state, build_validators_state};

const VALIDATORS_STATE_OUTPUT_FILE: &str = "validator_participation_validators_state.proof";
const PARTICIPATION_STATE_OUTPUT_FILE: &str = "validator_participation_participation_state.proof";

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
        &validators_tree,
        &accounts_tree,
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
    assert!(verify_public_inputs_hash(&proof), "Unexpected public inputs hash from proof.");
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
    assert!(verify_public_inputs_hash(&proof), "Unexpected public inputs hash from proof.");
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
    assert!(verify_public_inputs_hash(&proof), "Unexpected public inputs hash from proof.");
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
        let bn128_proof = bn128_wrapper.generate_proof(inner_circuit, inner_proof).unwrap();
        println!("(finished in {:?})", start.elapsed());
        assert!(bn128_wrapper.verify_proof(&bn128_proof).is_ok(), "BN128 wrapped proof verification failed.");
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        save_bn128_wrapper_proof(&bn128_proof, VALIDATOR_PARTICIPATION_CIRCUIT_DIR);
        let groth16_proof = generate_groth16_wrapper_proof(VALIDATOR_PARTICIPATION_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();

        //print final proof
        for i in 0..13 {
            println!("\"0x{}\",", to_hex(&groth16_proof[i]));
        }
        println!();
        println!("\"participationInputsHash\": \"0x{}\",", to_hex(&proof.participation_inputs_hash()));
        println!("\"account\": \"0x{}\",", to_hex(&proof.account_address()));
        println!("\"fromEpoch\": {},", proof.from_epoch());
        println!("\"toEpoch\": {},", proof.to_epoch());
        println!("\"withdrawMax\": {},", proof.withdraw_max());
        println!("\"withdrawUnearned\": {},", proof.withdraw_unearned());
        println!("\"rf\": {},", proof.param_rf());
        println!("\"st\": {},", proof.param_st());
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}

fn verify_public_inputs_hash(proof: &ValidatorParticipationProof) -> bool {
    let mut public_inputs_hash = [0u8; 32];
    for i in 0..4 {
        let bytes = proof.public_inputs_hash()[i].to_canonical_u64().to_be_bytes();
        public_inputs_hash[(i * 8)..((i * 8) + 8)].copy_from_slice(&bytes);
    }

    //manually hash
    let mut to_hash = [0u8; 84];
    to_hash[0..32].copy_from_slice(&proof.participation_inputs_hash());
    to_hash[32..52].copy_from_slice(&proof.account_address());
    to_hash[52..56].copy_from_slice(&proof.from_epoch().to_be_bytes());
    to_hash[56..60].copy_from_slice(&proof.to_epoch().to_be_bytes());
    to_hash[60..68].copy_from_slice(&proof.withdraw_max().to_be_bytes());
    to_hash[68..76].copy_from_slice(&proof.withdraw_unearned().to_be_bytes());
    to_hash[76..80].copy_from_slice(&proof.param_rf().to_be_bytes());
    to_hash[80..84].copy_from_slice(&proof.param_st().to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&to_hash);
    let result = hasher.finalize();
    let computed_hash: [u8; 32] = result.into();

    //apply mask to hash
    let mut masked_hash = computed_hash;
    masked_hash[0] = masked_hash[0] & 0x7f;
    masked_hash[8] = masked_hash[8] & 0x7f;
    masked_hash[16] = masked_hash[16] & 0x7f;
    masked_hash[24] = masked_hash[24] & 0x7f;

    public_inputs_hash == masked_hash
}
