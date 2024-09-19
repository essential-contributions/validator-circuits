use std::time::Instant;

use plonky2::field::types::PrimeField64;
use sha2::{Digest, Sha256};
use validator_circuits::circuits::attestation_aggregation_circuit::AttestationAggregationCircuit;
use validator_circuits::{
    circuits::wrappers::{
        bn128_wrapper_circuit_data_exists, load_or_create_bn128_wrapper_circuit,
        save_bn128_wrapper_proof,
    },
    circuits::wrappers::{generate_groth16_wrapper_proof, groth16_wrapper_circuit_data_exists},
    circuits::{
        attestation_aggregation_circuit::AttestationAggregatorProof, load_or_create_circuit,
        validators_state_circuit::ValidatorsStateCircuit, Circuit, Proof,
        ATTESTATION_AGGREGATION_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR,
    },
    commitment::example_commitment_proof,
    participation::participation_root,
    validators::ValidatorCommitmentReveal,
    Field, MAX_VALIDATORS,
};

use crate::actions::build_validators_state;

const VALIDATORS_STATE_OUTPUT_FILE: &str = "attestation_aggregation_validators_state.proof";

pub fn benchmark_prove_attestation_aggregation(full: bool) {
    //make sure circuits have been built
    if full {
        if !bn128_wrapper_circuit_data_exists(ATTESTATION_AGGREGATION_CIRCUIT_DIR)
            || !groth16_wrapper_circuit_data_exists(ATTESTATION_AGGREGATION_CIRCUIT_DIR)
        {
            log::error!("Cannot generate full wrapped proof until circuits are built.");
            log::error!("Please run the build util and try again. [cargo run --release --bin cbuild -- --full]");
            panic!();
        }
    }

    //generate the circuits
    println!("Building Atestation Aggregation Circuit(s)... ");
    let start = Instant::now();
    let attestation_agg_circuit = load_or_create_circuit::<AttestationAggregationCircuit>(
        ATTESTATION_AGGREGATION_CIRCUIT_DIR,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build proof for validator state
    println!("Building Validators State Data...");
    let start = Instant::now();
    let validators_state_circuit =
        load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    let accounts = [
        [11u8; 20], [22u8; 20], [33u8; 20], [44u8; 20], [55u8; 20], [66u8; 20],
    ];
    let validator_indexes = [21, 22, 23, 24, 25, 26];
    let stakes = [64, 64, 64, 32, 32, 32];
    let (validators_tree, _, validators_state_proof) = build_validators_state(
        &validators_state_circuit,
        &accounts,
        &validator_indexes,
        &stakes,
        VALIDATORS_STATE_OUTPUT_FILE,
    );
    println!("(finished in {:?})", start.elapsed());
    println!();

    //build reveal data
    let block_slot = 100;
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

    //prove
    println!("Generating Proof...");
    let start = Instant::now();
    let proof = attestation_agg_circuit
        .generate_proof(&validators_state_proof, &reveals, &validators_tree)
        .unwrap();
    println!("(finished in {:?})", start.elapsed());
    assert!(
        verify_public_inputs_hash(&proof),
        "Unexpected public inputs hash from proof."
    );
    assert_eq!(
        proof.participation_root(),
        calculate_participation_root(&validator_indexes),
        "Unexpected participation root from proof."
    );
    println!(
        "Proved attestations at inputs hash 0x{}",
        to_hex(&proof.validators_inputs_hash())
    );
    println!("total_staked - {:?}", proof.total_staked());
    println!("block_slot - {:?}", proof.block_slot());
    println!("participation_root - {:?}", proof.participation_root());
    println!("participation_count - {:?}", proof.participation_count());
    println!("attestations_stake - {:?}", proof.attestations_stake());
    println!();

    if full {
        let inner_circuit = attestation_agg_circuit.circuit_data();
        let inner_proof = proof.proof();

        //wrap proof to bn128
        println!("Building BN128 Wrapper Circuit... ");
        let start = Instant::now();
        let bn128_wrapper = load_or_create_bn128_wrapper_circuit(
            inner_circuit,
            ATTESTATION_AGGREGATION_CIRCUIT_DIR,
        );
        println!("(finished in {:?})", start.elapsed());
        println!();

        println!("Generating BN128 Wrapper Proof...");
        let start = Instant::now();
        let bn128_proof = bn128_wrapper
            .generate_proof(inner_circuit, inner_proof)
            .unwrap();
        println!("(finished in {:?})", start.elapsed());
        assert!(
            bn128_wrapper.verify_proof(&bn128_proof).is_ok(),
            "BN128 wrapped proof verification failed."
        );
        println!();

        //wrap proof to groth16
        println!("Generating Groth16 Wrapper Proof...");
        let start = Instant::now();
        save_bn128_wrapper_proof(&bn128_proof, ATTESTATION_AGGREGATION_CIRCUIT_DIR);
        let groth16_proof =
            generate_groth16_wrapper_proof(ATTESTATION_AGGREGATION_CIRCUIT_DIR).unwrap();
        println!("Proved with Groth16 wrapper!");
        println!("(finished in {:?})", start.elapsed());
        println!();

        //print final proof
        for i in 0..13 {
            println!("\"0x{}\",", to_hex(&groth16_proof[i]));
        }
        println!();
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
    }
}

fn calculate_participation_root(validator_indexes: &[usize]) -> [Field; 4] {
    let mut bytes: Vec<u8> = vec![0u8; MAX_VALIDATORS / 8];
    for validator_index in validator_indexes {
        bytes[validator_index / 8] += 0x80 >> (validator_index % 8);
    }
    participation_root(&bytes)
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

fn verify_public_inputs_hash(proof: &AttestationAggregatorProof) -> bool {
    let mut public_inputs_hash = [0u8; 32];
    for i in 0..4 {
        let bytes = proof.public_inputs_hash()[i]
            .to_canonical_u64()
            .to_be_bytes();
        public_inputs_hash[(i * 8)..((i * 8) + 8)].copy_from_slice(&bytes);
    }

    //manually hash
    let mut to_hash = [0u8; 88];
    to_hash[0..32].copy_from_slice(&proof.validators_inputs_hash());
    to_hash[32..40].copy_from_slice(&proof.total_staked().to_be_bytes());
    to_hash[40..44].copy_from_slice(&(proof.block_slot() as u32).to_be_bytes());
    to_hash[44..52].copy_from_slice(
        &proof.participation_root()[0]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[52..60].copy_from_slice(
        &proof.participation_root()[1]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[60..68].copy_from_slice(
        &proof.participation_root()[2]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[68..76].copy_from_slice(
        &proof.participation_root()[3]
            .to_canonical_u64()
            .to_be_bytes(),
    );
    to_hash[76..80].copy_from_slice(&(proof.participation_count() as u32).to_be_bytes());
    to_hash[80..88].copy_from_slice(&proof.attestations_stake().to_be_bytes());
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
