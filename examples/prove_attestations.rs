mod utils;
use crate::utils::commitment_reveal;
use crate::utils::generate_validator_set;

use validator_circuits::calculate_participation_root;
use validator_circuits::AttestationsAggregator1Data;
use validator_circuits::AttestationsAggregator1Proof;
use validator_circuits::AttestationsAggregator1RevealData;
use validator_circuits::AttestationsAggregator1ValidatorData;
use validator_circuits::AttestationsAggregator2Agg1Data;
use validator_circuits::AttestationsAggregator2Data;
use validator_circuits::AttestationsAggregator2Proof;
use validator_circuits::AttestationsAggregator3Agg2Data;
use validator_circuits::AttestationsAggregator3Data;
use validator_circuits::AttestationsAggregator3Proof;
use validator_circuits::Field;
use validator_circuits::ValidatorCircuits;
use validator_circuits::ValidatorSet;
use validator_circuits::AGGREGATION_PASS1_SUB_TREE_HEIGHT;
use validator_circuits::AGGREGATION_PASS2_SUB_TREE_HEIGHT;
use validator_circuits::ATTESTATION_AGGREGATION_PASS1_SIZE;
use validator_circuits::ATTESTATION_AGGREGATION_PASS2_SIZE;
use validator_circuits::ATTESTATION_AGGREGATION_PASS3_SIZE;
use validator_circuits::MAX_PARTICIPANTS;
use std::time::Instant;
use anyhow::*;


fn main() {
    //generate the circuits
    println!("Building Circuits... ");
    let start = Instant::now();
    let circuits = ValidatorCircuits::build();
    println!("(finished in {:?})", start.elapsed());
    println!();

    //create a quick validator set
    println!("Generating Test Validator Set... ");
    let start = Instant::now();
    let validators = generate_validator_set(circuits);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //generatep roofs
    let block_slot = 100;
    let num_attestations = 1000;
    let agg1_proof = attestations_aggregator1_proof(&validators, block_slot, num_attestations).unwrap();
    let agg2_proof = attestations_aggregator2_proof(&validators, &agg1_proof).unwrap();
    let agg3_proof = attestations_aggregator3_proof(&validators, &agg2_proof).unwrap();

    //done
    println!(
        "Proved a total validation stake of {} from {} validators for slot {} with validator root [{:?}] and participation root [{:?}]!", 
        agg3_proof.total_stake(), 
        agg3_proof.num_participants(), 
        agg3_proof.block_slot(), 
        agg3_proof.validators_root(),
        agg3_proof.participation_root(),
    );
    println!("expected validator root: {:?}", validators.root());
    println!("expected participation root: {:?}", participation_root(num_attestations));
}

fn attestations_aggregator1_proof(validators: &ValidatorSet, block_slot: usize, num_attestations: usize) -> Result<AttestationsAggregator1Proof> {
    //create data for proving
    let validators_data: Vec<AttestationsAggregator1ValidatorData> = (0..ATTESTATION_AGGREGATION_PASS1_SIZE).map(|i| {
        let validator = validators.validator(i);
        if i < num_attestations {
            let reveal = commitment_reveal(i, block_slot);
            AttestationsAggregator1ValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: Some(AttestationsAggregator1RevealData {
                    reveal: reveal.reveal,
                    reveal_proof: reveal.proof,
                }),
            }
        } else {
            AttestationsAggregator1ValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: None,
            }
        }
    }).collect();
    let data = AttestationsAggregator1Data {
        block_slot,
        validators: validators_data,
    };

    //generate proof for batch of attestations
    println!("Generating Attestation Aggregation1 Proof...");
    let start = Instant::now();
    let proof = validators.circuits().generate_attestations_aggregator1_proof(&data).unwrap();
    println!("(finished in {:?})", start.elapsed());
    println!();
    if validators.circuits().verify_attestations_aggregator1_proof(&proof).is_ok() {
        Ok(proof)
    } else {
        Err(anyhow!("Proof failed verification"))
    }
}

fn attestations_aggregator2_proof(validators: &ValidatorSet, agg1_proof: &AttestationsAggregator1Proof) -> Result<AttestationsAggregator2Proof> {
    let num_aggragations = 1;

    //create data for proving
    let block_slot = agg1_proof.block_slot();
    let agg1_data: Vec<AttestationsAggregator2Agg1Data> = (0..ATTESTATION_AGGREGATION_PASS2_SIZE).map(|i| {
        if i < num_aggragations {
            AttestationsAggregator2Agg1Data {
                validators_sub_root: agg1_proof.validators_sub_root().clone(),
                agg1_proof: Some(agg1_proof.clone()),
            }
        } else {
            AttestationsAggregator2Agg1Data {
                validators_sub_root: validators.sub_root(AGGREGATION_PASS1_SUB_TREE_HEIGHT, i).clone(),
                agg1_proof: None,
            }
        }
    }).collect();
    let data = AttestationsAggregator2Data {
        block_slot,
        agg1_data,
    };

    //generate proof for batch of attestations
    println!("Generating Attestation Aggregation2 Proof...");
    let start = Instant::now();
    let proof = validators.circuits().generate_attestations_aggregator2_proof(&data).unwrap();
    println!("(finished in {:?})", start.elapsed());
    println!();
    if validators.circuits().verify_attestations_aggregator2_proof(&proof).is_ok() {
        Ok(proof)
    } else {
        Err(anyhow!("Proof failed verification"))
    }
}

fn attestations_aggregator3_proof(validators: &ValidatorSet, agg2_proof: &AttestationsAggregator2Proof) -> Result<AttestationsAggregator3Proof> {
    let num_aggragations = 1;

    //create data for proving
    let block_slot = agg2_proof.block_slot();
    let agg2_data: Vec<AttestationsAggregator3Agg2Data> = (0..ATTESTATION_AGGREGATION_PASS3_SIZE).map(|i| {
        if i < num_aggragations {
            AttestationsAggregator3Agg2Data {
                validators_sub_root: agg2_proof.validators_sub_root().clone(),
                agg2_proof: Some(agg2_proof.clone()),
            }
        } else {
            let height = AGGREGATION_PASS1_SUB_TREE_HEIGHT + AGGREGATION_PASS2_SUB_TREE_HEIGHT;
            AttestationsAggregator3Agg2Data {
                validators_sub_root: validators.sub_root(height, i).clone(),
                agg2_proof: None,
            }
        }
    }).collect();
    let data = AttestationsAggregator3Data {
        block_slot,
        agg2_data,
    };

    //generate proof for batch of attestations
    println!("Generating Attestation Aggregation3 Proof...");
    let start = Instant::now();
    let proof = validators.circuits().generate_attestations_aggregator3_proof(&data).unwrap();
    println!("(finished in {:?})", start.elapsed());
    println!();
    if validators.circuits().verify_attestations_aggregator3_proof(&proof).is_ok() {
        Ok(proof)
    } else {
        Err(anyhow!("Proof failed verification"))
    }
}

fn participation_root(to: usize) -> [Field; 4] {
    let mut bytes: Vec<u8> = vec![0u8; MAX_PARTICIPANTS / 8];

    let full_bytes = to / 8;
    for i in 0..full_bytes {
        bytes[i] = 0xff;
    }

    let remainder = to - (full_bytes * 8);
    bytes[full_bytes] = 0xff << (8 - remainder);

    calculate_participation_root(&bytes)
}