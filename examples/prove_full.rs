mod utils;
use crate::utils::commitment_reveal;
use crate::utils::generate_validator_set;

use validator_circuits::BatchProof;
use validator_circuits::CommitmentReveal;
use validator_circuits::ValidatorCircuits;
use validator_circuits::AGGREGATOR_BATCH_SIZE;
use validator_circuits::REVEAL_BATCH_SIZE;
use std::time::Duration;
use std::time::Instant;


fn main() {
    //generate the circuits
    println!("Building Circuits... ");
    let start = Instant::now();
    let circuits = ValidatorCircuits::build();
    println!("(finished in {:?})", start.elapsed());
    println!("");

    //create a quick validator set
    let validators = generate_validator_set(circuits);

    //generate multiple batch proofs
    let block_slot = 100;
    let mut batch_proofs: Vec<BatchProof> = vec![];
    let mut total_batch_time: Duration = Duration::ZERO;
    for i in 0..AGGREGATOR_BATCH_SIZE {
        //create commitment reveals to batch together
        let reveals: Vec<CommitmentReveal> = ((REVEAL_BATCH_SIZE*i)..(REVEAL_BATCH_SIZE*(i+1))).map(|i| commitment_reveal(i, block_slot)).collect();
        
        //generate proof for batch of reveals
        println!("Generating Proof for Batch {} of {}... ", i + 1, AGGREGATOR_BATCH_SIZE);
        let start = Instant::now();
        let proof = validators.prove_batch(reveals).unwrap();
        let elapsed = start.elapsed();
        total_batch_time += elapsed;
        println!("(finished in {:?})", elapsed);
        batch_proofs.push(proof);
    }
    println!("");

    //generate aggregate proof for all batches
    println!("Generating Aggregate Proof...");
    let start = Instant::now();
    let proof = validators.prove_full(batch_proofs).unwrap();
    let elapsed = start.elapsed();
    println!("(finished in {:?})", elapsed);
    if validators.verify_full(&proof).is_ok() {
        println!("Proved a total validation stake of {} for slot {} with validator root [{:?}]!", proof.total_stake(), proof.block_slot(), proof.validators_root());
    } else {
        println!("Proof failed verification");
    }
    println!("");
    println!("(total proof generation time: {:?}))", elapsed + total_batch_time);
}
