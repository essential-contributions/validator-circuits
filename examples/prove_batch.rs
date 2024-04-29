mod utils;
use crate::utils::commitment_reveal;
use crate::utils::generate_validator_set;

use validator_circuits::CommitmentReveal;
use validator_circuits::ValidatorCircuits;
use validator_circuits::REVEAL_BATCH_SIZE;
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

    //create commitment reveals to batch together
    let block_slot = 100;
    let reveals: Vec<CommitmentReveal> = (0..REVEAL_BATCH_SIZE).map(|i| commitment_reveal(i, block_slot)).collect();

    //generate proof for batch of reveals
    println!("Generating Proof for Batch...");
    let start = Instant::now();
    let proof = validators.prove_batch(reveals).unwrap();
    println!("(finished in {:?})", start.elapsed());
    if validators.verify_batch(&proof).is_ok() {
        println!("Proved a total validation stake of {} for slot {} with validator root [{:?}]!", proof.total_stake(), proof.block_slot(), proof.validators_root());
    } else {
        println!("Proof failed verification");
    }
}
