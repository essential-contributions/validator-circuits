use std::time::Instant;

use validator_circuits::commitment::{load_commitment, save_commitment, Commitment};

pub fn benchmark_commitment_generation() {
    println!("Generating Commitment...");
    let start = Instant::now();
    let commitment = Commitment::from_rnd();
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_root: {:?}", commitment.root());
    println!();

    println!("Generating Commitment Reveal...");
    let start = Instant::now();
    let reveal = commitment.reveal(100);
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_reveal: {:?}", reveal.reveal);
    println!();

    println!("Loading Commitment from File...");
    save_commitment(&commitment).expect("failed to save commitment file");
    let start = Instant::now();
    let commitment = load_commitment().unwrap();
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_root: {:?}", commitment.root());
}
