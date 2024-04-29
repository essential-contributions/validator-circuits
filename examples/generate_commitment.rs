use validator_circuits::Commitment;
use std::time::Instant;

fn main() {
    println!("Generating Commitment...");
    let start = Instant::now();
    let commitment = Commitment::from_rnd();
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_root: {:?}", commitment.root());
}
