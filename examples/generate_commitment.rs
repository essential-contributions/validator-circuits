use validator_circuits::Commitment;
use std::time::Instant;
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    println!("Generating Commitment...");
    let start = Instant::now();
    let commitment = Commitment::from_rnd();
    println!("(finished in {:?})", start.elapsed());
    println!("commitment_root: {:?}", commitment.root());
}
