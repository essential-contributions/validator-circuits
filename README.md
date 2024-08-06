# Validator Circuits

Circuits for validators and validation including...
- A commitment reveal circuit (up to some amount) plus a proof aggregator to increase throughput
- An update circuit to prove how an staker update changes the state root

These circuits and proofs are intended to maintain a small rollup that can be updated efficiently and easily prove validator commitment reveals for block slots (also referred to as "signature"). They are optimized by using the Poseidon hash which is easy to verify in zk arithmetization.

### TODOs

- [ ] memory efficient data trees (particularly participation.rs and epochs.rs)
- [ ] use custom gates for sha256 hash
- [ ] include already compiled circuits in repo
- [ ] review security

## Building
The circuits should be built/compiled ahead of time in order to speed up the benchmarking. This is especially relevant when benchmarking with full wrapping to groth16. Please make sure you have both Rust [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) and [Go (1.19+)](https://go.dev/doc/install) installed. It can take around 30 minutes to finish building since the groth16 circuits need to go through the full generation routine with mock trusted setup ceremony and everything.
```
RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --bin cbuild -- --full
```

Exclude the `--full` flag if you want to skip the groth16 stuff. 

## Benchmarks

### Prove Attestations

Proves a minimal amount of "signatures" through the 3 stage attestation aggregation proofs
```
RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --bin benchmark -- attestations
```
***add a `--full` flag at the end to include wrapping to groth16***

### Generate Commitment

Generates a validator commitment merkle tree root. Because Poseidon hash is being used, this can take quite a bit of time compared to typical CPU friendly hash functions. Keep in mind that this only has to be computed once per validator.
```
RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --bin benchmark -- commitment
```
***add a `--full` flag at the end to include wrapping to groth16***

### Benchmark Results

```
CPU:          Intel Core i7-8700 3.2GHz

results
Generate Commitment:           144.7s
Update Validators State:       3.26
Update Participation State:    3.1s
Prove Validator Participation: 26.89s 
Prove Block Attestations:      66.13s 

Theoretical 1Year Participation Prove Time:  2260s (37.67m)
[19s + 7s*(num_epochs - 1) + 1s]

Theoretical 100K Attestation Prove Time:  550s (9.17m)
Theoretical 1M Attestation Prove Time:    5150s (85.83m)
[4s*ceil(num_att/1024) + 32s*ceil(num_att/(1024*32)) + 32s*ceil(num_att/(1024*32*32)) + 30s]
```
