# Validator Circuits

Circuits for validators and validation including...
- A commitment reveal circuit (up to some amount) plus a proof aggregator to increase throughput
- An update circuit to prove how an staker update changes the state root

These circuits and proofs are intended to maintain a small rollup that can be updated efficiently and easily proove validator commitment reveals for block slots (also referred to as "signature"). They are optimized by using the Poseidon hash which is easy to verify in zk arithmetization.

### TODOs

- [ ] support for proving validator inactivity
- [ ] improve batch handling
  - [ ] support for less than max batches
  - [ ] move batch and aggregation process behind the scenes
- [ ] review security
- [ ] the update circuit

## Examples

The following examples can be tweaked through some basic parameters found in `lib.rs`:
- `BATCH_SIZE` - the max amount of validator commitment reveals that can be batched together
- `AGGREGATOR_SIZE` - the max amount of batches that can be aggregated together

The total amount validator "signatres" that can be proven together is equal to `BATCH_SIZE * AGGREGATOR_SIZE`

### Prove Full

Proves the maximum amount of "signatures" first through individual batch proofs and then a single aggregate proof
```
cargo run --example prove_full --release
```

### Prove Batch

Proves just a single batch of `BATCH_SIZE` "signatures"
```
cargo run --example prove_batch --release
```

### Generate Commitment

Generates a validator commitment merkle tree root. Because Poseidon hash is being used, this can take quite a bit of time compared to typical CPU friendly hash functions. Keep in mind that this has not been made multi-threaded yet and only has to be computed once per validator.
```
cargo run --example generate_commitment --release
```

## Benchmarks

```
CPU:          Intel Core i7-8700 3.2GHz
Batch Size:   2048
Agg Size:     64
Validators:   131,072

results
Generate Commitment:  998.340866136s (16.639m)
Generate Circuits:    123.152302862s
Prove Single Batch:   16.658054934s
Prove Aggregate:      80.263568s

Total Prove Time:     1130.078654297s (18.83464m)
```

