# Validator Circuits

Circuits for validators and validation including...
- A commitment reveal circuit (up to some amount) plus a proof aggregator to increase throughput
- An update circuit to prove how an staker update changes the state root

These circuits and proofs are intended to maintain a small rollup that can be updated efficiently and easily prove validator commitment reveals for block slots (also referred to as "signature"). They are optimized by using the Poseidon hash which is easy to verify in zk arithmetization.

### TODOs

- [ ] support for proving validator inactivity
- [ ] review security

## Examples

### Prove Attestations

Proves a minimal amount of "signatures" through the 3 stage attestation aggregation proofs
```
cargo run --example prove_attestations --release
```

### Generate Commitment

Generates a validator commitment merkle tree root. Because Poseidon hash is being used, this can take quite a bit of time compared to typical CPU friendly hash functions. Keep in mind that this only has to be computed once per validator.
```
cargo run --example generate_commitment --release
```

## Benchmarks

```
CPU:          Rockchip RK3588 (OrangePi5Plus 16GB)

results
Generate Commitment:  438.357194521s (7.3m)
Generate Circuits:    118.091063397s
Prove Attestation Aggregation1:    8.345273417s
Prove Attestation Aggregation2:   71.388797726s
Prove Attestation Aggregation3:   71.951521909s

Theoretical 1M Prove Time:     10901.9530281s (181.7m)
```
```
CPU:          Intel Core i7-8700 3.2GHz

results
Generate Commitment:  146.920017455s
Generate Circuits:    122.938929116s
Prove Attestation Aggregation1:    3.919908366s
Prove Attestation Aggregation2:   43.232141139s
Prove Attestation Aggregation3:   38.024451707s

Theoretical 1M Prove Time:     5435.43913494s (90.59065m)
```

