use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use anyhow::Result;

use crate::{BatchCircuit, BatchProof, Config, Field, AGGREGATOR_SIZE, COMMITMENT_TREE_DEPTH, D, VALIDATORS_TREE_DEPTH};

//TODO: review the validator index incrementing constraint (may have to switch to a full batch of zero validators)

pub const AGGREGATOR_BATCH_SIZE: usize = AGGREGATOR_SIZE;

pub struct AggregatorCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AggregatorCircuitTargets,
}
struct AggregatorCircuitTargets {
    block_slot: Target,
    validators_root: HashOutTarget,
    batch_verifier: VerifierCircuitTarget,
    batch_proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

impl AggregatorCircuit {
    pub fn new(batch_circuit: &BatchCircuit) -> Self {
        //build the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = aggregator_circuit(&mut builder, batch_circuit.circuit_data());
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, data: &AggregatorCircuitData, batch_circuit: &BatchCircuit) -> Result<AggregateProof> {
        let pw = generate_partial_witness(&self.targets, data, batch_circuit.circuit_data());
        let proof = self.circuit_data.prove(pw)?;
        Ok(AggregateProof { proof })
    }

    pub fn verify_proof(&self, proof: &AggregateProof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }
}

pub struct AggregateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl AggregateProof {
    pub fn validators_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[0], self.proof.public_inputs[1], self.proof.public_inputs[2], self.proof.public_inputs[3]]
    }

    pub fn total_stake(&self) -> u64 {
        self.proof.public_inputs[4].to_canonical_u64()
    }

    pub fn block_slot(&self) -> usize{
        self.proof.public_inputs[5].to_canonical_u64() as usize
    }
}

fn aggregator_circuit(builder: &mut CircuitBuilder<Field, D>, batch_circuit_data: &CircuitData<Field, Config, D>) -> AggregatorCircuitTargets {
    let mut batch_proofs: Vec<ProofWithPublicInputsTarget<D>> = Vec::new();

    //Global targets
    let validators_root = builder.add_virtual_hash();
    let block_slot = builder.add_virtual_target();
    let mut total_stake = builder.zero();
    builder.range_check(block_slot, COMMITMENT_TREE_DEPTH);
    
    let mut previous_validator_end_index = builder.zero();
    let one = builder.one();

    //Circuit target
    let batch_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(batch_circuit_data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };

    for _ in 0..AGGREGATOR_BATCH_SIZE {
        let proof_target = builder.add_virtual_proof_with_pis(&batch_circuit_data.common);
        builder.verify_proof::<Config>(&proof_target, &batch_verifier, &batch_circuit_data.common);
        batch_proofs.push(proof_target.clone());

        // Keep running total of stake
        total_stake = builder.add(total_stake, proof_target.public_inputs[4]);

        // Make sure each batch has the same block_slot
        builder.connect(proof_target.public_inputs[5], block_slot);

        // Ensure that validator index is increasing (and only the same if previous_validator_end_index is 0)
        // note: equivalent to [((validator_start_index - previous_validator_end_index) - 1) * previous_validator_end_index < (VALIDATORS_TREE_DEPTH-1)*2]
        // note: an overflow error can occur if the VALIDATORS_TREE_DEPTH is at 32 or higher
        let validator_start_index = proof_target.public_inputs[6];
        let mut tmp = builder.sub(validator_start_index, previous_validator_end_index);
        tmp = builder.sub(tmp, one);
        tmp = builder.mul(tmp, previous_validator_end_index);
        builder.range_check(tmp, (VALIDATORS_TREE_DEPTH-1)*2);
        previous_validator_end_index = proof_target.public_inputs[7];
    }

    // Register the public inputs
    builder.register_public_inputs(&validators_root.elements);
    builder.register_public_input(total_stake);
    builder.register_public_input(block_slot);

    AggregatorCircuitTargets {
        block_slot,
        validators_root,
        batch_verifier,
        batch_proofs,
    }
}

pub struct AggregatorCircuitData {
    pub block_slot: usize,
    pub validators_root: [Field; 4],
    pub batch_proofs: Vec<BatchProof>,
}

fn generate_partial_witness(targets: &AggregatorCircuitTargets, data: &AggregatorCircuitData, batch_circuit_data: &CircuitData<Field, Config, D>) -> PartialWitness<Field> {
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Plonky2_Field::from_canonical_u64(data.block_slot as u64));
    pw.set_hash_target(targets.validators_root, HashOut::<Field> { elements: data.validators_root });

    pw.set_cap_target(&targets.batch_verifier.constants_sigmas_cap, &batch_circuit_data.verifier_only.constants_sigmas_cap);
    pw.set_hash_target(targets.batch_verifier.circuit_digest.clone(), batch_circuit_data.verifier_only.circuit_digest);

    for (t, v) in targets.batch_proofs.iter().zip(data.batch_proofs.iter()) {
        pw.set_proof_with_pis_target(t, v.raw_proof());
    }

    pw
}
