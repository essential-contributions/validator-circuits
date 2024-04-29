use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::Result;

use crate::{Config, Field, BATCH_SIZE, COMMITMENT_TREE_DEPTH, D, VALIDATORS_TREE_DEPTH};
use crate::Hash;

pub const REVEAL_BATCH_MAX_SIZE: usize = BATCH_SIZE;

pub struct BatchCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: BatchCircuitTargets,
}
struct BatchCircuitTargets {
    block_slot: Target,
    validators_root: HashOutTarget,
    validators: Vec<BatchCircuitValidatorTargets>,
}
struct BatchCircuitValidatorTargets {
    index: Target,
    stake: Target,
    commitment_root: HashOutTarget,
    validator_proof: MerkleProofTarget,
    reveal: Vec<Target>,
    reveal_proof: MerkleProofTarget,
}

impl BatchCircuit {
    pub fn new() -> Self {
        assert!(VALIDATORS_TREE_DEPTH < 32, "Circuit constraints could be compromized: Too many possible validators");

        //build the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = validation_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, data: &BatchCircuitData) -> Result<BatchProof> {
        let pw = generate_partial_witness(&self.targets, data);
        let proof = self.circuit_data.prove(pw)?;
        Ok(BatchProof { proof })
    }

    pub fn verify_proof(&self, proof: &BatchProof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }
}

pub struct BatchProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl BatchProof {
    pub fn total_stake(&self) -> u64 {
        self.proof.public_inputs[4].to_canonical_u64()
    }

    pub fn block_slot(&self) -> usize{
        self.proof.public_inputs[5].to_canonical_u64() as usize
    }

    pub fn validators_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[0], self.proof.public_inputs[1], self.proof.public_inputs[2], self.proof.public_inputs[3]]
    }
}

fn validation_circuit(builder: &mut CircuitBuilder<Field, D>) -> BatchCircuitTargets {
    let mut validator_targets: Vec<BatchCircuitValidatorTargets> = Vec::new();

    //Global targets
    let validators_root = builder.add_virtual_hash();
    let block_slot = builder.add_virtual_target();
    let mut total_stake = builder.zero();
    builder.range_check(block_slot, COMMITMENT_TREE_DEPTH);

    let mut previous_validator_index = builder.zero();
    let one = builder.one();

    for _ in 0..REVEAL_BATCH_MAX_SIZE {
        // Secrets tree
        let commitment_root = builder.add_virtual_hash();
        let block_slot_bits = builder.split_le(block_slot, COMMITMENT_TREE_DEPTH);
        let reveal = builder.add_virtual_targets(4);
        let reveal_hash = builder.hash_n_to_m_no_pad::<Hash>(reveal.clone(), 4);
        let reveal_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(COMMITMENT_TREE_DEPTH),
        };
        builder.verify_merkle_proof::<Hash>(
            reveal_hash, 
            &block_slot_bits, 
            commitment_root,
            &reveal_proof,
        );

        // Validators tree
        let validator_index = builder.add_virtual_target();
        let validator_index_bits = builder.split_le(validator_index, VALIDATORS_TREE_DEPTH);
        let validator_stake = builder.add_virtual_target();
        let validator_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(VALIDATORS_TREE_DEPTH),
        };
        builder.range_check(validator_index, VALIDATORS_TREE_DEPTH);
        builder.verify_merkle_proof::<Hash>(
            [commitment_root.elements.to_vec(), vec![validator_stake]].concat(), 
            &validator_index_bits, 
            validators_root,
            &validator_proof,
        );

        // Keep running total of stake
        total_stake = builder.add(total_stake, validator_stake);

        // Ensure that validator index is increasing (and only the same if previous_validator_index is 0)
        // note: equivalent to [((validator_index - previous_validator_index) - 1) * previous_validator_index < (VALIDATORS_TREE_DEPTH-1)*2]
        // note: an overflow error can occur if the VALIDATORS_TREE_DEPTH is at 32 or higher
        let mut tmp = builder.sub(validator_index, previous_validator_index);
        tmp = builder.sub(tmp, one);
        tmp = builder.mul(tmp, previous_validator_index);
        builder.range_check(tmp, (VALIDATORS_TREE_DEPTH-1)*2);
        previous_validator_index = validator_index;


        validator_targets.push(BatchCircuitValidatorTargets {
            index: validator_index,
            stake: validator_stake,
            validator_proof,
            reveal,
            reveal_proof,
            commitment_root,
        });
    }

    // Register the public inputs
    builder.register_public_inputs(&validators_root.elements);
    builder.register_public_input(total_stake);
    builder.register_public_input(block_slot);

    BatchCircuitTargets {
        block_slot,
        validators_root,
        validators: validator_targets,
    }
}

pub struct BatchCircuitData {
    pub block_slot: usize,
    pub validators_root: [Field; 4],
    pub validators: Vec<BatchCircuitValidatorData>,
}
pub struct BatchCircuitValidatorData {
    pub index: usize,
    pub stake: u64,
    pub commitment_root: [Field; 4],
    pub validator_proof: Vec<[Field; 4]>,

    pub block_slot: usize,
    pub reveal: [Field; 4],
    pub reveal_proof: Vec<[Field; 4]>,
}

fn generate_partial_witness(targets: &BatchCircuitTargets, data: &BatchCircuitData) -> PartialWitness<Field> {
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Plonky2_Field::from_canonical_u64(data.block_slot as u64));
    pw.set_hash_target(targets.validators_root, HashOut::<Field> { elements: data.validators_root });
    for (t, v) in targets.validators.iter().zip(data.validators.iter()) {
        pw.set_target(t.index, Plonky2_Field::from_canonical_u64(v.index as u64));
        pw.set_target(t.stake, Plonky2_Field::from_canonical_u64(v.stake));

        set_targets(&mut pw, t.reveal.clone(), v.reveal.to_vec());
        pw.set_hash_target(t.commitment_root, HashOut::<Field> { elements: v.commitment_root });
        set_merkle_targets(&mut pw, t.reveal_proof.clone(), v.reveal_proof.clone());
        set_merkle_targets(&mut pw, t.validator_proof.clone(), v.validator_proof.clone());
    }
    pw
}

fn set_targets(pw: &mut PartialWitness<Field>, targets: Vec<Target>, values: Vec<Field>) {
    for (t, v) in targets.iter().zip(values.iter()) {
        pw.set_target(*t, *v);
    }
}

fn set_merkle_targets(pw: &mut PartialWitness<Field>, target: MerkleProofTarget, value: Vec<[Field; 4]>) {
    for (t, v) in target.siblings.iter().zip(value.iter()) {
        let hash: HashOut<Field> = HashOut::<Field> { elements: *v };
        pw.set_hash_target(*t, hash);
    }
}
