use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher as Plonky2_Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::{anyhow, Result};

use crate::{Config, Field, AGGREGATION_PASS1_SIZE, AGGREGATION_PASS1_SUB_TREE_HEIGHT, AGGREGATION_PASS2_SIZE, AGGREGATION_PASS2_SUB_TREE_HEIGHT, AGGREGATION_PASS3_SIZE, AGGREGATION_PASS3_SUB_TREE_HEIGHT, D};
use crate::Hash;

const PARTICIPANTS_PER_FIELD: usize = 62;
const NUM_PARTICIPATION_FIELDS: usize = div_ceil(AGGREGATION_PASS1_SIZE, PARTICIPANTS_PER_FIELD);

pub const MAX_PARTICIPANTS: usize = AGGREGATION_PASS1_SIZE * AGGREGATION_PASS2_SIZE * AGGREGATION_PASS3_SIZE;
pub const PARTICIPATION_TREE_HEIGHT: usize = AGGREGATION_PASS2_SUB_TREE_HEIGHT + AGGREGATION_PASS3_SUB_TREE_HEIGHT;
pub const PARTICIPATION_TREE_SIZE: usize = AGGREGATION_PASS2_SIZE * AGGREGATION_PASS3_SIZE;
pub const PIS_PARTICIPATION_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_PARTICIPATION_VALIDATOR_INDEX: usize = 4;
pub const PIS_PARTICIPATION_PARTICIPATED: usize = 5;

pub struct ParticipationCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ParticipationCircuitTargets,
}
struct ParticipationCircuitTargets {
    validator_field_index: Target,
    participation_bit_field: Vec<Target>,
    participation_root: HashOutTarget,
    participation_root_index: Target,
    participation_root_merkle_proof: MerkleProofTarget,
}

impl ParticipationCircuit {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, data: &ParticipationCircuitData) -> Result<ParticipationProof> {
        let pw = generate_partial_witness(&self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ParticipationProof { proof })
    }

    pub fn verify_proof(&self, proof: &ParticipationProof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }
}

#[derive(Clone)]
pub struct ParticipationProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl ParticipationProof {
    pub fn participation_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_PARTICIPATION_ROOT[0]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROOT[1]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROOT[2]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROOT[3]]]
    }

    pub fn validator_index(&self) -> u32 {
        self.proof.public_inputs[PIS_PARTICIPATION_VALIDATOR_INDEX].to_canonical_u64() as u32
    }

    pub fn participated(&self) -> bool {
        self.proof.public_inputs[PIS_PARTICIPATION_PARTICIPATED].to_canonical_u64() == 1
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ParticipationCircuitTargets {
    //Global targets
    let agg_pass1_size = builder.constant(Plonky2_Field::from_canonical_usize(AGGREGATION_PASS1_SIZE));

    //Break participation into bits
    let mut participation_bit_field: Vec<Target> = Vec::new();
    let mut participation_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..NUM_PARTICIPATION_FIELDS {
        let num_bits = PARTICIPANTS_PER_FIELD.min(AGGREGATION_PASS1_SIZE - (i * PARTICIPANTS_PER_FIELD));
        let part = builder.add_virtual_target();
        let part_bits = builder.split_le(part, num_bits);
        
        participation_bit_field.push(part);
        for b in part_bits.iter().rev() {
            participation_bits.push(*b);
        }
    }

    //Break the validator sub index within the participation field into bits
    let validator_field_index: Target = builder.add_virtual_target();
    let validator_field_index_bits: Vec<BoolTarget> = builder.split_le(validator_field_index, AGGREGATION_PASS1_SUB_TREE_HEIGHT);
    let validator_field_index_bits_inv: Vec<BoolTarget> = validator_field_index_bits.iter().map(|b| builder.not(b.clone())).collect();
    
    //Determine if participated
    let mut participated: Target = builder.zero();
    for (index, participant_bit) in participation_bits.iter().enumerate() {
        let mut participant_bit_with_index_mask = participant_bit.clone();
        for b in 0..AGGREGATION_PASS1_SUB_TREE_HEIGHT {
            if ((1 << b) & index) > 0 {
                participant_bit_with_index_mask = builder.and(participant_bit_with_index_mask, validator_field_index_bits[b]);
            } else {
                participant_bit_with_index_mask = builder.and(participant_bit_with_index_mask, validator_field_index_bits_inv[b]);
            }
        }
        participated = builder.add(participated, participant_bit_with_index_mask.target);
    }

    //Merkle proof to get the participation root
    let participation_root = builder.add_virtual_hash();
    let participation_sub_root = builder.hash_n_to_hash_no_pad::<Hash>(participation_bit_field.clone());
    let participation_root_index = builder.add_virtual_target();
    let participation_root_index_bits = builder.split_le(participation_root_index, PARTICIPATION_TREE_HEIGHT);
    let participation_root_merkle_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(PARTICIPATION_TREE_HEIGHT),
    };
    builder.verify_merkle_proof::<Hash>(
        participation_sub_root.elements.to_vec(), 
        &participation_root_index_bits, 
        participation_root,
        &participation_root_merkle_proof,
    );

    //Compute complete index
    let validator_index: Target = builder.mul_add(participation_root_index, agg_pass1_size, validator_field_index);

    //Register the public inputs
    builder.register_public_inputs(&participation_root.elements);
    builder.register_public_input(validator_index);
    builder.register_public_input(participated);

    ParticipationCircuitTargets {
        validator_field_index,
        participation_bit_field,
        participation_root,
        participation_root_index,
        participation_root_merkle_proof,
    }
}

#[derive(Clone)]
pub struct ParticipationCircuitData {
    pub participation_bit_field: Vec<u8>,
    pub validator_index: usize,
}

fn generate_partial_witness(targets: &ParticipationCircuitTargets, data: &ParticipationCircuitData) -> Result<PartialWitness<Field>> {
    if data.validator_index >= MAX_PARTICIPANTS {
        return Err(anyhow!("Invalid validator index (max: {})", MAX_PARTICIPANTS));
    }

    let participation_root_index = data.validator_index / AGGREGATION_PASS1_SIZE;
    let participation_root_merkle_data = participation_merkle_data(&data.participation_bit_field, data.validator_index);
    let validator_field_index = data.validator_index % AGGREGATION_PASS1_SIZE;
    let participation_bit_field = participation_fields(&data.participation_bit_field, participation_root_index);

    let mut pw = PartialWitness::new();
    pw.set_target(targets.validator_field_index, Plonky2_Field::from_canonical_usize(validator_field_index));
    set_targets(&mut pw, targets.participation_bit_field.clone(), participation_bit_field);
    set_targets(&mut pw, targets.participation_root.elements.to_vec(), participation_root_merkle_data.root.to_vec());
    pw.set_target(targets.participation_root_index, Plonky2_Field::from_canonical_usize(participation_root_index));
    set_merkle_targets(&mut pw, targets.participation_root_merkle_proof.clone(), participation_root_merkle_data.proof);

    Ok(pw)
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

pub fn calculate_participation_root(participation_bit_field: &Vec<u8>) -> [Field; 4] {
    participation_merkle_data(participation_bit_field, 0).root
}

struct MerkleData {
    pub root: [Field; 4],
    pub proof: Vec<[Field; 4]>,
}

fn participation_merkle_data(participation_bit_field: &Vec<u8>, validator_index: usize) -> MerkleData {
    let mut nodes: Vec<[Field; 4]> = Vec::new();
    for i in 0..PARTICIPATION_TREE_SIZE {
        let fields = participation_fields(participation_bit_field, i);
        nodes.push(field_hash(fields.as_slice()));
    }

    for h in (0..PARTICIPATION_TREE_HEIGHT).rev() {
        let start = nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            nodes.push(field_hash_two(nodes[start + (i * 2)], nodes[start + (i * 2) + 1]));
        }
    }
    let root = *nodes.last().unwrap();

    let mut proof: Vec<[Field; 4]> = vec![[Field::ZERO; 4]; PARTICIPATION_TREE_HEIGHT];
    let mut start: usize = 0;
    let mut jump: usize = PARTICIPATION_TREE_SIZE;
    let mut idx = validator_index / AGGREGATION_PASS1_SIZE;
    for i in 0..PARTICIPATION_TREE_HEIGHT {
        if (idx & 1) == 0 {
            proof[i] = nodes[start + idx + 1];
        } else {
            proof[i] = nodes[start + idx - 1];
        }
        start = start + jump;
        jump = jump / 2;
        idx = idx / 2;
    }

    MerkleData { root, proof }
}

fn participation_fields(participation_bit_field: &Vec<u8>, group_index: usize) -> Vec<Field> {
    let mut b = group_index * AGGREGATION_PASS1_SIZE;
    let mut participation_bit_field_u64: Vec<u64> = Vec::new();
    for _ in 0..NUM_PARTICIPATION_FIELDS {
        let mut field_u64: u64 = 0;
        for _ in 0..PARTICIPANTS_PER_FIELD {
            if b < AGGREGATION_PASS1_SIZE {
                field_u64 = field_u64 << 1;
                if bit_from_field(participation_bit_field, b) {
                    field_u64 += 1;
                }
            }
            b += 1;
        }
        participation_bit_field_u64.push(field_u64);
    }
    let fields: Vec<Field> = participation_bit_field_u64.iter().map(|f| Plonky2_Field::from_canonical_u64(*f)).collect();
    fields
}

fn field_hash(input: &[Field]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::hash_no_pad(input).elements
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}

fn bit_from_field(participation_bit_field: &Vec<u8>, index: usize) -> bool {
    match participation_bit_field.get(index / 8) {
        Some(byte) => byte & (128u8 >> (index % 8)) > 0,
        None => false,
    }
}

const fn div_ceil(x: usize, y: usize) -> usize {
    if x == 0 {
        return 0;
    }

    let div = x / y;
    if y * div == x {
        return div;
    }
    div + 1
}
