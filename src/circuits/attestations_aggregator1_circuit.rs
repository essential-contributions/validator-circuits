use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher as Plonky2_Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use anyhow::{anyhow, Result};

use crate::{Config, Field, AGGREGATION_PASS1_SIZE, AGGREGATION_PASS1_SUB_TREE_HEIGHT, D, VALIDATOR_COMMITMENT_TREE_HEIGHT};
use crate::Hash;

use super::serialization::{deserialize_circuit, serialize_circuit};

const PARTICIPANTS_PER_FIELD: usize = 62;
const NUM_PARTICIPATION_FIELDS: usize = div_ceil(AGGREGATION_PASS1_SIZE, PARTICIPANTS_PER_FIELD);

pub const VALIDATORS_TREE_AGG1_SUB_HEIGHT: usize = AGGREGATION_PASS1_SUB_TREE_HEIGHT;
pub const ATTESTATION_AGGREGATION_PASS1_SIZE: usize = AGGREGATION_PASS1_SIZE;
pub const PIS_AGG1_VALIDATORS_SUB_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_AGG1_PARTICIPATION_SUB_ROOT: [usize; 4] = [4, 5, 6, 7];
pub const PIS_AGG1_NUM_PARTICIPANTS: usize = 8;
pub const PIS_AGG1_BLOCK_SLOT: usize = 9;
pub const PIS_AGG1_TOTAL_STAKE: usize = 10;

pub struct AttestationsAggregator1Circuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttsAgg1Targets,
}
struct AttsAgg1Targets {
    block_slot: Target,
    validators: Vec<AttsAgg1ValidatorTargets>,
    participation_bit_field: Vec<Target>,
}
struct AttsAgg1ValidatorTargets {
    stake: Target,
    commitment_root: HashOutTarget,
    reveal: Vec<Target>,
    reveal_proof: MerkleProofTarget,
}

impl AttestationsAggregator1Circuit {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, data: &AttestationsAggregator1Data) -> Result<AttestationsAggregator1Proof> {
        let pw = generate_partial_witness(&self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationsAggregator1Proof { proof })
    }

    pub fn verify_proof(&self, proof: &AttestationsAggregator1Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    pub fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        Ok(buffer)
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = read_targets(&mut buffer);
        if targets.is_err() {
            return Err(anyhow!("Failed to deserialize circuit targets"));
        }
        Ok(Self { circuit_data, targets: targets.unwrap() })
    }
}

#[derive(Clone)]
pub struct AttestationsAggregator1Proof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl AttestationsAggregator1Proof {
    pub fn validators_sub_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[3]]]
    }

    pub fn participation_sub_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[3]]]
    }

    pub fn num_participants(&self) -> usize{
        self.proof.public_inputs[PIS_AGG1_NUM_PARTICIPANTS].to_canonical_u64() as usize
    }

    pub fn block_slot(&self) -> usize{
        self.proof.public_inputs[PIS_AGG1_BLOCK_SLOT].to_canonical_u64() as usize
    }

    pub fn total_stake(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG1_TOTAL_STAKE].to_canonical_u64()
    }

    pub fn raw_proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> AttsAgg1Targets {
    let mut validator_targets: Vec<AttsAgg1ValidatorTargets> = Vec::new();

    // Global targets
    let skip_root = build_skip_root(builder);
    let block_slot = builder.add_virtual_target();
    let block_slot_bits = builder.split_le(block_slot, VALIDATOR_COMMITMENT_TREE_HEIGHT);
    let mut total_stake = builder.zero();
    let mut num_participants = builder.zero();
    
    // Participation targets
    let mut participation_bit_field: Vec<Target> = Vec::new();
    let mut participation_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..NUM_PARTICIPATION_FIELDS {
        let num_bits = PARTICIPANTS_PER_FIELD.min(ATTESTATION_AGGREGATION_PASS1_SIZE - (i * PARTICIPANTS_PER_FIELD));
        let part = builder.add_virtual_target();
        let part_bits = builder.split_le(part, num_bits);
        
        participation_bit_field.push(part);
        for b in part_bits.iter().rev() {
            participation_bits.push(*b);
        }
    }
    let participation_root = builder.hash_n_to_hash_no_pad::<Hash>(participation_bit_field.clone());

    // Verify each validator reveal
    for not_skip in participation_bits {
        let skip = builder.not(not_skip);
        let commitment_root = builder.add_virtual_hash();
        let stake = builder.add_virtual_target();

        // Determine commitment root vs skip root
        let maybe_skip_root1 = builder.mul(skip.target, skip_root.elements[0]);
        let maybe_skip_root2 = builder.mul(skip.target, skip_root.elements[1]);
        let maybe_skip_root3 = builder.mul(skip.target, skip_root.elements[2]);
        let maybe_skip_root4 = builder.mul(skip.target, skip_root.elements[3]);
        let root1 = builder.mul_add(not_skip.target, commitment_root.elements[0], maybe_skip_root1);
        let root2 = builder.mul_add(not_skip.target, commitment_root.elements[1], maybe_skip_root2);
        let root3 = builder.mul_add(not_skip.target, commitment_root.elements[2], maybe_skip_root3);
        let root4 = builder.mul_add(not_skip.target, commitment_root.elements[3], maybe_skip_root4);
        let merkle_root = HashOutTarget {
            elements: [root1, root2, root3, root4],
        };

        // Commitment tree
        let reveal = builder.add_virtual_targets(4);
        let reveal_hash = builder.hash_n_to_m_no_pad::<Hash>(reveal.clone(), 4);
        let reveal_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(VALIDATOR_COMMITMENT_TREE_HEIGHT),
        };
        builder.verify_merkle_proof::<Hash>(
            reveal_hash, 
            &block_slot_bits, 
            merkle_root,
            &reveal_proof,
        );

        // Keep running total of stake and num participants
        total_stake = builder.mul_add(stake, not_skip.target, total_stake);
        num_participants = builder.add(num_participants, not_skip.target);

        validator_targets.push(AttsAgg1ValidatorTargets {
            stake,
            commitment_root,
            reveal,
            reveal_proof,
        });
    }

    // Compute the validators sub root
    let mut nodes: Vec<HashOutTarget> = Vec::new();
    for validator in validator_targets.iter() {
        let leaf_data = [validator.commitment_root.elements.to_vec(), vec![validator.stake]].concat();
        nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(leaf_data));
    }
    for h in (0..VALIDATORS_TREE_AGG1_SUB_HEIGHT).rev() {
        let start = nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [nodes[start + (i * 2)].elements.to_vec(), nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let validators_sub_root = nodes.last().unwrap();

    // Register the public inputs
    builder.register_public_inputs(&validators_sub_root.elements);
    builder.register_public_inputs(&participation_root.elements);
    builder.register_public_input(num_participants);
    builder.register_public_input(block_slot);
    builder.register_public_input(total_stake);

    AttsAgg1Targets {
        block_slot,
        validators: validator_targets,
        participation_bit_field,
    }
}

#[derive(Clone)]
pub struct AttestationsAggregator1Data {
    pub block_slot: usize,
    pub validators: Vec<AttestationsAggregator1ValidatorData>,
}
#[derive(Clone)]
pub struct AttestationsAggregator1ValidatorData {
    pub stake: u64,
    pub commitment_root: [Field; 4],
    pub reveal: Option<AttestationsAggregator1RevealData>,
}
#[derive(Clone)]
pub struct AttestationsAggregator1RevealData {
    pub reveal: [Field; 4],
    pub reveal_proof: Vec<[Field; 4]>,
}

fn generate_partial_witness(targets: &AttsAgg1Targets, data: &AttestationsAggregator1Data) -> Result<PartialWitness<Field>> {
    if data.validators.len() != ATTESTATION_AGGREGATION_PASS1_SIZE {
        return Err(anyhow!("Must include {} validators in attestation aggregation first pass", ATTESTATION_AGGREGATION_PASS1_SIZE));
    }

    //identify non-participating validators to skip (null reveal)
    let empty_commit = empty_commitment();
    let mut validators = data.validators.clone();
    let mut validator_participation: Vec<bool> = Vec::new();
    for validator in validators.iter_mut() {
        match validator.reveal {
            Some(_) => validator_participation.push(true),
            None => {
                validator_participation.push(false);
                validator.reveal = Some(AttestationsAggregator1RevealData {
                    reveal: empty_commit.reveal.clone(),
                    reveal_proof: empty_commit.proof.clone(),
                });
            },
        }
    }

    //create partial witness
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Plonky2_Field::from_canonical_u64(data.block_slot as u64));

    for (t, v) in targets.validators.iter().zip(validators.iter()) {
        pw.set_target(t.stake, Plonky2_Field::from_canonical_u64(v.stake));
        pw.set_hash_target(t.commitment_root, HashOut::<Field> { elements: v.commitment_root });
        set_targets(&mut pw, t.reveal.clone(), v.reveal.clone().unwrap().reveal.to_vec());
        set_merkle_targets(&mut pw, t.reveal_proof.clone(), v.reveal.clone().unwrap().reveal_proof.clone());
    }

    let participation_bit_field = participation_fields(validator_participation);
    for (t, v) in targets.participation_bit_field.iter().zip(participation_bit_field.iter()) {
        pw.set_target(*t, *v);
    }

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

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &AttsAgg1Targets) -> IoResult<()> {
    buffer.write_target(targets.block_slot)?;
    buffer.write_usize(targets.validators.len())?;
    for v in &targets.validators {
        buffer.write_target(v.stake)?;
        buffer.write_target_hash(&v.commitment_root)?;
        buffer.write_target_vec(&v.reveal)?;
        buffer.write_target_merkle_proof(&v.reveal_proof)?;
    }
    buffer.write_target_vec(&targets.participation_bit_field)?;

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<AttsAgg1Targets> {
    let block_slot = buffer.read_target()?;
    let mut validators: Vec<AttsAgg1ValidatorTargets> = Vec::new();
    let validators_length = buffer.read_usize()?;
    for _ in 0..validators_length {
        let stake = buffer.read_target()?;
        let commitment_root = buffer.read_target_hash()?;
        let reveal = buffer.read_target_vec()?;
        let reveal_proof = buffer.read_target_merkle_proof()?;
        validators.push(AttsAgg1ValidatorTargets {
            stake,
            commitment_root,
            reveal,
            reveal_proof,
        });
    }
    let participation_bit_field = buffer.read_target_vec()?;

    Ok(AttsAgg1Targets {
        block_slot,
        validators,
        participation_bit_field,
    })
}

struct EmptyCommitment {
    pub root: [Field; 4],
    pub reveal: [Field; 4],
    pub proof: Vec<[Field; 4]>,
}

fn build_skip_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let validator = empty_commitment();
    HashOutTarget {
        elements: validator.root.map(|f| { builder.constant(f) }),
    }
}

fn empty_commitment() -> EmptyCommitment {
    let reveal = [
        Plonky2_Field::from_canonical_usize(0),
        Plonky2_Field::from_canonical_usize(0),
        Plonky2_Field::from_canonical_usize(0),
        Plonky2_Field::from_canonical_usize(0),
    ];
    let mut node = field_hash(&reveal);
    let mut proof: Vec<[Field; 4]> = vec![];
    for _ in 0..VALIDATOR_COMMITMENT_TREE_HEIGHT {
        proof.push(node);
        node = field_hash_two(node, node);
    }

    EmptyCommitment {
        root: node,
        reveal,
        proof,
    }
}

pub fn empty_agg1_participation_sub_root() -> [Field; 4] {
    field_hash(&participation_fields(vec![false; ATTESTATION_AGGREGATION_PASS1_SIZE]))
}

fn participation_fields(validator_participation: Vec<bool>) -> Vec<Field> {
    let mut b = 0;
    let mut participation_bit_field_u64: Vec<u64> = Vec::new();
    for _ in 0..NUM_PARTICIPATION_FIELDS {
        let mut field_u64: u64 = 0;
        for _ in 0..PARTICIPANTS_PER_FIELD {
            if b < AGGREGATION_PASS1_SIZE {
                field_u64 = field_u64 << 1;
                if validator_participation[b] {
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
