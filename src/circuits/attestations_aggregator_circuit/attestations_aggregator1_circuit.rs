use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use anyhow::{anyhow, Result};

use crate::circuits::extensions::{CircuitBuilderExtended, PartialWitnessExtended};
use crate::circuits::serialization::{deserialize_circuit, serialize_circuit};
use crate::commitment::{empty_commitment, empty_commitment_root, example_commitment_proof};
use crate::participation::{leaf_fields, PARTICIPANTS_PER_FIELD, PARTICIPATION_FIELDS_PER_LEAF};
use crate::validators::example_validator_set;
use crate::{Config, Field, AGGREGATION_PASS1_SIZE, AGGREGATION_PASS1_SUB_TREE_HEIGHT, D, VALIDATOR_COMMITMENT_TREE_HEIGHT};
use crate::Hash;

use super::{Circuit, Proof, Serializeable};

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
    participation_bits_fields: Vec<Target>,
}
struct AttsAgg1ValidatorTargets {
    stake: Target,
    commitment_root: HashOutTarget,
    reveal: Vec<Target>,
    reveal_proof: MerkleProofTarget,
}
impl Circuit for AttestationsAggregator1Circuit {
    type Data = AttestationsAggregator1Data;
    type Proof = AttestationsAggregator1Proof;

    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof> {
        let pw = generate_partial_witness(&self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationsAggregator1Proof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        let data = example_data();
        let pw = generate_partial_witness(&self.targets, &data).unwrap();
        let proof = self.circuit_data.prove(pw).unwrap();
        AttestationsAggregator1Proof { proof }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }
}
impl Serializeable for AttestationsAggregator1Circuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
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
}
impl Proof for AttestationsAggregator1Proof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
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
    let mut participation_bits_fields: Vec<Target> = Vec::new();
    let mut participation_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..PARTICIPATION_FIELDS_PER_LEAF {
        let num_bits = PARTICIPANTS_PER_FIELD.min(ATTESTATION_AGGREGATION_PASS1_SIZE - (i * PARTICIPANTS_PER_FIELD));
        let part = builder.add_virtual_target();
        let part_bits = builder.split_le(part, num_bits);
        
        participation_bits_fields.push(part);
        for b in part_bits.iter().rev() {
            participation_bits.push(*b);
        }
    }
    let participation_root = builder.hash_n_to_hash_no_pad::<Hash>(participation_bits_fields.clone());

    // Verify each validator reveal
    for not_skip in participation_bits {
        let commitment_root = builder.add_virtual_hash();
        let stake = builder.add_virtual_target();

        // Commitment tree
        let reveal = builder.add_virtual_targets(4);
        let reveal_hash = builder.hash_n_to_m_no_pad::<Hash>(reveal.clone(), 4);
        let reveal_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(VALIDATOR_COMMITMENT_TREE_HEIGHT),
        };
        let merkle_root = builder.select_hash(not_skip, commitment_root, skip_root);
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
        participation_bits_fields,
    }
}

#[derive(Clone)]
pub struct AttestationsAggregator1Data {
    pub block_slot: usize,
    pub validators: Vec<AttestationsAggregator1ValidatorData>,
}
#[derive(Clone)]
pub struct AttestationsAggregator1ValidatorData {
    pub stake: u32,
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
    pw.set_target(targets.block_slot, Field::from_canonical_u64(data.block_slot as u64));

    for (t, v) in targets.validators.iter().zip(validators.iter()) {
        pw.set_target(t.stake, Field::from_canonical_u32(v.stake));
        pw.set_hash_target(t.commitment_root, HashOut::<Field> { elements: v.commitment_root });
        pw.set_target_arr(&t.reveal, &v.reveal.clone().unwrap().reveal);
        pw.set_merkle_proof_target(t.reveal_proof.clone(), &v.reveal.clone().unwrap().reveal_proof);
    }

    let participation_bits_fields = leaf_fields(validator_participation);
    for (t, v) in targets.participation_bits_fields.iter().zip(participation_bits_fields.iter()) {
        pw.set_target(*t, *v);
    }

    Ok(pw)
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
    buffer.write_target_vec(&targets.participation_bits_fields)?;

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
    let participation_bits_fields = buffer.read_target_vec()?;

    Ok(AttsAgg1Targets {
        block_slot,
        validators,
        participation_bits_fields,
    })
}

fn build_skip_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_commitment_root();
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}

fn example_data() -> AttestationsAggregator1Data {
    let num_attestations = 500;
    let validator_set = example_validator_set();
    let validators: Vec<AttestationsAggregator1ValidatorData> = (0..ATTESTATION_AGGREGATION_PASS1_SIZE).map(|i| {
        let validator = validator_set.validator(i);
        if i < num_attestations {
            let commitment_proof = example_commitment_proof(i);
            AttestationsAggregator1ValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: Some(AttestationsAggregator1RevealData {
                    reveal: commitment_proof.reveal,
                    reveal_proof: commitment_proof.proof,
                }),
            }
        } else {
            AttestationsAggregator1ValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: None,
            }
        }
    }).collect();

    AttestationsAggregator1Data {
        block_slot: 100,
        validators,
    }
}
