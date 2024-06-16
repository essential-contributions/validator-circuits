use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::{anyhow, Result};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::{example_validator_set, Config, Field, D, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT};
use crate::Hash;

use super::serialization::{deserialize_circuit, serialize_circuit};
use super::{Circuit, Proof, Serializeable};

pub const PIS_VALIDATORS_UPDATE_INDEX: usize = 0;
pub const PIS_VALIDATORS_UPDATE_PREVIOUS_ROOT: [usize; 4] = [1, 2, 3, 4];
pub const PIS_VALIDATORS_UPDATE_PREVIOUS_STAKE: usize = 5;
pub const PIS_VALIDATORS_UPDATE_NEW_ROOT: [usize; 4] = [6, 7, 8, 9];
pub const PIS_VALIDATORS_UPDATE_NEW_COMMITMENT: [usize; 4] = [10, 11, 12, 13];
pub const PIS_VALIDATORS_UPDATE_NEW_STAKE: usize = 14;

pub struct ValidatorsUpdateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorsUpdateCircuitTargets,
}
struct ValidatorsUpdateCircuitTargets {
    index: Target,
    previous_root: HashOutTarget,
    previous_commitment: HashOutTarget,
    previous_stake: Target,
    new_root: HashOutTarget,
    new_commitment: HashOutTarget,
    new_stake: Target,
    merkle_proof: MerkleProofTarget,
}
impl Circuit for ValidatorsUpdateCircuit {
    type Data = ValidatorsUpdateCircuitData;
    type Proof = ValidatorsUpdateProof;
    
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
        Ok(ValidatorsUpdateProof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        let data = example_data();
        let pw = generate_partial_witness(&self.targets, &data).unwrap();
        let proof = self.circuit_data.prove(pw).unwrap();
        ValidatorsUpdateProof { proof }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }
}
impl Serializeable for ValidatorsUpdateCircuit {
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
pub struct ValidatorsUpdateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ValidatorsUpdateProof {
    pub fn validator_index(&self) -> u32 {
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_INDEX].to_canonical_u64() as u32
    }

    pub fn previous_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_VALIDATORS_UPDATE_PREVIOUS_ROOT[0]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_PREVIOUS_ROOT[1]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_PREVIOUS_ROOT[2]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_PREVIOUS_ROOT[3]]]
    }

    pub fn previous_stake(&self) -> u32 {
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_PREVIOUS_STAKE].to_canonical_u64() as u32
    }

    pub fn new_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_ROOT[0]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_ROOT[1]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_ROOT[2]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_ROOT[3]]]
    }

    pub fn new_commitment(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_COMMITMENT[0]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_COMMITMENT[1]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_COMMITMENT[2]], 
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_COMMITMENT[3]]]
    }

    pub fn new_stake(&self) -> u32 {
        self.proof.public_inputs[PIS_VALIDATORS_UPDATE_NEW_STAKE].to_canonical_u64() as u32
    }
}
impl Proof for ValidatorsUpdateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ValidatorsUpdateCircuitTargets {
    //Global targets
    let index = builder.add_virtual_target();
    let index_bits = builder.split_le(index, VALIDATORS_TREE_HEIGHT);
    let merkle_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(VALIDATORS_TREE_HEIGHT),
    };

    //Prove previous state
    let previous_root = builder.add_virtual_hash();
    let previous_commitment = builder.add_virtual_hash();
    let previous_stake = builder.add_virtual_target();
    builder.verify_merkle_proof::<Hash>(
        [previous_commitment.elements.to_vec(), vec![previous_stake]].concat(), 
        &index_bits, 
        previous_root,
        &merkle_proof,
    );

    //Prove new state
    let new_root = builder.add_virtual_hash();
    let new_commitment = builder.add_virtual_hash();
    let new_stake = builder.add_virtual_target();
    builder.verify_merkle_proof::<Hash>(
        [new_commitment.elements.to_vec(), vec![new_stake]].concat(), 
        &index_bits, 
        new_root,
        &merkle_proof,
    );

    //Register the public inputs
    builder.register_public_input(index);
    builder.register_public_inputs(&previous_root.elements);
    builder.register_public_input(previous_stake);
    builder.register_public_inputs(&new_root.elements);
    builder.register_public_inputs(&new_commitment.elements);
    builder.register_public_input(new_stake);

    ValidatorsUpdateCircuitTargets {
        index,
        previous_root,
        previous_commitment,
        previous_stake,
        new_root,
        new_commitment,
        new_stake,
        merkle_proof,
    }
}

#[derive(Clone)]
pub struct ValidatorsUpdateCircuitData {
    pub validator_index: usize,
    pub previous_root: [Field; 4],
    pub previous_commitment: [Field; 4],
    pub previous_stake: u64,
    pub new_root: [Field; 4],
    pub new_commitment: [Field; 4],
    pub new_stake: u64,
    pub merkle_proof: Vec<[Field; 4]>,
}

fn generate_partial_witness(targets: &ValidatorsUpdateCircuitTargets, data: &ValidatorsUpdateCircuitData) -> Result<PartialWitness<Field>> {
    if data.validator_index >= MAX_VALIDATORS {
        return Err(anyhow!("Invalid validator index (max: {})", MAX_VALIDATORS));
    }

    let mut pw = PartialWitness::new();
    pw.set_target(targets.index, Plonky2_Field::from_canonical_usize(data.validator_index));
    set_targets(&mut pw, targets.previous_root.elements.to_vec(), data.previous_root.to_vec());
    set_targets(&mut pw, targets.previous_commitment.elements.to_vec(), data.previous_commitment.to_vec());
    pw.set_target(targets.previous_stake, Plonky2_Field::from_canonical_u64(data.previous_stake));
    set_targets(&mut pw, targets.new_root.elements.to_vec(), data.new_root.to_vec());
    set_targets(&mut pw, targets.new_commitment.elements.to_vec(), data.new_commitment.to_vec());
    pw.set_target(targets.new_stake, Plonky2_Field::from_canonical_u64(data.new_stake));
    set_merkle_targets(&mut pw, targets.merkle_proof.clone(), data.merkle_proof.clone());

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
fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorsUpdateCircuitTargets) -> IoResult<()> {
    buffer.write_target(targets.index)?;
    buffer.write_target_hash(&targets.previous_root)?;
    buffer.write_target_hash(&targets.previous_commitment)?;
    buffer.write_target(targets.previous_stake)?;
    buffer.write_target_hash(&targets.new_root)?;
    buffer.write_target_hash(&targets.new_commitment)?;
    buffer.write_target(targets.new_stake)?;
    buffer.write_target_merkle_proof(&targets.merkle_proof)?;

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorsUpdateCircuitTargets> {
    let index = buffer.read_target()?;
    let previous_root = buffer.read_target_hash()?;
    let previous_commitment = buffer.read_target_hash()?;
    let previous_stake = buffer.read_target()?;
    let new_root = buffer.read_target_hash()?;
    let new_commitment = buffer.read_target_hash()?;
    let new_stake = buffer.read_target()?;
    let merkle_proof = buffer.read_target_merkle_proof()?;

    Ok(ValidatorsUpdateCircuitTargets {
        index,
        previous_root,
        previous_commitment,
        previous_stake,
        new_root,
        new_commitment,
        new_stake,
        merkle_proof,
    })
}

fn example_data() -> ValidatorsUpdateCircuitData {
    let mut validator_set = example_validator_set();

    let validator_index = 10;
    let mut validator = validator_set.validator(validator_index).clone();
    let previous_root = validator_set.root().clone();
    let previous_commitment = validator.commitment_root.clone();
    let previous_stake = validator.stake;

    let new_commitment = [Field::ONE; 4];
    let new_stake = 21;
    validator.commitment_root = new_commitment;
    validator.stake = new_stake;
    validator_set.set_validator(validator, validator_index);

    let new_root = validator_set.root().clone();
    let merkle_proof = validator_set.validator_merkle_proof(validator_index);

    ValidatorsUpdateCircuitData {
        validator_index,
        previous_root,
        previous_commitment,
        previous_stake,
        new_root,
        new_commitment,
        new_stake,
        merkle_proof,
    }
}
