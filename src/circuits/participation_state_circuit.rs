use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::epochs::initial_validator_epochs_root;
use crate::participation::initial_participation_rounds_root;
use crate::{Config, Field, D, PARTICIPATION_ROUNDS_PER_STATE_EPOCH, PARTICIPATION_ROUNDS_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT, VALIDATOR_EPOCHS_TREE_HEIGHT};
use crate::Hash;

use super::extensions::{common_data_for_recursion, CircuitBuilderExtended, PartialWitnessExtended};
use super::serialization::{deserialize_circuit, serialize_circuit};
use super::{Circuit, Proof, Serializeable};

pub const PIS_PARTICIPATION_STATE_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_VALIDATOR_EPOCHS_TREE_ROOT: [usize; 4] = [8, 9, 10, 11];
pub const PIS_PARTICIPATION_ROUNDS_TREE_ROOT: [usize; 4] = [12, 13, 14, 15];

const MAX_GATES: usize = 1 << 14;

pub struct ParticipationStateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ParticipationStateCircuitTargets,
}
struct ParticipationStateCircuitTargets {
    epoch_num: Target,
    val_state_inputs_hash: Vec<Target>,
    round_num: Target,
    participation_root: HashOutTarget,
    participation_count: Target,

    current_val_state_inputs_hash: Vec<Target>,
    validator_epoch_proof: MerkleProofTarget,
    current_participation_root: HashOutTarget,
    current_participation_count: Target,
    participation_round_proof: MerkleProofTarget,
    
    init_zero: BoolTarget,
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
}
impl ParticipationStateCircuit {
    pub fn generate_proof(&self, data: &ParticipationStateCircuitData) -> Result<ParticipationStateProof> {
        let pw = generate_partial_witness(&self.circuit_data, &self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ParticipationStateProof { proof })
    }
}
impl Circuit for ParticipationStateCircuit {
    type Proof = ParticipationStateProof;
    
    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        check_cyclic_proof_verifier_data(
            &proof.proof,
            &self.circuit_data.verifier_only,
            &self.circuit_data.common,
        )?;
        self.circuit_data.verify(proof.proof.clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    fn is_wrappable() -> bool {
        false
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        None
    }
}

impl Serializeable for ParticipationStateCircuit {
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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ParticipationStateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ParticipationStateProof {
    pub fn inputs_hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes = (self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn validator_epochs_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[3]]]
    }

    pub fn participation_rounds_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[3]]]
    }
}
impl Proof for ParticipationStateProof {
    fn from_proof(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        Self { proof }
    }
    
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ParticipationStateCircuitTargets {
    let rounds_per_epoch = builder.constant(Field::from_canonical_usize(PARTICIPATION_ROUNDS_PER_STATE_EPOCH));

    //Init flag
    let init_zero = builder.add_virtual_bool_target_safe();

    //Inputs
    let round_num = builder.add_virtual_target();
    let val_state_inputs_hash = builder.add_virtual_targets(8);
    let participation_root = builder.add_virtual_hash();
    let participation_count = builder.add_virtual_target();

    //Current state targets (will be connected to inner proof later)
    let current_inputs_hash = builder.add_virtual_targets(8);
    let current_epochs_tree_root = builder.add_virtual_hash();
    let current_pr_tree_root = builder.add_virtual_hash();

    //Compute the new inputs hash
    let mut inputs: Vec<Target> = Vec::new();
    current_inputs_hash.iter().for_each(|t| inputs.push(*t));
    inputs.push(round_num);
    val_state_inputs_hash.iter().for_each(|t| inputs.push(*t));
    participation_root.elements.iter().for_each(|t| {
        let parts = builder.split_low_high(*t, 32, 64);
        inputs.push(parts.1);
        inputs.push(parts.0);
    });
    inputs.push(participation_count);
    let new_inputs_hash = builder.sha256_hash(inputs);

    //Verify merkle proof for existing validator epoch data
    let current_val_state_inputs_hash = builder.add_virtual_targets(8);
    let current_epoch_hash = builder.hash_n_to_hash_no_pad::<Hash>(current_val_state_inputs_hash.clone());
    let validator_epoch_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(VALIDATOR_EPOCHS_TREE_HEIGHT),
    };
    let epoch_num = builder.add_virtual_target();
    let epoch_num_bits = builder.split_le(epoch_num, VALIDATOR_EPOCHS_TREE_HEIGHT);
    builder.verify_merkle_proof::<Hash>(
        current_epoch_hash.elements.to_vec(), 
        &epoch_num_bits, 
        current_epochs_tree_root,
        &validator_epoch_proof,
    );
    builder.div_round_down(round_num, rounds_per_epoch, epoch_num, 32);

    //Verify merkle proof for existing round data
    let current_participation_root = builder.add_virtual_hash();
    let current_participation_count = builder.add_virtual_target();
    let current_round_hash = builder.hash_n_to_hash_no_pad::<Hash>([
        &current_participation_root.elements[..], 
        &[current_participation_count],
    ].concat());
    let participation_round_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(PARTICIPATION_ROUNDS_TREE_HEIGHT),
    };
    let round_num_bits = builder.split_le(round_num, PARTICIPATION_ROUNDS_TREE_HEIGHT);
    builder.verify_merkle_proof::<Hash>(
        current_round_hash.elements.to_vec(), 
        &round_num_bits, 
        current_pr_tree_root,
        &participation_round_proof,
    );

    //Update the validator epoch tree
    let new_epochs_tree_root = builder.merkle_root_from_prev_proof::<Hash>(
        val_state_inputs_hash.clone(), 
        &epoch_num_bits, 
        &validator_epoch_proof
    );

    //Determine the new round data based on the input and current participation count
    let input_is_less = builder.less_than(participation_count, current_participation_count, VALIDATORS_TREE_HEIGHT);
    let new_participation_root = builder.select_hash(input_is_less, current_participation_root, participation_root);
    let new_participation_count = builder.select(input_is_less, current_participation_count, participation_count);
    let new_pr_tree_root = builder.merkle_root_from_prev_proof::<Hash>(
        [
            &new_participation_root.elements[..], 
            &[new_participation_count],
        ].concat(), 
        &round_num_bits, 
        &participation_round_proof
    );

    //Register all public inputs
    builder.register_public_inputs(&new_inputs_hash);
    builder.register_public_inputs(&new_epochs_tree_root.elements);
    builder.register_public_inputs(&new_pr_tree_root.elements);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_inputs_hash = inner_cyclic_pis[0..8].to_vec();
    let inner_proof_epochs_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[8..12]).unwrap();
    let inner_proof_pr_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[12..16]).unwrap();

    //Connect the current inputs hash with inner proof or initial value
    inner_proof_inputs_hash.iter().zip(current_inputs_hash).for_each(|(inner_proof, prev)| {
        let inner_proof_or_init = builder.mul(*inner_proof, init_zero.target);
        builder.connect(prev, inner_proof_or_init);
    });

    //Connect the current validator epochs tree root with inner proof or initial value
    let initial_epochs_tree_root = HashOutTarget { 
        elements: initial_validator_epochs_root().map(|f| builder.constant(f)) 
    };
    let inner_proof_epochs_tree_root_or_init = builder.select_hash(init_zero, inner_proof_epochs_tree_root, initial_epochs_tree_root);
    builder.connect_hashes(current_epochs_tree_root, inner_proof_epochs_tree_root_or_init);

    //Connect the current participation rounds tree root with inner proof or initial value
    let initial_pr_tree_root = HashOutTarget { 
        elements: initial_participation_rounds_root().map(|f| builder.constant(f)) 
    };
    let inner_proof_pr_tree_root_or_init = builder.select_hash(init_zero, inner_proof_pr_tree_root, initial_pr_tree_root);
    builder.connect_hashes(current_pr_tree_root, inner_proof_pr_tree_root_or_init);

    //Finally verify the previous (inner) proof
    builder.conditionally_verify_cyclic_proof_or_dummy::<Config>(
        init_zero,
        &inner_cyclic_proof_with_pis,
        &common_data,
    ).expect("cyclic proof verification failed");

    ParticipationStateCircuitTargets {
        epoch_num,
        val_state_inputs_hash,
        round_num,
        participation_root,
        participation_count,
        current_val_state_inputs_hash,
        validator_epoch_proof,
        current_participation_root,
        current_participation_count,
        participation_round_proof,
        init_zero,
        verifier: verifier_data_target,
        previous_proof: inner_cyclic_proof_with_pis,
    }
}

#[derive(Clone)]
pub struct ParticipationStateCircuitData {
    pub round_num: usize,
    pub val_state_inputs_hash: [u8; 32],
    pub participation_root: [Field; 4],
    pub participation_count: u32,

    pub current_val_state_inputs_hash: [u8; 32],
    pub validator_epoch_proof: Vec<[Field; 4]>,
    pub current_participation_root: [Field; 4],
    pub current_participation_count: u32,
    pub participation_round_proof: Vec<[Field; 4]>,
    
    pub previous_proof: Option<ParticipationStateProof>,
}

fn generate_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    targets: &ParticipationStateCircuitTargets, 
    data: &ParticipationStateCircuitData,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    pw.set_target(targets.epoch_num, Field::from_canonical_usize(data.round_num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH));
    data.val_state_inputs_hash.chunks(4).enumerate().for_each(|(i, c)| {
        let value = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        pw.set_target(targets.val_state_inputs_hash[i], value);
    });
    pw.set_target(targets.round_num, Field::from_canonical_usize(data.round_num));
    pw.set_hash_target(targets.participation_root, HashOut::<Field> { elements: data.participation_root });
    pw.set_target(targets.participation_count, Field::from_canonical_u32(data.participation_count));
    
    data.current_val_state_inputs_hash.chunks(4).enumerate().for_each(|(i, c)| {
        let value = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        pw.set_target(targets.current_val_state_inputs_hash[i], value);
    });
    pw.set_merkle_proof_target(targets.validator_epoch_proof.clone(), &data.validator_epoch_proof);
    pw.set_hash_target(targets.current_participation_root, HashOut::<Field> { elements: data.current_participation_root });
    pw.set_target(targets.current_participation_count, Field::from_canonical_u32(data.current_participation_count));
    pw.set_merkle_proof_target(targets.participation_round_proof.clone(), &data.participation_round_proof);

    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);
    match &data.previous_proof {
        Some(previous_proof) => {
            pw.set_bool_target(targets.init_zero, true);
            pw.set_proof_with_pis_target(&targets.previous_proof, &previous_proof.proof);
        },
        None => {
            //setup for using initial state (no previous proof)
            let base_proof = initial_proof(circuit_data);
            pw.set_bool_target(targets.init_zero, false);
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
        },
    };
    Ok(pw)
}

fn initial_proof(circuit_data: &CircuitData<Field, Config, D>) -> ProofWithPublicInputs<Field, Config, D> {
    let initial_inputs_hash = [Field::ZERO; 8];
    let initial_validator_epochs_root = initial_validator_epochs_root();
    let initial_participation_rounds_root = initial_participation_rounds_root();
    let initial_public_inputs = [
        &initial_inputs_hash[..],
        &initial_validator_epochs_root[..],
        &initial_participation_rounds_root[..]
    ].concat();
    cyclic_base_proof(
        &circuit_data.common,
        &circuit_data.verifier_only,
        initial_public_inputs.into_iter().enumerate().collect(),
    )
}

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &ParticipationStateCircuitTargets) -> IoResult<()> {
    buffer.write_target(targets.epoch_num)?;
    buffer.write_target_vec(&targets.val_state_inputs_hash)?;
    buffer.write_target(targets.round_num)?;
    buffer.write_target_hash(&targets.participation_root)?;
    buffer.write_target(targets.participation_count)?;
    
    buffer.write_target_vec(&targets.current_val_state_inputs_hash)?;
    buffer.write_target_merkle_proof(&targets.validator_epoch_proof)?;
    buffer.write_target_hash(&targets.current_participation_root)?;
    buffer.write_target(targets.current_participation_count)?;
    buffer.write_target_merkle_proof(&targets.participation_round_proof)?;

    buffer.write_target_bool(targets.init_zero)?;
    buffer.write_target_verifier_circuit(&targets.verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.previous_proof)?;

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<ParticipationStateCircuitTargets> {
    let epoch_num = buffer.read_target()?;
    let val_state_inputs_hash = buffer.read_target_vec()?;
    let round_num = buffer.read_target()?;
    let participation_root = buffer.read_target_hash()?;
    let participation_count = buffer.read_target()?;

    let current_val_state_inputs_hash = buffer.read_target_vec()?;
    let validator_epoch_proof = buffer.read_target_merkle_proof()?;
    let current_participation_root = buffer.read_target_hash()?;
    let current_participation_count = buffer.read_target()?;
    let participation_round_proof = buffer.read_target_merkle_proof()?;
    
    let init_zero = buffer.read_target_bool()?;
    let verifier = buffer.read_target_verifier_circuit()?;
    let previous_proof = buffer.read_target_proof_with_public_inputs()?;

    Ok(ParticipationStateCircuitTargets {
        epoch_num,
        val_state_inputs_hash,
        round_num,
        participation_root,
        participation_count,
        current_val_state_inputs_hash,
        validator_epoch_proof,
        current_participation_root,
        current_participation_count,
        participation_round_proof,
        init_zero,
        verifier,
        previous_proof,
    })
}
