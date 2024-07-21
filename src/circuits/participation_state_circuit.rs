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
use anyhow::Result;

use crate::participation::initial_participation_rounds_root;
use crate::{Config, Field, D, PARTICIPATION_ROUNDS_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT};
use crate::Hash;

use super::extensions::{common_data_for_recursion, CircuitBuilderExtended, PartialWitnessExtended};
use super::{Circuit, Proof};

pub const PIS_PARTICIPATION_STATE_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_PARTICIPATION_ROUNDS_TREE_ROOT: [usize; 4] = [8, 9, 10, 11];

const MAX_GATES: usize = 1 << 14;

pub struct ParticipationStateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ParticipationStateCircuitTargets,
}
struct ParticipationStateCircuitTargets {
    round_num: Target,
    state_inputs_hash: Vec<Target>,
    participation_root: HashOutTarget,
    participation_count: Target,

    current_state_inputs_hash: Vec<Target>,
    current_participation_root: HashOutTarget,
    current_participation_count: Target,
    participation_round_proof: MerkleProofTarget,
    
    init_zero: BoolTarget,
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
}
impl Circuit for ParticipationStateCircuit {
    type Data = ParticipationStateCircuitData;
    type Proof = ParticipationStateProof;
    
    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }

    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof> {
        let pw = generate_partial_witness(&self.circuit_data, &self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ParticipationStateProof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        todo!()
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
}
/*
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
*/

#[derive(Clone)]
pub struct ParticipationStateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ParticipationStateProof {
    pub fn inputs_hash(&self) -> [u64; 4] {
        [(self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[0]].to_canonical_u64() << 32)
            + self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[1]].to_canonical_u64(), 
        (self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[2]].to_canonical_u64() << 32)
            + self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[3]].to_canonical_u64(), 
        (self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[4]].to_canonical_u64() << 32)
            + self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[5]].to_canonical_u64(), 
        (self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[6]].to_canonical_u64() << 32)
            + self.proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[7]].to_canonical_u64()]
    }

    pub fn participation_rounds_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[3]]]
    }
}
impl Proof for ParticipationStateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ParticipationStateCircuitTargets {
    //Init flag
    let init_zero = builder.add_virtual_bool_target_safe();

    //Inputs
    let round_num = builder.add_virtual_target();
    let state_inputs_hash = builder.add_virtual_targets(8);
    let participation_root = builder.add_virtual_hash();
    let participation_count = builder.add_virtual_target();

    //Previous state targets (will be connected to inner proof later)
    let prev_inputs_hash = builder.add_virtual_targets(8);
    let prev_pr_tree_root = builder.add_virtual_hash();

    //Compute the new inputs hash
    let mut inputs: Vec<Target> = Vec::new();
    prev_inputs_hash.iter().for_each(|t| inputs.push(*t));
    inputs.push(round_num);
    state_inputs_hash.iter().for_each(|t| inputs.push(*t));
    participation_root.elements.iter().for_each(|t| {
        let parts = builder.split_low_high(*t, 32, 64);
        inputs.push(parts.1);
        inputs.push(parts.0);
    });
    inputs.push(participation_count);
    let new_inputs_hash = builder.sha256_hash(inputs);

    //Verify merkle proof for existing round data
    let current_state_inputs_hash = builder.add_virtual_targets(8);
    let current_participation_root = builder.add_virtual_hash();
    let current_participation_count = builder.add_virtual_target();
    let current_round_hash = builder.hash_n_to_hash_no_pad::<Hash>([
        &current_state_inputs_hash[..], 
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
        prev_pr_tree_root,
        &participation_round_proof,
    );

    //Determine the new round data based on the input and previous participation count
    let input_is_less = builder.less_than(participation_count, current_participation_count, VALIDATORS_TREE_HEIGHT);
    let new_participation_root = builder.select_hash(input_is_less, current_participation_root, participation_root);
    let new_participation_count = builder.select(input_is_less, current_participation_count, participation_count);
    
    //Compute the new participation rounds tree root
    let mut new_pr_tree_root = builder.hash_n_to_hash_no_pad::<Hash>([
        &state_inputs_hash[..], 
        &new_participation_root.elements[..], 
        &[new_participation_count],
    ].concat());
    for (&bit, &sibling) in round_num_bits.iter().zip(&participation_round_proof.siblings) {
        let perm_inputs_a = [&new_pr_tree_root.elements[..], &sibling.elements[..]].concat();
        let perm_inputs_b = [&sibling.elements[..], &new_pr_tree_root.elements[..]].concat();
        let perm_inputs = builder.select_many(bit, &perm_inputs_b, &perm_inputs_a);
        new_pr_tree_root = builder.hash_n_to_hash_no_pad::<Hash>(perm_inputs);
    }

    //Register all public inputs
    builder.register_public_inputs(&new_inputs_hash);
    builder.register_public_inputs(&new_pr_tree_root.elements);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_inputs_hash = inner_cyclic_pis[0..8].to_vec();
    let inner_proof_pr_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[8..12]).unwrap();

    //Connect the previous inputs hash with inner proof or initial value
    inner_proof_inputs_hash.iter().zip(prev_inputs_hash).for_each(|(inner_proof, prev)| {
        let inner_proof_or_init = builder.mul(*inner_proof, init_zero.target);
        builder.connect(prev, inner_proof_or_init);
    });

    //Connect the previous participation rounds tree root with inner proof or initial value
    let initial_pr_tree_root = HashOutTarget { 
        elements: initial_participation_rounds_root().map(|f| builder.constant(f)) 
    };
    let inner_proof_pr_tree_root_or_init = builder.select_hash(init_zero, inner_proof_pr_tree_root, initial_pr_tree_root);
    builder.connect_hashes(prev_pr_tree_root, inner_proof_pr_tree_root_or_init);

    //Finally verify the previous (inner) proof
    builder.conditionally_verify_cyclic_proof_or_dummy::<Config>(
        init_zero,
        &inner_cyclic_proof_with_pis,
        &common_data,
    ).expect("cyclic proof verification failed");

    ParticipationStateCircuitTargets {
        round_num,
        state_inputs_hash,
        participation_root,
        participation_count,
        current_state_inputs_hash,
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
    pub state_inputs_hash: [u64; 4],
    pub participation_root: [Field; 4],
    pub participation_count: u32,

    pub current_state_inputs_hash: [u64; 4],
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

    pw.set_target(targets.round_num, Field::from_canonical_usize(data.round_num));
    data.state_inputs_hash.iter().enumerate().for_each(|(i, t)| {
        pw.set_target(targets.state_inputs_hash[i * 2], Field::from_canonical_u64(*t >> 32));
        pw.set_target(targets.state_inputs_hash[(i * 2) + 1], Field::from_canonical_u32(*t as u32));
    });
    pw.set_hash_target(targets.participation_root, HashOut::<Field> { elements: data.participation_root });
    pw.set_target(targets.participation_count, Field::from_canonical_u32(data.participation_count));
    
    data.current_state_inputs_hash.iter().enumerate().for_each(|(i, t)| {
        pw.set_target(targets.current_state_inputs_hash[i * 2], Field::from_canonical_u64(*t >> 32));
        pw.set_target(targets.current_state_inputs_hash[(i * 2) + 1], Field::from_canonical_u32(*t as u32));
    });
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
            pw.set_bool_target(targets.init_zero, false);
            let initial_inputs_hash = [Field::ZERO; 8];
            let initial_participation_rounds_root = initial_participation_rounds_root();
            let initial_public_inputs = [&initial_inputs_hash[..], &initial_participation_rounds_root[..]].concat();
            let base_proof = cyclic_base_proof(
                &circuit_data.common,
                &circuit_data.verifier_only,
                initial_public_inputs.into_iter().enumerate().collect(),
            );
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
        },
    };
    Ok(pw)
}
/*
#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &ParticipationStateCircuitTargets) -> IoResult<()> {
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
fn read_targets(buffer: &mut Buffer) -> IoResult<ParticipationStateCircuitTargets> {
    let index = buffer.read_target()?;
    let previous_root = buffer.read_target_hash()?;
    let previous_commitment = buffer.read_target_hash()?;
    let previous_stake = buffer.read_target()?;
    let new_root = buffer.read_target_hash()?;
    let new_commitment = buffer.read_target_hash()?;
    let new_stake = buffer.read_target()?;
    let merkle_proof = buffer.read_target_merkle_proof()?;

    Ok(ParticipationStateCircuitTargets {
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
*/
