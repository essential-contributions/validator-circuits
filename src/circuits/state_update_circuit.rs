use plonky2::field::extension::Extendable;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use anyhow::{anyhow, Result};

use crate::{example_validator_set, Config, Field, D, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT};
use crate::Hash;

use super::serialization::{deserialize_circuit, serialize_circuit};
use super::{Circuit, Proof, Serializeable};

//pub const PIS_STATE_UPDATE_INDEX: usize = 0;
//pub const PIS_STATE_UPDATE_PREVIOUS_ROOT: [usize; 4] = [1, 2, 3, 4];
//pub const PIS_STATE_UPDATE_PREVIOUS_STAKE: usize = 5;
//pub const PIS_STATE_UPDATE_NEW_ROOT: [usize; 4] = [6, 7, 8, 9];
//pub const PIS_STATE_UPDATE_NEW_COMMITMENT: [usize; 4] = [10, 11, 12, 13];
//pub const PIS_STATE_UPDATE_NEW_STAKE: usize = 14;

pub struct StateUpdateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    //TODO: can this be removed and just use the common from "circuit_data"?
    base_common_data: CommonCircuitData<Field, D>,
    ////
    targets: StateUpdateCircuitTargets,
}
struct StateUpdateCircuitTargets {
    condition: BoolTarget,
    inner_proof: ProofWithPublicInputsTarget<D>,
    verifier: VerifierCircuitTarget,
}
impl Circuit for StateUpdateCircuit {
    type Data = StateUpdateCircuitData;
    type Proof = StateUpdateProof;
    
    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let (targets, base_common_data) = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, base_common_data, targets }
    }

    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof> {
        let pw = generate_partial_witness(&self.circuit_data, &self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(StateUpdateProof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        self.initial_proof()
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
impl Serializeable for StateUpdateCircuit {
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
impl StateUpdateCircuit {
    pub fn initial_proof(&self) -> StateUpdateProof {
        let initial_hash = [Field::ZERO, Field::ONE, Field::TWO, Field::from_canonical_usize(3)];
        let pw = generate_initial_partial_witness(&self.circuit_data, &self.base_common_data, &self.targets, initial_hash).unwrap();
        let proof = self.circuit_data.prove(pw).unwrap();
        StateUpdateProof { proof }
    }
}

#[derive(Clone)]
pub struct StateUpdateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl StateUpdateProof {
    pub fn initial_hash(&self) -> [Field; 4] {
        [self.proof.public_inputs[0], 
        self.proof.public_inputs[1], 
        self.proof.public_inputs[2], 
        self.proof.public_inputs[3]]
    }

    pub fn hash(&self) -> [Field; 4] {
        [self.proof.public_inputs[4], 
        self.proof.public_inputs[5], 
        self.proof.public_inputs[6], 
        self.proof.public_inputs[7]]
    }

    pub fn counter(&self) -> u32 {
        self.proof.public_inputs[8].to_canonical_u64() as u32
    }
}
impl Proof for StateUpdateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> (StateUpdateCircuitTargets, CommonCircuitData<Field, D>) {
    let one = builder.one();

    // Circuit that computes a repeated hash.
    let initial_hash_target = builder.add_virtual_hash();
    builder.register_public_inputs(&initial_hash_target.elements);
    let current_hash_in = builder.add_virtual_hash();
    let current_hash_out = builder.hash_n_to_hash_no_pad::<Hash>(current_hash_in.elements.to_vec());
    builder.register_public_inputs(&current_hash_out.elements);
    let counter = builder.add_virtual_public_input();

    let mut common_data = common_data_for_recursion::<Field, Config, D>();
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    let condition = builder.add_virtual_bool_target_safe();

    // Unpack inner proof's public inputs.
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_cyclic_initial_hash = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_cyclic_latest_hash = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_cyclic_counter = inner_cyclic_pis[8];

    // Connect our initial hash to that of our inner proof. (If there is no inner proof, the initial hash will be unconstrained, which is intentional.)
    builder.connect_hashes(initial_hash_target, inner_cyclic_initial_hash);

    // The input hash is the previous hash output if we have an inner proof, or the initial hash if this is the base case.
    let actual_hash_in =  HashOutTarget {
        elements: core::array::from_fn(|i| builder.select(condition, inner_cyclic_latest_hash.elements[i], initial_hash_target.elements[i])),
    };
    builder.connect_hashes(current_hash_in, actual_hash_in);

    // Our chain length will be inner_counter + 1 if we have an inner proof, or 1 if not.
    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    builder.conditionally_verify_cyclic_proof_or_dummy::<Config>(
        condition,
        &inner_cyclic_proof_with_pis,
        &common_data,
    ).expect("cyclic proof verification failed");


    (StateUpdateCircuitTargets {
        condition,
        inner_proof: inner_cyclic_proof_with_pis,
        verifier: verifier_data_target,
    }, common_data)
}

//TODO: move this to a more common place
fn common_data_for_recursion<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>() -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << 12 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

#[derive(Clone)]
pub struct StateUpdateCircuitData {
    pub previous_proof: StateUpdateProof,
}

fn generate_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    targets: &StateUpdateCircuitTargets, 
    data: &StateUpdateCircuitData,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();
    pw.set_bool_target(targets.condition, true);
    pw.set_proof_with_pis_target(&targets.inner_proof, &data.previous_proof.proof);
    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);

    Ok(pw)
}

fn generate_initial_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    common_data: &CommonCircuitData<Field, D>, 
    targets: &StateUpdateCircuitTargets, 
    initial_hash: [Field; 4],
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    let initial_hash_pis = initial_hash.into_iter().enumerate().collect();
    let base_proof = cyclic_base_proof(
        &common_data,
        &circuit_data.verifier_only,
        initial_hash_pis,
    );

    pw.set_bool_target(targets.condition, false);
    pw.set_proof_with_pis_target::<Config, D>(&targets.inner_proof, &base_proof);
    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);

    Ok(pw)
}
/*
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
fn write_targets(buffer: &mut Vec<u8>, targets: &StateUpdateCircuitTargets) -> IoResult<()> {
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
fn read_targets(buffer: &mut Buffer) -> IoResult<StateUpdateCircuitTargets> {
    let index = buffer.read_target()?;
    let previous_root = buffer.read_target_hash()?;
    let previous_commitment = buffer.read_target_hash()?;
    let previous_stake = buffer.read_target()?;
    let new_root = buffer.read_target_hash()?;
    let new_commitment = buffer.read_target_hash()?;
    let new_stake = buffer.read_target()?;
    let merkle_proof = buffer.read_target_merkle_proof()?;

    Ok(StateUpdateCircuitTargets {
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
