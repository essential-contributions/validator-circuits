use plonky2::hash::hash_types::HashOutTarget;
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

use crate::{Config, Field, D};
use crate::Hash;

use super::extensions::{common_data_for_recursion, CircuitBuilderExtended};
use super::{Circuit, Proof};

//pub const PIS_STATE_UPDATE_INDEX: usize = 0;
//pub const PIS_STATE_UPDATE_PREVIOUS_ROOT: [usize; 4] = [1, 2, 3, 4];
//pub const PIS_STATE_UPDATE_PREVIOUS_STAKE: usize = 5;
//pub const PIS_STATE_UPDATE_NEW_ROOT: [usize; 4] = [6, 7, 8, 9];
//pub const PIS_STATE_UPDATE_NEW_COMMITMENT: [usize; 4] = [10, 11, 12, 13];
//pub const PIS_STATE_UPDATE_NEW_STAKE: usize = 14;

const STATE_UPDATE_NUM_OPCODES: usize = 3;
pub const STATE_UPDATE_OP_STAKE: u8 = 1;
pub const STATE_UPDATE_OP_ADD: u8 = 2;
pub const STATE_UPDATE_OP_MUL: u8 = 4;

const STATE_UPDATE_MAX_PARAMS: usize = 1;

const STATE_UPDATE_INITIAL_ROOT: [u64; 4] = [0, 0, 0, 0];
const STATE_UPDATE_INITIAL_VALIDATORS_TREE_ROOT: [u64; 4] = [0, 0, 0, 0];

const MAX_GATES: usize = 1 << 12;

pub struct StateUpdateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: StateUpdateCircuitTargets,
}
struct StateUpdateCircuitTargets {
    op: Target,
    params: [Target; STATE_UPDATE_MAX_PARAMS],
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
}
impl Circuit for StateUpdateCircuit {
    type Data = StateUpdateCircuitData;
    type Proof = StateUpdateProof;
    
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
        let pw = generate_initial_partial_witness(&self.circuit_data, &self.targets).unwrap();
        let proof = self.circuit_data.prove(pw).unwrap();
        StateUpdateProof { proof }
    }
}

#[derive(Clone)]
pub struct StateUpdateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl StateUpdateProof {
    pub fn root(&self) -> [Field; 4] {
        [self.proof.public_inputs[0], 
        self.proof.public_inputs[1], 
        self.proof.public_inputs[2], 
        self.proof.public_inputs[3]]
    }

    pub fn total_staked(&self) -> u32 {
        self.proof.public_inputs[4].to_canonical_u64() as u32
    }
}
impl Proof for StateUpdateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> StateUpdateCircuitTargets {
    //Operation flags
    let op = builder.add_virtual_target();
    let op_bits = builder.split_le(op, STATE_UPDATE_NUM_OPCODES);
    let op_stake = op_bits[0];
    let op_add = op_bits[1];
    let op_mul = op_bits[2];
    let init_zero = BoolTarget::new_unsafe(
        op_bits.into_iter().fold(builder.zero(), |acc, t| builder.add(acc, t.target))
    );
    builder.assert_bool(init_zero);

    //Params
    let params = builder.add_virtual_target_arr::<STATE_UPDATE_MAX_PARAMS>();

    //Previous state targets (will be connected to actual proof later)
    let prev_root = builder.add_virtual_hash();
    let prev_total_staked = builder.add_virtual_target();

    //Compute the new root
    let params_or_init = params.map(|p| builder.mul(p, init_zero.target));
    let data_to_hash = [&prev_root.elements[..], &[op], &params_or_init[..]].concat();
    let new_root = builder.hash_n_to_hash_no_pad::<Hash>(data_to_hash);

    //Compute new state depending on the op
    let new_total_staked = op_add_execute(builder, op_add, prev_total_staked, &params);
    let new_total_staked = op_mul_execute(builder, op_mul, new_total_staked, &params);

    //Register all public inputs
    builder.register_public_inputs(&new_root.elements);
    builder.register_public_input(new_total_staked);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_root = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_proof_total_staked = inner_cyclic_pis[4];

    //Connect the previous root with inner proof or initial value
    let initial_root = HashOutTarget {
        elements: [
            builder.constant(Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[0])),
            builder.constant(Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[1])),
            builder.constant(Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[2])),
            builder.constant(Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[3]))
        ],
    };
    let prev_root_or_init = builder.select_hash(init_zero, inner_proof_root, initial_root);
    builder.connect_hashes(prev_root, prev_root_or_init);

    //Connect the previous total staked with inner proof or initial value
    let initial_total_staked = builder.constant(Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[0]));
    let prev_total_staked_or_init = builder.select(init_zero, inner_proof_total_staked, initial_total_staked);
    builder.connect(prev_total_staked, prev_total_staked_or_init);

    //Finally verify the previous (inner) proof
    builder.conditionally_verify_cyclic_proof_or_dummy::<Config>(
        init_zero,
        &inner_cyclic_proof_with_pis,
        &common_data,
    ).expect("cyclic proof verification failed");

    StateUpdateCircuitTargets {
        op,
        params,
        verifier: verifier_data_target,
        previous_proof: inner_cyclic_proof_with_pis,
    }
}








#[derive(Clone)]
pub struct StateUpdateCircuitData {
    pub op_code: u8,
    pub params: [u64; STATE_UPDATE_MAX_PARAMS],
    pub previous_proof: StateUpdateProof,
}

fn generate_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    targets: &StateUpdateCircuitTargets, 
    data: &StateUpdateCircuitData,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    pw.set_target(targets.op, Field::from_canonical_u8(data.op_code));
    targets.params.iter().zip(data.params).for_each(|(t, v)| {
        pw.set_target(*t, Field::from_canonical_u64(v));
    });
    pw.set_proof_with_pis_target(&targets.previous_proof, &data.previous_proof.proof);
    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);

    Ok(pw)
}

fn generate_initial_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    targets: &StateUpdateCircuitTargets, 
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    let initial_hash = [
        Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[0]),
        Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[1]),
        Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[2]),
        Field::from_canonical_u64(STATE_UPDATE_INITIAL_ROOT[3])
    ];
    let initial_hash_pis = initial_hash.into_iter().enumerate().collect();
    let base_proof = cyclic_base_proof(
        &circuit_data.common,
        &circuit_data.verifier_only,
        initial_hash_pis,
    );

    pw.set_target(targets.op, Field::ZERO);
    targets.params.iter().for_each(|t| {
        pw.set_target(*t, Field::ZERO);
    });
    pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);

    Ok(pw)
}

struct PublicStateTargets {
    total_staked: Target,
    validators_tree_root: HashOutTarget,
    withdrawals_tree_root: HashOutTarget,
}

/////////////////////////////////////////////////////////////////
//////////////////////// stake operation //////////////////////////
/////////////////////////////////////////////////////////////////
fn op_stake_execute(builder: &mut CircuitBuilder<Field, D>, op_flag: BoolTarget, curr_total_staked: Target, params: &[Target; 1]) -> Target {
    //note: initial accounts tree needs to set first 1m accounts as the active account for each validator index (but with zero stake)

    /*stake/unstake
        keep track of a target that can roll back root update

        verify merkle proof for validator index
        verify merkle proof for previous account
        verify account validator index matches
        verify account is flagged as active  
        flag rollback if stake is not greater than previous (unless new stake is 0)

        previous accounts balance += current stake amount
        active flag is turned off for that account
        epoch check end is set to the given epoch

        compute the new accounts root

        verify merkle proof for new account
        flag rollback if account is active
        flag rollback if validator index is or epoch checks are not null

        active flag is turned on
        set validator index
        set epoch check start to current epoch

        compute the new accounts root

        set validator stake amount
        set validator commitment

        update total staked

        compute new validators root

        if rollback
            increase the new accounts balance to later withdraw
    */

    /*reward
        verify merkle proof for account

        if active
            update epoch check start to epoch
        else
            if epoch is greater than or equal to epoch check end
                clear validator index, epoch checks
            else
                update epoch check start to epoch

        increase balance
    */

    /*withdraw
        verify merkle proof for account

        if active
            update epoch check stat to epoch
             
        decrease balance
    */

    builder.add_virtual_target()
}







/////////////////////////////////////////////////////////////////
//////////////////////// add operation //////////////////////////
/////////////////////////////////////////////////////////////////
fn op_add_execute(builder: &mut CircuitBuilder<Field, D>, op_flag: BoolTarget, curr_total_staked: Target, params: &[Target; 1]) -> Target {
    let add_result = builder.add(curr_total_staked, params[0]);
    builder.select(op_flag, add_result, curr_total_staked)
}









/////////////////////////////////////////////////////////////////
//////////////////////// mul operation //////////////////////////
/////////////////////////////////////////////////////////////////
fn op_mul_execute(builder: &mut CircuitBuilder<Field, D>, op_flag: BoolTarget, curr_total_staked: Target, params: &[Target; 1]) -> Target {
    let add_result = builder.mul(curr_total_staked, params[0]);
    builder.select(op_flag, add_result, curr_total_staked)
}










/*

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
