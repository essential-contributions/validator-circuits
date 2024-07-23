use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, Field64, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use anyhow::Result;

use crate::accounts::initial_accounts_tree_root;
use crate::validators::initial_validators_tree_root;
use crate::{Config, Field, D, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT};
use crate::Hash;

use super::extensions::{common_data_for_recursion, CircuitBuilderExtended, PartialWitnessExtended};
use super::{Circuit, Proof};

pub const PIS_VALIDATORS_STATE_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_VALIDATORS_STATE_TOTAL_STAKED: usize = 8;
pub const PIS_VALIDATORS_STATE_TOTAL_VALIDATORS: usize = 9;
pub const PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT: [usize; 4] = [10, 11, 12, 13];
pub const PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT: [usize; 4] = [14, 15, 16, 17];

const MAX_GATES: usize = 1 << 14;
const ACCOUNTS_TREE_HEIGHT: usize = 160;

pub struct ValidatorsStateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorsStateCircuitTargets,
}
struct ValidatorsStateCircuitTargets {
    index: Target,
    stake: Target,
    commitment: HashOutTarget,
    account: Vec<Target>,
    
    validator_index: Target,
    validator_stake: Target,
    validator_commitment: HashOutTarget,
    validator_proof: MerkleProofTarget,
    from_account: Vec<Target>,
    from_acc_index: Target,
    from_acc_proof: MerkleProofTarget,
    to_account: Vec<Target>,
    to_acc_index: Target,
    to_acc_proof: MerkleProofTarget,
    
    init_zero: BoolTarget,
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
}
impl Circuit for ValidatorsStateCircuit {
    type Data = ValidatorsStateCircuitData;
    type Proof = ValidatorsStateProof;
    
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
        Ok(ValidatorsStateProof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        //TODO
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
impl Serializeable for ValidatorsStateCircuit {
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
pub struct ValidatorsStateProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ValidatorsStateProof {
    pub fn inputs_hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes = (self.proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn total_staked(&self) -> u32 {
        self.proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_STAKED].to_canonical_u64() as u32
    }

    pub fn total_validators(&self) -> u32 {
        self.proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_VALIDATORS].to_canonical_u64() as u32
    }

    pub fn validators_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[3]]]
    }

    pub fn accounts_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[3]]]
    }
}
impl Proof for ValidatorsStateProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ValidatorsStateCircuitTargets {
    let zero = builder.zero();
    let one = builder.one();
    let null = builder.constant(Field::ZERO.sub_one());
    let max_validators = builder.constant(Field::from_canonical_usize(MAX_VALIDATORS));

    //Init flag
    let init_zero = builder.add_virtual_bool_target_safe();

    //Inputs
    let index = builder.add_virtual_target();
    let stake = builder.add_virtual_target();
    let commitment = builder.add_virtual_hash();
    let account = builder.add_virtual_targets(5);

    //Current state targets (will be connected to inner proof later)
    let current_inputs_hash = builder.add_virtual_targets(8);
    let current_total_staked = builder.add_virtual_target();
    let current_total_validators = builder.add_virtual_target();
    let current_validators_tree_root = builder.add_virtual_hash();
    let current_accounts_tree_root = builder.add_virtual_hash();

    //Compute the new inputs hash
    let mut inputs: Vec<Target> = Vec::new();
    current_inputs_hash.iter().for_each(|t| inputs.push(*t));
    inputs.push(index);
    inputs.push(stake);
    commitment.elements.iter().for_each(|t| {
        let parts = builder.split_low_high(*t, 32, 64);
        inputs.push(parts.1);
        inputs.push(parts.0);
    });
    account.iter().for_each(|t| inputs.push(*t));
    let new_inputs_hash = builder.sha256_hash(inputs);

    //Verify private input merkle proof for validator tree
    let validator_stake = builder.add_virtual_target();
    let validator_commitment = builder.add_virtual_hash();
    let current_validator_hash = builder.hash_n_to_hash_no_pad::<Hash>([
        &validator_commitment.elements[..], 
        &[validator_stake],
    ].concat());
    let validator_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(VALIDATORS_TREE_HEIGHT),
    };
    let validator_index = builder.add_virtual_target();
    let validator_index_bits = builder.split_le(validator_index, VALIDATORS_TREE_HEIGHT);
    builder.verify_merkle_proof::<Hash>(
        current_validator_hash.elements.to_vec(), 
        &validator_index_bits, 
        current_validators_tree_root,
        &validator_proof,
    );

    //Verify private input merkle proof for the account the validator index is moving from
    let from_account = builder.add_virtual_targets(5);
    let from_acc_index = builder.add_virtual_target();
    let from_acc_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(ACCOUNTS_TREE_HEIGHT),
    };
    let from_acc_bits: Vec<BoolTarget> = from_account.iter().rev().map(|t| {
        builder.split_le(*t, 32)
    }).collect::<Vec<Vec<BoolTarget>>>().concat();
    builder.verify_merkle_proof::<Hash>(
        vec![from_acc_index], 
        &from_acc_bits, 
        current_accounts_tree_root,
        &from_acc_proof,
    );

    //Verify private input merkle proof for the account the validator index is moving to
    let to_account = builder.add_virtual_targets(5);
    let to_acc_index = builder.add_virtual_target();
    let to_acc_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(ACCOUNTS_TREE_HEIGHT),
    };
    let to_acc_bits: Vec<BoolTarget> = to_account.iter().rev().map(|t| {
        builder.split_le(*t, 32)
    }).collect::<Vec<Vec<BoolTarget>>>().concat();
    builder.verify_merkle_proof::<Hash>(
        vec![to_acc_index], 
        &to_acc_bits, 
        current_accounts_tree_root,
        &to_acc_proof,
    );

    //Determine what kind of operation this is and start new targets to help build a new state
    let is_stake_operation = builder.is_equal(stake, zero);
    let is_unstake_operation = builder.not(is_stake_operation);
    let mut new_total_staked = current_total_staked;
    let mut new_total_validators = current_total_validators;
    let mut new_validator_stake = validator_stake;
    let mut new_validator_commitment = validator_commitment;
    let mut new_from_acc_index = from_acc_index;
    let mut new_to_acc_index = to_acc_index;

    //Process for stake operation (stake amount is non-zero)
    {
        //Constrain the private inputs
        let validator_index_eq_input = builder.is_equal(validator_index, index);
        let to_acc_eq_input = builder.is_equal_many(&to_account, &account);
        let from_acc_index_eq_input = builder.is_equal(from_acc_index, index);
        let terms = [
            validator_index_eq_input, 
            to_acc_eq_input, 
            from_acc_index_eq_input
        ];
        builder.assert_true_if(is_stake_operation, &terms);

        //Determine if the stake operation is valid
        let stake_increase = builder.greater_than(stake, validator_stake, 32);
        let same_account = builder.is_equal(from_acc_index, to_acc_index);
        let to_acc_index_is_null = builder.is_equal(to_acc_index, null);
        let same_acc_or_to_acc_index_null = builder.or(same_account, to_acc_index_is_null);
        let from_acc_is_null = is_account_null(builder, &from_account, index);
        let validators_at_max = builder.is_equal(current_total_validators, max_validators);
        let from_acc_is_null_or_max_validators = builder.or(from_acc_is_null, validators_at_max);
        let is_valid_stake_op = builder.and_many(&[
            is_stake_operation,
            stake_increase,
            from_acc_is_null_or_max_validators,
            same_acc_or_to_acc_index_null,
        ]);

        //Compute the theoretically updated values
        let stake_delta = builder.sub(stake, validator_stake);
        let updated_total_staked = builder.add(current_total_staked, stake_delta);
        let updated_total_validators = builder.add(current_total_validators, from_acc_is_null.target);
        let updated_validator_stake = stake;
        let updated_validator_commitment = commitment;
        let updated_from_acc_index = null;
        let updated_to_acc_index = index;

        //Set the final values if applicable
        new_total_staked = builder.select(is_valid_stake_op, updated_total_staked, new_total_staked);
        new_total_validators = builder.select(is_valid_stake_op, updated_total_validators, new_total_validators);
        new_validator_stake = builder.select(is_valid_stake_op, updated_validator_stake, new_validator_stake);
        new_validator_commitment = builder.select_hash(is_valid_stake_op, updated_validator_commitment, new_validator_commitment);
        new_from_acc_index = builder.select(is_valid_stake_op, updated_from_acc_index, new_from_acc_index);
        new_to_acc_index = builder.select(is_valid_stake_op, updated_to_acc_index, new_to_acc_index);
    }

    //Process for unstake operation (stake amount is zero)
    {
        //Constrain the private inputs
        let validator_index_eq_from_acc_index = builder.is_equal(validator_index, from_acc_index);
        let to_acc_eq_null_acc = is_account_null(builder, &to_account, validator_index);
        let from_acc_eq_input = builder.is_equal_many(&from_account, &account);
        let from_acc_index_is_null = builder.is_equal(from_acc_index, null);
        let terms = [
            builder.or(validator_index_eq_from_acc_index, from_acc_index_is_null),
            to_acc_eq_null_acc, 
            from_acc_eq_input, 
        ];
        builder.assert_true_if(is_unstake_operation, &terms);

        //Determine if the unstake operation is valid
        let from_acc_index_is_not_null = builder.not(from_acc_index_is_null);
        let is_valid_unstake_op = builder.and_many(&[
            is_unstake_operation,
            from_acc_index_is_not_null,
        ]);

        //Compute the theoretically updated values
        let updated_total_staked = builder.sub(current_total_staked, validator_stake);
        let updated_total_validators = builder.sub(current_total_validators, one);
        let updated_validator_stake = zero;
        let updated_validator_commitment = HashOutTarget {
            elements: [zero, zero, zero, zero]
        };
        let updated_from_acc_index = null;
        let updated_to_acc_index = validator_index;

        //Set the final values if applicable
        new_total_staked = builder.select(is_valid_unstake_op, updated_total_staked, new_total_staked);
        new_total_validators = builder.select(is_valid_unstake_op, updated_total_validators, new_total_validators);
        new_validator_stake = builder.select(is_valid_unstake_op, updated_validator_stake, new_validator_stake);
        new_validator_commitment = builder.select_hash(is_valid_unstake_op, updated_validator_commitment, new_validator_commitment);
        new_from_acc_index = builder.select(is_valid_unstake_op, updated_from_acc_index, new_from_acc_index);
        new_to_acc_index = builder.select(is_valid_unstake_op, updated_to_acc_index, new_to_acc_index);
    }

    //Compute the new tree roots
    let new_validators_tree_root = builder.merkle_root_from_prev_proof::<Hash>(
        [
            &new_validator_commitment.elements[..], 
            &[new_validator_stake],
        ].concat(), 
        &validator_index_bits, 
        &validator_proof
    );
    let new_accounts_tree_root = builder.merkle_root_from_prev_two_proofs::<Hash>(
        vec![new_from_acc_index],
        &from_acc_bits, 
        &from_acc_proof,
        vec![new_to_acc_index],
        &to_acc_bits, 
        &to_acc_proof,
    );

    //Register all public inputs
    builder.register_public_inputs(&new_inputs_hash);
    builder.register_public_input(new_total_staked);
    builder.register_public_input(new_total_validators);
    builder.register_public_inputs(&new_validators_tree_root.elements);
    builder.register_public_inputs(&new_accounts_tree_root.elements);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_inputs_hash = inner_cyclic_pis[0..8].to_vec();
    let inner_proof_total_staked = inner_cyclic_pis[8];
    let inner_proof_total_validators = inner_cyclic_pis[9];
    let inner_proof_validators_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[10..14]).unwrap();
    let inner_proof_accounts_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[14..18]).unwrap();

    //Connect the current inputs hash with inner proof or initial value
    inner_proof_inputs_hash.iter().zip(current_inputs_hash).for_each(|(inner_proof, prev)| {
        let inner_proof_or_init = builder.mul(*inner_proof, init_zero.target);
        builder.connect(prev, inner_proof_or_init);
    });

    //Connect the current totals with inner proof or initial values
    let inner_proof_total_staked_or_init = builder.mul(inner_proof_total_staked, init_zero.target);
    builder.connect(current_total_staked, inner_proof_total_staked_or_init);
    let inner_proof_total_validators_or_init = builder.mul(inner_proof_total_validators, init_zero.target);
    builder.connect(current_total_validators, inner_proof_total_validators_or_init);

    //Connect the current validators tree root with inner proof or initial value
    let initial_validators_tree_root = HashOutTarget { 
        elements: initial_validators_tree_root().map(|f| builder.constant(f)) 
    };
    let inner_proof_validators_tree_root_or_init = builder.select_hash(init_zero, inner_proof_validators_tree_root, initial_validators_tree_root);
    builder.connect_hashes(current_validators_tree_root, inner_proof_validators_tree_root_or_init);

    //Connect the current accounts tree root with inner proof or initial value
    let initial_accounts_tree_root = HashOutTarget { 
        elements: initial_accounts_tree_root().map(|f| builder.constant(f)) 
    };
    let inner_proof_accounts_tree_root_or_init = builder.select_hash(init_zero, inner_proof_accounts_tree_root, initial_accounts_tree_root);
    builder.connect_hashes(current_accounts_tree_root, inner_proof_accounts_tree_root_or_init);

    //Finally verify the previous (inner) proof
    builder.conditionally_verify_cyclic_proof_or_dummy::<Config>(
        init_zero,
        &inner_cyclic_proof_with_pis,
        &common_data,
    ).expect("cyclic proof verification failed");

    ValidatorsStateCircuitTargets {
        index,
        stake,
        commitment,
        account,

        validator_index,
        validator_stake,
        validator_commitment,
        validator_proof,
        from_account,
        from_acc_index,
        from_acc_proof,
        to_account,
        to_acc_index,
        to_acc_proof,

        init_zero,
        verifier: verifier_data_target,
        previous_proof: inner_cyclic_proof_with_pis,
    }
}

fn is_account_null(builder: &mut CircuitBuilder<Field, D>, account: &[Target], validator_index: Target) -> BoolTarget {
    let null_account = [builder.zero(), builder.zero(), builder.zero(), builder.zero(), validator_index];
    builder.is_equal_many(account, &null_account)
}

#[derive(Clone)]
pub struct ValidatorsStateCircuitData {
    pub round_num: usize,
    pub state_inputs_hash: [u8; 32],
    pub participation_root: [Field; 4],
    pub participation_count: u32,

    pub current_state_inputs_hash: [u8; 32],
    pub current_participation_root: [Field; 4],
    pub current_participation_count: u32,
    pub participation_round_proof: Vec<[Field; 4]>,
    
    pub previous_proof: Option<ValidatorsStateProof>,

    /*
    index: Target,
    stake: Target,
    commitment: HashOutTarget,
    account: Vec<Target>,
    
    validator_index: Target,
    validator_stake: Target,
    validator_commitment: HashOutTarget,
    validator_proof: MerkleProofTarget,
    from_account: Vec<Target>,
    from_acc_index: Target,
    from_acc_proof: MerkleProofTarget,
    to_account: Vec<Target>,
    to_acc_index: Target,
    to_acc_proof: MerkleProofTarget,
    
    init_zero: BoolTarget,
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
    */
}

fn generate_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    targets: &ValidatorsStateCircuitTargets, 
    data: &ValidatorsStateCircuitData,
    
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    pw.set_target(targets.round_num, Field::from_canonical_usize(data.round_num));
    data.state_inputs_hash.chunks(4).enumerate().for_each(|(i, c)| {
        let value = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        pw.set_target(targets.state_inputs_hash[i], value);
    });
    pw.set_hash_target(targets.participation_root, HashOut::<Field> { elements: data.participation_root });
    pw.set_target(targets.participation_count, Field::from_canonical_u32(data.participation_count));
    
    data.current_state_inputs_hash.chunks(4).enumerate().for_each(|(i, c)| {
        let value = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        pw.set_target(targets.current_state_inputs_hash[i], value);
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
fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorsStateCircuitTargets) -> IoResult<()> {
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
fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorsStateCircuitTargets> {
    let index = buffer.read_target()?;
    let previous_root = buffer.read_target_hash()?;
    let previous_commitment = buffer.read_target_hash()?;
    let previous_stake = buffer.read_target()?;
    let new_root = buffer.read_target_hash()?;
    let new_commitment = buffer.read_target_hash()?;
    let new_stake = buffer.read_target()?;
    let merkle_proof = buffer.read_target_merkle_proof()?;

    Ok(ValidatorsStateCircuitTargets {
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
