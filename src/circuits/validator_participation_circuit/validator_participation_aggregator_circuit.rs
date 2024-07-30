use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, Field64, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use anyhow::{anyhow, Result};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::circuits::extensions::{common_data_for_recursion, CircuitBuilderExtended, PartialWitnessExtended};
use crate::circuits::serialization::{deserialize_circuit, serialize_circuit};
use crate::circuits::validators_state_circuit::{ValidatorsStateProof, PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT, PIS_VALIDATORS_STATE_INPUTS_HASH, PIS_VALIDATORS_STATE_TOTAL_STAKED};
use crate::circuits::{Circuit, Proof, Serializeable};
use crate::participation::{empty_participation_root, participation_merkle_data, PARTICIPANTS_PER_FIELD, PARTICIPATION_BITS_BYTE_SIZE, PARTICIPATION_FIELDS_PER_LEAF, PARTICIPATION_TREE_HEIGHT};
use crate::{Config, Field, ACCOUNTS_TREE_HEIGHT, AGGREGATION_PASS1_SIZE, AGGREGATION_PASS1_SUB_TREE_HEIGHT, D, MAX_VALIDATORS, PARTICIPATION_ROUNDS_PER_STATE_EPOCH, PARTICIPATION_ROUNDS_TREE_HEIGHT};
use crate::Hash;

pub const PIS_PR_TREE_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_ACCOUNT_ADDRESS: [usize; 5] = [4, 5, 6, 7, 8];
pub const PIS_FROM_EPOCH: usize = 9;
pub const PIS_TO_EPOCH: usize = 10;
pub const PIS_WITHDRAW_MAX: usize = 11;
pub const PIS_WITHDRAW_UNEARNED: usize = 12;
pub const PIS_PARAM_RF: usize = 13;
pub const PIS_PARAM_ST: usize = 14;

const MAX_GATES: usize = 1 << 12;

pub struct ValidatorParticipationAggCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorParticipationAggCircuitTargets,
}
struct ValidatorParticipationAggCircuitTargets {
    init_pr_tree_root: HashOutTarget,
    init_account_address: Vec<Target>,
    init_epoch: Target,
    init_param_rf: Target,
    init_param_st: Target,

    validators_state_verifier: VerifierCircuitTarget,
    validators_state_proof: ProofWithPublicInputsTarget<D>,

    validator_index: Target,
    validator_bit_index: Target,
    validator_field_index: Target,
    account_validator_index_proof: MerkleProofTarget,

    participation_rounds_targets: Vec<ValidatorParticipationRoundTargets>,
    
    init_zero: BoolTarget,
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
}
struct ValidatorParticipationRoundTargets {
    participation_root: HashOutTarget,
    participation_count: Target,
    participation_round_proof: MerkleProofTarget,

    skip_participation: BoolTarget,
    participation_bits_fields: Vec<Target>,
    participation_proof: MerkleProofTarget,
}
impl Circuit for ValidatorParticipationAggCircuit {
    type Data = ValidatorParticipationAggCircuitData;
    type Proof = ValidatorParticipationAggProof;
    
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
        Ok(ValidatorParticipationAggProof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        let data = ValidatorParticipationAggCircuitData {
            participation_bits: vec![0u8; PARTICIPATION_BITS_BYTE_SIZE],
            validator_index: 0,
        };
        let pw = generate_partial_witness(&self.targets, &data).unwrap();
        let proof = self.circuit_data.prove(pw).unwrap();
        ValidatorParticipationAggProof { proof }
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
impl Serializeable for ValidatorParticipationAggCircuit {
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
pub struct ValidatorParticipationAggProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ValidatorParticipationAggProof {
    pub fn pr_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_PR_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_PR_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_PR_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_PR_TREE_ROOT[3]]]
    }

    pub fn account_address(&self) -> [u8; 20] {
        let mut hash = [0u8; 20];
        for i in 0..5 {
            let bytes = (self.proof.public_inputs[PIS_ACCOUNT_ADDRESS[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn from_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_FROM_EPOCH].to_canonical_u64() as u32
    }

    pub fn to_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_TO_EPOCH].to_canonical_u64() as u32
    }

    pub fn withdraw_max(&self) -> u64 {
        self.proof.public_inputs[PIS_WITHDRAW_MAX].to_canonical_u64()
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.proof.public_inputs[PIS_WITHDRAW_UNEARNED].to_canonical_u64()
    }

    pub fn param_rf(&self) -> u64 {
        self.proof.public_inputs[PIS_PARAM_RF].to_canonical_u64()
    }

    pub fn parma_st(&self) -> u64 {
        self.proof.public_inputs[PIS_PARAM_ST].to_canonical_u64()
    }
}
impl Proof for ValidatorParticipationAggProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>, val_state_circuit_data: &CircuitData<Field, Config, D>) -> ValidatorParticipationAggCircuitTargets {
    let empty_participation_root = build_empty_participation_root(builder);
    let agg_pass1_size = builder.constant(Field::from_canonical_usize(AGGREGATION_PASS1_SIZE));
    let null = builder.constant(Field::ZERO.sub_one());
    let zero = builder.zero();
    let one = builder.one();

    //Init flag and starting values
    let init_zero = builder.add_virtual_bool_target_safe();
    let init_pr_tree_root = builder.add_virtual_hash();
    let init_account_address = builder.add_virtual_targets(5);
    let init_param_rf = builder.add_virtual_target();
    let init_param_st = builder.add_virtual_target();
    let init_epoch = builder.add_virtual_target();

    //Current aggregation state targets (will be connected to inner proof later)
    let current_pr_tree_root = builder.add_virtual_hash();
    let current_account_address = builder.add_virtual_targets(5);
    let current_from_epoch = builder.add_virtual_target();
    let current_to_epoch = builder.add_virtual_target();
    let current_withdraw_max = builder.add_virtual_target();
    let current_withdraw_unearned = builder.add_virtual_target();
    let current_param_rf = builder.add_virtual_target();
    let current_param_st = builder.add_virtual_target();

    //Verify the validators state proof
    let validators_state_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(val_state_circuit_data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let validators_state_proof = builder.add_virtual_proof_with_pis(&val_state_circuit_data.common);
    builder.verify_proof::<Config>(&validators_state_proof, &validators_state_verifier, &val_state_circuit_data.common);
    let validators_state_inputs_hash = vec![
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[0]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[1]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[2]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[3]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[4]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[5]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[6]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[7]],
    ];
    let validators_state_accounts_tree_root = HashOutTarget::try_from(
        &validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[0]..PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[3]]
    ).unwrap();
    let total_staked = validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_STAKED];
    
    //Verify the validator index
    let validator_index = builder.add_virtual_target();
    let validator_index_is_null = builder.is_equal(validator_index, null);
    let validator_index_is_not_null = builder.not(validator_index_is_null);
    let account_validator_index_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(ACCOUNTS_TREE_HEIGHT),
    };
    let account_address_bits: Vec<BoolTarget> = current_account_address.iter().rev().map(|t| {
        builder.split_le(*t, 32)
    }).collect::<Vec<Vec<BoolTarget>>>().concat();
    builder.verify_merkle_proof::<Hash>(
        vec![validator_index], 
        &account_address_bits, 
        validators_state_accounts_tree_root,
        &account_validator_index_proof,
    );
    let validator_field_index = builder.add_virtual_target();
    let validator_bit_index = builder.add_virtual_target();
    let expected_validator_index = builder.mul_add(validator_field_index, agg_pass1_size, validator_bit_index);
    let validator_index_deconstruction_is_valid = builder.is_equal(validator_index, expected_validator_index);
    builder.assert_true_if(validator_index_is_not_null, &[validator_index_deconstruction_is_valid]);

    //Start tracking the new withdraw values
    let mut new_withdraw_max = current_withdraw_max;
    let mut new_withdraw_unearned = current_withdraw_unearned;

    //Loop through each participation round in the epoch (the epoch last left off on)
    let epoch = current_to_epoch;
    let mut participation_rounds_targets: Vec<ValidatorParticipationRoundTargets> = Vec::new();
    for i in 0..PARTICIPATION_ROUNDS_PER_STATE_EPOCH {
        //Verify participation round
        let participation_root = builder.add_virtual_hash();
        let participation_count = builder.add_virtual_target();
        let participation_round_hash = builder.hash_n_to_hash_no_pad::<Hash>([
            &validators_state_inputs_hash[..], 
            &participation_root.elements[..], 
            &[participation_count],
        ].concat());
        let round_num = builder.arithmetic(
            Field::from_canonical_usize(PARTICIPATION_ROUNDS_PER_STATE_EPOCH), 
            Field::from_canonical_usize(i), 
            epoch, 
            one, 
            one
        );
        let round_num_bits = builder.split_le(round_num, PARTICIPATION_ROUNDS_TREE_HEIGHT);
        let participation_round_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(PARTICIPATION_ROUNDS_TREE_HEIGHT),
        };
        builder.verify_merkle_proof::<Hash>(
            participation_round_hash.elements.to_vec(), 
            &round_num_bits, 
            current_pr_tree_root,
            &participation_round_proof,
        );
        
        //Verify participation
        let skip_participation = builder.add_virtual_bool_target_safe();
        let mut participation_bits_fields: Vec<Target> = Vec::new();
        let participation_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(PARTICIPATION_TREE_HEIGHT),
        };
        let mut participated: Target = builder.zero();
        {
            //Break participation into bits
            let mut participation_bits: Vec<BoolTarget> = Vec::new();
            for i in 0..PARTICIPATION_FIELDS_PER_LEAF {
                let num_bits = PARTICIPANTS_PER_FIELD.min(AGGREGATION_PASS1_SIZE - (i * PARTICIPANTS_PER_FIELD));
                let part = builder.add_virtual_target();
                let part_bits = builder.split_le(part, num_bits);
                
                participation_bits_fields.push(part);
                for b in part_bits.iter().rev() {
                    participation_bits.push(*b);
                }
            }

            //Determine if participated
            let validator_bit_index_bits: Vec<BoolTarget> = builder.split_le(validator_bit_index, AGGREGATION_PASS1_SUB_TREE_HEIGHT);
            let validator_bit_index_bits_inv: Vec<BoolTarget> = validator_bit_index_bits.iter().map(|b| builder.not(b.clone())).collect();
            for (index, participant_bit) in participation_bits.iter().enumerate() {
                let mut participant_bit_with_index_mask = participant_bit.clone();
                for b in 0..AGGREGATION_PASS1_SUB_TREE_HEIGHT {
                    if ((1 << b) & index) > 0 {
                        participant_bit_with_index_mask = builder.and(participant_bit_with_index_mask, validator_bit_index_bits[b]);
                    } else {
                        participant_bit_with_index_mask = builder.and(participant_bit_with_index_mask, validator_bit_index_bits_inv[b]);
                    }
                }
                participated = builder.add(participated, participant_bit_with_index_mask.target);
            }

            //Verify merkle proof to the participation root unless explicitly skipped
            let participation_sub_root = builder.hash_n_to_hash_no_pad::<Hash>(participation_bits_fields.clone());
            let validator_field_index_bits = builder.split_le(validator_field_index, PARTICIPATION_TREE_HEIGHT);
            let merkle_root = builder.select_hash(skip_participation, empty_participation_root, participation_root);
            builder.verify_merkle_proof::<Hash>(
                participation_sub_root.elements.to_vec(), 
                &validator_field_index_bits, 
                merkle_root,
                &participation_proof,
            );
        }

        //Compute total max withdraw value
        let round_has_no_participation = builder.is_equal(participation_count, zero);
        let round_has_participation = builder.not(round_has_no_participation);
        //TODO: better compute amount based on things like total_staked
        let amount = builder.mul(round_has_participation.target, one);
        new_withdraw_max = builder.add(new_withdraw_max, amount);

        //Compute unearned withdraw value
        let not_skip_participation = builder.not(skip_participation);
        let not_participated = builder.not(BoolTarget::new_unsafe(participated));
        let not_skip_and_not_participated = builder.and(not_skip_participation, not_participated);
        let proved_acc_not_participate = builder.or(validator_index_is_null, not_skip_and_not_participated);
        let unearned_amount = builder.mul(proved_acc_not_participate.target, amount);
        new_withdraw_unearned = builder.add(new_withdraw_unearned, unearned_amount);

        //Add round targets
        participation_rounds_targets.push(ValidatorParticipationRoundTargets {
            participation_root,
            participation_count,
            participation_round_proof,
            skip_participation,
            participation_bits_fields,
            participation_proof,
        });
    }

    //Update the new to epoch value
    let new_to_epoch = builder.add(current_to_epoch, one);

    //Register all public inputs
    builder.register_public_inputs(&current_pr_tree_root.elements);
    builder.register_public_inputs(&current_account_address);
    builder.register_public_input(current_from_epoch);
    builder.register_public_input(new_to_epoch);
    builder.register_public_input(new_withdraw_max);
    builder.register_public_input(new_withdraw_unearned);
    builder.register_public_input(current_param_rf);
    builder.register_public_input(current_param_st);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_pr_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_proof_account_address = inner_cyclic_pis[4..9].to_vec();
    let inner_proof_from_epoch = inner_cyclic_pis[9];
    let inner_proof_to_epoch = inner_cyclic_pis[10];
    let inner_proof_withdraw_max = inner_cyclic_pis[11];
    let inner_proof_withdraw_unearned = inner_cyclic_pis[12];
    let inner_proof_param_rf = inner_cyclic_pis[13];
    let inner_proof_param_st = inner_cyclic_pis[14];

    //Connect the current participation rounds tree root with inner proof or initial value
    let inner_proof_pr_tree_root_or_init = builder.select_hash(init_zero, inner_proof_pr_tree_root, init_pr_tree_root);
    builder.connect_hashes(current_pr_tree_root, inner_proof_pr_tree_root_or_init);

    //Connect the current account address with inner proof or initial value
    inner_proof_account_address.iter().zip(current_account_address).for_each(|(inner_proof, prev)| {
        let inner_proof_or_init = builder.mul(*inner_proof, init_zero.target);
        builder.connect(prev, inner_proof_or_init);
    });

    //Connect the other public inputs
    let inner_proof_from_epoch_or_init = builder.select(init_zero, inner_proof_from_epoch, init_epoch);
    let inner_proof_to_epoch_or_init = builder.select(init_zero, inner_proof_to_epoch, init_epoch);
    let inner_proof_withdraw_max_or_init = builder.mul(init_zero.target, inner_proof_withdraw_max);
    let inner_proof_withdraw_unearned_or_init = builder.mul(init_zero.target, inner_proof_withdraw_unearned);
    let inner_proof_param_rf_or_init = builder.select(init_zero, inner_proof_param_rf, init_param_rf);
    let inner_proof_param_st_or_init = builder.select(init_zero, inner_proof_param_st, init_param_st);
    builder.connect(current_from_epoch, inner_proof_from_epoch_or_init);
    builder.connect(current_to_epoch, inner_proof_to_epoch_or_init);
    builder.connect(current_withdraw_max, inner_proof_withdraw_max_or_init);
    builder.connect(current_withdraw_unearned, inner_proof_withdraw_unearned_or_init);
    builder.connect(current_param_rf, inner_proof_param_rf_or_init);
    builder.connect(current_param_st, inner_proof_param_st_or_init);

    //Finally verify the previous (inner) proof
    builder.conditionally_verify_cyclic_proof_or_dummy::<Config>(
        init_zero,
        &inner_cyclic_proof_with_pis,
        &common_data,
    ).expect("cyclic proof verification failed");

    ValidatorParticipationAggCircuitTargets {
        init_pr_tree_root,
        init_account_address,
        init_epoch,
        init_param_rf,
        init_param_st,
    
        validators_state_verifier,
        validators_state_proof,
    
        validator_index,
        validator_bit_index,
        validator_field_index,
        account_validator_index_proof,
    
        participation_rounds_targets,
        
        init_zero,
        verifier: verifier_data_target,
        previous_proof: inner_cyclic_proof_with_pis,
    }
}


/*

struct ValidatorParticipationAggCircuitTargets {
    init_pr_tree_root: HashOutTarget,
    init_account_address: Vec<Target>,
    init_epoch: Target,
    init_param_rf: Target,
    init_param_st: Target,

    validators_state_verifier: VerifierCircuitTarget,
    validators_state_proof: ProofWithPublicInputsTarget<D>,

    validator_index: Target,
    validator_bit_index: Target,
    validator_field_index: Target,
    account_validator_index_proof: MerkleProofTarget,

    participation_rounds_targets: Vec<ValidatorParticipationRoundTargets>,
    
    init_zero: BoolTarget,
    verifier: VerifierCircuitTarget,
    previous_proof: ProofWithPublicInputsTarget<D>,
}
struct ValidatorParticipationRoundTargets {
    participation_root: HashOutTarget,
    participation_count: Target,
    participation_round_proof: MerkleProofTarget,

    skip_participation: BoolTarget,
    participation_bits_fields: Vec<Target>,
    participation_proof: MerkleProofTarget,
}
    
*/
#[derive(Clone)]
pub struct ValidatorParticipationAggCircuitData {
    pub validator_index: Option<usize>,
    pub account_validator_index_proof: Vec<[Field; 4]>,
    pub validators_state_proof: ValidatorsStateProof,

    pub participation_rounds: Vec<ValidatorPartAggRoundData>,

    pub previous_data: ValidatorPartAggPrevData,
}
#[derive(Clone)]
pub struct ValidatorPartAggRoundData {
    pub participation_root: [Field; 4],
    pub participation_count: u32,
    pub participation_round_proof: Vec<[Field; 4]>,

    pub participation_bits: Option<Vec<u8>>,
}
#[derive(Clone)]
pub struct ValidatorPartAggStartData {
    pub pr_tree_root: [Field; 4],
    pub account: [u8; 20],
    pub epoch: u32,
    pub param_rf: u64,
    pub param_st: u64,
}
#[derive(Clone)]
pub enum ValidatorPartAggPrevData {
    Start(ValidatorPartAggStartData),
    Continue(ValidatorParticipationAggProof),
}

fn generate_partial_witness(
    targets: &ValidatorParticipationAggCircuitTargets, 
    data: &ValidatorParticipationAggCircuitData, 
    circuit_data: &CircuitData<Field, Config, D>, 
    validators_state_circuit_data: &CircuitData<Field, Config, D>
) -> Result<PartialWitness<Field>> {
    assert!(data.validator_index.is_none() || data.validator_index.unwrap() < MAX_VALIDATORS, "Invalid validator index (max: {})", MAX_VALIDATORS);
    assert_eq!(data.participation_rounds.len(), PARTICIPATION_ROUNDS_PER_STATE_EPOCH, "Incorrect number of rounds data (expected: {})", PARTICIPATION_ROUNDS_PER_STATE_EPOCH);
    let mut pw = PartialWitness::new();

    //validators state proof
    pw.set_verifier_data_target(&targets.validators_state_verifier, &validators_state_circuit_data.verifier_only);
    pw.set_proof_with_pis_target(&targets.validators_state_proof, data.validators_state_proof.proof());

    //account validator index
    match data.validator_index {
        Some(validator_index) => {
            let validator_field_index = validator_index / AGGREGATION_PASS1_SIZE;
            let validator_bit_index = validator_index % AGGREGATION_PASS1_SIZE;
            pw.set_target(targets.validator_index, Field::from_canonical_usize(validator_index));
            pw.set_target(targets.validator_field_index, Field::from_canonical_usize(validator_field_index));
            pw.set_target(targets.validator_bit_index, Field::from_canonical_usize(validator_bit_index));
        },
        None => {
            //fill in with null data
            pw.set_target(targets.validator_index, Field::ZERO.sub_one());
            pw.set_target(targets.validator_field_index, Field::ZERO);
            pw.set_target(targets.validator_bit_index, Field::ZERO);
        },
    }
    pw.set_merkle_proof_target(targets.account_validator_index_proof.clone(), &data.account_validator_index_proof);

    //participation rounds targets
    targets.participation_rounds_targets.iter().zip(data.participation_rounds.clone()).for_each(|(t, d)| {
        pw.set_hash_target(t.participation_root, HashOut::<Field> { elements: d.participation_root });
        pw.set_target(t.participation_count, Field::from_canonical_u32(d.participation_count));
        pw.set_merkle_proof_target(t.participation_round_proof.clone(), &d.participation_round_proof);

        if data.validator_index.is_some() && d.participation_bits.is_some() {
            let validator_index = data.validator_index.unwrap();
            let participation_bits = d.participation_bits.unwrap();
            let participation_merkle_data = participation_merkle_data(&participation_bits, validator_index);
            assert_eq!(participation_merkle_data.root, d.participation_root, "Root caluclated from participation bits is different from given root");
            pw.set_bool_target(t.skip_participation, false);
            pw.set_target_arr(&t.participation_bits_fields, &participation_merkle_data.leaf_fields);
            pw.set_merkle_proof_target(t.participation_proof.clone(), &participation_merkle_data.proof);
        } else {
            //fill in with empty participation data
            let participation_merkle_data = participation_merkle_data(&vec![], 0);
            pw.set_bool_target(t.skip_participation, false);
            pw.set_target_arr(&t.participation_bits_fields, &participation_merkle_data.leaf_fields);
            pw.set_merkle_proof_target(t.participation_proof.clone(), &participation_merkle_data.proof);
        }
    });
    
    //previous data to build off of
    match &data.previous_data {
        ValidatorPartAggPrevData::Start(start_data) => {
            pw.set_hash_target(targets.init_pr_tree_root, HashOut::<Field> { elements: start_data.pr_tree_root });
            pw.set_target_arr(&targets.init_account_address, &account_to_fields(start_data.account));
            pw.set_target(targets.init_epoch, Field::from_canonical_u32(start_data.epoch));
            pw.set_target(targets.init_param_rf, Field::from_canonical_u64(start_data.param_rf));
            pw.set_target(targets.init_param_st, Field::from_canonical_u64(start_data.param_st));

            //create starter proof initial state (no previous proof)
            let base_proof = initial_proof(circuit_data, start_data);
            pw.set_bool_target(targets.init_zero, false);
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);

        },
        ValidatorPartAggPrevData::Continue(previous_proof) => {
            pw.set_bool_target(targets.init_zero, true);
            pw.set_proof_with_pis_target(&targets.previous_proof, &previous_proof.proof);

            //blank out init data
            pw.set_hash_target(targets.init_pr_tree_root, HashOut::<Field> { elements: [Field::ZERO; 4] });
            pw.set_target_arr(&targets.init_account_address, &[Field::ZERO; 5]);
            pw.set_target(targets.init_epoch, Field::ZERO);
            pw.set_target(targets.init_param_rf, Field::ZERO);
            pw.set_target(targets.init_param_st, Field::ZERO);
        },
    }
    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);

    Ok(pw)
}

fn initial_proof(circuit_data: &CircuitData<Field, Config, D>, init_data: &ValidatorPartAggStartData) -> ProofWithPublicInputs<Field, Config, D> {
    let initial_public_inputs = [
        &init_data.pr_tree_root[..], 
        &account_to_fields(init_data.account)[..], 
        &[Field::from_canonical_u32(init_data.epoch)],
        &[Field::from_canonical_u32(init_data.epoch)],
        &[Field::ZERO],
        &[Field::ZERO],
        &[Field::from_canonical_u64(init_data.param_rf)],
        &[Field::from_canonical_u64(init_data.param_st)],
    ].concat();
    cyclic_base_proof(
        &circuit_data.common,
        &circuit_data.verifier_only,
        initial_public_inputs.into_iter().enumerate().collect(),
    )
}

fn account_to_fields(account: [u8; 20]) -> [Field; 5] {
    let mut account_fields = [Field::ZERO; 5];
    account.chunks(4).enumerate().for_each(|(i, c)| {
        account_fields[i] = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    });
    account_fields
}
/*
#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorParticipationAggCircuitTargets) -> IoResult<()> {
    buffer.write_target(targets.validator_bit_index)?;
    buffer.write_target_vec(&targets.participation_bits_fields)?;
    buffer.write_target_hash(&targets.participation_root)?;
    buffer.write_target(targets.validator_field_index)?;
    buffer.write_target_merkle_proof(&targets.participation_root_merkle_proof)?;

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggCircuitTargets> {
    let validator_bit_index = buffer.read_target()?;
    let participation_bits_fields = buffer.read_target_vec()?;
    let participation_root = buffer.read_target_hash()?;
    let validator_field_index = buffer.read_target()?;
    let participation_root_merkle_proof = buffer.read_target_merkle_proof()?;

    Ok(ValidatorParticipationAggCircuitTargets {
        validator_bit_index,
        participation_bits_fields,
        participation_root,
        validator_field_index,
        participation_root_merkle_proof,
    })
}
*/

fn build_empty_participation_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_root();
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}
