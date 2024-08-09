use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, Field64, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::circuits::extensions::{common_data_for_recursion, CircuitBuilderExtended, PartialWitnessExtended};
use crate::circuits::serialization::{deserialize_circuit, read_verifier, serialize_circuit, write_verifier};
use crate::circuits::validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateProof, PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT, PIS_VALIDATORS_STATE_INPUTS_HASH, PIS_VALIDATORS_STATE_TOTAL_STAKED, PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT};
use crate::circuits::{load_or_create_circuit, Circuit, Proof, Serializeable, VALIDATORS_STATE_CIRCUIT_DIR};
use crate::participation::{empty_participation_root, participation_merkle_data, PARTICIPANTS_PER_FIELD, PARTICIPATION_FIELDS_PER_LEAF, PARTICIPATION_TREE_HEIGHT};
use crate::validators::{empty_validators_tree_proof, empty_validators_tree_root};
use crate::{Config, Field, ACCOUNTS_TREE_HEIGHT, AGGREGATION_STAGE1_SIZE, AGGREGATION_STAGE1_SUB_TREE_HEIGHT, D, MAX_VALIDATORS, PARTICIPATION_ROUNDS_PER_STATE_EPOCH, PARTICIPATION_ROUNDS_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT, VALIDATOR_EPOCHS_TREE_HEIGHT};
use crate::Hash;

pub const PIS_AGG_EPOCHS_TREE_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_AGG_PR_TREE_ROOT: [usize; 4] = [4, 5, 6, 7];
pub const PIS_AGG_ACCOUNT_ADDRESS: [usize; 5] = [8, 9, 10, 11, 12];
pub const PIS_AGG_FROM_EPOCH: usize = 13;
pub const PIS_AGG_TO_EPOCH: usize = 14;
pub const PIS_AGG_WITHDRAW_MAX: usize = 15;
pub const PIS_AGG_WITHDRAW_UNEARNED: usize = 16;
pub const PIS_AGG_PARAM_RF: usize = 17;
pub const PIS_AGG_PARAM_ST: usize = 18;

const MAX_GATES: usize = 1 << 15;

pub struct ValidatorParticipationAggCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorParticipationAggCircuitTargets,

    validators_state_verifier: VerifierOnlyCircuitData<Config, D>,
}
struct ValidatorParticipationAggCircuitTargets {
    init_val_epochs_tree_root: HashOutTarget,
    init_pr_tree_root: HashOutTarget,
    init_account_address: Vec<Target>,
    init_epoch: Target,
    init_param_rf: Target,
    init_param_st: Target,

    validators_state_verifier: VerifierCircuitTarget,
    validators_state_proof: ProofWithPublicInputsTarget<D>,
    validator_epochs_proof: MerkleProofTarget,

    validator_index: Target,
    validator_bit_index: Target,
    validator_field_index: Target,
    validator_stake: Target,
    validator_commitment: HashOutTarget,
    validator_stake_proof: MerkleProofTarget,
    account_validator_proof: MerkleProofTarget,

    gamma: Target,
    lambda: Target,
    round_issuance: Target,
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
impl ValidatorParticipationAggCircuit {
    pub fn generate_proof(&self, data: &ValidatorParticipationAggCircuitData) -> Result<ValidatorParticipationAggProof> {
        let pw = generate_partial_witness(
            &self.targets, 
            data, 
            &self.circuit_data, 
            &self.validators_state_verifier,
        )?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ValidatorParticipationAggProof { proof })
    }
}
impl Circuit for ValidatorParticipationAggCircuit {
    type Proof = ValidatorParticipationAggProof;
    
    fn new() -> Self {
        let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
        let validators_state_common_data = &validators_state_circuit.circuit_data().common;
        let validators_state_verifier = validators_state_circuit.circuit_data().verifier_only.clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, validators_state_common_data);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets, validators_state_verifier }
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

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        Ok(proof.proof.to_bytes())
    }

    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof> {
        let common_data = &self.circuit_data.common;
        let proof = ProofWithPublicInputs::<Field, Config, D>::from_bytes(bytes, common_data)?;
        Ok(Self::Proof { proof })
    }

    fn is_wrappable() -> bool {
        false
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        None
    }
}
impl Serializeable for ValidatorParticipationAggCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        if write_verifier(&mut buffer, &self.validators_state_verifier).is_err() {
            return Err(anyhow!("Failed to serialize sub circuit verifier"));
        }

        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = match read_targets(&mut buffer) {
            Ok(targets) => Ok(targets),
            Err(_) => Err(anyhow!("Failed to deserialize circuit targets")),
        }?;
        let validators_state_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;

        Ok(Self { 
            circuit_data, 
            targets, 
            validators_state_verifier, 
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorParticipationAggProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ValidatorParticipationAggProof {
    pub fn validator_epochs_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[3]]]
    }
    
    pub fn participation_rounds_tree_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG_PR_TREE_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG_PR_TREE_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG_PR_TREE_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG_PR_TREE_ROOT[3]]]
    }

    pub fn account_address(&self) -> [u8; 20] {
        let mut hash = [0u8; 20];
        for i in 0..5 {
            let bytes = (self.proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn from_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_FROM_EPOCH].to_canonical_u64() as u32
    }

    pub fn to_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_TO_EPOCH].to_canonical_u64() as u32
    }

    pub fn withdraw_max(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG_WITHDRAW_MAX].to_canonical_u64()
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG_WITHDRAW_UNEARNED].to_canonical_u64()
    }

    pub fn param_rf(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_PARAM_RF].to_canonical_u64() as u32
    }

    pub fn param_st(&self) -> u32 {
        self.proof.public_inputs[PIS_AGG_PARAM_ST].to_canonical_u64() as u32
    }
}
impl Proof for ValidatorParticipationAggProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>, val_state_common_data: &CommonCircuitData<Field, D>) -> ValidatorParticipationAggCircuitTargets {
    let empty_participation_root = build_empty_participation_root(builder);
    let empty_stake_validators_root = build_empty_stake_root(builder);
    let agg_pass1_size = builder.constant(Field::from_canonical_usize(AGGREGATION_STAGE1_SIZE));
    let x1000000 = builder.constant(Field::from_canonical_u32(1000000));
    let null = builder.constant(Field::ZERO.sub_one());
    let zero = builder.zero();
    let one = builder.one();

    //Init flag and starting values
    let init_zero = builder.add_virtual_bool_target_safe();
    let init_val_epochs_tree_root = builder.add_virtual_hash();
    let init_pr_tree_root = builder.add_virtual_hash();
    let init_account_address = builder.add_virtual_targets(5);
    let init_param_rf = builder.add_virtual_target();
    let init_param_st = builder.add_virtual_target();
    let init_epoch = builder.add_virtual_target();

    //Current aggregation state targets (will be connected to inner proof later)
    let current_val_epochs_tree_root = builder.add_virtual_hash();
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
        constants_sigmas_cap: builder.add_virtual_cap(val_state_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let validators_state_proof = builder.add_virtual_proof_with_pis(val_state_common_data);
    builder.verify_proof::<Config>(&validators_state_proof, &validators_state_verifier, val_state_common_data);
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
        &validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[0]..(PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[3] + 1)]
    ).unwrap();
    let validators_state_validators_tree_root = HashOutTarget::try_from(
        &validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[0]..(PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[3] + 1)]
    ).unwrap();
    let total_staked = validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_STAKED];

    //Verify the validators state inputs hash in the validator epochs tree
    let epoch = current_to_epoch;
    let epoch_bits = builder.split_le(epoch, VALIDATOR_EPOCHS_TREE_HEIGHT);
    let validator_epochs_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(VALIDATOR_EPOCHS_TREE_HEIGHT),
    };
    builder.verify_merkle_proof::<Hash>(
        validators_state_inputs_hash, 
        &epoch_bits, 
        current_val_epochs_tree_root,
        &validator_epochs_proof,
    );

    //Verify the validator index
    let validator_index = builder.add_virtual_target();
    let validator_index_is_null = builder.is_equal(validator_index, null);
    let validator_index_is_not_null = builder.not(validator_index_is_null);
    let account_validator_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(ACCOUNTS_TREE_HEIGHT),
    };
    let account_address_bits: Vec<BoolTarget> = current_account_address.iter().rev().map(|t| {
        builder.split_le(*t, 32)
    }).collect::<Vec<Vec<BoolTarget>>>().concat();
    builder.verify_merkle_proof::<Hash>(
        vec![validator_index], 
        &account_address_bits, 
        validators_state_accounts_tree_root,
        &account_validator_proof,
    );
    let validator_field_index = builder.add_virtual_target();
    let validator_bit_index = builder.add_virtual_target();
    let expected_validator_index = builder.mul_add(validator_field_index, agg_pass1_size, validator_bit_index);
    let validator_index_deconstruction_is_valid = builder.is_equal(validator_index, expected_validator_index);
    builder.assert_true_if(validator_index_is_not_null, &[validator_index_deconstruction_is_valid]);
    let validator_field_index_is_zero = builder.is_equal(validator_field_index, zero);
    let validator_bit_index_is_zero = builder.is_equal(validator_bit_index, zero);
    builder.assert_true_if(validator_index_is_null, &[validator_field_index_is_zero, validator_bit_index_is_zero]);

    //Verify the stake amount
    let validator_stake = builder.add_virtual_target();
    let validator_commitment = builder.add_virtual_hash();
    let validator_hash = builder.hash_n_to_hash_no_pad::<Hash>([
        &validator_commitment.elements[..], 
        &[validator_stake],
    ].concat());
    let validator_stake_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(VALIDATORS_TREE_HEIGHT),
    };
    let validator_stake_index = builder.mul(validator_index, validator_index_is_not_null.target);
    let validator_stake_index_bits = builder.split_le(validator_stake_index, VALIDATORS_TREE_HEIGHT);
    let validator_stake_merkle_root = builder.select_hash(
        validator_index_is_null, 
        empty_stake_validators_root, 
        validators_state_validators_tree_root
    );
    builder.verify_merkle_proof::<Hash>(
        validator_hash.elements.to_vec(), 
        &validator_stake_index_bits, 
        validator_stake_merkle_root,
        &validator_stake_proof,
    );

    //Build constants for calculating withdrawals
    let gamma = builder.add_virtual_target(); //`sqrt(total_staked * 1000000)` rounded down
    let lambda = builder.add_virtual_target(); //`(rf * st * stake * 1000000) / gamma` rounded down
    let round_issuance = builder.add_virtual_target(); //`(lambda * 1000000) / (total_staked + (st * 1000000))` rounded down
    let total_staked_x1000000 = builder.mul(total_staked, x1000000);
    builder.sqrt_round_down(total_staked_x1000000, gamma, 60);
    let rf_st_stake_x1000000 = builder.mul_many(&[current_param_rf, current_param_st, validator_stake, x1000000]);
    builder.div_round_down(rf_st_stake_x1000000, gamma, lambda, 60);
    let st_x1000000 = builder.mul(current_param_st, x1000000);
    let total_staked_st_x1000000 = builder.add(total_staked, st_x1000000);
    let lambda_x1000000 = builder.mul(lambda, x1000000);
    builder.div_round_down(lambda_x1000000, total_staked_st_x1000000, round_issuance, 60);

    //Start tracking the new withdraw values
    let mut new_withdraw_max = current_withdraw_max;
    let mut new_withdraw_unearned = current_withdraw_unearned;

    //Loop through each participation round in the epoch (the epoch last left off on)
    let mut participation_rounds_targets: Vec<ValidatorParticipationRoundTargets> = Vec::new();
    for i in 0..PARTICIPATION_ROUNDS_PER_STATE_EPOCH {
        //Participation round data
        let participation_root = builder.add_virtual_hash();
        let participation_count = builder.add_virtual_target();
        let round_has_no_participation = builder.is_equal(participation_count, zero);
        let round_has_participation = builder.not(round_has_no_participation);

        //Verify participation round
        let participation_round_hash = builder.hash_n_to_hash_no_pad::<Hash>([
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
                let num_bits = PARTICIPANTS_PER_FIELD.min(AGGREGATION_STAGE1_SIZE - (i * PARTICIPANTS_PER_FIELD));
                let part = builder.add_virtual_target();
                let part_bits = builder.split_le(part, num_bits);
                
                participation_bits_fields.push(part);
                for b in part_bits.iter().rev() {
                    participation_bits.push(*b);
                }
            }

            //Determine if participated
            let validator_bit_index_bits: Vec<BoolTarget> = builder.split_le(validator_bit_index, AGGREGATION_STAGE1_SUB_TREE_HEIGHT);
            let validator_bit_index_bits_inv: Vec<BoolTarget> = validator_bit_index_bits.iter().map(|b| builder.not(b.clone())).collect();
            for (index, participant_bit) in participation_bits.iter().enumerate() {
                let mut participant_bit_with_index_mask = participant_bit.clone();
                for b in 0..AGGREGATION_STAGE1_SUB_TREE_HEIGHT {
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
            let participation_merkle_root = builder.select_hash(skip_participation, empty_participation_root, participation_root);
            builder.verify_merkle_proof::<Hash>(
                participation_sub_root.elements.to_vec(), 
                &validator_field_index_bits, 
                participation_merkle_root,
                &participation_proof,
            );
        }

        //Compute total max withdraw value
        let amount = builder.mul_many(&[round_issuance, round_has_participation.target, validator_index_is_not_null.target]);
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
    builder.register_public_inputs(&current_val_epochs_tree_root.elements);
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
    let inner_proof_val_epochs_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_proof_pr_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_proof_account_address = inner_cyclic_pis[8..13].to_vec();
    let inner_proof_from_epoch = inner_cyclic_pis[13];
    let inner_proof_to_epoch = inner_cyclic_pis[14];
    let inner_proof_withdraw_max = inner_cyclic_pis[15];
    let inner_proof_withdraw_unearned = inner_cyclic_pis[16];
    let inner_proof_param_rf = inner_cyclic_pis[17];
    let inner_proof_param_st = inner_cyclic_pis[18];

    //Connect the current validators epochs tree root with inner proof or initial value
    let inner_proof_val_epochs_tree_root_or_init = builder.select_hash(init_zero, inner_proof_val_epochs_tree_root, init_val_epochs_tree_root);
    builder.connect_hashes(current_val_epochs_tree_root, inner_proof_val_epochs_tree_root_or_init);

    //Connect the current participation rounds tree root with inner proof or initial value
    let inner_proof_pr_tree_root_or_init = builder.select_hash(init_zero, inner_proof_pr_tree_root, init_pr_tree_root);
    builder.connect_hashes(current_pr_tree_root, inner_proof_pr_tree_root_or_init);

    //Connect the current account address with inner proof or initial value
    let inner_proof_account_address_or_init = builder.select_many(init_zero, &inner_proof_account_address, &init_account_address);
    builder.connect_many(&current_account_address, &inner_proof_account_address_or_init);

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
        init_val_epochs_tree_root,
        init_pr_tree_root,
        init_account_address,
        init_epoch,
        init_param_rf,
        init_param_st,
    
        validators_state_verifier,
        validators_state_proof,
        validator_epochs_proof,
    
        validator_index,
        validator_bit_index,
        validator_field_index,
        validator_stake,
        validator_commitment,
        validator_stake_proof,
        account_validator_proof,
    
        gamma,
        lambda,
        round_issuance,
        participation_rounds_targets,
        
        init_zero,
        verifier: verifier_data_target,
        previous_proof: inner_cyclic_proof_with_pis,
    }
}

#[derive(Clone)]
pub struct ValidatorParticipationAggCircuitData {
    pub validator: Option<ValidatorParticipationValidatorData>,
    pub account_validator_proof: Vec<[Field; 4]>,
    pub validators_state_proof: ValidatorsStateProof,
    pub validator_epochs_proof: Vec<[Field; 4]>,

    pub participation_rounds: Vec<ValidatorPartAggRoundData>,

    pub previous_data: ValidatorPartAggPrevData,
}
#[derive(Clone)]
pub struct ValidatorParticipationValidatorData {
    pub index: usize,
    pub stake: u32,
    pub commitment: [Field; 4],
    pub proof: Vec<[Field; 4]>,
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
    pub val_epochs_tree_root: [Field; 4],
    pub pr_tree_root: [Field; 4],
    pub account: [u8; 20],
    pub epoch: u32,
    pub param_rf: u32,
    pub param_st: u32,
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
    validators_state_verifier: &VerifierOnlyCircuitData<Config, D>
) -> Result<PartialWitness<Field>> {
    let validator_index = match &data.validator {
        Some(v) => Some(v.index),
        None => None,
    };
    if validator_index.is_some_and(|i| i >= MAX_VALIDATORS) {
        return Err(anyhow!("Invalid validator index (max: {})", MAX_VALIDATORS));
    }
    if data.participation_rounds.len() != PARTICIPATION_ROUNDS_PER_STATE_EPOCH {
        return Err(anyhow!("Incorrect number of rounds data (expected: {})", PARTICIPATION_ROUNDS_PER_STATE_EPOCH));
    }
    let mut pw = PartialWitness::new();

    //validators state proof
    pw.set_verifier_data_target(&targets.validators_state_verifier, validators_state_verifier);
    pw.set_proof_with_pis_target(&targets.validators_state_proof, data.validators_state_proof.proof());
    pw.set_merkle_proof_target(targets.validator_epochs_proof.clone(), &data.validator_epochs_proof);

    //account validator index
    match &data.validator {
        Some(validator) => {
            let validator_field_index = validator.index / AGGREGATION_STAGE1_SIZE;
            let validator_bit_index = validator.index % AGGREGATION_STAGE1_SIZE;
            pw.set_target(targets.validator_index, Field::from_canonical_usize(validator.index));
            pw.set_target(targets.validator_field_index, Field::from_canonical_usize(validator_field_index));
            pw.set_target(targets.validator_bit_index, Field::from_canonical_usize(validator_bit_index));
            pw.set_target(targets.validator_stake, Field::from_canonical_u32(validator.stake));
            pw.set_hash_target(targets.validator_commitment, HashOut::<Field> { elements: validator.commitment });
            pw.set_merkle_proof_target(targets.validator_stake_proof.clone(), &validator.proof);
        },
        None => {
            //fill in with null data
            pw.set_target(targets.validator_index, Field::ZERO.sub_one());
            pw.set_target(targets.validator_field_index, Field::ZERO);
            pw.set_target(targets.validator_bit_index, Field::ZERO);
            pw.set_target(targets.validator_stake, Field::ZERO);
            pw.set_hash_target(targets.validator_commitment, HashOut::<Field> { elements: [Field::ZERO; 4] });
            pw.set_merkle_proof_target(targets.validator_stake_proof.clone(), &empty_validators_tree_proof());
        },
    }
    pw.set_merkle_proof_target(targets.account_validator_proof.clone(), &data.account_validator_proof);

    //participation round issuance
    let (rf, st) = match &data.previous_data {
        ValidatorPartAggPrevData::Start(start_data) => (start_data.param_rf as u64, start_data.param_st as u64),
        ValidatorPartAggPrevData::Continue(previous_proof) => (previous_proof.param_rf() as u64, previous_proof.param_st() as u64),
    };
    let validator_stake = match &data.validator {
        Some(validator) => validator.stake as u64,
        None => 0,
    };
    let total_staked = data.validators_state_proof.total_staked() as u64;
    let gamma = integer_sqrt(total_staked * 1000000); //`sqrt(total_staked * 1000000)` rounded down
    let lambda = (rf * st * validator_stake * 1000000) / gamma; //`(rf * st * stake * 1000000) / gamma` rounded down
    let round_issuance = (lambda * 1000000) / (total_staked + (st * 1000000)); //`(lambda * 1000000) / (total_staked + (st * 1000000))` rounded down
    pw.set_target(targets.gamma, Field::from_canonical_u64(gamma));
    pw.set_target(targets.lambda, Field::from_canonical_u64(lambda));
    pw.set_target(targets.round_issuance, Field::from_canonical_u64(round_issuance));

    //participation rounds targets
    for (t, d) in targets.participation_rounds_targets.iter().zip(data.participation_rounds.clone()) {
        pw.set_hash_target(t.participation_root, HashOut::<Field> { elements: d.participation_root });
        pw.set_target(t.participation_count, Field::from_canonical_u32(d.participation_count));
        pw.set_merkle_proof_target(t.participation_round_proof.clone(), &d.participation_round_proof);

        if validator_index.is_some() && d.participation_bits.is_some() {
            let validator_index = validator_index.unwrap();
            let participation_bits = d.participation_bits.unwrap();
            let participation_merkle_data = participation_merkle_data(&participation_bits, validator_index);
            if participation_merkle_data.root != d.participation_root {
                return Err(anyhow!("Root caluclated from participation bits is different from given root"));
            }
            pw.set_bool_target(t.skip_participation, false);
            pw.set_target_arr(&t.participation_bits_fields, &participation_merkle_data.leaf_fields);
            pw.set_merkle_proof_target(t.participation_proof.clone(), &participation_merkle_data.proof);
        } else {
            //fill in with empty participation data
            let participation_merkle_data = participation_merkle_data(&vec![], 0);
            pw.set_bool_target(t.skip_participation, true);
            pw.set_target_arr(&t.participation_bits_fields, &participation_merkle_data.leaf_fields);
            pw.set_merkle_proof_target(t.participation_proof.clone(), &participation_merkle_data.proof);
        }
    }
    
    //previous data to build off of
    match &data.previous_data {
        ValidatorPartAggPrevData::Start(start_data) => {
            pw.set_hash_target(targets.init_val_epochs_tree_root, HashOut::<Field> { elements: start_data.val_epochs_tree_root });
            pw.set_hash_target(targets.init_pr_tree_root, HashOut::<Field> { elements: start_data.pr_tree_root });
            pw.set_target_arr(&targets.init_account_address, &account_to_fields(start_data.account));
            pw.set_target(targets.init_epoch, Field::from_canonical_u32(start_data.epoch));
            pw.set_target(targets.init_param_rf, Field::from_canonical_u32(start_data.param_rf));
            pw.set_target(targets.init_param_st, Field::from_canonical_u32(start_data.param_st));

            //create starter proof initial state (no previous proof)
            let base_proof = initial_proof(circuit_data, start_data);
            pw.set_bool_target(targets.init_zero, false);
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
        },
        ValidatorPartAggPrevData::Continue(previous_proof) => {
            pw.set_bool_target(targets.init_zero, true);
            pw.set_proof_with_pis_target(&targets.previous_proof, &previous_proof.proof);

            //blank out init data
            pw.set_hash_target(targets.init_val_epochs_tree_root, HashOut::<Field> { elements: [Field::ZERO; 4] });
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
        &init_data.val_epochs_tree_root[..], 
        &init_data.pr_tree_root[..], 
        &account_to_fields(init_data.account)[..], 
        &[Field::from_canonical_u32(init_data.epoch)],
        &[Field::from_canonical_u32(init_data.epoch)],
        &[Field::ZERO],
        &[Field::ZERO],
        &[Field::from_canonical_u32(init_data.param_rf)],
        &[Field::from_canonical_u32(init_data.param_st)],
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

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorParticipationAggCircuitTargets) -> IoResult<()> {
    buffer.write_target_hash(&targets.init_val_epochs_tree_root)?;
    buffer.write_target_hash(&targets.init_pr_tree_root)?;
    buffer.write_target_vec(&targets.init_account_address)?;
    buffer.write_target(targets.init_epoch)?;
    buffer.write_target(targets.init_param_rf)?;
    buffer.write_target(targets.init_param_st)?;

    buffer.write_target_verifier_circuit(&targets.validators_state_verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.validators_state_proof)?;
    buffer.write_target_merkle_proof(&targets.validator_epochs_proof)?;

    buffer.write_target(targets.validator_index)?;
    buffer.write_target(targets.validator_bit_index)?;
    buffer.write_target(targets.validator_field_index)?;
    buffer.write_target(targets.validator_stake)?;
    buffer.write_target_hash(&targets.validator_commitment)?;
    buffer.write_target_merkle_proof(&targets.validator_stake_proof)?;
    buffer.write_target_merkle_proof(&targets.account_validator_proof)?;

    buffer.write_target(targets.gamma)?;
    buffer.write_target(targets.lambda)?;
    buffer.write_target(targets.round_issuance)?;
    buffer.write_usize(targets.participation_rounds_targets.len())?;
    for d in &targets.participation_rounds_targets {
        buffer.write_target_hash(&d.participation_root)?;
        buffer.write_target(d.participation_count)?;
        buffer.write_target_merkle_proof(&d.participation_round_proof)?;

        buffer.write_target_bool(d.skip_participation)?;
        buffer.write_target_vec(&d.participation_bits_fields)?;
        buffer.write_target_merkle_proof(&d.participation_proof)?;
    }
    
    buffer.write_target_bool(targets.init_zero)?;
    buffer.write_target_verifier_circuit(&targets.verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.previous_proof)?;

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggCircuitTargets> {
    let init_val_epochs_tree_root = buffer.read_target_hash()?;
    let init_pr_tree_root = buffer.read_target_hash()?;
    let init_account_address = buffer.read_target_vec()?;
    let init_epoch = buffer.read_target()?;
    let init_param_rf = buffer.read_target()?;
    let init_param_st = buffer.read_target()?;

    let validators_state_verifier = buffer.read_target_verifier_circuit()?;
    let validators_state_proof = buffer.read_target_proof_with_public_inputs()?;
    let validator_epochs_proof = buffer.read_target_merkle_proof()?;

    let validator_index = buffer.read_target()?;
    let validator_bit_index = buffer.read_target()?;
    let validator_field_index = buffer.read_target()?;
    let validator_stake = buffer.read_target()?;
    let validator_commitment = buffer.read_target_hash()?;
    let validator_stake_proof = buffer.read_target_merkle_proof()?;
    let account_validator_proof = buffer.read_target_merkle_proof()?;

    let gamma = buffer.read_target()?;
    let lambda = buffer.read_target()?;
    let round_issuance = buffer.read_target()?;
    let mut participation_rounds_targets: Vec<ValidatorParticipationRoundTargets> = Vec::new();
    let participation_rounds_targets_length = buffer.read_usize()?;
    for _ in 0..participation_rounds_targets_length {
        let participation_root = buffer.read_target_hash()?;
        let participation_count = buffer.read_target()?;
        let participation_round_proof = buffer.read_target_merkle_proof()?;

        let skip_participation = buffer.read_target_bool()?;
        let participation_bits_fields = buffer.read_target_vec()?;
        let participation_proof = buffer.read_target_merkle_proof()?;

        participation_rounds_targets.push(ValidatorParticipationRoundTargets {
            participation_root,
            participation_count,
            participation_round_proof,
            skip_participation,
            participation_bits_fields,
            participation_proof,
        });
    }
    
    let init_zero = buffer.read_target_bool()?;
    let verifier = buffer.read_target_verifier_circuit()?;
    let previous_proof = buffer.read_target_proof_with_public_inputs()?;

    Ok(ValidatorParticipationAggCircuitTargets {
        init_val_epochs_tree_root,
        init_pr_tree_root,
        init_account_address,
        init_epoch,
        init_param_rf,
        init_param_st,
        validators_state_verifier,
        validators_state_proof,
        validator_epochs_proof,
        validator_index,
        validator_bit_index,
        validator_field_index,
        validator_stake,
        validator_commitment,
        validator_stake_proof,
        account_validator_proof,
        gamma,
        lambda,
        round_issuance,
        participation_rounds_targets,
        init_zero,
        verifier,
        previous_proof,
    })
}

fn build_empty_participation_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_root();
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}

fn build_empty_stake_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_validators_tree_root();
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}

fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }

    let mut left: u64 = 1;
    let mut right: u64 = n;
    let mut result: u64 = 0;

    while left <= right {
        let mid = left + (right - left) / 2;
        if mid * mid <= n {
            result = mid;
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    result
}
