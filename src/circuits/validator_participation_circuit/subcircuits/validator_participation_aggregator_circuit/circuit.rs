use plonky2::field::types::{Field as Plonky2_Field, Field64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitTarget};

use crate::circuits::extensions::{common_data_for_recursion, CircuitBuilderExtended};
use crate::circuits::validators_state_circuit::{
    PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT, PIS_VALIDATORS_STATE_INPUTS_HASH,
    PIS_VALIDATORS_STATE_TOTAL_STAKED, PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT,
};
use crate::participation::{
    empty_participation_root, PARTICIPANTS_PER_FIELD, PARTICIPATION_FIELDS_PER_LEAF,
    PARTICIPATION_TREE_HEIGHT,
};
use crate::validators::empty_validators_tree_root;
use crate::Hash;
use crate::{
    Config, Field, ACCOUNTS_TREE_HEIGHT, AGGREGATION_STAGE1_SIZE,
    AGGREGATION_STAGE1_SUB_TREE_HEIGHT, D, PARTICIPATION_ROUNDS_PER_STATE_EPOCH,
    PARTICIPATION_ROUNDS_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT, VALIDATOR_EPOCHS_TREE_HEIGHT,
};

use super::{ValidatorParticipationAggCircuitTargets, ValidatorParticipationRoundTargets};

const MAX_GATES: usize = 1 << 15;

pub fn generate_circuit(
    builder: &mut CircuitBuilder<Field, D>,
    val_state_common_data: &CommonCircuitData<Field, D>,
) -> ValidatorParticipationAggCircuitTargets {
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
        constants_sigmas_cap: builder
            .add_virtual_cap(val_state_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let validators_state_proof = builder.add_virtual_proof_with_pis(val_state_common_data);
    builder.verify_proof::<Config>(
        &validators_state_proof,
        &validators_state_verifier,
        val_state_common_data,
    );
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
        &validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[0]
            ..(PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT[3] + 1)],
    )
    .unwrap();
    let validators_state_validators_tree_root = HashOutTarget::try_from(
        &validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[0]
            ..(PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[3] + 1)],
    )
    .unwrap();
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
    let account_address_bits: Vec<BoolTarget> = current_account_address
        .iter()
        .rev()
        .map(|t| builder.split_le(*t, 32))
        .collect::<Vec<Vec<BoolTarget>>>()
        .concat();
    builder.verify_merkle_proof::<Hash>(
        vec![validator_index],
        &account_address_bits,
        validators_state_accounts_tree_root,
        &account_validator_proof,
    );
    let validator_field_index = builder.add_virtual_target();
    let validator_bit_index = builder.add_virtual_target();
    let expected_validator_index =
        builder.mul_add(validator_field_index, agg_pass1_size, validator_bit_index);
    let validator_index_deconstruction_is_valid =
        builder.is_equal(validator_index, expected_validator_index);
    builder.assert_true_if(
        validator_index_is_not_null,
        &[validator_index_deconstruction_is_valid],
    );
    let validator_field_index_is_zero = builder.is_equal(validator_field_index, zero);
    let validator_bit_index_is_zero = builder.is_equal(validator_bit_index, zero);
    builder.assert_true_if(
        validator_index_is_null,
        &[validator_field_index_is_zero, validator_bit_index_is_zero],
    );

    //Verify the stake amount
    let validator_stake = builder.add_virtual_target();
    let validator_commitment = builder.add_virtual_hash();
    let validator_hash = builder.hash_n_to_hash_no_pad::<Hash>(
        [&validator_commitment.elements[..], &[validator_stake]].concat(),
    );
    let validator_stake_proof = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(VALIDATORS_TREE_HEIGHT),
    };
    let validator_stake_index = builder.mul(validator_index, validator_index_is_not_null.target);
    let validator_stake_index_bits =
        builder.split_le(validator_stake_index, VALIDATORS_TREE_HEIGHT);
    let validator_stake_merkle_root = builder.select_hash(
        validator_index_is_null,
        empty_stake_validators_root,
        validators_state_validators_tree_root,
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
    let rf_st_stake_x1000000 = builder.mul_many(&[
        current_param_rf,
        current_param_st,
        validator_stake,
        x1000000,
    ]);
    builder.div_round_down(rf_st_stake_x1000000, gamma, lambda, 60);
    let st_x1000000 = builder.mul(current_param_st, x1000000);
    let total_staked_st_x1000000 = builder.add(total_staked, st_x1000000);
    let lambda_x1000000 = builder.mul(lambda, x1000000);
    builder.div_round_down(
        lambda_x1000000,
        total_staked_st_x1000000,
        round_issuance,
        60,
    );

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
        let participation_round_hash = builder.hash_n_to_hash_no_pad::<Hash>(
            [&participation_root.elements[..], &[participation_count]].concat(),
        );
        let round_num = builder.arithmetic(
            Field::from_canonical_usize(PARTICIPATION_ROUNDS_PER_STATE_EPOCH),
            Field::from_canonical_usize(i),
            epoch,
            one,
            one,
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
                let num_bits = PARTICIPANTS_PER_FIELD
                    .min(AGGREGATION_STAGE1_SIZE - (i * PARTICIPANTS_PER_FIELD));
                let part = builder.add_virtual_target();
                let part_bits = builder.split_le(part, num_bits);

                participation_bits_fields.push(part);
                for b in part_bits.iter().rev() {
                    participation_bits.push(*b);
                }
            }

            //Determine if participated
            let validator_bit_index_bits: Vec<BoolTarget> =
                builder.split_le(validator_bit_index, AGGREGATION_STAGE1_SUB_TREE_HEIGHT);
            let validator_bit_index_bits_inv: Vec<BoolTarget> = validator_bit_index_bits
                .iter()
                .map(|b| builder.not(b.clone()))
                .collect();
            for (index, participant_bit) in participation_bits.iter().enumerate() {
                let mut participant_bit_with_index_mask = participant_bit.clone();
                for b in 0..AGGREGATION_STAGE1_SUB_TREE_HEIGHT {
                    if ((1 << b) & index) > 0 {
                        participant_bit_with_index_mask = builder
                            .and(participant_bit_with_index_mask, validator_bit_index_bits[b]);
                    } else {
                        participant_bit_with_index_mask = builder.and(
                            participant_bit_with_index_mask,
                            validator_bit_index_bits_inv[b],
                        );
                    }
                }
                participated = builder.add(participated, participant_bit_with_index_mask.target);
            }

            //Verify merkle proof to the participation root unless explicitly skipped
            let participation_sub_root =
                builder.hash_n_to_hash_no_pad::<Hash>(participation_bits_fields.clone());
            let validator_field_index_bits =
                builder.split_le(validator_field_index, PARTICIPATION_TREE_HEIGHT);
            let participation_merkle_root = builder.select_hash(
                skip_participation,
                empty_participation_root,
                participation_root,
            );
            builder.verify_merkle_proof::<Hash>(
                participation_sub_root.elements.to_vec(),
                &validator_field_index_bits,
                participation_merkle_root,
                &participation_proof,
            );
        }

        //Compute total max withdraw value
        let amount = builder.mul_many(&[
            round_issuance,
            round_has_participation.target,
            validator_index_is_not_null.target,
        ]);
        new_withdraw_max = builder.add(new_withdraw_max, amount);

        //Compute unearned withdraw value
        let not_skip_participation = builder.not(skip_participation);
        let not_participated = builder.not(BoolTarget::new_unsafe(participated));
        let not_skip_and_not_participated = builder.and(not_skip_participation, not_participated);
        let proved_acc_not_participate =
            builder.or(validator_index_is_null, not_skip_and_not_participated);
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
    let inner_proof_val_epochs_tree_root =
        HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_proof_pr_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_proof_account_address = inner_cyclic_pis[8..13].to_vec();
    let inner_proof_from_epoch = inner_cyclic_pis[13];
    let inner_proof_to_epoch = inner_cyclic_pis[14];
    let inner_proof_withdraw_max = inner_cyclic_pis[15];
    let inner_proof_withdraw_unearned = inner_cyclic_pis[16];
    let inner_proof_param_rf = inner_cyclic_pis[17];
    let inner_proof_param_st = inner_cyclic_pis[18];

    //Connect the current validators epochs tree root with inner proof or initial value
    let inner_proof_val_epochs_tree_root_or_init = builder.select_hash(
        init_zero,
        inner_proof_val_epochs_tree_root,
        init_val_epochs_tree_root,
    );
    builder.connect_hashes(
        current_val_epochs_tree_root,
        inner_proof_val_epochs_tree_root_or_init,
    );

    //Connect the current participation rounds tree root with inner proof or initial value
    let inner_proof_pr_tree_root_or_init =
        builder.select_hash(init_zero, inner_proof_pr_tree_root, init_pr_tree_root);
    builder.connect_hashes(current_pr_tree_root, inner_proof_pr_tree_root_or_init);

    //Connect the current account address with inner proof or initial value
    let inner_proof_account_address_or_init = builder.select_many(
        init_zero,
        &inner_proof_account_address,
        &init_account_address,
    );
    builder.connect_many(
        &current_account_address,
        &inner_proof_account_address_or_init,
    );

    //Connect the other public inputs
    let inner_proof_from_epoch_or_init =
        builder.select(init_zero, inner_proof_from_epoch, init_epoch);
    let inner_proof_to_epoch_or_init = builder.select(init_zero, inner_proof_to_epoch, init_epoch);
    let inner_proof_withdraw_max_or_init = builder.mul(init_zero.target, inner_proof_withdraw_max);
    let inner_proof_withdraw_unearned_or_init =
        builder.mul(init_zero.target, inner_proof_withdraw_unearned);
    let inner_proof_param_rf_or_init =
        builder.select(init_zero, inner_proof_param_rf, init_param_rf);
    let inner_proof_param_st_or_init =
        builder.select(init_zero, inner_proof_param_st, init_param_st);
    builder.connect(current_from_epoch, inner_proof_from_epoch_or_init);
    builder.connect(current_to_epoch, inner_proof_to_epoch_or_init);
    builder.connect(current_withdraw_max, inner_proof_withdraw_max_or_init);
    builder.connect(
        current_withdraw_unearned,
        inner_proof_withdraw_unearned_or_init,
    );
    builder.connect(current_param_rf, inner_proof_param_rf_or_init);
    builder.connect(current_param_st, inner_proof_param_st_or_init);

    //Finally verify the previous (inner) proof
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<Config>(
            init_zero,
            &inner_cyclic_proof_with_pis,
            &common_data,
        )
        .expect("cyclic proof verification failed");

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

fn build_empty_participation_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_root();
    HashOutTarget {
        elements: root.map(|f| builder.constant(f)),
    }
}

fn build_empty_stake_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_validators_tree_root();
    HashOutTarget {
        elements: root.map(|f| builder.constant(f)),
    }
}
