use plonky2::field::types::{Field as Plonky2_Field, Field64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::accounts::initial_accounts_tree_root;
use crate::circuits::extensions::{common_data_for_recursion, CircuitBuilderExtended};
use crate::validators::initial_validators_tree_root;
use crate::Hash;
use crate::{Config, Field, ACCOUNTS_TREE_HEIGHT, D, MAX_VALIDATORS, VALIDATORS_TREE_HEIGHT};

use super::ValidatorsStateCircuitTargets;

const MAX_GATES: usize = 1 << 14;

pub fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ValidatorsStateCircuitTargets {
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
    let current_validator_hash = builder.hash_n_to_hash_no_pad::<Hash>(
        [&validator_commitment.elements[..], &[validator_stake]].concat(),
    );
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
    let from_acc_bits: Vec<BoolTarget> = from_account
        .iter()
        .rev()
        .map(|t| builder.split_le(*t, 32))
        .collect::<Vec<Vec<BoolTarget>>>()
        .concat();
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
    let to_acc_bits: Vec<BoolTarget> = to_account
        .iter()
        .rev()
        .map(|t| builder.split_le(*t, 32))
        .collect::<Vec<Vec<BoolTarget>>>()
        .concat();
    builder.verify_merkle_proof::<Hash>(
        vec![to_acc_index],
        &to_acc_bits,
        current_accounts_tree_root,
        &to_acc_proof,
    );

    //Determine what kind of operation this is and start new targets to help build a new state
    let is_unstake_operation = builder.is_equal(stake, zero);
    let is_stake_operation = builder.not(is_unstake_operation);
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
            from_acc_index_eq_input,
        ];
        builder.assert_true_if(is_stake_operation, &terms);

        //Determine if the stake operation is valid
        let stake_increase = builder.greater_than(stake, validator_stake, 32);
        let same_account = builder.is_equal(from_acc_index, to_acc_index);
        let to_acc_index_is_null = builder.is_equal(to_acc_index, null);
        let from_acc_is_null = is_account_null(builder, &from_account, index);
        let validators_at_max = builder.is_equal(current_total_validators, max_validators);
        let from_acc_is_null_or_max_validators = builder.or(from_acc_is_null, validators_at_max);
        let terms = [
            is_stake_operation,
            stake_increase,
            builder.or(same_account, from_acc_is_null_or_max_validators),
            builder.or(same_account, to_acc_index_is_null),
        ];
        let is_valid_stake_op = builder.and_many(&terms);

        //Compute the theoretically updated values
        let stake_delta = builder.sub(stake, validator_stake);
        let updated_total_staked = builder.add(current_total_staked, stake_delta);
        let updated_total_validators =
            builder.add(current_total_validators, from_acc_is_null.target);
        let updated_validator_stake = stake;
        let updated_validator_commitment = commitment;
        let updated_from_acc_index = null;
        let updated_to_acc_index = index;

        //Set the final values if applicable
        new_total_staked =
            builder.select(is_valid_stake_op, updated_total_staked, new_total_staked);
        new_total_validators = builder.select(
            is_valid_stake_op,
            updated_total_validators,
            new_total_validators,
        );
        new_validator_stake = builder.select(
            is_valid_stake_op,
            updated_validator_stake,
            new_validator_stake,
        );
        new_validator_commitment = builder.select_hash(
            is_valid_stake_op,
            updated_validator_commitment,
            new_validator_commitment,
        );
        new_from_acc_index = builder.select(
            is_valid_stake_op,
            updated_from_acc_index,
            new_from_acc_index,
        );
        new_to_acc_index =
            builder.select(is_valid_stake_op, updated_to_acc_index, new_to_acc_index);
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
        let is_valid_unstake_op =
            builder.and_many(&[is_unstake_operation, from_acc_index_is_not_null]);

        //Compute the theoretically updated values
        let updated_total_staked = builder.sub(current_total_staked, validator_stake);
        let updated_total_validators = builder.sub(current_total_validators, one);
        let updated_validator_stake = zero;
        let updated_validator_commitment = HashOutTarget {
            elements: [zero, zero, zero, zero],
        };
        let updated_from_acc_index = null;
        let updated_to_acc_index = validator_index;

        //Set the final values if applicable
        new_total_staked =
            builder.select(is_valid_unstake_op, updated_total_staked, new_total_staked);
        new_total_validators = builder.select(
            is_valid_unstake_op,
            updated_total_validators,
            new_total_validators,
        );
        new_validator_stake = builder.select(
            is_valid_unstake_op,
            updated_validator_stake,
            new_validator_stake,
        );
        new_validator_commitment = builder.select_hash(
            is_valid_unstake_op,
            updated_validator_commitment,
            new_validator_commitment,
        );
        new_from_acc_index = builder.select(
            is_valid_unstake_op,
            updated_from_acc_index,
            new_from_acc_index,
        );
        new_to_acc_index =
            builder.select(is_valid_unstake_op, updated_to_acc_index, new_to_acc_index);
    }

    //Compute the new tree roots
    let new_validators_tree_root = builder.merkle_root_from_prev_proof::<Hash>(
        [
            &new_validator_commitment.elements[..],
            &[new_validator_stake],
        ]
        .concat(),
        &validator_index_bits,
        &validator_proof,
    );
    let new_accounts_tree_root = builder.merkle_root_from_prev_two_proofs::<Hash>(
        vec![new_from_acc_index],
        &from_acc_bits,
        &from_acc_proof,
        vec![new_to_acc_index],
        &to_acc_bits,
        &to_acc_proof,
    );

    //Select between new values or initial values (initial proof)
    let initial_validators_tree_root = HashOutTarget {
        elements: initial_validators_tree_root().map(|f| builder.constant(f)),
    };
    let initial_accounts_tree_root = HashOutTarget {
        elements: initial_accounts_tree_root().map(|f| builder.constant(f)),
    };
    let new_inputs_hash_or_init: Vec<Target> = new_inputs_hash
        .iter()
        .map(|&h| builder.mul(h, init_zero.target))
        .collect();
    let new_total_staked_or_init = builder.mul(new_total_staked, init_zero.target);
    let new_total_validators_or_init = builder.mul(new_total_validators, init_zero.target);
    let new_validators_tree_root_or_init = builder.select_hash(
        init_zero,
        new_validators_tree_root,
        initial_validators_tree_root,
    );
    let new_accounts_tree_root_or_init = builder.select_hash(
        init_zero,
        new_accounts_tree_root,
        initial_accounts_tree_root,
    );

    //Register all public inputs
    builder.register_public_inputs(&new_inputs_hash_or_init);
    builder.register_public_input(new_total_staked_or_init);
    builder.register_public_input(new_total_validators_or_init);
    builder.register_public_inputs(&new_validators_tree_root_or_init.elements);
    builder.register_public_inputs(&new_accounts_tree_root_or_init.elements);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_inputs_hash = inner_cyclic_pis[0..8].to_vec();
    let inner_proof_total_staked = inner_cyclic_pis[8];
    let inner_proof_total_validators = inner_cyclic_pis[9];
    let inner_proof_validators_tree_root =
        HashOutTarget::try_from(&inner_cyclic_pis[10..14]).unwrap();
    let inner_proof_accounts_tree_root =
        HashOutTarget::try_from(&inner_cyclic_pis[14..18]).unwrap();

    //Connect the current inputs with proof public inputs
    builder.connect_many(&current_inputs_hash, &inner_proof_inputs_hash);
    builder.connect(current_total_staked, inner_proof_total_staked);
    builder.connect(current_total_validators, inner_proof_total_validators);
    builder.connect_hashes(
        current_validators_tree_root,
        inner_proof_validators_tree_root,
    );
    builder.connect_hashes(current_accounts_tree_root, inner_proof_accounts_tree_root);

    //Finally verify the previous (inner) proof
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<Config>(
            init_zero,
            &inner_cyclic_proof_with_pis,
            &common_data,
        )
        .expect("cyclic proof verification failed");

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

fn is_account_null(
    builder: &mut CircuitBuilder<Field, D>,
    account: &[Target],
    validator_index: Target,
) -> BoolTarget {
    let shift_amount = builder.constant(Field::from_canonical_usize(
        1 << (32 - VALIDATORS_TREE_HEIGHT),
    ));
    let validator_index_shifted = builder.mul(validator_index, shift_amount);
    let null_account = [
        validator_index_shifted,
        builder.zero(),
        builder.zero(),
        builder.zero(),
        builder.zero(),
    ];
    builder.is_equal_many(account, &null_account)
}
