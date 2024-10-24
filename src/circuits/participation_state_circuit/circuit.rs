use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuits::extensions::{common_data_for_recursion, CircuitBuilderExtended};
use crate::epochs::initial_validator_epochs_tree_root;
use crate::participation::initial_participation_rounds_tree_root;
use crate::Hash;
use crate::{
    Config, Field, D, PARTICIPATION_ROUNDS_PER_STATE_EPOCH, PARTICIPATION_ROUNDS_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT,
    VALIDATOR_EPOCHS_TREE_HEIGHT,
};

use super::ParticipationStateCircuitTargets;

const MAX_GATES: usize = 1 << 14;

pub fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> ParticipationStateCircuitTargets {
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
    let current_round_hash = builder.hash_n_to_hash_no_pad::<Hash>(
        [&current_participation_root.elements[..], &[current_participation_count]].concat(),
    );
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
        &validator_epoch_proof,
    );

    //Determine the new round data based on the input and current participation count
    let input_is_less = builder.less_than(participation_count, current_participation_count, VALIDATORS_TREE_HEIGHT);
    let new_participation_root = builder.select_hash(input_is_less, current_participation_root, participation_root);
    let new_participation_count = builder.select(input_is_less, current_participation_count, participation_count);
    let new_pr_tree_root = builder.merkle_root_from_prev_proof::<Hash>(
        [&new_participation_root.elements[..], &[new_participation_count]].concat(),
        &round_num_bits,
        &participation_round_proof,
    );

    //Select between new values or initial values (initial proof)
    let initial_epochs_tree_root = HashOutTarget {
        elements: initial_validator_epochs_tree_root().map(|f| builder.constant(f)),
    };
    let initial_pr_tree_root = HashOutTarget {
        elements: initial_participation_rounds_tree_root().map(|f| builder.constant(f)),
    };
    let new_inputs_hash_or_init: Vec<Target> = new_inputs_hash
        .iter()
        .map(|&h| builder.mul(h, init_zero.target))
        .collect();
    let new_epochs_tree_root_or_init = builder.select_hash(init_zero, new_epochs_tree_root, initial_epochs_tree_root);
    let new_pr_tree_root_or_init = builder.select_hash(init_zero, new_pr_tree_root, initial_pr_tree_root);

    //Register all public inputs
    builder.register_public_inputs(&new_inputs_hash_or_init);
    builder.register_public_inputs(&new_epochs_tree_root_or_init.elements);
    builder.register_public_inputs(&new_pr_tree_root_or_init.elements);

    //Unpack inner proof public inputs
    let mut common_data = common_data_for_recursion(MAX_GATES);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_proof_inputs_hash = inner_cyclic_pis[0..8].to_vec();
    let inner_proof_epochs_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[8..12]).unwrap();
    let inner_proof_pr_tree_root = HashOutTarget::try_from(&inner_cyclic_pis[12..16]).unwrap();

    //Connect the current inputs with proof public inputs
    builder.connect_many(&current_inputs_hash, &inner_proof_inputs_hash);
    builder.connect_hashes(current_epochs_tree_root, inner_proof_epochs_tree_root);
    builder.connect_hashes(current_pr_tree_root, inner_proof_pr_tree_root);

    //Finally verify the previous (inner) proof
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<Config>(init_zero, &inner_cyclic_proof_with_pis, &common_data)
        .expect("cyclic proof verification failed");

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
