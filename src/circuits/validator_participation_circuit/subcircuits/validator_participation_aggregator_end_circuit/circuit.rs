use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitTarget};

use crate::circuits::extensions::CircuitBuilderExtended;
use crate::circuits::participation_state_circuit::{
    PIS_PARTICIPATION_ROUNDS_TREE_ROOT, PIS_PARTICIPATION_STATE_INPUTS_HASH, PIS_VALIDATOR_EPOCHS_TREE_ROOT,
};
use crate::{Config, Field, D};

use super::{
    ValidatorParticipationAggEndCircuitTargets, PIS_AGG_ACCOUNT_ADDRESS, PIS_AGG_EPOCHS_TREE_ROOT, PIS_AGG_FROM_EPOCH,
    PIS_AGG_PARAM_RF, PIS_AGG_PARAM_ST, PIS_AGG_PR_TREE_ROOT, PIS_AGG_TO_EPOCH, PIS_AGG_WITHDRAW_MAX,
    PIS_AGG_WITHDRAW_UNEARNED,
};

pub fn generate_circuit(
    builder: &mut CircuitBuilder<Field, D>,
    participation_agg_common_data: &CommonCircuitData<Field, D>,
    participation_state_common_data: &CommonCircuitData<Field, D>,
) -> ValidatorParticipationAggEndCircuitTargets {
    //Verify validator participation aggregation proof
    let participation_agg_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(participation_agg_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let participation_agg_proof = builder.add_virtual_proof_with_pis(participation_agg_common_data);
    builder.verify_proof::<Config>(
        &participation_agg_proof,
        &participation_agg_verifier,
        participation_agg_common_data,
    );
    let participation_agg_val_epochs_tree_root = vec![
        participation_agg_proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[0]],
        participation_agg_proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[1]],
        participation_agg_proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[2]],
        participation_agg_proof.public_inputs[PIS_AGG_EPOCHS_TREE_ROOT[3]],
    ];
    let participation_agg_pr_tree_root = vec![
        participation_agg_proof.public_inputs[PIS_AGG_PR_TREE_ROOT[0]],
        participation_agg_proof.public_inputs[PIS_AGG_PR_TREE_ROOT[1]],
        participation_agg_proof.public_inputs[PIS_AGG_PR_TREE_ROOT[2]],
        participation_agg_proof.public_inputs[PIS_AGG_PR_TREE_ROOT[3]],
    ];
    let account_address = vec![
        participation_agg_proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[0]],
        participation_agg_proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[1]],
        participation_agg_proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[2]],
        participation_agg_proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[3]],
        participation_agg_proof.public_inputs[PIS_AGG_ACCOUNT_ADDRESS[4]],
    ];
    let from_epoch = participation_agg_proof.public_inputs[PIS_AGG_FROM_EPOCH];
    let to_epoch = participation_agg_proof.public_inputs[PIS_AGG_TO_EPOCH];
    let withdraw_max = participation_agg_proof.public_inputs[PIS_AGG_WITHDRAW_MAX];
    let withdraw_unearned = participation_agg_proof.public_inputs[PIS_AGG_WITHDRAW_UNEARNED];
    let param_rf = participation_agg_proof.public_inputs[PIS_AGG_PARAM_RF];
    let param_st = participation_agg_proof.public_inputs[PIS_AGG_PARAM_ST];

    //Verify participation state proof
    let participation_state_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(participation_state_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let participation_state_proof = builder.add_virtual_proof_with_pis(participation_state_common_data);
    builder.verify_proof::<Config>(
        &participation_state_proof,
        &participation_state_verifier,
        participation_state_common_data,
    );
    let participation_state_inputs_hash = vec![
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[0]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[1]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[2]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[3]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[4]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[5]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[6]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_STATE_INPUTS_HASH[7]],
    ];
    let participation_state_val_epochs_tree_root = vec![
        participation_state_proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[0]],
        participation_state_proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[1]],
        participation_state_proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[2]],
        participation_state_proof.public_inputs[PIS_VALIDATOR_EPOCHS_TREE_ROOT[3]],
    ];
    let participation_state_pr_tree_root = vec![
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[0]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[1]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[2]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[3]],
    ];

    //Connect data between proofs
    for (&a, s) in participation_agg_val_epochs_tree_root
        .iter()
        .zip(participation_state_val_epochs_tree_root)
    {
        builder.connect(a, s);
    }
    for (&a, s) in participation_agg_pr_tree_root
        .iter()
        .zip(participation_state_pr_tree_root)
    {
        builder.connect(a, s);
    }

    //Register the hash of the public inputs
    let inputs = [
        &participation_state_inputs_hash[..],
        &account_address[..],
        &[from_epoch],
        &[to_epoch],
        &builder.to_u32s(withdraw_max),
        &builder.to_u32s(withdraw_unearned),
        &[param_rf],
        &[param_st],
    ]
    .concat();
    let inputs_hash = builder.sha256_hash(inputs);
    let inputs_hash_compressed = builder.compress_hash(inputs_hash);
    builder.register_public_inputs(&inputs_hash_compressed.elements);

    ValidatorParticipationAggEndCircuitTargets {
        participation_agg_proof,
        participation_agg_verifier,

        participation_state_proof,
        participation_state_verifier,
    }
}
