use plonky2::hash::hash_types::HashOutTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitTarget};

use super::{
    AttAgg3Agg2Targets, AttAgg3Targets, PIS_AGG2_ATTESTATIONS_STAKE, PIS_AGG2_BLOCK_SLOT, PIS_AGG2_PARTICIPATION_COUNT,
    PIS_AGG2_PARTICIPATION_SUB_ROOT, PIS_AGG2_VALIDATORS_SUB_ROOT,
};
use crate::circuits::extensions::CircuitBuilderExtended;
use crate::circuits::validators_state_circuit::{
    PIS_VALIDATORS_STATE_INPUTS_HASH, PIS_VALIDATORS_STATE_TOTAL_STAKED, PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT,
};
use crate::participation::empty_participation_sub_root;
use crate::{
    Config, Field, Hash, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, AGGREGATION_STAGE3_SIZE,
    AGGREGATION_STAGE3_SUB_TREE_HEIGHT, D,
};

pub fn generate_circuit(
    builder: &mut CircuitBuilder<Field, D>,
    atts_agg2_common_data: &CommonCircuitData<Field, D>,
    val_state_common_data: &CommonCircuitData<Field, D>,
) -> AttAgg3Targets {
    let mut atts_agg2_data: Vec<AttAgg3Agg2Targets> = Vec::new();

    // Global targets
    let empty_participation_root = build_empty_participation_sub_root(builder);
    let block_slot = builder.add_virtual_target();
    let mut attestations_stake = builder.zero();
    let mut participation_count = builder.zero();

    // Circuit target
    let atts_agg2_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(atts_agg2_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };

    //Verify the validators state proof
    let validators_state_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(val_state_common_data.config.fri_config.cap_height),
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
    let validators_state_validators_tree_root = vec![
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[0]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[1]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[2]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[3]],
    ];
    let validator_state_total_staked = validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_TOTAL_STAKED];

    // Verify each agg2 data
    let mut validator_nodes: Vec<HashOutTarget> = Vec::new();
    let mut participation_nodes: Vec<HashOutTarget> = Vec::new();
    for _ in 0..AGGREGATION_STAGE3_SIZE {
        let validators_sub_root = builder.add_virtual_hash();
        let has_participation = builder.add_virtual_bool_target_safe();
        let proof_target = builder.add_virtual_proof_with_pis(&atts_agg2_common_data);

        // Verify proof if has participation
        builder.verify_proof::<Config>(&proof_target, &atts_agg2_verifier, &atts_agg2_common_data);

        // Determine applicable validator node
        let proof_validators_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[3]],
            ],
        };
        validator_nodes.push(builder.select_hash(has_participation, proof_validators_sub_root, validators_sub_root));

        // Determine applicable participation node
        let proof_participation_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[3]],
            ],
        };
        participation_nodes.push(builder.select_hash(
            has_participation,
            proof_participation_sub_root,
            empty_participation_root,
        ));

        // Make sure each agg2 data has the same block_slot
        builder.connect(proof_target.public_inputs[PIS_AGG2_BLOCK_SLOT], block_slot);

        // Keep running total of stake and num participants
        attestations_stake = builder.mul_add(
            has_participation.target,
            proof_target.public_inputs[PIS_AGG2_ATTESTATIONS_STAKE],
            attestations_stake,
        );
        participation_count = builder.mul_add(
            has_participation.target,
            proof_target.public_inputs[PIS_AGG2_PARTICIPATION_COUNT],
            participation_count,
        );

        atts_agg2_data.push(AttAgg3Agg2Targets {
            validators_sub_root,
            has_participation,
            proof: proof_target,
        });
    }

    // Compute the validators sub root
    for h in (0..AGGREGATION_STAGE3_SUB_TREE_HEIGHT).rev() {
        let start = validator_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [
                validator_nodes[start + (i * 2)].elements.to_vec(),
                validator_nodes[start + (i * 2) + 1].elements.to_vec(),
            ]
            .concat();
            validator_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let validators_sub_root = validator_nodes.last().unwrap();

    // Connect the validators root to the root from the validators state proof
    for (&c, p) in validators_sub_root
        .elements
        .iter()
        .zip(validators_state_validators_tree_root)
    {
        builder.connect(c, p);
    }

    // Compute the participation sub root
    for h in (0..AGGREGATION_STAGE3_SUB_TREE_HEIGHT).rev() {
        let start = participation_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [
                participation_nodes[start + (i * 2)].elements.to_vec(),
                participation_nodes[start + (i * 2) + 1].elements.to_vec(),
            ]
            .concat();
            participation_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let participation_root = participation_nodes.last().unwrap();

    //Register the hash of the public inputs
    let inputs = [
        &validators_state_inputs_hash[..],
        &builder.to_u32s(validator_state_total_staked),
        &[block_slot],
        &builder.to_u32s(participation_root.elements[0]),
        &builder.to_u32s(participation_root.elements[1]),
        &builder.to_u32s(participation_root.elements[2]),
        &builder.to_u32s(participation_root.elements[3]),
        &[participation_count],
        &builder.to_u32s(attestations_stake),
    ]
    .concat();
    let inputs_hash = builder.sha256_hash(inputs);
    let inputs_hash_compressed = builder.compress_hash(inputs_hash);
    builder.register_public_inputs(&inputs_hash_compressed.elements);

    AttAgg3Targets {
        block_slot,
        validators_state_verifier,
        validators_state_proof,
        atts_agg2_verifier,
        atts_agg2_data,
    }
}

fn build_empty_participation_sub_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_sub_root(AGGREGATION_STAGE2_SUB_TREE_HEIGHT);
    HashOutTarget {
        elements: root.map(|f| builder.constant(f)),
    }
}
