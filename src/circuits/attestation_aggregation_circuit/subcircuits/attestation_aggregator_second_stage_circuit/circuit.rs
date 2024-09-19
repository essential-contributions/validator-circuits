use plonky2::hash::hash_types::HashOutTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierCircuitTarget};

use super::{
    AttAgg2Agg1Targets, AttAgg2Targets, PIS_AGG1_ATTESTATIONS_STAKE, PIS_AGG1_BLOCK_SLOT,
    PIS_AGG1_PARTICIPATION_COUNT, PIS_AGG1_PARTICIPATION_SUB_ROOT, PIS_AGG1_VALIDATORS_SUB_ROOT,
};
use crate::circuits::extensions::CircuitBuilderExtended;
use crate::participation::empty_participation_sub_root;
use crate::{Config, Field, Hash, AGGREGATION_STAGE2_SIZE, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, D};

pub fn generate_circuit(
    builder: &mut CircuitBuilder<Field, D>,
    atts_agg1_common_data: &CommonCircuitData<Field, D>,
) -> AttAgg2Targets {
    let mut atts_agg1_data: Vec<AttAgg2Agg1Targets> = Vec::new();

    // Global targets
    let empty_participation_sub_root = build_empty_participation_sub_root(builder);
    let block_slot = builder.add_virtual_target();
    let mut attestations_stake = builder.zero();
    let mut participation_count = builder.zero();

    // Circuit target
    let atts_agg1_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(atts_agg1_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };

    // Verify each agg1 data
    let mut validator_nodes: Vec<HashOutTarget> = Vec::new();
    let mut participation_nodes: Vec<HashOutTarget> = Vec::new();
    for _ in 0..AGGREGATION_STAGE2_SIZE {
        let validators_sub_root = builder.add_virtual_hash();
        let has_participation = builder.add_virtual_bool_target_safe();
        let proof_target = builder.add_virtual_proof_with_pis(&atts_agg1_common_data);

        // Verify proof (ignored if not flagged as has participation)
        builder.verify_proof::<Config>(&proof_target, &atts_agg1_verifier, &atts_agg1_common_data);

        // Determine applicable validator node
        let proof_validators_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[3]],
            ],
        };
        validator_nodes.push(builder.select_hash(
            has_participation,
            proof_validators_sub_root,
            validators_sub_root,
        ));

        // Determine applicable participation node
        let proof_participation_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[3]],
            ],
        };
        participation_nodes.push(builder.select_hash(
            has_participation,
            proof_participation_sub_root,
            empty_participation_sub_root,
        ));

        // Make sure each agg1 data has the same block_slot
        builder.connect(proof_target.public_inputs[PIS_AGG1_BLOCK_SLOT], block_slot);

        // Keep running total of stake and num participants
        attestations_stake = builder.mul_add(
            has_participation.target,
            proof_target.public_inputs[PIS_AGG1_ATTESTATIONS_STAKE],
            attestations_stake,
        );
        participation_count = builder.mul_add(
            has_participation.target,
            proof_target.public_inputs[PIS_AGG1_PARTICIPATION_COUNT],
            participation_count,
        );

        atts_agg1_data.push(AttAgg2Agg1Targets {
            validators_sub_root,
            has_participation,
            proof: proof_target,
        });
    }

    // Compute the validators sub root
    for h in (0..AGGREGATION_STAGE2_SUB_TREE_HEIGHT).rev() {
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

    // Compute the participation sub root
    for h in (0..AGGREGATION_STAGE2_SUB_TREE_HEIGHT).rev() {
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
    let participation_sub_root = participation_nodes.last().unwrap();

    // Register the public inputs
    builder.register_public_inputs(&validators_sub_root.elements);
    builder.register_public_inputs(&participation_sub_root.elements);
    builder.register_public_input(participation_count);
    builder.register_public_input(attestations_stake);
    builder.register_public_input(block_slot);

    AttAgg2Targets {
        block_slot,
        atts_agg1_verifier,
        atts_agg1_data,
    }
}

fn build_empty_participation_sub_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_sub_root(0);
    HashOutTarget {
        elements: root.map(|f| builder.constant(f)),
    }
}
