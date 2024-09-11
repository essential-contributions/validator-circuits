use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuits::extensions::CircuitBuilderExtended;
use crate::commitment::empty_commitment_root;
use crate::participation::{PARTICIPANTS_PER_FIELD, PARTICIPATION_FIELDS_PER_LEAF};
use crate::{Field, AGGREGATION_STAGE1_SIZE, AGGREGATION_STAGE1_SUB_TREE_HEIGHT, D, VALIDATOR_COMMITMENT_TREE_HEIGHT};
use crate::Hash;

use super::{AttAgg1Targets, AttAgg1ValidatorTargets};

pub fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> AttAgg1Targets {
    let mut validator_targets: Vec<AttAgg1ValidatorTargets> = Vec::new();

    // Global targets
    let skip_root = build_skip_root(builder);
    let block_slot = builder.add_virtual_target();
    let block_slot_bits = builder.split_le(block_slot, VALIDATOR_COMMITMENT_TREE_HEIGHT);
    let mut attestations_stake = builder.zero();
    let mut participation_count = builder.zero();
    
    // Participation targets
    let mut participation_bits_fields: Vec<Target> = Vec::new();
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
    let participation_root = builder.hash_n_to_hash_no_pad::<Hash>(participation_bits_fields.clone());

    // Verify each validator reveal
    for not_skip in participation_bits {
        let commitment_root = builder.add_virtual_hash();
        let stake = builder.add_virtual_target();

        // Commitment tree
        let reveal = builder.add_virtual_targets(4);
        let reveal_hash = builder.hash_n_to_m_no_pad::<Hash>(reveal.clone(), 4);
        let reveal_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(VALIDATOR_COMMITMENT_TREE_HEIGHT),
        };
        let merkle_root = builder.select_hash(not_skip, commitment_root, skip_root);
        builder.verify_merkle_proof::<Hash>(
            reveal_hash, 
            &block_slot_bits, 
            merkle_root,
            &reveal_proof,
        );

        // Keep running total of stake and num participants
        attestations_stake = builder.mul_add(stake, not_skip.target, attestations_stake);
        participation_count = builder.add(participation_count, not_skip.target);

        validator_targets.push(AttAgg1ValidatorTargets {
            stake,
            commitment_root,
            reveal,
            reveal_proof,
        });
    }

    // Compute the validators sub root
    let mut nodes: Vec<HashOutTarget> = Vec::new();
    for validator in validator_targets.iter() {
        let leaf_data = [validator.commitment_root.elements.to_vec(), vec![validator.stake]].concat();
        nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(leaf_data));
    }
    for h in (0..AGGREGATION_STAGE1_SUB_TREE_HEIGHT).rev() {
        let start = nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [nodes[start + (i * 2)].elements.to_vec(), nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let validators_sub_root = nodes.last().unwrap();

    // Register the public inputs
    builder.register_public_inputs(&validators_sub_root.elements);
    builder.register_public_inputs(&participation_root.elements);
    builder.register_public_input(participation_count);
    builder.register_public_input(attestations_stake);
    builder.register_public_input(block_slot);

    AttAgg1Targets {
        block_slot,
        validators: validator_targets,
        participation_bits_fields,
    }
}

fn build_skip_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_commitment_root();
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}
