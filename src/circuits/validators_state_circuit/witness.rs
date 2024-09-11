use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, Field64};
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use anyhow::Result;

use crate::accounts::{initial_accounts_tree, initial_accounts_tree_root, null_account_address};
use crate::circuits::extensions::PartialWitnessExtended;
use crate::validators::{initial_validators_tree, initial_validators_tree_root};
use crate::{Config, Field, D};

use super::{Proof, ValidatorsStateCircuitTargets, ValidatorsStateProof};

#[derive(Clone)]
pub struct ValidatorsStateCircuitData {
    pub index: usize,
    pub stake: u32,
    pub commitment: [Field; 4],
    pub account: [u8; 20],

    pub validator_index: usize,
    pub validator_stake: u32,
    pub validator_commitment: [Field; 4],
    pub validator_proof: Vec<[Field; 4]>,

    pub from_account: [u8; 20],
    pub from_acc_index: Option<usize>,
    pub from_acc_proof: Vec<[Field; 4]>,

    pub to_account: [u8; 20],
    pub to_acc_index: Option<usize>,
    pub to_acc_proof: Vec<[Field; 4]>,
    
    pub previous_proof: Option<ValidatorsStateProof>,
}

pub fn generate_partial_witness(
    circuit_data: &CircuitData<Field, Config, D>, 
    targets: &ValidatorsStateCircuitTargets, 
    data: &ValidatorsStateCircuitData,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    pw.set_target(targets.index, Field::from_canonical_usize(data.index));
    pw.set_target(targets.stake, Field::from_canonical_u32(data.stake));
    pw.set_hash_target(targets.commitment, HashOut::<Field> { elements: data.commitment });
    pw.set_target_arr(&targets.account, &account_to_fields(data.account));

    pw.set_target(targets.validator_index, Field::from_canonical_usize(data.validator_index));
    pw.set_target(targets.validator_stake, Field::from_canonical_u32(data.validator_stake));
    pw.set_hash_target(targets.validator_commitment, HashOut::<Field> { elements: data.validator_commitment });
    pw.set_merkle_proof_target(targets.validator_proof.clone(), &data.validator_proof);

    pw.set_target_arr(&targets.from_account, &account_to_fields(data.from_account));
    pw.set_target(targets.from_acc_index, index_to_field(data.from_acc_index));
    pw.set_merkle_proof_target(targets.from_acc_proof.clone(), &data.from_acc_proof);

    pw.set_target_arr(&targets.to_account, &account_to_fields(data.to_account));
    pw.set_target(targets.to_acc_index, index_to_field(data.to_acc_index));
    pw.set_merkle_proof_target(targets.to_acc_proof.clone(), &data.to_acc_proof);

    pw.set_verifier_data_target(&targets.verifier, &circuit_data.verifier_only);
    match &data.previous_proof {
        Some(previous_proof) => {
            pw.set_bool_target(targets.init_zero, true);
            pw.set_proof_with_pis_target(&targets.previous_proof, previous_proof.proof());
        },
        None => {
            //setup for using initial state (no previous proof)
            let base_proof = initial_proof(circuit_data);
            pw.set_bool_target(targets.init_zero, false);
            pw.set_proof_with_pis_target::<Config, D>(&targets.previous_proof, &base_proof);
        },
    };
    Ok(pw)
}

pub fn generate_initial_data() -> ValidatorsStateCircuitData {
    let validators_tree = initial_validators_tree();
    let accounts_tree = initial_accounts_tree();

    let index = 0;
    let from_account = null_account_address(index);
    let to_account = [12u8; 20];
    let validator = validators_tree.validator(index);
    ValidatorsStateCircuitData {
        index,
        stake: 32,
        commitment: [Field::ZERO, Field::ONE, Field::TWO, Field::TWO],
        account: to_account,

        validator_index: index,
        validator_stake: validator.stake,
        validator_commitment: validator.commitment_root,
        validator_proof: validators_tree.merkle_proof(index),

        from_account,
        from_acc_index: accounts_tree.account(from_account).validator_index,
        from_acc_proof: accounts_tree.merkle_proof(from_account),

        to_account,
        to_acc_index: accounts_tree.account(to_account).validator_index,
        to_acc_proof: accounts_tree.merkle_proof(to_account),

        previous_proof: None,
    }
}

fn initial_proof(circuit_data: &CircuitData<Field, Config, D>) -> ProofWithPublicInputs<Field, Config, D> {
    let initial_inputs_hash = [Field::ZERO; 8];
    let initial_total_staked = Field::ZERO;
    let initial_total_validators = Field::ZERO;
    let initial_validators_tree_root = initial_validators_tree_root();
    let initial_accounts_tree_root = initial_accounts_tree_root();
    let initial_public_inputs = [
        &initial_inputs_hash[..], 
        &[initial_total_staked],
        &[initial_total_validators],
        &initial_validators_tree_root[..],
        &initial_accounts_tree_root[..]
    ].concat();
    cyclic_base_proof(
        &circuit_data.common,
        &circuit_data.verifier_only,
        initial_public_inputs.into_iter().enumerate().collect(),
    )
}

fn index_to_field(index: Option<usize>) -> Field {
    match index {
        Some(index) => Field::from_canonical_usize(index),
        None => Field::ZERO.sub_one(),
    }
}

fn account_to_fields(account: [u8; 20]) -> [Field; 5] {
    let mut account_fields = [Field::ZERO; 5];
    account.chunks(4).enumerate().for_each(|(i, c)| {
        account_fields[i] = Field::from_canonical_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    });
    account_fields
}
