use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, Field64, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use anyhow::{anyhow, Result};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

use crate::circuits::extensions::{common_data_for_recursion, CircuitBuilderExtended, PartialWitnessExtended};
use crate::circuits::participation_state_circuit::{ParticipationStateCircuit, ParticipationStateProof, PIS_PARTICIPATION_ROUNDS_TREE_ROOT, PIS_PARTICIPATION_STATE_INPUTS_HASH};
use crate::circuits::serialization::{deserialize_circuit, serialize_circuit};
use crate::circuits::validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateProof, PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT, PIS_VALIDATORS_STATE_INPUTS_HASH, PIS_VALIDATORS_STATE_TOTAL_STAKED, PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT};
use crate::circuits::{load_or_create_circuit, Circuit, Proof, Serializeable, PARTICIPATION_STATE_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR};
use crate::participation::{empty_participation_root, participation_merkle_data, PARTICIPANTS_PER_FIELD, PARTICIPATION_BITS_BYTE_SIZE, PARTICIPATION_FIELDS_PER_LEAF, PARTICIPATION_TREE_HEIGHT};
use crate::validators::{empty_validators_tree_proof, empty_validators_tree_root};
use crate::{Config, Field, ACCOUNTS_TREE_HEIGHT, AGGREGATION_PASS1_SIZE, AGGREGATION_PASS1_SUB_TREE_HEIGHT, D, MAX_VALIDATORS, PARTICIPATION_ROUNDS_PER_STATE_EPOCH, PARTICIPATION_ROUNDS_TREE_HEIGHT, VALIDATORS_TREE_HEIGHT};
use crate::Hash;

use super::{ValidatorParticipationAggCircuit, ValidatorParticipationAggProof, PIS_AGG_ACCOUNT_ADDRESS, PIS_AGG_FROM_EPOCH, PIS_AGG_PARAM_RF, PIS_AGG_PARAM_ST, PIS_AGG_PR_TREE_ROOT, PIS_AGG_TO_EPOCH, PIS_AGG_WITHDRAW_MAX, PIS_AGG_WITHDRAW_UNEARNED};

pub const PIS_END_PARTICIPATION_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_END_ACCOUNT_ADDRESS: [usize; 5] = [8, 9, 10, 11, 12];
pub const PIS_END_FROM_EPOCH: usize = 13;
pub const PIS_END_TO_EPOCH: usize = 14;
pub const PIS_END_WITHDRAW_MAX: usize = 15;
pub const PIS_END_WITHDRAW_UNEARNED: usize = 16;
pub const PIS_END_PARAM_RF: usize = 17;
pub const PIS_END_PARAM_ST: usize = 18;

pub struct ValidatorParticipationAggEndCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorParticipationAggEndCircuitTargets,

    participation_agg_verifier: VerifierOnlyCircuitData<Config, D>,
    participation_state_verifier: VerifierOnlyCircuitData<Config, D>,
}
struct ValidatorParticipationAggEndCircuitTargets {
    participation_agg_proof: ProofWithPublicInputsTarget<D>,
    participation_agg_verifier: VerifierCircuitTarget,

    participation_state_proof: ProofWithPublicInputsTarget<D>,
    participation_state_verifier: VerifierCircuitTarget,
}
impl ValidatorParticipationAggEndCircuit {
    pub fn from_subcircuits(participation_agg_circuit: &ValidatorParticipationAggCircuit) -> Self {
        let participation_state_circuit = load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
        let participation_state_common_data = &participation_state_circuit.circuit_data().common;
        let participation_state_verifier = participation_state_circuit.circuit_data().verifier_only.clone();

        let participation_agg_common_data = &participation_agg_circuit.circuit_data().common;
        let participation_agg_verifier = participation_agg_circuit.circuit_data().verifier_only.clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(
            &mut builder,
            participation_agg_common_data,
            participation_state_common_data,
        );
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets, participation_agg_verifier, participation_state_verifier }
    }

    pub fn generate_proof(&self, data: &ValidatorParticipationAggEndCircuitData) -> Result<ValidatorParticipationAggEndProof> {
        let pw = generate_partial_witness(
            &self.targets, 
            data, 
            &self.participation_agg_verifier, 
            &self.participation_state_verifier,
        )?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ValidatorParticipationAggEndProof { proof })
    }
}
impl Circuit for ValidatorParticipationAggEndCircuit {
    type Proof = ValidatorParticipationAggEndProof;
    
    fn new() -> Self {
        let participation_agg_circuit = ValidatorParticipationAggCircuit::new();
        Self::from_subcircuits(&participation_agg_circuit)
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    fn is_wrappable() -> bool {
        false
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        None
    }
}
impl Serializeable for ValidatorParticipationAggEndCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        //let validators_state_verifier_bytes = self.validators_state_verifier.to_bytes();
        //if validators_state_verifier_bytes.is_err() {
        //    return Err(anyhow!("Failed to serialize sub circuit verifier"));
        //}
        //buffer.write_all(&validators_state_verifier_bytes.unwrap()).expect("Buffer write failure");

        //Ok(buffer)
        todo!()
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = read_targets(&mut buffer);
        if targets.is_err() {
            return Err(anyhow!("Failed to deserialize circuit targets"));
        }
        //let validators_state_verifier = VerifierOnlyCircuitData::<Config, D>::from_bytes(buffer.unread_bytes().to_vec());
        //if validators_state_verifier.is_err() {
        //    return Err(anyhow!("Failed to deserialize sub circuit verifier"));
        //}

        //Ok(Self { 
        //    circuit_data, 
        //    targets: targets.unwrap(), 
        //    validators_state_verifier: validators_state_verifier.unwrap() 
        //})
        todo!()
    }
}

#[derive(Clone)]
pub struct ValidatorParticipationAggEndProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl ValidatorParticipationAggEndProof {
    pub fn participation_inputs_hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes = (self.proof.public_inputs[PIS_END_PARTICIPATION_INPUTS_HASH[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn account_address(&self) -> [u8; 20] {
        let mut hash = [0u8; 20];
        for i in 0..5 {
            let bytes = (self.proof.public_inputs[PIS_END_ACCOUNT_ADDRESS[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
    }

    pub fn from_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_END_FROM_EPOCH].to_canonical_u64() as u32
    }

    pub fn to_epoch(&self) -> u32 {
        self.proof.public_inputs[PIS_END_TO_EPOCH].to_canonical_u64() as u32
    }

    pub fn withdraw_max(&self) -> u64 {
        self.proof.public_inputs[PIS_END_WITHDRAW_MAX].to_canonical_u64()
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.proof.public_inputs[PIS_END_WITHDRAW_UNEARNED].to_canonical_u64()
    }

    pub fn param_rf(&self) -> u64 {
        self.proof.public_inputs[PIS_END_PARAM_RF].to_canonical_u64()
    }

    pub fn param_st(&self) -> u64 {
        self.proof.public_inputs[PIS_END_PARAM_ST].to_canonical_u64()
    }
}
impl Proof for ValidatorParticipationAggEndProof {
    fn from_proof(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        Self { proof }
    }
    
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(
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
        participation_agg_common_data
    );
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
        participation_state_common_data
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
    let participation_state_pr_tree_root = vec![
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[0]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[1]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[2]],
        participation_state_proof.public_inputs[PIS_PARTICIPATION_ROUNDS_TREE_ROOT[3]],
    ];

    //Connect data between proofs
    for (&a, s) in participation_agg_pr_tree_root.iter().zip(participation_state_pr_tree_root) {
        builder.connect(a, s);
    }

    //Register all public inputs
    builder.register_public_inputs(&participation_state_inputs_hash);
    builder.register_public_inputs(&account_address);
    builder.register_public_input(from_epoch);
    builder.register_public_input(to_epoch);
    builder.register_public_input(withdraw_max);
    builder.register_public_input(withdraw_unearned);
    builder.register_public_input(param_rf);
    builder.register_public_input(param_st);

    ValidatorParticipationAggEndCircuitTargets {
        participation_agg_proof,
        participation_agg_verifier,
    
        participation_state_proof,
        participation_state_verifier,
    }
}

#[derive(Clone)]
pub struct ValidatorParticipationAggEndCircuitData {
    pub participation_agg_proof: ValidatorParticipationAggProof,
    pub participation_state_proof: ParticipationStateProof,
}

fn generate_partial_witness(
    targets: &ValidatorParticipationAggEndCircuitTargets,
    data: &ValidatorParticipationAggEndCircuitData,
    participation_agg_verifier: &VerifierOnlyCircuitData<Config, D>,
    participation_state_verifier: &VerifierOnlyCircuitData<Config, D>,
) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();

    //participation agg proof
    pw.set_verifier_data_target(&targets.participation_agg_verifier, participation_agg_verifier);
    pw.set_proof_with_pis_target(&targets.participation_agg_proof, data.participation_agg_proof.proof());

    //participation state proof
    pw.set_verifier_data_target(&targets.participation_state_verifier, participation_state_verifier);
    pw.set_proof_with_pis_target(&targets.participation_state_proof, data.participation_state_proof.proof());

    Ok(pw)
}

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorParticipationAggEndCircuitTargets) -> IoResult<()> {
    todo!()
    /*
    buffer.write_target(targets.validator_bit_index)?;
    buffer.write_target_vec(&targets.participation_bits_fields)?;
    buffer.write_target_hash(&targets.participation_root)?;
    buffer.write_target(targets.validator_field_index)?;
    buffer.write_target_merkle_proof(&targets.participation_root_merkle_proof)?;

    Ok(())
    */
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggEndCircuitTargets> {
    todo!()
    /*
    let validator_bit_index = buffer.read_target()?;
    let participation_bits_fields = buffer.read_target_vec()?;
    let participation_root = buffer.read_target_hash()?;
    let validator_field_index = buffer.read_target()?;
    let participation_root_merkle_proof = buffer.read_target_merkle_proof()?;

    Ok(ValidatorParticipationAggEndCircuitTargets {
        validator_bit_index,
        participation_bits_fields,
        participation_root,
        validator_field_index,
        participation_root_merkle_proof,
    })
    */
}
