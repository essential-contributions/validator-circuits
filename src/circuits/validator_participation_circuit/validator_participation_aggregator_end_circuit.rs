use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::circuits::extensions::CircuitBuilderExtended;
use crate::circuits::participation_state_circuit::{ParticipationStateCircuit, ParticipationStateProof, PIS_PARTICIPATION_ROUNDS_TREE_ROOT, PIS_PARTICIPATION_STATE_INPUTS_HASH, PIS_VALIDATOR_EPOCHS_TREE_ROOT};
use crate::circuits::serialization::{deserialize_circuit, read_verifier, serialize_circuit, write_verifier};
use crate::circuits::{load_or_create_circuit, Circuit, Proof, Serializeable, PARTICIPATION_STATE_CIRCUIT_DIR};
use crate::{Config, Field, D};

use super::{ValidatorParticipationAggCircuit, ValidatorParticipationAggProof, PIS_AGG_ACCOUNT_ADDRESS, PIS_AGG_EPOCHS_TREE_ROOT, PIS_AGG_FROM_EPOCH, PIS_AGG_PARAM_RF, PIS_AGG_PARAM_ST, PIS_AGG_PR_TREE_ROOT, PIS_AGG_TO_EPOCH, PIS_AGG_WITHDRAW_MAX, PIS_AGG_WITHDRAW_UNEARNED};

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
        let proof_data = proof_data(&data);
        Ok(ValidatorParticipationAggEndProof { proof, data: proof_data })
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

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        if write_proof_data(&mut buffer, &proof.data).is_err() {
            return Err(anyhow!("Failed to serialize proof data"));
        }
        if buffer.write_all(&proof.proof.to_bytes()).is_err() {
            return Err(anyhow!("Failed to serialize proof"));
        }
        Ok(buffer)
    }

    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof> {
        let mut buffer = Buffer::new(&bytes);
        let proof_data = match read_proof_data(&mut buffer) {
            Ok(proof_data) => Ok(proof_data),
            Err(_) => Err(anyhow!("Failed to deserialize proof data")),
        }?;

        let common_data = &self.circuit_data.common;
        let unread_bytes = buffer.unread_bytes().to_vec();
        let proof = ProofWithPublicInputs::<Field, Config, D>::from_bytes(unread_bytes, common_data)?;

        Ok(Self::Proof { proof, data: proof_data })
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
        if write_verifier(&mut buffer, &self.participation_agg_verifier).is_err() {
            return Err(anyhow!("Failed to serialize sub circuit verifier"));
        }
        if write_verifier(&mut buffer, &self.participation_state_verifier).is_err() {
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
        let participation_agg_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        let participation_state_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;

        Ok(Self { 
            circuit_data, 
            targets, 
            participation_agg_verifier,
            participation_state_verifier,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ValidatorParticipationAggEndProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
    data: ValidatorParticipationAggEndProofData,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct ValidatorParticipationAggEndProofData {
    pub participation_inputs_hash: [u8; 32],
    pub account_address: [u8; 20],
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub withdraw_max: u64,
    pub withdraw_unearned: u64,
    pub param_rf: u32,
    pub param_st: u32,
}
impl ValidatorParticipationAggEndProof {
    pub fn public_inputs_hash(&self) -> [Field; 4] {
        [self.proof.public_inputs[0], 
        self.proof.public_inputs[1], 
        self.proof.public_inputs[2], 
        self.proof.public_inputs[3]]
    }

    pub fn participation_inputs_hash(&self) -> [u8; 32] {
        self.data.participation_inputs_hash
    }

    pub fn account_address(&self) -> [u8; 20] {
        self.data.account_address
    }

    pub fn from_epoch(&self) -> u32 {
        self.data.from_epoch
    }

    pub fn to_epoch(&self) -> u32 {
        self.data.to_epoch
    }

    pub fn withdraw_max(&self) -> u64 {
        self.data.withdraw_max
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.data.withdraw_unearned
    }

    pub fn param_rf(&self) -> u32 {
        self.data.param_rf
    }

    pub fn param_st(&self) -> u32 {
        self.data.param_st
    }
}
impl Proof for ValidatorParticipationAggEndProof {
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
    for (&a, s) in participation_agg_val_epochs_tree_root.iter().zip(participation_state_val_epochs_tree_root) {
        builder.connect(a, s);
    }
    for (&a, s) in participation_agg_pr_tree_root.iter().zip(participation_state_pr_tree_root) {
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
    ].concat();
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
fn proof_data(data: &ValidatorParticipationAggEndCircuitData) -> ValidatorParticipationAggEndProofData {
    ValidatorParticipationAggEndProofData {
        participation_inputs_hash: data.participation_state_proof.inputs_hash(),
        account_address: data.participation_agg_proof.account_address(),
        from_epoch: data.participation_agg_proof.from_epoch(),
        to_epoch: data.participation_agg_proof.to_epoch(),
        withdraw_max: data.participation_agg_proof.withdraw_max(),
        withdraw_unearned: data.participation_agg_proof.withdraw_unearned(),
        param_rf: data.participation_agg_proof.param_rf(),
        param_st: data.participation_agg_proof.param_st(),
    }
}

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &ValidatorParticipationAggEndCircuitTargets) -> IoResult<()> {
    buffer.write_target_proof_with_public_inputs(&targets.participation_agg_proof)?;
    buffer.write_target_verifier_circuit(&targets.participation_agg_verifier)?;

    buffer.write_target_proof_with_public_inputs(&targets.participation_state_proof)?;
    buffer.write_target_verifier_circuit(&targets.participation_state_verifier)?;

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggEndCircuitTargets> {
    let participation_agg_proof = buffer.read_target_proof_with_public_inputs()?;
    let participation_agg_verifier = buffer.read_target_verifier_circuit()?;

    let participation_state_proof = buffer.read_target_proof_with_public_inputs()?;
    let participation_state_verifier = buffer.read_target_verifier_circuit()?;

    Ok(ValidatorParticipationAggEndCircuitTargets {
        participation_agg_proof,
        participation_agg_verifier,
        participation_state_proof,
        participation_state_verifier,
    })
}

#[inline]
fn write_proof_data(buffer: &mut Vec<u8>, data: &ValidatorParticipationAggEndProofData) -> IoResult<()> {
    buffer.write_all(&data.participation_inputs_hash)?;
    buffer.write_all(&data.account_address)?;
    buffer.write_u32(data.from_epoch)?;
    buffer.write_u32(data.to_epoch)?;
    buffer.write_usize(data.withdraw_max as usize)?;
    buffer.write_usize(data.withdraw_unearned as usize)?;
    buffer.write_u32(data.param_rf)?;
    buffer.write_u32(data.param_st)?;

    Ok(())
}

#[inline]
fn read_proof_data(buffer: &mut Buffer) -> IoResult<ValidatorParticipationAggEndProofData> {
    let mut participation_inputs_hash = [0u8; 32];
    let mut account_address = [0u8; 20];
    buffer.read_exact(&mut participation_inputs_hash)?;
    buffer.read_exact(&mut account_address)?;
    let from_epoch = buffer.read_u32()?;
    let to_epoch = buffer.read_u32()?;
    let withdraw_max = buffer.read_usize()? as u64;
    let withdraw_unearned = buffer.read_usize()? as u64;
    let param_rf = buffer.read_u32()?;
    let param_st = buffer.read_u32()?;

    Ok(ValidatorParticipationAggEndProofData {
        participation_inputs_hash,
        account_address,
        from_epoch,
        to_epoch,
        withdraw_max,
        withdraw_unearned,
        param_rf,
        param_st,
    })
}
