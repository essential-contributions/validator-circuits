mod circuit;
mod proof;
mod targets;
mod witness;

use circuit::*;
use targets::*;
use witness::*;

use anyhow::{anyhow, Result};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::Buffer;

use crate::circuits::participation_state_circuit::ParticipationStateCircuit;
use crate::circuits::serialization::{deserialize_circuit, read_verifier, serialize_circuit, write_verifier};
use crate::circuits::{load_or_create_circuit, Circuit, Proof, Serializeable, PARTICIPATION_STATE_CIRCUIT_DIR};
use crate::{Config, Field, D};

use super::{
    ValidatorParticipationAggCircuit, ValidatorParticipationAggProof, PIS_AGG_ACCOUNT_ADDRESS,
    PIS_AGG_EPOCHS_TREE_ROOT, PIS_AGG_FROM_EPOCH, PIS_AGG_PARAM_RF, PIS_AGG_PARAM_ST, PIS_AGG_PR_TREE_ROOT,
    PIS_AGG_TO_EPOCH, PIS_AGG_WITHDRAW_MAX, PIS_AGG_WITHDRAW_UNEARNED,
};

pub use proof::ValidatorParticipationAggEndProof;
pub use witness::ValidatorParticipationAggEndCircuitData;

pub struct ValidatorParticipationAggEndCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorParticipationAggEndCircuitTargets,

    participation_agg_verifier: VerifierOnlyCircuitData<Config, D>,
    participation_state_verifier: VerifierOnlyCircuitData<Config, D>,
}

impl ValidatorParticipationAggEndCircuit {
    pub fn from_subcircuits(participation_agg_circuit: &ValidatorParticipationAggCircuit) -> Self {
        let participation_state_circuit =
            load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);
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

        Self {
            circuit_data,
            targets,
            participation_agg_verifier,
            participation_state_verifier,
        }
    }

    pub fn generate_proof(
        &self,
        data: &ValidatorParticipationAggEndCircuitData,
    ) -> Result<ValidatorParticipationAggEndProof> {
        let pw = generate_partial_witness(
            &self.targets,
            data,
            &self.participation_agg_verifier,
            &self.participation_state_verifier,
        )?;
        let proof = self.circuit_data.prove(pw)?;
        let proof_data = generate_proof_data(&data);
        Ok(ValidatorParticipationAggEndProof::new(proof, proof_data))
    }
}

impl Circuit for ValidatorParticipationAggEndCircuit {
    type Proof = ValidatorParticipationAggEndProof;

    fn new() -> Self {
        let participation_agg_circuit = ValidatorParticipationAggCircuit::new();
        Self::from_subcircuits(&participation_agg_circuit)
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof().clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        proof.to_bytes()
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

        Ok(Self::Proof::new(proof, proof_data))
    }

    fn is_cyclical() -> bool {
        false
    }

    fn cyclical_init_proof(&self) -> Option<Self::Proof> {
        None
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
