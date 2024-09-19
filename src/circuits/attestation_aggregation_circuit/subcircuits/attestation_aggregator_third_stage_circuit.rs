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

use super::{
    AttestationAggregatorSecondStageCircuit, AttestationAggregatorSecondStageProof,
    PIS_AGG2_ATTESTATIONS_STAKE, PIS_AGG2_BLOCK_SLOT, PIS_AGG2_PARTICIPATION_COUNT,
    PIS_AGG2_PARTICIPATION_SUB_ROOT, PIS_AGG2_VALIDATORS_SUB_ROOT,
};
use crate::circuits::serialization::{
    deserialize_circuit, read_verifier, serialize_circuit, write_verifier,
};
use crate::circuits::validators_state_circuit::ValidatorsStateCircuit;
use crate::circuits::{load_or_create_circuit, VALIDATORS_STATE_CIRCUIT_DIR};
use crate::circuits::{Circuit, Proof, Serializeable};
use crate::{Config, Field, D};

pub use proof::AttestationAggregatorThirdStageProof;
pub use witness::AttestationAggregatorThirdStageAgg2Data;
pub use witness::AttestationAggregatorThirdStageData;

pub struct AttestationAggregatorThirdStageCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttAgg3Targets,

    atts_agg2_verifier: VerifierOnlyCircuitData<Config, D>,
    validators_state_verifier: VerifierOnlyCircuitData<Config, D>,
}

impl AttestationAggregatorThirdStageCircuit {
    pub fn from_subcircuits(
        atts_agg_second_stage_circuit: &AttestationAggregatorSecondStageCircuit,
    ) -> Self {
        let validators_state_circuit =
            load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
        let validators_state_common_data = &validators_state_circuit.circuit_data().common;
        let validators_state_verifier = validators_state_circuit
            .circuit_data()
            .verifier_only
            .clone();

        let atts_agg2_common_data = &atts_agg_second_stage_circuit.circuit_data().common;
        let atts_agg2_verifier = atts_agg_second_stage_circuit
            .circuit_data()
            .verifier_only
            .clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(
            &mut builder,
            atts_agg2_common_data,
            validators_state_common_data,
        );
        let circuit_data = builder.build::<Config>();

        Self {
            circuit_data,
            targets,
            atts_agg2_verifier,
            validators_state_verifier,
        }
    }

    pub fn generate_proof(
        &self,
        data: &AttestationAggregatorThirdStageData,
    ) -> Result<AttestationAggregatorThirdStageProof> {
        let pw = generate_partial_witness(
            &self.targets,
            data,
            &self.atts_agg2_verifier,
            &self.validators_state_verifier,
        )?;
        let proof = self.circuit_data.prove(pw)?;
        let proof_data = generate_proof_data(&data);
        Ok(AttestationAggregatorThirdStageProof::new(proof, proof_data))
    }
}

impl Circuit for AttestationAggregatorThirdStageCircuit {
    type Proof = AttestationAggregatorThirdStageProof;

    fn new() -> Self {
        let atts_agg_second_stage_circuit = AttestationAggregatorSecondStageCircuit::new();
        Self::from_subcircuits(&atts_agg_second_stage_circuit)
    }

    fn verify_proof(&self, proof: &AttestationAggregatorThirdStageProof) -> Result<()> {
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
        let proof =
            ProofWithPublicInputs::<Field, Config, D>::from_bytes(unread_bytes, common_data)?;

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

impl Serializeable for AttestationAggregatorThirdStageCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        if write_verifier(&mut buffer, &self.atts_agg2_verifier).is_err() {
            return Err(anyhow!("Failed to serialize sub circuit verifier"));
        }
        if write_verifier(&mut buffer, &self.validators_state_verifier).is_err() {
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
        let atts_agg2_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        let validators_state_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        Ok(Self {
            circuit_data,
            targets,
            atts_agg2_verifier,
            validators_state_verifier,
        })
    }
}
