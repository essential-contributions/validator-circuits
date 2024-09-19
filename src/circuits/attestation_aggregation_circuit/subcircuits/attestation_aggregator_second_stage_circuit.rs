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

use super::{
    AttestationAggregatorFirstStageCircuit, AttestationAggregatorFirstStageProof,
    PIS_AGG1_ATTESTATIONS_STAKE, PIS_AGG1_BLOCK_SLOT, PIS_AGG1_PARTICIPATION_COUNT,
    PIS_AGG1_PARTICIPATION_SUB_ROOT, PIS_AGG1_VALIDATORS_SUB_ROOT,
};
use crate::circuits::serialization::{
    deserialize_circuit, read_verifier, serialize_circuit, write_verifier,
};
use crate::circuits::{Circuit, Proof, Serializeable};
use crate::{Config, Field, D};

pub use proof::AttestationAggregatorSecondStageProof;
pub use witness::AttestationAggregatorSecondStageAgg1Data;
pub use witness::AttestationAggregatorSecondStageData;

pub use proof::PIS_AGG2_ATTESTATIONS_STAKE;
pub use proof::PIS_AGG2_BLOCK_SLOT;
pub use proof::PIS_AGG2_PARTICIPATION_COUNT;
pub use proof::PIS_AGG2_PARTICIPATION_SUB_ROOT;
pub use proof::PIS_AGG2_VALIDATORS_SUB_ROOT;

pub struct AttestationAggregatorSecondStageCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttAgg2Targets,

    atts_agg1_verifier: VerifierOnlyCircuitData<Config, D>,
}

impl AttestationAggregatorSecondStageCircuit {
    pub fn from_subcircuits(
        atts_agg_first_stage_circuit: &AttestationAggregatorFirstStageCircuit,
    ) -> Self {
        let atts_agg1_common_data = &atts_agg_first_stage_circuit.circuit_data().common;
        let atts_agg1_verifier = atts_agg_first_stage_circuit
            .circuit_data()
            .verifier_only
            .clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, atts_agg1_common_data);
        let circuit_data = builder.build::<Config>();

        Self {
            circuit_data,
            targets,
            atts_agg1_verifier,
        }
    }

    pub fn generate_proof(
        &self,
        data: &AttestationAggregatorSecondStageData,
    ) -> Result<AttestationAggregatorSecondStageProof> {
        let pw = generate_partial_witness(&self.targets, data, &self.atts_agg1_verifier)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationAggregatorSecondStageProof::new(proof))
    }
}

impl Circuit for AttestationAggregatorSecondStageCircuit {
    type Proof = AttestationAggregatorSecondStageProof;

    fn new() -> Self {
        let atts_agg_first_stage_circuit = AttestationAggregatorFirstStageCircuit::new();
        Self::from_subcircuits(&atts_agg_first_stage_circuit)
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof().clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        Ok(proof.proof().to_bytes())
    }

    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof> {
        let common_data = &self.circuit_data.common;
        let proof = ProofWithPublicInputs::<Field, Config, D>::from_bytes(bytes, common_data)?;
        Ok(Self::Proof::new(proof))
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

impl Serializeable for AttestationAggregatorSecondStageCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        if write_verifier(&mut buffer, &self.atts_agg1_verifier).is_err() {
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
        let atts_agg1_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        Ok(Self {
            circuit_data,
            targets,
            atts_agg1_verifier,
        })
    }
}
