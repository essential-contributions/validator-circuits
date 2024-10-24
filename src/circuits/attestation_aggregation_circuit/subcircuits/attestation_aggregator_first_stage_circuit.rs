mod circuit;
mod proof;
mod targets;
mod witness;

use circuit::*;
use targets::*;
use witness::*;

use anyhow::{anyhow, Result};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::circuits::serialization::{deserialize_circuit, serialize_circuit};
use crate::circuits::{Circuit, Proof, Serializeable};
use crate::{Config, Field, D};

pub use proof::AttestationAggregatorFirstStageProof;
pub use witness::AttestationAggregatorFirstStageData;
pub use witness::AttestationAggregatorFirstStageRevealData;
pub use witness::AttestationAggregatorFirstStageValidatorData;

pub use proof::PIS_AGG1_ATTESTATIONS_STAKE;
pub use proof::PIS_AGG1_BLOCK_SLOT;
pub use proof::PIS_AGG1_PARTICIPATION_COUNT;
pub use proof::PIS_AGG1_PARTICIPATION_SUB_ROOT;
pub use proof::PIS_AGG1_VALIDATORS_SUB_ROOT;

pub struct AttestationAggregatorFirstStageCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttAgg1Targets,
}

impl AttestationAggregatorFirstStageCircuit {
    pub fn generate_proof(
        &self,
        data: &AttestationAggregatorFirstStageData,
    ) -> Result<AttestationAggregatorFirstStageProof> {
        let pw = generate_partial_witness(&self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationAggregatorFirstStageProof::new(proof))
    }
}

impl Circuit for AttestationAggregatorFirstStageCircuit {
    type Proof = AttestationAggregatorFirstStageProof;

    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
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

impl Serializeable for AttestationAggregatorFirstStageCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = match read_targets(&mut buffer) {
            Ok(targets) => Ok(targets),
            Err(_) => Err(anyhow!("Failed to deserialize circuit targets")),
        }?;
        Ok(Self { circuit_data, targets })
    }
}
