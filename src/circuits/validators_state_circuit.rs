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
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

use crate::{Config, Field, D};

use super::serialization::{deserialize_circuit, serialize_circuit};
use super::{Circuit, Proof, Serializeable};

pub use proof::ValidatorsStateProof;
pub use witness::ValidatorsStateCircuitData;

pub use proof::PIS_VALIDATORS_STATE_ACCOUNTS_TREE_ROOT;
pub use proof::PIS_VALIDATORS_STATE_INPUTS_HASH;
pub use proof::PIS_VALIDATORS_STATE_TOTAL_STAKED;
pub use proof::PIS_VALIDATORS_STATE_TOTAL_VALIDATORS;
pub use proof::PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT;

pub struct ValidatorsStateCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorsStateCircuitTargets,
}

impl ValidatorsStateCircuit {
    pub fn generate_proof(&self, data: &ValidatorsStateCircuitData) -> Result<ValidatorsStateProof> {
        let pw = generate_partial_witness(&self.circuit_data, &self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ValidatorsStateProof::new(proof))
    }
}

impl Circuit for ValidatorsStateCircuit {
    type Proof = ValidatorsStateProof;

    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        check_cyclic_proof_verifier_data(
            proof.proof(),
            &self.circuit_data.verifier_only,
            &self.circuit_data.common,
        )?;
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
        true
    }

    fn cyclical_init_proof(&self) -> Option<Self::Proof> {
        let data = generate_initial_data();
        let pw = generate_partial_witness(&self.circuit_data, &self.targets, &data).unwrap();
        let proof = self.circuit_data.prove(pw).unwrap();
        Some(Self::Proof::new(proof))
    }

    fn is_wrappable() -> bool {
        false
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        None
    }
}

impl Serializeable for ValidatorsStateCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = read_targets(&mut buffer);
        if targets.is_err() {
            return Err(anyhow!("Failed to deserialize circuit targets"));
        }
        Ok(Self {
            circuit_data,
            targets: targets.unwrap(),
        })
    }
}
