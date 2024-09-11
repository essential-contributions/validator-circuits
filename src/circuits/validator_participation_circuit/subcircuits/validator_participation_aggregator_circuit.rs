mod circuit;
mod proof;
mod targets;
mod witness;

use circuit::*;
use targets::*;
use witness::*;

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use anyhow::{anyhow, Result};

use crate::circuits::serialization::{deserialize_circuit, read_verifier, serialize_circuit, write_verifier};
use crate::circuits::validators_state_circuit::ValidatorsStateCircuit;
use crate::circuits::{load_or_create_circuit, Circuit, Proof, Serializeable, VALIDATORS_STATE_CIRCUIT_DIR};
use crate::{Config, Field, D};

pub use proof::ValidatorParticipationAggProof;
pub use witness::ValidatorParticipationAggCircuitData;
pub use witness::ValidatorParticipationValidatorData;
pub use witness::ValidatorPartAggRoundData;
pub use witness::ValidatorPartAggStartData;
pub use witness::ValidatorPartAggPrevData;

pub use proof::PIS_AGG_EPOCHS_TREE_ROOT;
pub use proof::PIS_AGG_PR_TREE_ROOT;
pub use proof::PIS_AGG_ACCOUNT_ADDRESS;
pub use proof::PIS_AGG_FROM_EPOCH;
pub use proof::PIS_AGG_TO_EPOCH;
pub use proof::PIS_AGG_WITHDRAW_MAX;
pub use proof::PIS_AGG_WITHDRAW_UNEARNED;
pub use proof::PIS_AGG_PARAM_RF;
pub use proof::PIS_AGG_PARAM_ST;

pub struct ValidatorParticipationAggCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: ValidatorParticipationAggCircuitTargets,

    validators_state_verifier: VerifierOnlyCircuitData<Config, D>,
}

impl ValidatorParticipationAggCircuit {
    pub fn generate_proof(&self, data: &ValidatorParticipationAggCircuitData) -> Result<ValidatorParticipationAggProof> {
        let pw = generate_partial_witness(
            &self.targets, 
            data, 
            &self.circuit_data, 
            &self.validators_state_verifier,
        )?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(ValidatorParticipationAggProof::new(proof))
    }
}

impl Circuit for ValidatorParticipationAggCircuit {
    type Proof = ValidatorParticipationAggProof;
    
    fn new() -> Self {
        let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
        let validators_state_common_data = &validators_state_circuit.circuit_data().common;
        let validators_state_verifier = validators_state_circuit.circuit_data().verifier_only.clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, validators_state_common_data);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets, validators_state_verifier }
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

impl Serializeable for ValidatorParticipationAggCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
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
        let validators_state_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;

        Ok(Self { 
            circuit_data, 
            targets, 
            validators_state_verifier, 
        })
    }
}
