use anyhow::Result;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};

use crate::{ConfigBN128, Config, Field, D};

pub struct WrapperCircuit {
    circuit_data: CircuitData<Field, ConfigBN128, D>,
    targets: WrapperCircuitTargets,
}
struct WrapperCircuitTargets {
    verifier: VerifierCircuitTarget,
    proof: ProofWithPublicInputsTarget<D>,
}

impl WrapperCircuit {
    pub fn new(inner_circuit: &CircuitData<Field, Config, D>) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<ConfigBN128 as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, inner_circuit);
        let circuit_data = builder.build::<ConfigBN128>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, inner_circuit: &CircuitData<Field, Config, D>, inner_proof: &ProofWithPublicInputs<Field, Config, D>) -> Result<ProofWithPublicInputs<Field, ConfigBN128, D>> {
        let pw = generate_partial_witness(&self.targets, inner_proof, inner_circuit)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(proof)
    }

    pub fn verify_proof(&self, proof: &ProofWithPublicInputs<Field, ConfigBN128, D>) -> Result<()> {
        self.circuit_data.verify(proof.clone())
    }

    pub fn circuit_data(&self) -> &CircuitData<Field, ConfigBN128, D> {
        return &self.circuit_data;
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>, inner_circuit: &CircuitData<Field, Config, D>) -> WrapperCircuitTargets {
    let inner_circuit_proof_target = builder.add_virtual_proof_with_pis(&inner_circuit.common);
    let inner_circuit_verifier_target = builder.constant_verifier_data(&inner_circuit.verifier_only);
    builder.verify_proof::<Config>(
        &inner_circuit_proof_target,
        &inner_circuit_verifier_target,
        &inner_circuit.common,
    );
    builder.register_public_inputs(&inner_circuit_proof_target.public_inputs);
    
    WrapperCircuitTargets{
        verifier: inner_circuit_verifier_target,
        proof: inner_circuit_proof_target,
    }
}

fn generate_partial_witness(targets: &WrapperCircuitTargets, inner_proof: &ProofWithPublicInputs<Field, Config, D>, inner_circuit: &CircuitData<Field, Config, D>) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();
    pw.set_verifier_data_target(&targets.verifier, &inner_circuit.verifier_only);
    pw.set_proof_with_pis_target(&targets.proof, inner_proof);

    Ok(pw)
}
