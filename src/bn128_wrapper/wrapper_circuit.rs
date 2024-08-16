use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use anyhow::{anyhow, Result};

use crate::{Config, Field, D};

use super::serialization::{deserialize_circuit, serialize_circuit};
use super::PoseidonBN128GoldilocksConfig;

pub struct BN128WrapperCircuit {
    circuit_data: CircuitData<Field, PoseidonBN128GoldilocksConfig, D>,
    targets: WrapperCircuitTargets,
}
struct WrapperCircuitTargets {
    verifier: VerifierCircuitTarget,
    proof: ProofWithPublicInputsTarget<D>,
}

impl BN128WrapperCircuit {
    pub fn new(inner_circuit: &CircuitData<Field, Config, D>) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<PoseidonBN128GoldilocksConfig as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, inner_circuit);
        let circuit_data = builder.build::<PoseidonBN128GoldilocksConfig>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, inner_circuit: &CircuitData<Field, Config, D>, inner_proof: &ProofWithPublicInputs<Field, Config, D>) -> Result<ProofWithPublicInputs<Field, PoseidonBN128GoldilocksConfig, D>> {
        let pw = generate_partial_witness(&self.targets, inner_proof, inner_circuit)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(proof)
    }

    pub fn verify_proof(&self, proof: &ProofWithPublicInputs<Field, PoseidonBN128GoldilocksConfig, D>) -> Result<()> {
        self.circuit_data.verify(proof.clone())
    }

    pub fn circuit_data(&self) -> &CircuitData<Field, PoseidonBN128GoldilocksConfig, D> {
        return &self.circuit_data;
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        Ok(buffer)
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = read_targets(&mut buffer);
        if targets.is_err() {
            return Err(anyhow!("Failed to deserialize circuit targets"));
        }
        Ok(Self { circuit_data, targets: targets.unwrap() })
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

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &WrapperCircuitTargets) -> IoResult<()> {
    buffer.write_target_verifier_circuit(&targets.verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.proof)?;
    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<WrapperCircuitTargets> {
    let verifier = buffer.read_target_verifier_circuit()?;
    let proof = buffer.read_target_proof_with_public_inputs()?;
    Ok(WrapperCircuitTargets {
        verifier,
        proof,
    })
}
