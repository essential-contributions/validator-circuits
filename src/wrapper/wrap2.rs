use anyhow::Result;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};

use crate::{ConfigBN128, Config, Field, D};

pub struct WrapperCircuit {
    circuit_data1: CircuitData<Field, Config, D>,
    circuit_data2: CircuitData<Field, ConfigBN128, D>,
    targets1: WrapperCircuitTargets,
    targets2: WrapperCircuitTargets,
}
struct WrapperCircuitTargets {
    verifier: VerifierCircuitTarget,
    proof: ProofWithPublicInputsTarget<D>,
}

impl WrapperCircuit {
    pub fn new(inner_circuit: &CircuitData<Field, Config, D>) -> Self {
        //let config = CircuitConfig::standard_recursion_config();
        let config = CircuitConfig {
            num_wires: 136,
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            zero_knowledge: false,
            max_quotient_degree_factor: 8,
            fri_config: FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
                num_query_rounds: 28,
            },
        };

        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config.clone());
        let targets1 = generate_circuit(&mut builder, inner_circuit);
        let circuit_data1 = builder.build::<Config>();
        
        let mut builder = CircuitBuilder::<<ConfigBN128 as GenericConfig<D>>::F, D>::new(config);
        let targets2 = generate_circuit(&mut builder, &circuit_data1);
        let circuit_data2 = builder.build::<ConfigBN128>();

        Self { circuit_data1, circuit_data2, targets1, targets2 }
    }
    
    pub fn generate_proof(&self, inner_circuit: &CircuitData<Field, Config, D>, inner_proof: &ProofWithPublicInputs<Field, Config, D>) -> Result<ProofWithPublicInputs<Field, ConfigBN128, D>> {
        let pw1 = generate_partial_witness(&self.targets1, inner_proof, inner_circuit)?;
        let proof1 = self.circuit_data1.prove(pw1)?;

        let pw2 = generate_partial_witness(&self.targets2, &proof1, &self.circuit_data1)?;
        let proof2 = self.circuit_data2.prove(pw2)?;

        Ok(proof2)
    }

    pub fn verify_proof(&self, proof: &ProofWithPublicInputs<Field, ConfigBN128, D>) -> Result<()> {
        self.circuit_data2.verify(proof.clone())
    }

    pub fn circuit_data(&self) -> &CircuitData<Field, ConfigBN128, D> {
        return &self.circuit_data2;
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
