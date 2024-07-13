use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::Result;

use crate::{Config, Field, D};

use super::extensions::CircuitBuilderExtended;
use super::{Circuit, Proof};

const BYTE_SIZE: usize = 128;
const INPUT_ELEMENTS: usize = BYTE_SIZE / 4;

pub struct Sha256Circuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: Sha256CircuitTargets,
}
struct Sha256CircuitTargets {
    inputs: Vec<Target>,
}
impl Circuit for Sha256Circuit {
    type Data = Sha256CircuitData;
    type Proof = Sha256Proof;
    
    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof> {
        let pw = generate_partial_witness(&self.targets, data)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(Sha256Proof { proof })
    }

    fn example_proof(&self) -> Self::Proof {
        todo!();
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }
}

#[derive(Clone)]
pub struct Sha256Proof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl Sha256Proof {
    pub fn input(&self) -> [Field; INPUT_ELEMENTS] {
        let mut input = [Field::ZERO; INPUT_ELEMENTS];
        for i in 0..INPUT_ELEMENTS {
            input[i] = self.proof.public_inputs[i];
        }
        input
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for (i, chunk) in hash.chunks_mut(4).enumerate() {
            let word = self.proof.public_inputs[INPUT_ELEMENTS + i].to_canonical_u64() as u32;
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        hash
    }
}
impl Proof for Sha256Proof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>) -> Sha256CircuitTargets {
    let inputs = builder.add_virtual_targets(INPUT_ELEMENTS);
    for i in 0..INPUT_ELEMENTS {
        builder.register_public_input(inputs[i]);
    }

    let hash = builder.sha256_hash(inputs.clone());

    for i in 0..8 {
        builder.register_public_input(hash[i]);
    }

    Sha256CircuitTargets {
        inputs,
    }
}

#[derive(Clone)]
pub struct Sha256CircuitData {
    pub input: Vec<u8>,
}

fn generate_partial_witness(targets: &Sha256CircuitTargets, data: &Sha256CircuitData) -> Result<PartialWitness<Field>> {
    let mut pw = PartialWitness::new();
    data.input.chunks_exact(4).zip(targets.inputs.clone()).for_each(|(d, t)| {
        let chunk = ((d[0] as u32) << 24) | ((d[1] as u32) << 16) | ((d[2] as u32) << 8) | (d[3] as u32);
        pw.set_target(t, Field::from_canonical_u32(chunk));
    });

    Ok(pw)
}
