use std::{collections::HashSet, marker::PhantomData};
use plonky2::{
    field::extension::Extendable, gadgets::{
        arithmetic::EqualityGenerator, arithmetic_extension::QuotientGeneratorExtension, range_check::LowHighGenerator, split_base::BaseSumGenerator, split_join::WireSplitGenerator
    }, gates::{
        arithmetic_base::ArithmeticBaseGenerator, 
        arithmetic_extension::ArithmeticExtensionGenerator, 
        base_sum::BaseSplitGenerator, 
        coset_interpolation::InterpolationGenerator, 
        exponentiation::ExponentiationGenerator, 
        multiplication_extension::MulExtensionGenerator, 
        poseidon::PoseidonGenerator, 
        poseidon_mds::PoseidonMdsGenerator, 
        random_access::RandomAccessGenerator, 
        reducing::ReducingGenerator, 
        reducing_extension::ReducingGenerator as ReducingExtensionGenerator
    }, hash::hash_types::RichField, iop::generator::{
        ConstantGenerator, 
        RandomValueGenerator
    }, plonk::{
        circuit_data::{CircuitData, VerifierOnlyCircuitData}, 
        config::{
            AlgebraicHasher, 
            GenericConfig
        }
    }, recursion::dummy_circuit::DummyProofGenerator, util::serialization::{
        Buffer, DefaultGateSerializer, IoResult, Read, WitnessGeneratorSerializer, Write
    }
};
use plonky2::{get_generator_tag_impl, impl_generator_serializer, read_generator_impl};
use anyhow::anyhow;

use crate::{Config, Field, D};

#[derive(Default)]
pub struct CustomGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}
impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for CustomGeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        CustomGeneratorSerializer, 
        DummyProofGenerator<F, C, D>, 
        EqualityGenerator, 
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
        ConstantGenerator<F>,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingExtensionGenerator<D>,
        ReducingGenerator<D>,
        WireSplitGenerator
    }
}

pub fn serialize_circuit(circuit_data: &CircuitData<Field, Config, D>) -> anyhow::Result<Vec<u8>> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = CustomGeneratorSerializer::<Config, D>::default();
    let data_bytes = circuit_data.to_bytes(&gate_serializer, &generator_serializer);
    if data_bytes.is_err() {
        //get a list of the generators that might be missing
        let mut unique_generators = HashSet::new();
        for generator in &circuit_data.prover_only.generators {
            unique_generators.insert(generator.0.id());
        }
        let unique_vec: Vec<&str> = unique_generators.iter().map(|s| s.as_str()).collect();
        return Err(anyhow!("Failed to serialize circuit. Check that CustomGeneratorSerializer supports all of the following generators: {}", unique_vec.join(", ")));
    }

    Ok(data_bytes.unwrap())
}

pub fn deserialize_circuit(bytes: &Vec<u8>) -> anyhow::Result<(CircuitData<Field, Config, D>, Buffer)> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = CustomGeneratorSerializer::<Config, D>::default();

    let mut buffer = Buffer::new(bytes);
    let circuit_data = buffer.read_circuit_data::<Field, Config, D>(&gate_serializer, &generator_serializer);
    if circuit_data.is_err() {
        return Err(anyhow!("Failed to deserialize circuit. It may help to delete the circuit bins and have them be regenerated."));
    }

    Ok((circuit_data.unwrap(), buffer))
}

#[inline]
pub fn write_verifier(buffer: &mut Vec<u8>, verifier: &VerifierOnlyCircuitData<Config, D>) -> IoResult<()> {
    let bytes = verifier.to_bytes()?;
    buffer.write_usize(bytes.len())?;
    buffer.write_all(&bytes)?;

    Ok(())
}

#[inline]
pub fn read_verifier(buffer: &mut Buffer) -> IoResult<VerifierOnlyCircuitData<Config, D>> {
    let len = buffer.read_usize()?;
    let mut bytes = vec![0u8; len];
    buffer.read_exact(&mut bytes)?;

    VerifierOnlyCircuitData::<Config, D>::from_bytes(bytes)
}
