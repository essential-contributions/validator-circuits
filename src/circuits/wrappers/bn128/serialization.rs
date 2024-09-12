use anyhow::anyhow;
use plonky2::{
    field::extension::Extendable,
    gadgets::{arithmetic_extension::QuotientGeneratorExtension, split_join::WireSplitGenerator},
    gates::{
        arithmetic_base::ArithmeticBaseGenerator,
        arithmetic_extension::ArithmeticExtensionGenerator, base_sum::BaseSplitGenerator,
        coset_interpolation::InterpolationGenerator, exponentiation::ExponentiationGenerator,
        multiplication_extension::MulExtensionGenerator, poseidon::PoseidonGenerator,
        poseidon_mds::PoseidonMdsGenerator, random_access::RandomAccessGenerator,
        reducing::ReducingGenerator,
        reducing_extension::ReducingGenerator as ReducingExtensionGenerator,
    },
    hash::hash_types::RichField,
    iop::generator::{ConstantGenerator, RandomValueGenerator},
    plonk::{
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::serialization::{Buffer, DefaultGateSerializer, Read, WitnessGeneratorSerializer},
};
use plonky2::{get_generator_tag_impl, impl_generator_serializer, read_generator_impl};
use std::{collections::HashSet, marker::PhantomData};

use crate::{Config, Field, D};

use super::PoseidonBN128GoldilocksConfig;

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
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        ConstantGenerator<F>,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
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

pub fn serialize_circuit(
    circuit_data: &CircuitData<Field, PoseidonBN128GoldilocksConfig, D>,
) -> anyhow::Result<Vec<u8>> {
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

pub fn deserialize_circuit(
    bytes: &Vec<u8>,
) -> anyhow::Result<(CircuitData<Field, PoseidonBN128GoldilocksConfig, D>, Buffer)> {
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = CustomGeneratorSerializer::<Config, D>::default();

    let mut buffer = Buffer::new(bytes);
    let circuit_data = buffer.read_circuit_data::<Field, PoseidonBN128GoldilocksConfig, D>(
        &gate_serializer,
        &generator_serializer,
    );
    if circuit_data.is_err() {
        return Err(anyhow!("Failed to deserialize circuit. It may help to delete the circuit bins and have them be regenerated."));
    }

    Ok((circuit_data.unwrap(), buffer))
}
