use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::GeneratedValues;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartitionWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::vars::{EvaluationTargets, EvaluationVarsBasePacked};
use plonky2::util::serialization::{Read, Write};
use plonky2::{
    hash::hash_types::RichField,
    plonk::vars::EvaluationVars,
    util::serialization::{Buffer, IoResult},
};

use super::utils;

const LIMB_BITS: usize = 3;

/// A gate for checking that a value falls within a range.
/// note: checks ranges in powers of 2.
/// note: the field size must be greater than (2^range_bits - 1).
#[derive(Clone, Debug, Default)]
pub struct RangeCheckWires {
    pub input_wire: usize,
    pub adv_limb_wires: Vec<usize>,
    pub config: RangeCheckWiresConfig,
}
#[derive(Clone, Debug, Default)]
pub struct RangeCheckWiresConfig {
    pub range_bits: usize,
    pub top_limb_bits: usize,
    pub num_limbs: usize,
}

impl RangeCheckWires {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(input_wire: usize, advice_wires: &[usize], range_bits: usize) -> Self {
        let adv_limb_wires = advice_wires.to_vec();
        let config = RangeCheckWiresConfig::new(range_bits);

        //verify the field size is large enough to support the comparison
        let two = BigUint::from(2u32);
        let field_max = (F::ZERO - F::ONE).to_canonical_biguint();
        let constraint_max = two.pow(range_bits as u32);
        assert!(
            field_max >= constraint_max,
            "Field size is too small to support range check with range_bits: {}",
            range_bits,
        );

        Self {
            input_wire,
            adv_limb_wires,
            config,
        }
    }

    pub const fn min_range_bits(max_value: usize) -> usize {
        let mut range_bits = 0;
        let mut value = 1;
        while value < max_value {
            value <<= 1;
            range_bits += 1;
        }
        range_bits
    }

    pub const fn num_wires(range_bits: usize) -> usize {
        Self::num_limbs(range_bits) + 1
    }

    pub const fn num_advice_wires(range_bits: usize) -> usize {
        Self::num_limbs(range_bits)
    }

    pub const fn num_constraints(range_bits: usize) -> usize {
        Self::num_limbs(range_bits) + 1
    }

    pub const fn num_constants() -> usize {
        0
    }

    pub const fn degree() -> usize {
        1 << LIMB_BITS
    }

    pub fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_usize(self.input_wire)?;
        dst.write_usize_vec(&self.adv_limb_wires)?;
        self.config.serialize(dst)
    }

    pub fn deserialize(src: &mut Buffer) -> IoResult<Self> {
        let input_wire = src.read_usize()?;
        let adv_limb_wires = src.read_usize_vec()?;
        let config = RangeCheckWiresConfig::deserialize(src)?;
        Ok(Self {
            input_wire,
            adv_limb_wires,
            config,
        })
    }

    const fn num_limbs(range_bits: usize) -> usize {
        (range_bits + LIMB_BITS - 1) / LIMB_BITS
    }

    //note: runs during verification
    pub fn eval_unfiltered<F: RichField + Extendable<D>, const D: usize>(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let alpha0 = F::Extension::from_canonical_u64(1 << LIMB_BITS);
        let num_constraints = Self::num_constraints(self.config.range_bits);
        let mut constraints: Vec<F::Extension> = Vec::with_capacity(num_constraints);

        // range-check limbs
        let inputs_diff_limbs: Vec<F::Extension> = (0..self.config.num_limbs).map(|j| vars.local_wires[self.adv_limb_wires[j]]).collect();
        let product: F::Extension = (0..(1 << self.config.top_limb_bits))
            .map(|x| inputs_diff_limbs[0] - F::Extension::from_canonical_usize(x))
            .product();
        constraints.push(product);
        for j in 1..self.config.num_limbs {
            let product: F::Extension = (0..(1 << LIMB_BITS))
                .map(|x| inputs_diff_limbs[j] - F::Extension::from_canonical_usize(x))
                .product();
            constraints.push(product);
        }

        // constrain the limbs to the input
        let input = vars.local_wires[self.input_wire];
        let mut limbs_combined = F::Extension::ZEROS;
        for j in 0..self.config.num_limbs {
            limbs_combined = limbs_combined * alpha0 + inputs_diff_limbs[j];
        }
        constraints.push(input - limbs_combined);

        constraints
    }

    //note: runs during proving
    pub fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        yield_constr: &mut StridedConstraintConsumer<P>,
    ) {
        let alpha0 = F::from_canonical_u64(1 << LIMB_BITS);

        // range-check limbs
        let inputs_diff_limbs: Vec<P> = (0..self.config.num_limbs).map(|j| vars.local_wires[self.adv_limb_wires[j]]).collect();
        let product: P = (0..(1 << self.config.top_limb_bits))
            .map(|x| inputs_diff_limbs[0] - F::from_canonical_usize(x))
            .product();
        yield_constr.one(product);
        for j in 1..self.config.num_limbs {
            let product: P = (0..(1 << LIMB_BITS)).map(|x| inputs_diff_limbs[j] - F::from_canonical_usize(x)).product();
            yield_constr.one(product);
        }

        // constrain the limbs to the input
        let input = vars.local_wires[self.input_wire];
        let mut limbs_combined = P::ZEROS;
        for j in 0..self.config.num_limbs {
            limbs_combined = limbs_combined * alpha0 + inputs_diff_limbs[j];
        }
        yield_constr.one(input - limbs_combined);
    }

    //note: runs during recursion (in circuit)
    pub fn eval_unfiltered_circuit<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        let alpha0 = builder.constant_extension(F::Extension::from_canonical_u64(1 << LIMB_BITS));
        let zero = builder.zero_extension();
        let one = builder.one_extension();
        let num_constraints = Self::num_constraints(self.config.range_bits);
        let mut constraints = Vec::with_capacity(num_constraints);

        // range-check limbs
        let inputs_diff_limbs: Vec<ExtensionTarget<D>> = (0..self.config.num_limbs).map(|j| vars.local_wires[self.adv_limb_wires[j]]).collect();
        let mut product = one;
        for x in 0..(1 << self.config.top_limb_bits) {
            let x = builder.constant_extension(F::Extension::from_canonical_usize(x));
            let diff = builder.sub_extension(inputs_diff_limbs[0], x);
            product = builder.mul_extension(product, diff);
        }
        constraints.push(product);
        for j in 1..self.config.num_limbs {
            let mut product = one;
            for x in 0..(1 << LIMB_BITS) {
                let x = builder.constant_extension(F::Extension::from_canonical_usize(x));
                let diff = builder.sub_extension(inputs_diff_limbs[j], x);
                product = builder.mul_extension(product, diff);
            }
            constraints.push(product);
        }

        // constrain the limbs to the input
        let input = vars.local_wires[self.input_wire];
        let mut limbs_combined = zero;
        for j in 0..self.config.num_limbs {
            limbs_combined = builder.mul_add_extension(limbs_combined, alpha0, inputs_diff_limbs[j]);
        }
        let constraint_diff = builder.sub_extension(input, limbs_combined);
        constraints.push(constraint_diff);

        constraints
    }

    //note: runs during witness generation
    pub fn run_generator<F: RichField + Extendable<D>, const D: usize>(&self, row: usize, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let alpha0 = 1 << LIMB_BITS;
        let alpha1 = 1 << self.config.range_bits;

        //check result
        let input = utils::get_wire(row, self.input_wire, witness, out_buffer).to_canonical_u64();
        assert!(input < alpha1, "Input value is out of range: {}", input);

        //compute limbs
        let mut value = input;
        let mut limbs: Vec<u64> = Vec::with_capacity(self.config.num_limbs);
        for _ in 0..(self.config.num_limbs - 1) {
            limbs.push(value % alpha0);
            value /= alpha0;
        }
        limbs.push(value % (1 << self.config.top_limb_bits));
        limbs.reverse();

        //set targets
        for j in 0..self.config.num_limbs {
            let inputs_diff_limbs_target = Target::wire(row, self.adv_limb_wires[j]);
            out_buffer.set_target(inputs_diff_limbs_target, F::from_canonical_u64(limbs[j]));
        }
    }

    //note: runs for testing
    #[cfg(test)]
    pub fn fill_test_wires<F: RichField + Extendable<D>, const D: usize>(&self, input: F, wire_values: &mut [F]) {
        let representative_map: Vec<usize> = (0..wire_values.len()).map(|i| i).collect();
        let mut witness = PartitionWitness::<F>::new(wire_values.len(), 1, &representative_map);
        let mut out_buffer = GeneratedValues::<F>::with_capacity(wire_values.len());

        wire_values[self.input_wire] = input;
        utils::values_to_witness(wire_values, &mut witness);

        self.run_generator::<F, D>(0, &witness, &mut out_buffer);
        utils::output_to_values(&out_buffer, wire_values);
    }
}

impl RangeCheckWiresConfig {
    pub const fn new(range_bits: usize) -> RangeCheckWiresConfig {
        let num_limbs = RangeCheckWires::num_limbs(range_bits);
        let top_limb_bits = range_bits % LIMB_BITS;
        let top_limb_bits = if top_limb_bits == 0 { LIMB_BITS } else { top_limb_bits };
        RangeCheckWiresConfig {
            range_bits,
            top_limb_bits,
            num_limbs,
        }
    }

    pub fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_usize(self.range_bits)
    }

    pub fn deserialize(src: &mut Buffer) -> IoResult<Self> {
        let range_bits = src.read_usize()?;
        Ok(Self::new(range_bits))
    }
}
