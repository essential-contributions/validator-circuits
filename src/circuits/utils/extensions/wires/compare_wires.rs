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

/// A gate for checking that one value is greater than or equal to another.
/// note: can compare any two values whose difference is less than 2^max_diff_bits.
/// note: the field size must be greater than 2^(max_diff_bits + 1).
#[derive(Clone, Debug, Default)]
pub struct CompareWires {
    pub first_input_wire: usize,
    pub second_input_wire: usize,
    pub result_bool_wire: Option<usize>,
    pub adv_diff_limb_wires: Vec<usize>,
    pub config: CompareWiresConfig,
}
#[derive(Clone, Debug, Default)]
pub struct CompareWiresConfig {
    pub compare_type: CompareType,
    pub max_diff_bits: usize,
    pub top_limb_bits: usize,
    pub num_limbs: usize,
}
#[derive(Clone, Debug, Default, PartialEq)]
pub enum CompareType {
    #[default]
    LessThan = 0,
    GreaterThan = 1,
    LessThanOrEqual = 2,
    GreaterThanOrEqual = 3,
}

impl CompareWires {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        first_input_wire: usize,
        second_input_wire: usize,
        result_bool_wire: Option<usize>,
        advice_wires: &[usize],
        compare_type: CompareType,
        max_diff_bits: usize,
    ) -> Self {
        let adv_diff_limb_wires = advice_wires.to_vec();
        let config = CompareWiresConfig::new(compare_type, max_diff_bits);

        //verify the field size is large enough to support the comparison
        let one = BigUint::from(1 as usize);
        let two = BigUint::from(2 as usize);
        let field_max = (F::ZERO - F::ONE).to_canonical_biguint();
        let constraint_max = (two.pow(max_diff_bits as u32) * two) - one;
        assert!(
            field_max >= constraint_max,
            "Field size is too small to support comparisons with [max_diff_bits: {}]",
            max_diff_bits,
        );

        Self {
            first_input_wire,
            second_input_wire,
            result_bool_wire,
            adv_diff_limb_wires,
            config,
        }
    }

    pub const fn num_wires(max_diff_bits: usize, has_result_wire: bool) -> usize {
        let routed_wires = 2 + if has_result_wire { 1 } else { 0 };
        Self::num_limbs(max_diff_bits) + routed_wires
    }

    pub const fn num_advice_wires(max_diff_bits: usize) -> usize {
        Self::num_limbs(max_diff_bits)
    }

    pub const fn num_constraints(max_diff_bits: usize, has_result_wire: bool) -> usize {
        let logic_constraints = 1 + if has_result_wire { 1 } else { 0 };
        Self::num_limbs(max_diff_bits) + logic_constraints
    }

    pub const fn num_constants() -> usize {
        0
    }

    pub const fn degree() -> usize {
        1 << LIMB_BITS
    }

    pub fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_usize(self.first_input_wire)?;
        dst.write_usize(self.second_input_wire)?;
        dst.write_bool(self.result_bool_wire.is_some())?;
        if self.result_bool_wire.is_some() {
            dst.write_usize(self.result_bool_wire.unwrap())?;
        }
        dst.write_usize_vec(&self.adv_diff_limb_wires)?;
        self.config.serialize(dst)
    }

    pub fn deserialize(src: &mut Buffer) -> IoResult<Self> {
        let first_input_wire = src.read_usize()?;
        let second_input_wire = src.read_usize()?;
        let result_bool_wire = if src.read_bool()? { Some(src.read_usize()?) } else { None };
        let adv_diff_limb_wires = src.read_usize_vec()?;
        let config = CompareWiresConfig::deserialize(src)?;
        Ok(Self {
            first_input_wire,
            second_input_wire,
            result_bool_wire,
            adv_diff_limb_wires,
            config,
        })
    }

    const fn num_limbs(max_diff_bits: usize) -> usize {
        (max_diff_bits + LIMB_BITS - 1) / LIMB_BITS
    }

    //note: runs during verification
    pub fn eval_unfiltered<F: RichField + Extendable<D>, const D: usize>(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let alpha0 = F::Extension::from_canonical_u64(1 << LIMB_BITS);
        let alpha1 = F::Extension::from_canonical_u64(1 << self.config.max_diff_bits);
        let num_constraints = Self::num_constraints(self.config.max_diff_bits, self.result_bool_wire.is_some());
        let mut constraints: Vec<F::Extension> = Vec::with_capacity(num_constraints);

        // range-check limbs of the diff
        let inputs_diff_limbs: Vec<F::Extension> = (0..self.config.num_limbs).map(|j| vars.local_wires[self.adv_diff_limb_wires[j]]).collect();
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

        // range-check the result bool
        let (result_bool, result_bool_inv) = match self.result_bool_wire {
            Some(result_bool_wire) => {
                let result_bool = vars.local_wires[result_bool_wire];
                let result_bool_inv = F::Extension::ONE - result_bool;
                constraints.push(result_bool * result_bool_inv);

                (result_bool, result_bool_inv)
            }
            None => (F::Extension::ONE, F::Extension::ZERO),
        };

        // determine how to constrain the inputs computed diff
        let first_input = vars.local_wires[self.first_input_wire];
        let second_input = vars.local_wires[self.second_input_wire];
        let (top_bit, computed_diff) = match self.config.compare_type {
            CompareType::LessThanOrEqual => {
                // Iff first <= second, the top (n + 1st) bit will be 1
                let computed_diff = (second_input - first_input) + alpha1;
                let top_bit = result_bool;
                (top_bit, computed_diff)
            }
            CompareType::GreaterThanOrEqual => {
                // Iff first >= second, the top (n + 1st) bit will be 1
                let computed_diff = (first_input - second_input) + alpha1;
                let top_bit = result_bool;
                (top_bit, computed_diff)
            }
            CompareType::GreaterThan => {
                // same computed_diff as LessThanOrEqual, but the top bit should be inverse to result
                let computed_diff = (second_input - first_input) + alpha1;
                let top_bit = result_bool_inv;
                (top_bit, computed_diff)
            }
            CompareType::LessThan => {
                // same computed_diff as GreaterThanOrEqual, but the top bit should be inverse to result
                let computed_diff = (first_input - second_input) + alpha1;
                let top_bit = result_bool_inv;
                (top_bit, computed_diff)
            }
        };

        // constrain the top bit and diff limbs
        let mut inputs_diff_limbs_combined = F::Extension::ZEROS;
        for j in 0..self.config.num_limbs {
            inputs_diff_limbs_combined = inputs_diff_limbs_combined * alpha0 + inputs_diff_limbs[j];
        }
        inputs_diff_limbs_combined += top_bit * alpha1;
        constraints.push(computed_diff - inputs_diff_limbs_combined);

        constraints
    }

    //note: runs during proving
    pub fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        yield_constr: &mut StridedConstraintConsumer<P>,
    ) {
        let alpha0 = F::from_canonical_u64(1 << LIMB_BITS);
        let alpha1 = F::from_canonical_u64(1 << self.config.max_diff_bits);

        // range-check limbs of the diff
        let inputs_diff_limbs: Vec<P> = (0..self.config.num_limbs).map(|j| vars.local_wires[self.adv_diff_limb_wires[j]]).collect();
        let product: P = (0..(1 << self.config.top_limb_bits))
            .map(|x| inputs_diff_limbs[0] - F::from_canonical_usize(x))
            .product();
        yield_constr.one(product);
        for j in 1..self.config.num_limbs {
            let product: P = (0..(1 << LIMB_BITS)).map(|x| inputs_diff_limbs[j] - F::from_canonical_usize(x)).product();
            yield_constr.one(product);
        }

        // range-check the result bool
        let (result_bool, result_bool_inv) = match self.result_bool_wire {
            Some(result_bool_wire) => {
                let result_bool = vars.local_wires[result_bool_wire];
                let result_bool_inv = P::ONES - result_bool;
                yield_constr.one(result_bool * result_bool_inv);

                (result_bool, result_bool_inv)
            }
            None => (P::ONES, P::ZEROS),
        };

        // determine how to constrain the inputs computed diff
        let first_input = vars.local_wires[self.first_input_wire];
        let second_input = vars.local_wires[self.second_input_wire];
        let (top_bit, computed_diff) = match self.config.compare_type {
            CompareType::LessThanOrEqual => {
                // Iff first <= second, the top (n + 1st) bit will be 1
                let computed_diff = (second_input - first_input) + alpha1;
                let top_bit = result_bool;
                (top_bit, computed_diff)
            }
            CompareType::GreaterThanOrEqual => {
                // Iff first >= second, the top (n + 1st) bit will be 1
                let computed_diff = (first_input - second_input) + alpha1;
                let top_bit = result_bool;
                (top_bit, computed_diff)
            }
            CompareType::GreaterThan => {
                // same computed_diff as LessThanOrEqual, but the top bit should be inverse to result
                let computed_diff = (second_input - first_input) + alpha1;
                let top_bit = result_bool_inv;
                (top_bit, computed_diff)
            }
            CompareType::LessThan => {
                // same computed_diff as GreaterThanOrEqual, but the top bit should be inverse to result
                let computed_diff = (first_input - second_input) + alpha1;
                let top_bit = result_bool_inv;
                (top_bit, computed_diff)
            }
        };

        // constrain the top bit and diff limbs
        let mut inputs_diff_limbs_combined = P::ZEROS;
        for j in 0..self.config.num_limbs {
            inputs_diff_limbs_combined = inputs_diff_limbs_combined * alpha0 + inputs_diff_limbs[j];
        }
        inputs_diff_limbs_combined += top_bit * alpha1;
        yield_constr.one(computed_diff - inputs_diff_limbs_combined);
    }

    //note: runs during recursion (in circuit)
    pub fn eval_unfiltered_circuit<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        let alpha0 = builder.constant_extension(F::Extension::from_canonical_u64(1 << LIMB_BITS));
        let alpha1 = builder.constant_extension(F::Extension::from_canonical_u64(1 << self.config.max_diff_bits));
        let zero = builder.zero_extension();
        let one = builder.one_extension();
        let num_constraints = Self::num_constraints(self.config.max_diff_bits, self.result_bool_wire.is_some());
        let mut constraints = Vec::with_capacity(num_constraints);

        // range-check limbs of the diff
        let inputs_diff_limbs: Vec<ExtensionTarget<D>> = (0..self.config.num_limbs).map(|j| vars.local_wires[self.adv_diff_limb_wires[j]]).collect();
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

        // range-check the result bool
        let (result_bool, result_bool_inv) = match self.result_bool_wire {
            Some(result_bool_wire) => {
                let result_bool = vars.local_wires[result_bool_wire];
                let result_bool_inv = builder.sub_extension(one, result_bool);
                constraints.push(builder.mul_extension(result_bool, result_bool_inv));

                (result_bool, result_bool_inv)
            }
            None => (builder.one_extension(), builder.zero_extension()),
        };

        // determine how to constrain the inputs computed diff
        let first_input = vars.local_wires[self.first_input_wire];
        let second_input = vars.local_wires[self.second_input_wire];
        let (top_bit, computed_diff) = match self.config.compare_type {
            CompareType::LessThanOrEqual => {
                // Iff first <= second, the top (n + 1st) bit will be 1
                let computed_diff = builder.sub_extension(second_input, first_input);
                let computed_diff = builder.add_extension(computed_diff, alpha1);
                let top_bit = result_bool;
                (top_bit, computed_diff)
            }
            CompareType::GreaterThanOrEqual => {
                // Iff first >= second, the top (n + 1st) bit will be 1
                let computed_diff = builder.sub_extension(first_input, second_input);
                let computed_diff = builder.add_extension(computed_diff, alpha1);
                let top_bit = result_bool;
                (top_bit, computed_diff)
            }
            CompareType::GreaterThan => {
                // same computed_diff as LessThanOrEqual, but the top bit should be inverse to result
                let computed_diff = builder.sub_extension(second_input, first_input);
                let computed_diff = builder.add_extension(computed_diff, alpha1);
                let top_bit = result_bool_inv;
                (top_bit, computed_diff)
            }
            CompareType::LessThan => {
                // same computed_diff as GreaterThanOrEqual, but the top bit should be inverse to result
                let computed_diff = builder.sub_extension(first_input, second_input);
                let computed_diff = builder.add_extension(computed_diff, alpha1);
                let top_bit = result_bool_inv;
                (top_bit, computed_diff)
            }
        };

        // constrain the top bit and diff limbs
        let mut inputs_diff_limbs_combined = zero;
        for j in 0..self.config.num_limbs {
            inputs_diff_limbs_combined = builder.mul_add_extension(inputs_diff_limbs_combined, alpha0, inputs_diff_limbs[j]);
        }
        inputs_diff_limbs_combined = builder.mul_add_extension(top_bit, alpha1, inputs_diff_limbs_combined);
        let constraint_diff = builder.sub_extension(computed_diff, inputs_diff_limbs_combined);
        constraints.push(constraint_diff);

        constraints
    }

    //note: runs during witness generation
    pub fn run_generator<F: RichField + Extendable<D>, const D: usize>(&self, row: usize, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let alpha0 = 1 << LIMB_BITS;
        let alpha1 = 1 << self.config.max_diff_bits;

        //compute result
        let first_input = utils::get_wire(row, self.first_input_wire, witness, out_buffer).to_canonical_u64();
        let second_input = utils::get_wire(row, self.second_input_wire, witness, out_buffer).to_canonical_u64();
        let result = match self.config.compare_type {
            CompareType::LessThan => first_input < second_input,
            CompareType::GreaterThan => first_input > second_input,
            CompareType::LessThanOrEqual => first_input <= second_input,
            CompareType::GreaterThanOrEqual => first_input >= second_input,
        };

        //compute limbs
        let mut computed_diff = match self.config.compare_type {
            CompareType::LessThanOrEqual => (second_input + alpha1) - first_input,
            CompareType::GreaterThanOrEqual => (first_input + alpha1) - second_input,
            CompareType::GreaterThan => (second_input + alpha1) - first_input,
            CompareType::LessThan => (first_input + alpha1) - second_input,
        };
        let mut limbs: Vec<u64> = Vec::with_capacity(self.config.num_limbs);
        for _ in 0..(self.config.num_limbs - 1) {
            limbs.push(computed_diff % alpha0);
            computed_diff /= alpha0;
        }
        limbs.push(computed_diff % (1 << self.config.top_limb_bits));
        limbs.reverse();

        //set targets
        if self.result_bool_wire.is_some() {
            let result_target = Target::wire(row, self.result_bool_wire.unwrap());
            out_buffer.set_target(result_target, F::from_bool(result));
        }
        for j in 0..self.config.num_limbs {
            let inputs_diff_limbs_target = Target::wire(row, self.adv_diff_limb_wires[j]);
            out_buffer.set_target(inputs_diff_limbs_target, F::from_canonical_u64(limbs[j]));
        }
    }

    //note: runs for testing
    #[cfg(test)]
    pub fn fill_test_wires<F: RichField + Extendable<D>, const D: usize>(&self, first_input: F, second_input: F, wire_values: &mut [F]) {
        let representative_map: Vec<usize> = (0..wire_values.len()).map(|i| i).collect();
        let mut witness = PartitionWitness::<F>::new(wire_values.len(), 1, &representative_map);
        let mut out_buffer = GeneratedValues::<F>::with_capacity(wire_values.len());

        wire_values[self.first_input_wire] = first_input;
        wire_values[self.second_input_wire] = second_input;
        utils::values_to_witness(wire_values, &mut witness);

        self.run_generator::<F, D>(0, &witness, &mut out_buffer);
        utils::output_to_values(&out_buffer, wire_values);
    }
}

impl CompareWiresConfig {
    pub const fn new(compare_type: CompareType, max_diff_bits: usize) -> CompareWiresConfig {
        let num_limbs = CompareWires::num_limbs(max_diff_bits);
        let top_limb_bits = max_diff_bits % LIMB_BITS;
        let top_limb_bits = if top_limb_bits == 0 { LIMB_BITS } else { top_limb_bits };
        CompareWiresConfig {
            compare_type,
            max_diff_bits,
            top_limb_bits,
            num_limbs,
        }
    }

    pub fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_usize(self.compare_type.clone() as usize)?;
        dst.write_usize(self.max_diff_bits)
    }

    pub fn deserialize(src: &mut Buffer) -> IoResult<Self> {
        let compare_type = match src.read_usize()? {
            0 => CompareType::LessThan,
            1 => CompareType::GreaterThan,
            2 => CompareType::LessThanOrEqual,
            3 => CompareType::GreaterThanOrEqual,
            _ => CompareType::LessThan,
        };
        let max_diff_bits = src.read_usize()?;
        Ok(Self::new(compare_type, max_diff_bits))
    }
}
