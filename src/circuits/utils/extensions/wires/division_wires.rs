use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
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

use super::compare_wires::CompareType;
use super::{utils, CompareWires, RangeCheckWires};

//TODO: support using a constant divisor

/// A gate for computing integer based division.
/// note: the field size must be greater than quotient_max * divisor_max + (divisor_max - 1).
#[derive(Clone, Debug, Default)]
pub struct DivisionWires {
    pub dividend_wire: usize,
    pub divisor_wire: usize,
    pub quotient_wire: usize,
    pub remainder_wire: usize,
    pub adv_quotient_constrain_wires: RangeCheckWires,
    pub adv_remainder_constrain_wires: CompareWires,
    pub config: DivisionWiresConfig,
}
#[derive(Clone, Debug, Default)]
pub struct DivisionWiresConfig {
    pub num_constraints: usize,
}

impl DivisionWires {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        dividend_wire: usize,
        divisor_wire: usize,
        quotient_wire: usize,
        remainder_wire: usize,
        advice_wires: &[usize],
        dividend_max: usize,
        divisor_min_max: (usize, usize),
    ) -> Self {
        let range_bits = RangeCheckWires::min_range_bits(dividend_max / divisor_min_max.0);
        let adv_split = RangeCheckWires::num_advice_wires(range_bits);
        let adv_quotient_constrain_wires = RangeCheckWires::new::<F, D>(quotient_wire, &advice_wires[..adv_split], range_bits);
        let adv_remainder_constrain_wires = CompareWires::new::<F, D>(
            remainder_wire,
            divisor_wire,
            None,
            &advice_wires[adv_split..],
            CompareType::LessThan,
            range_bits,
        );

        //verify the field size is large enough to support the division
        let one = BigUint::from(1 as usize);
        let two = BigUint::from(2 as usize);
        let field_max = (F::ZERO - F::ONE).to_canonical_biguint();
        let quotient_max = two.pow(range_bits as u32) - one.clone();
        let divisor_max = BigUint::from(divisor_min_max.1);
        let constraint_max = (quotient_max * divisor_max) + (divisor_min_max.1 - one);
        assert!(
            field_max >= constraint_max,
            "Field size is too small to support division with [dividend_max: {}, divisor_min: {}, divisor_max: {}]",
            dividend_max,
            divisor_min_max.0,
            divisor_min_max.1,
        );

        Self {
            dividend_wire,
            divisor_wire,
            quotient_wire,
            remainder_wire,
            adv_quotient_constrain_wires,
            adv_remainder_constrain_wires,
            config: DivisionWiresConfig {
                num_constraints: Self::num_constraints(dividend_max, divisor_min_max.0),
            }
        }
    }

    pub const fn num_wires(dividend_max: usize, divisor_min: usize) -> usize {
        Self::num_advice_wires(dividend_max, divisor_min) + 4
    }

    pub const fn num_advice_wires(dividend_max: usize, divisor_min: usize) -> usize {
        let range_bits = RangeCheckWires::min_range_bits(dividend_max / divisor_min);
        RangeCheckWires::num_advice_wires(range_bits) + CompareWires::num_advice_wires(range_bits)
    }

    pub const fn num_constraints(dividend_max: usize, divisor_min: usize) -> usize {
        let range_bits = RangeCheckWires::min_range_bits(dividend_max / divisor_min);
        RangeCheckWires::num_constraints(range_bits) + CompareWires::num_constraints(range_bits, false) + 1
    }

    pub const fn num_constants() -> usize {
        RangeCheckWires::num_constants() + CompareWires::num_constants()
    }

    pub const fn degree() -> usize {
        let compare_degree = CompareWires::degree();
        let range_degree = RangeCheckWires::degree();
        if compare_degree > range_degree {
            compare_degree
        } else {
            range_degree
        }
    }

    pub fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_usize(self.dividend_wire)?;
        dst.write_usize(self.divisor_wire)?;
        dst.write_usize(self.quotient_wire)?;
        dst.write_usize(self.remainder_wire)?;
        dst.write_usize(self.config.num_constraints)?;
        self.adv_quotient_constrain_wires.serialize(dst)?;
        self.adv_remainder_constrain_wires.serialize(dst)
    }

    pub fn deserialize(src: &mut Buffer) -> IoResult<Self> {
        let dividend_wire = src.read_usize()?;
        let divisor_wire = src.read_usize()?;
        let quotient_wire = src.read_usize()?;
        let remainder_wire = src.read_usize()?;
        let num_constraints = src.read_usize()?;
        let adv_quotient_constrain_wires = RangeCheckWires::deserialize(src)?;
        let adv_remainder_constrain_wires = CompareWires::deserialize(src)?;

        Ok(Self {
            dividend_wire,
            divisor_wire,
            quotient_wire,
            remainder_wire,
            adv_quotient_constrain_wires,
            adv_remainder_constrain_wires,
            config: DivisionWiresConfig { num_constraints }
        })
    }

    //note: runs during verification
    pub fn eval_unfiltered<F: RichField + Extendable<D>, const D: usize>(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints: Vec<F::Extension> = Vec::with_capacity(self.config.num_constraints);
        
        //constrain the quotient range
        constraints.append(&mut self.adv_quotient_constrain_wires.eval_unfiltered(vars));

        //constrain the remainder to be less than the divisor
        constraints.append(&mut self.adv_remainder_constrain_wires.eval_unfiltered(vars));

        //constrain the reverse computation
        let dividend = vars.local_wires[self.dividend_wire];
        let divisor = vars.local_wires[self.divisor_wire];
        let quotient = vars.local_wires[self.quotient_wire];
        let remainder = vars.local_wires[self.remainder_wire];
        let computed_dividend = quotient * divisor + remainder;
        constraints.push(computed_dividend - dividend);

        constraints
    }

    //note: runs during proving
    pub fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        yield_constr: &mut StridedConstraintConsumer<P>,
    ) {
        //constrain the quotient range
        self.adv_quotient_constrain_wires.eval_unfiltered_base_packed(vars, yield_constr);

        //constrain the remainder to be less than the divisor
        self.adv_remainder_constrain_wires.eval_unfiltered_base_packed(vars, yield_constr);

        //constrain the reverse computation
        let dividend = vars.local_wires[self.dividend_wire];
        let divisor = vars.local_wires[self.divisor_wire];
        let quotient = vars.local_wires[self.quotient_wire];
        let remainder = vars.local_wires[self.remainder_wire];
        let computed_dividend = quotient * divisor + remainder;
        yield_constr.one(computed_dividend - dividend);
    }

    //note: runs during recursion (in circuit)
    pub fn eval_unfiltered_circuit<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        let mut constraints: Vec<ExtensionTarget<D>> = Vec::with_capacity(self.config.num_constraints);

        //constrain the quotient range
        constraints.append(&mut self.adv_quotient_constrain_wires.eval_unfiltered_circuit(builder, vars));

        //constrain the remainder to be less than the divisor
        constraints.append(&mut self.adv_remainder_constrain_wires.eval_unfiltered_circuit(builder, vars));

        //constrain the reverse computation
        let dividend = vars.local_wires[self.dividend_wire];
        let divisor = vars.local_wires[self.divisor_wire];
        let quotient = vars.local_wires[self.quotient_wire];
        let remainder = vars.local_wires[self.remainder_wire];
        let computed_dividend = builder.mul_add_extension(quotient, divisor, remainder);
        let constraint_diff = builder.sub_extension(computed_dividend, dividend);
        constraints.push(constraint_diff);

        constraints
    }

    //note: runs during witness generation
    pub fn run_generator<F: RichField + Extendable<D>, const D: usize>(&self, row: usize, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        //generate witness data for the quotient and remainder
        let dividend = utils::get_wire(row, self.dividend_wire, witness, out_buffer).to_canonical_u64();
        let divisor = utils::get_wire(row, self.divisor_wire, witness, out_buffer).to_canonical_u64();
        let quotient = dividend / divisor;
        let remainder = dividend % divisor;

        //set targets
        let quotient_target = Target::wire(row, self.quotient_wire);
        out_buffer.set_target(quotient_target, F::from_canonical_usize(quotient as usize));

        let remainder_target = Target::wire(row, self.remainder_wire);
        out_buffer.set_target(remainder_target, F::from_canonical_usize(remainder as usize));

        //generate witness data for the quotient range
        self.adv_quotient_constrain_wires.run_generator(row, witness, out_buffer);

        //generate witness data for the divisor and remainder comparison
        self.adv_remainder_constrain_wires.run_generator(row, witness, out_buffer);
    }

    //note: runs for testing
    #[cfg(test)]
    pub fn fill_test_wires<F: RichField + Extendable<D>, const D: usize>(&self, dividend: F, divisor: F, wire_values: &mut [F]) {
        let representative_map: Vec<usize> = (0..wire_values.len()).map(|i| i).collect();
        let mut witness = PartitionWitness::<F>::new(wire_values.len(), 1, &representative_map);
        let mut out_buffer = GeneratedValues::<F>::with_capacity(wire_values.len());

        wire_values[self.dividend_wire] = dividend;
        wire_values[self.divisor_wire] = divisor;
        utils::values_to_witness(wire_values, &mut witness);

        self.run_generator::<F, D>(0, &witness, &mut out_buffer);
        utils::output_to_values(&out_buffer, wire_values);
    }
}
