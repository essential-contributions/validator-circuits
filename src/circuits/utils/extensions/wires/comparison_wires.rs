use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::GeneratedValues;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::vars::{EvaluationTargets, EvaluationVarsBasePacked};
use plonky2::util::serialization::{Read, Write};
use plonky2::{
    hash::hash_types::RichField,
    plonk::vars::EvaluationVars,
    util::serialization::{Buffer, IoResult},
};

const NUM_LIMBS: usize = 21;
const LIMB_BITS: usize = 3;
const TOP_LIMB_BITS: usize = 2;
const MAX_DIFF_BITS: usize = 62;

/// A gate for checking that one value is greater than or equal to another.
#[derive(Clone, Debug, Default)]
pub struct ComparisonWires {
    pub first_input_wire: usize,
    pub second_input_wire: usize,
    pub result_bool_wire: usize,
    pub inputs_diff_limbs_wire: [usize; NUM_LIMBS],
    pub less_than: bool,
}

impl ComparisonWires {
    pub const fn new(
        first_input_wire: usize,
        second_input_wire: usize,
        result_bool_wire: usize,
        inputs_diff_limbs_wire: [usize; NUM_LIMBS],
        less_than: bool,
    ) -> Self {
        Self {
            first_input_wire,
            second_input_wire,
            result_bool_wire,
            inputs_diff_limbs_wire,
            less_than,
        }
    }

    pub const fn num_wires() -> usize {
        24
    }

    pub const fn num_routed_wires() -> usize {
        3
    }

    pub const fn num_advice_wires() -> usize {
        Self::num_wires() - Self::num_routed_wires()
    }

    pub const fn num_constraints() -> usize {
        23
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
        dst.write_usize(self.result_bool_wire)?;
        dst.write_usize_vec(&self.inputs_diff_limbs_wire)?;
        dst.write_bool(self.less_than)
    }

    pub fn deserialize(src: &mut Buffer) -> IoResult<Self> {
        let first_input_wire = src.read_usize()?;
        let second_input_wire = src.read_usize()?;
        let result_bool_wire = src.read_usize()?;
        let inputs_diff_limbs_wire_vec = src.read_usize_vec()?;
        let less_than = src.read_bool()?;

        let mut inputs_diff_limbs_wire = [0; NUM_LIMBS];
        inputs_diff_limbs_wire.copy_from_slice(&inputs_diff_limbs_wire_vec);

        Ok(Self {
            first_input_wire,
            second_input_wire,
            result_bool_wire,
            inputs_diff_limbs_wire,
            less_than,
        })
    }

    //note: runs during verification
    pub fn eval_unfiltered<F: RichField + Extendable<D>, const D: usize>(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let alpha0 = F::Extension::from_canonical_u64(1 << LIMB_BITS);
        let alpha1 = F::Extension::from_canonical_u64(1 << MAX_DIFF_BITS);
        let mut constraints: Vec<F::Extension> = Vec::with_capacity(Self::num_constraints());

        // constrain the inputs diff
        let first_input = vars.local_wires[self.first_input_wire];
        let second_input = vars.local_wires[self.second_input_wire];
        let computed_diff = if self.less_than {
            (first_input - second_input) + alpha1
        } else {
            (second_input - first_input) + alpha1
        };

        // range-check limbs of the diff
        let inputs_diff_limbs: Vec<F::Extension> = (0..NUM_LIMBS).map(|j| vars.local_wires[self.inputs_diff_limbs_wire[j]]).collect();
        let product: F::Extension = (0..(1 << TOP_LIMB_BITS))
            .map(|x| inputs_diff_limbs[0] - F::Extension::from_canonical_usize(x))
            .product();
        constraints.push(product);
        for j in 1..NUM_LIMBS {
            let product: F::Extension = (0..(1 << LIMB_BITS))
                .map(|x| inputs_diff_limbs[j] - F::Extension::from_canonical_usize(x))
                .product();
            constraints.push(product);
        }

        // less_than: Iff first >= second, the top (n + 1st) bit will be 1 and result should be 0
        // greater_than: Iff first <= second, the top (n + 1st) bit will be 1 and result should be 0
        let result_bool = vars.local_wires[self.result_bool_wire];
        let result_bool_inv = F::Extension::ONE - result_bool;
        let top_bit = result_bool_inv;

        // range-check the result bool (and effectively the top bit too)
        constraints.push(result_bool * result_bool_inv);

        // make sure the top bit and diff limbs are consistent with the diff
        let mut inputs_diff_limbs_combined = F::Extension::ZEROS;
        for j in 0..NUM_LIMBS {
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
        let alpha1 = F::from_canonical_u64(1 << MAX_DIFF_BITS);

        // constrain the inputs diff
        let first_input = vars.local_wires[self.first_input_wire];
        let second_input = vars.local_wires[self.second_input_wire];
        let computed_diff = if self.less_than {
            (first_input - second_input) + alpha1
        } else {
            (second_input - first_input) + alpha1
        };

        // range-check limbs of the diff
        let inputs_diff_limbs: Vec<P> = (0..NUM_LIMBS).map(|j| vars.local_wires[self.inputs_diff_limbs_wire[j]]).collect();
        let product: P = (0..(1 << TOP_LIMB_BITS)).map(|x| inputs_diff_limbs[0] - F::from_canonical_usize(x)).product();
        yield_constr.one(product);
        for j in 1..NUM_LIMBS {
            let product: P = (0..(1 << LIMB_BITS)).map(|x| inputs_diff_limbs[j] - F::from_canonical_usize(x)).product();
            yield_constr.one(product);
        }

        // less_than: Iff first >= second, the top (n + 1st) bit will be 1 and result should be 0
        // greater_than: Iff first <= second, the top (n + 1st) bit will be 1 and result should be 0
        let result_bool = vars.local_wires[self.result_bool_wire];
        let result_bool_inv = P::ONES - result_bool;
        let top_bit = result_bool_inv;

        // range-check the result bool (and effectively the top bit too)
        yield_constr.one(result_bool * result_bool_inv);

        // make sure the top bit and diff limbs are consistent with the diff
        let mut inputs_diff_limbs_combined = P::ZEROS;
        for j in 0..NUM_LIMBS {
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
        let alpha1 = builder.constant_extension(F::Extension::from_canonical_u64(1 << MAX_DIFF_BITS));
        let zero = builder.zero_extension();
        let one = builder.one_extension();
        let mut constraints = Vec::with_capacity(Self::num_constraints());

        // constrain the inputs diff
        let first_input = vars.local_wires[self.first_input_wire];
        let second_input = vars.local_wires[self.second_input_wire];
        let computed_diff = if self.less_than {
            builder.sub_extension(first_input, second_input)
        } else {
            builder.sub_extension(second_input, first_input)
        };
        let computed_diff = builder.add_extension(computed_diff, alpha1);

        // range-check limbs of the diff
        let inputs_diff_limbs: Vec<ExtensionTarget<D>> = (0..NUM_LIMBS).map(|j| vars.local_wires[self.inputs_diff_limbs_wire[j]]).collect();
        let mut product = one;
        for x in 0..(1 << TOP_LIMB_BITS) {
            let x = builder.constant_extension(F::Extension::from_canonical_usize(x));
            let diff = builder.sub_extension(inputs_diff_limbs[0], x);
            product = builder.mul_extension(product, diff);
        }
        constraints.push(product);
        for j in 1..NUM_LIMBS {
            let mut product = one;
            for x in 0..(1 << LIMB_BITS) {
                let x = builder.constant_extension(F::Extension::from_canonical_usize(x));
                let diff = builder.sub_extension(inputs_diff_limbs[j], x);
                product = builder.mul_extension(product, diff);
            }
            constraints.push(product);
        }

        // less_than: Iff first >= second, the top (n + 1st) bit will be 1 and result should be 0
        // greater_than: Iff first <= second, the top (n + 1st) bit will be 1 and result should be 0
        let result_bool = vars.local_wires[self.result_bool_wire];
        let result_bool_inv = builder.sub_extension(one, result_bool);
        let top_bit = result_bool_inv;

        // range-check the result bool (and effectively the top bit too)
        constraints.push(builder.mul_extension(result_bool, result_bool_inv));

        // make sure the top bit and diff limbs are consistent with the diff
        let mut inputs_diff_limbs_combined = zero;
        for j in 0..NUM_LIMBS {
            inputs_diff_limbs_combined = builder.mul_add_extension(inputs_diff_limbs_combined, alpha0, inputs_diff_limbs[j]);
        }
        inputs_diff_limbs_combined = builder.mul_add_extension(top_bit, alpha1, inputs_diff_limbs_combined);
        let constraint_diff = builder.sub_extension(computed_diff, inputs_diff_limbs_combined);
        constraints.push(constraint_diff);

        constraints
    }

    //note: runs during witness generation
    pub fn run_generator<F: RichField + Extendable<D>, const D: usize>(&self, row: usize, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let get_wire = |wire: usize| -> F { witness.get_target(Target::wire(row, wire)) };

        let first_input = get_wire(self.first_input_wire).to_canonical_u64();
        let second_input = get_wire(self.second_input_wire).to_canonical_u64();
        let result = if self.less_than {
            first_input < second_input
        } else {
            first_input > second_input
        };
        let diff = if self.less_than {
            (first_input + (1 << MAX_DIFF_BITS)) - second_input
        } else {
            (second_input + (1 << MAX_DIFF_BITS)) - first_input
        };

        let mut limbs: Vec<u64> = Vec::with_capacity(NUM_LIMBS);
        let mut decomposing_diff = diff;
        for _ in 0..(NUM_LIMBS - 1) {
            limbs.push(decomposing_diff % (1 << LIMB_BITS));
            decomposing_diff /= 1 << LIMB_BITS;
        }
        limbs.push(decomposing_diff % (1 << TOP_LIMB_BITS));
        limbs.reverse();

        //set targets
        let result_target = Target::wire(row, self.result_bool_wire);
        out_buffer.set_target(result_target, F::from_canonical_usize(result as usize));

        for j in 0..NUM_LIMBS {
            let inputs_diff_limbs_target = Target::wire(row, self.inputs_diff_limbs_wire[j]);
            out_buffer.set_target(inputs_diff_limbs_target, F::from_canonical_u64(limbs[j]));
        }
    }

    //note: runs for testing
    #[cfg(test)]
    pub fn get_wires<F: RichField + Extendable<D>, const D: usize>(first_input: F, second_input: F, less_than: bool) -> (Vec<F>, Vec<F>) {
        let mut routed_wires = Vec::new();
        let mut advice_wires = Vec::new();

        let first_input_u64 = first_input.to_canonical_u64();
        let second_input_u64 = second_input.to_canonical_u64();

        let result_bool = if less_than {
            F::from_bool(first_input_u64 < second_input_u64)
        } else {
            F::from_bool(first_input_u64 > second_input_u64)
        };

        routed_wires.push(first_input);
        routed_wires.push(second_input);
        routed_wires.push(result_bool);

        let mut inputs_diff_limbs: Vec<F> = Vec::with_capacity(NUM_LIMBS);
        let mut decomposing_diff = if less_than {
            (first_input_u64 + (1 << MAX_DIFF_BITS)) - second_input_u64
        } else {
            (second_input_u64 + (1 << MAX_DIFF_BITS)) - first_input_u64
        };
        for _ in 0..(NUM_LIMBS - 1) {
            inputs_diff_limbs.push(F::from_canonical_u64(decomposing_diff % (1 << LIMB_BITS)));
            decomposing_diff /= 1 << LIMB_BITS;
        }
        inputs_diff_limbs.push(F::from_canonical_u64(decomposing_diff % (1 << TOP_LIMB_BITS)));
        inputs_diff_limbs.reverse();

        advice_wires.append(&mut inputs_diff_limbs);

        (routed_wires, advice_wires)
    }
}
