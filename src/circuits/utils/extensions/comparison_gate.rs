use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::gates::packed_util::PackedEvaluableBase;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGeneratorRef};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::PartitionWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::vars::{EvaluationTargets, EvaluationVarsBase, EvaluationVarsBaseBatch, EvaluationVarsBasePacked};
use plonky2::util::serialization::{Read, Write};
use plonky2::{
    gates::gate::Gate,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CircuitConfig, CommonCircuitData},
        vars::EvaluationVars,
    },
    util::serialization::{Buffer, IoResult},
};

use super::wires::ComparisonWires;

/// A gate for checking that one value is greater than or equal to another.
#[derive(Debug, Clone)]
pub struct ComparisonGate {
    pub num_ops: usize,
    pub comparison_ops: Vec<ComparisonWires>,
    pub less_than: bool,
}

impl ComparisonGate {
    pub fn new(config: &CircuitConfig, less_than: bool) -> Self {
        Self::from_num_ops(Self::num_ops(config), less_than)
    }

    pub fn from_num_ops(num_ops: usize, less_than: bool) -> Self {
        const NUM_ROUTED_WIRES_PER_OP: usize = ComparisonWires::num_routed_wires();
        const NUM_ADVICE_WIRES_PER_OP: usize = ComparisonWires::num_advice_wires();
        let num_routed_wires: usize = NUM_ROUTED_WIRES_PER_OP * num_ops;
        let comparison_ops = (0..num_ops)
            .map(|i| {
                let first_input_wire = NUM_ROUTED_WIRES_PER_OP * i;
                let second_input_wire = (NUM_ROUTED_WIRES_PER_OP * i) + 1;
                let result_bool_wire = (NUM_ROUTED_WIRES_PER_OP * i) + 2;
                let mut inputs_diff_limbs_wire = [0; 21];
                for j in 0..21 {
                    inputs_diff_limbs_wire[j] = num_routed_wires + (NUM_ADVICE_WIRES_PER_OP * i) + j;
                }
                ComparisonWires::new(first_input_wire, second_input_wire, result_bool_wire, inputs_diff_limbs_wire, less_than)
            })
            .collect();

        Self {
            num_ops,
            comparison_ops,
            less_than,
        }
    }

    pub const fn num_ops(config: &CircuitConfig) -> usize {
        let routed_size = config.num_routed_wires / ComparisonWires::num_routed_wires();
        let full_size = config.num_wires / ComparisonWires::num_wires();
        if routed_size < full_size {
            routed_size
        } else {
            full_size
        }
    }

    pub const fn num_constraints(&self) -> usize {
        self.num_ops * ComparisonWires::num_constraints()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for ComparisonGate {
    fn id(&self) -> String {
        format!("ComparisonGate {{ less_than: {} }}", self.less_than)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.num_ops)?;
        for op in &self.comparison_ops {
            op.serialize(dst)?;
        }
        dst.write_bool(self.less_than)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let num_ops = src.read_usize()?;
        let mut comparison_ops = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            comparison_ops.push(ComparisonWires::deserialize(src)?);
        }
        let less_than = src.read_bool()?;
        Ok(Self {
            comparison_ops,
            num_ops,
            less_than,
        })
    }

    //note: runs during verification
    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = Vec::with_capacity(self.num_constraints());
        for comparison_wires in &self.comparison_ops {
            constraints.extend(comparison_wires.eval_unfiltered(vars));
        }
        constraints
    }

    //note: runs during proving
    fn eval_unfiltered_base_one(&self, _vars: EvaluationVarsBase<F>, _yield_constr: StridedConstraintConsumer<F>) {
        panic!("use eval_unfiltered_base_packed instead");
    }

    //note: runs during proving
    fn eval_unfiltered_base_batch(&self, vars_base: EvaluationVarsBaseBatch<F>) -> Vec<F> {
        self.eval_unfiltered_base_batch_packed(vars_base)
    }

    //note: runs during recursion (in circuit)
    fn eval_unfiltered_circuit(&self, builder: &mut CircuitBuilder<F, D>, vars: EvaluationTargets<D>) -> Vec<ExtensionTarget<D>> {
        let mut constraints = Vec::with_capacity(self.num_constraints());
        for comparison_wires in &self.comparison_ops {
            constraints.extend(comparison_wires.eval_unfiltered_circuit(builder, vars));
        }
        constraints
    }

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<WitnessGeneratorRef<F, D>> {
        (0..self.num_ops)
            .map(|i| {
                WitnessGeneratorRef::new(
                    ComparisonGenerator {
                        row,
                        comparison_wires: self.comparison_ops[i].clone(),
                    }
                    .adapter(),
                )
            })
            .collect()
    }

    fn num_wires(&self) -> usize {
        ComparisonWires::num_wires() * self.num_ops
    }

    fn num_constants(&self) -> usize {
        ComparisonWires::num_constants() * self.num_ops
    }

    fn degree(&self) -> usize {
        ComparisonWires::degree()
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D> for ComparisonGate {
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(&self, vars: EvaluationVarsBasePacked<P>, mut yield_constr: StridedConstraintConsumer<P>) {
        for comparison_wires in &self.comparison_ops {
            comparison_wires.eval_unfiltered_base_packed(vars, &mut yield_constr);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ComparisonGenerator {
    row: usize,
    comparison_wires: ComparisonWires,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for ComparisonGenerator {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn dependencies(&self) -> Vec<Target> {
        [self.comparison_wires.first_input_wire, self.comparison_wires.second_input_wire]
            .iter()
            .map(|&i| Target::wire(self.row, i))
            .collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        self.comparison_wires.run_generator(self.row, witness, out_buffer);
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.row)?;
        self.comparison_wires.serialize(dst)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let row = src.read_usize()?;
        let comparison_wires = ComparisonWires::deserialize(src)?;
        Ok(Self { row, comparison_wires })
    }
}

pub trait ComparisonGateCircuitBuilder<F: RichField + Extendable<D>, const D: usize> {
    /// Compares a and b and returns if a < b (note: abs(b - a) must be less than 2^62)
    fn less_than(&mut self, a: Target, b: Target) -> BoolTarget;

    /// Compares a and b and returns if a > b (note: abs(b - a) must be less than 2^62)
    fn greater_than(&mut self, a: Target, b: Target) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> ComparisonGateCircuitBuilder<F, D> for CircuitBuilder<F, D> {
    /// Compares a and b and returns if a < b (note: abs(b - a) must be less than 2^62)
    fn less_than(&mut self, a: Target, b: Target) -> BoolTarget {
        const IS_LESS_THAN: bool = true;
        let gate = ComparisonGate::new(&self.config, IS_LESS_THAN);
        let params = vec![F::from_canonical_usize(IS_LESS_THAN as usize)];
        let (row, i) = self.find_slot(gate.clone(), &params, &[]);

        let target_first_input = Target::wire(row, gate.comparison_ops[i].first_input_wire);
        let target_second_input = Target::wire(row, gate.comparison_ops[i].second_input_wire);

        self.connect(a, target_first_input);
        self.connect(b, target_second_input);

        BoolTarget::new_unsafe(Target::wire(row, gate.comparison_ops[i].result_bool_wire))
    }

    /// Compares a and b and returns if a > b (note: abs(b - a) must be less than 2^62)
    fn greater_than(&mut self, a: Target, b: Target) -> BoolTarget {
        const IS_LESS_THAN: bool = false;
        let gate = ComparisonGate::new(&self.config, IS_LESS_THAN);
        let params = vec![F::from_canonical_usize(IS_LESS_THAN as usize)];
        let (row, i) = self.find_slot(gate.clone(), &params, &[]);

        let target_first_input = Target::wire(row, gate.comparison_ops[i].first_input_wire);
        let target_second_input = Target::wire(row, gate.comparison_ops[i].second_input_wire);

        self.connect(a, target_first_input);
        self.connect(b, target_second_input);

        BoolTarget::new_unsafe(Target::wire(row, gate.comparison_ops[i].result_bool_wire))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{Field, Sample};
    use plonky2::gates::gate_testing::{test_eval_fns, test_low_degree};
    use plonky2::hash::hash_types::HashOut;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::rngs::OsRng;
    use rand::Rng;

    use super::*;

    #[test]
    fn low_degree() {
        const D: usize = 4;
        let config = CircuitConfig::standard_recursion_config();
        test_low_degree::<GoldilocksField, _, D>(ComparisonGate::new(&config, true));
        test_low_degree::<GoldilocksField, _, D>(ComparisonGate::new(&config, false))
    }

    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        test_eval_fns::<F, C, _, D>(ComparisonGate::new(&config, true))?;
        test_eval_fns::<F, C, _, D>(ComparisonGate::new(&config, false))
    }

    #[test]
    fn test_gate_constraint() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type FF = <C as GenericConfig<D>>::FE;

        // Returns the local wires for a comparison gate given the two inputs.
        let get_wires = |first_input: F, second_input: F, less_than: bool, num_ops: usize| -> Vec<FF> {
            let mut routed_wires = Vec::new();
            let mut advice_wires = Vec::new();

            for _ in 0..num_ops {
                let (mut r, mut a) = ComparisonWires::get_wires::<F, D>(first_input, second_input, less_than);
                routed_wires.append(&mut r);
                advice_wires.append(&mut a);
            }

            let mut v = Vec::new();
            v.append(&mut routed_wires);
            v.append(&mut advice_wires);
            v.iter().map(|&x| x.into()).collect()
        };

        let config = CircuitConfig::standard_recursion_config();

        let mut rng = OsRng;
        let max: u64 = 1 << 62;
        let first_input_u64 = rng.gen_range(0..max);
        let second_input_u64 = {
            let mut val = rng.gen_range(0..max);
            while val < first_input_u64 {
                val = rng.gen_range(0..max);
            }
            val
        };

        let num_ops = ComparisonGate::num_ops(&config);
        let first_input = F::from_canonical_u64(first_input_u64);
        let second_input = F::from_canonical_u64(second_input_u64);

        let less_than_gate = ComparisonGate::new(&config, true);
        let less_than_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(first_input, second_input, true, num_ops)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            less_than_gate.eval_unfiltered(less_than_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied (less than)."
        );

        let greater_than_gate = ComparisonGate::new(&config, false);
        let greater_than_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(first_input, second_input, false, num_ops)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            greater_than_gate.eval_unfiltered(greater_than_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied (greater than)."
        );

        let equal_gate = ComparisonGate::new(&config, true);
        let equal_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(first_input, first_input, true, num_ops)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            equal_gate.eval_unfiltered(equal_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied (equal)."
        );
    }
}
