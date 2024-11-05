use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::gates::packed_util::PackedEvaluableBase;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGeneratorRef};
use plonky2::iop::target::Target;
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

use crate::custom_ops::wires::compare_wires::{CompareType, CompareWiresConfig};
use crate::custom_ops::wires::CompareWires;

/// A gate for checking that one value is greater than or equal to another.
#[derive(Debug, Clone)]
pub struct CompareGate {
    pub num_ops: usize,
    pub comparison_ops: Vec<CompareWires>,
    pub wires_config: CompareWiresConfig,
}

impl CompareGate {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(config: &CircuitConfig, compare_type: CompareType, max_diff_bits: usize) -> Self {
        let num_ops = Self::num_ops(config, max_diff_bits);
        let wires_per_op = CompareWires::num_wires(max_diff_bits, true);
        let advice_wires_per_op = CompareWires::num_advice_wires(max_diff_bits);
        let routed_wires_per_op = wires_per_op - advice_wires_per_op;
        let num_routed_wires: usize = routed_wires_per_op * num_ops;
        let wires_config = CompareWiresConfig::new(compare_type.clone(), max_diff_bits);
        let comparison_ops = (0..num_ops)
            .map(|i| {
                let first_input_wire = routed_wires_per_op * i;
                let second_input_wire = (routed_wires_per_op * i) + 1;
                let result_bool_wire = (routed_wires_per_op * i) + 2;
                let advice_wires: Vec<usize> = (0..advice_wires_per_op).map(|j| num_routed_wires + (advice_wires_per_op * i) + j).collect();
                CompareWires::new::<F, D>(
                    first_input_wire,
                    second_input_wire,
                    Some(result_bool_wire),
                    &advice_wires,
                    compare_type.clone(),
                    max_diff_bits,
                )
            })
            .collect();

        Self {
            num_ops,
            comparison_ops,
            wires_config,
        }
    }

    pub const fn num_ops(config: &CircuitConfig, max_diff_bits: usize) -> usize {
        let wires_per_op = CompareWires::num_wires(max_diff_bits, true);
        let routed_wires_per_op = wires_per_op - CompareWires::num_advice_wires(max_diff_bits);
        let routed_size = config.num_routed_wires / routed_wires_per_op;
        let full_size = config.num_wires / wires_per_op;
        if routed_size < full_size {
            routed_size
        } else {
            full_size
        }
    }

    pub const fn num_constraints(&self) -> usize {
        self.num_ops * CompareWires::num_constraints(self.wires_config.max_diff_bits, true)
    }

    pub const fn num_wires(&self) -> usize {
        CompareWires::num_wires(self.wires_config.max_diff_bits, true) * self.num_ops
    }

    pub const fn num_constants(&self) -> usize {
        CompareWires::num_constants() * self.num_ops
    }

    pub const fn degree(&self) -> usize {
        CompareWires::degree()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for CompareGate {
    fn id(&self) -> String {
        let less_than = self.wires_config.compare_type == CompareType::LessThan;
        let bits = self.wires_config.max_diff_bits;
        format!("CompareGate {{ num_ops: {}, less_than: {}, max_diff_bits: {} }}", self.num_ops, less_than, bits)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.num_ops)?;
        for op in &self.comparison_ops {
            op.serialize(dst)?;
        }
        Ok(())
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let num_ops = src.read_usize()?;
        let mut comparison_ops = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            comparison_ops.push(CompareWires::deserialize(src)?);
        }
        let wires_config = match comparison_ops.get(0) {
            Some(wires) => wires.config.clone(),
            None => CompareWiresConfig::default(),
        };
        Ok(Self {
            comparison_ops,
            num_ops,
            wires_config,
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
                    CompareGenerator {
                        row,
                        comparison_wires: self.comparison_ops[i].clone(),
                    }
                    .adapter(),
                )
            })
            .collect()
    }

    fn num_wires(&self) -> usize {
        self.num_wires()
    }

    fn num_constants(&self) -> usize {
        self.num_constants()
    }

    fn degree(&self) -> usize {
        self.degree()
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D> for CompareGate {
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(&self, vars: EvaluationVarsBasePacked<P>, mut yield_constr: StridedConstraintConsumer<P>) {
        for comparison_wires in &self.comparison_ops {
            comparison_wires.eval_unfiltered_base_packed(vars, &mut yield_constr);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CompareGenerator {
    row: usize,
    comparison_wires: CompareWires,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for CompareGenerator {
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
        let comparison_wires = CompareWires::deserialize(src)?;
        Ok(Self { row, comparison_wires })
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
        type F = GoldilocksField;

        let config = CircuitConfig::standard_recursion_config();
        test_low_degree::<F, _, D>(CompareGate::new::<F, D>(&config, CompareType::LessThan, 62));
        test_low_degree::<F, _, D>(CompareGate::new::<F, D>(&config, CompareType::GreaterThan, 62));
        test_low_degree::<F, _, D>(CompareGate::new::<F, D>(&config, CompareType::LessThanOrEqual, 62));
        test_low_degree::<F, _, D>(CompareGate::new::<F, D>(&config, CompareType::GreaterThanOrEqual, 62));
        test_low_degree::<F, _, D>(CompareGate::new::<F, D>(&config, CompareType::LessThan, 32));
        test_low_degree::<F, _, D>(CompareGate::new::<F, D>(&config, CompareType::GreaterThan, 32))
    }

    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        test_eval_fns::<F, C, _, D>(CompareGate::new::<F, D>(&config, CompareType::LessThan, 62))?;
        test_eval_fns::<F, C, _, D>(CompareGate::new::<F, D>(&config, CompareType::GreaterThan, 62))?;
        test_eval_fns::<F, C, _, D>(CompareGate::new::<F, D>(&config, CompareType::LessThanOrEqual, 62))?;
        test_eval_fns::<F, C, _, D>(CompareGate::new::<F, D>(&config, CompareType::GreaterThanOrEqual, 62))?;
        test_eval_fns::<F, C, _, D>(CompareGate::new::<F, D>(&config, CompareType::LessThan, 32))?;
        test_eval_fns::<F, C, _, D>(CompareGate::new::<F, D>(&config, CompareType::GreaterThan, 32))
    }

    #[test]
    fn test_gate_constraint() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type FF = <C as GenericConfig<D>>::FE;

        // Returns the local wires for a comparison gate given the two inputs.
        let get_wires = |gate: &CompareGate, first_input: F, second_input: F| -> Vec<FF> {
            let mut wire_values: Vec<F> = vec![F::ZERO; gate.num_wires()];
            for compare_wires in &gate.comparison_ops {
                compare_wires.fill_test_wires::<F, D>(first_input, second_input, &mut wire_values);
            }

            wire_values.iter().map(|&x| x.into()).collect()
        };

        let mut rng = OsRng;
        let max_bits_diff = 62;
        let max: u64 = 1 << max_bits_diff;
        let first_input_u64 = rng.gen_range(0..max);
        let second_input_u64 = {
            let mut val = rng.gen_range(0..max);
            while val < first_input_u64 {
                val = rng.gen_range(0..max);
            }
            val
        };

        let config = CircuitConfig::standard_recursion_config();
        let first_input = F::from_canonical_u64(first_input_u64);
        let second_input = F::from_canonical_u64(second_input_u64);

        let less_than_gate = CompareGate::new::<F, D>(&config, CompareType::LessThan, max_bits_diff);
        let less_than_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(&less_than_gate, first_input, second_input)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            less_than_gate.eval_unfiltered(less_than_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied (less than)."
        );

        let greater_than_gate = CompareGate::new::<F, D>(&config, CompareType::GreaterThan, max_bits_diff);
        let greater_than_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(&greater_than_gate, first_input, second_input)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            greater_than_gate.eval_unfiltered(greater_than_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied (greater than)."
        );

        let equal_gate = CompareGate::new::<F, D>(&config, CompareType::LessThan, max_bits_diff);
        let equal_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(&equal_gate, first_input, first_input)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            equal_gate.eval_unfiltered(equal_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied (equal)."
        );
    }
}
