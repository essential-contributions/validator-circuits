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

use crate::custom_ops::wires::DivisionWires;

const U32_MAX: usize = u32::MAX as usize;

/// A gate for checking that one value is greater than or equal to another.
#[derive(Debug, Clone)]
pub struct DivisionU32ByU32Gate {
    pub num_ops: usize,
    pub division_ops: Vec<DivisionWires>,
}

impl DivisionU32ByU32Gate {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(config: &CircuitConfig) -> Self {
        let num_ops = Self::num_ops(config);
        let wires_per_op = DivisionWires::num_wires(U32_MAX, 1);
        let advice_wires_per_op = DivisionWires::num_advice_wires(U32_MAX, 1);
        let routed_wires_per_op = wires_per_op - advice_wires_per_op;
        let num_routed_wires: usize = routed_wires_per_op * num_ops;
        let division_ops = (0..num_ops)
            .map(|i| {
                let dividend_wire = routed_wires_per_op * i;
                let divisor_wire = (routed_wires_per_op * i) + 1;
                let quotient_wire = (routed_wires_per_op * i) + 2;
                let remainder_wire = (routed_wires_per_op * i) + 3;
                let advice_wires: Vec<usize> = (0..advice_wires_per_op).map(|j| num_routed_wires + (advice_wires_per_op * i) + j).collect();
                DivisionWires::new::<F, D>(dividend_wire, divisor_wire, quotient_wire, remainder_wire, &advice_wires, U32_MAX, (1, U32_MAX))
            })
            .collect();

        Self { num_ops, division_ops }
    }

    pub const fn num_ops(config: &CircuitConfig) -> usize {
        let wires_per_op = DivisionWires::num_wires(U32_MAX, 1);
        let routed_wires_per_op = wires_per_op - DivisionWires::num_advice_wires(U32_MAX, 1);
        let routed_size = config.num_routed_wires / routed_wires_per_op;
        let full_size = config.num_wires / wires_per_op;
        if routed_size < full_size {
            routed_size
        } else {
            full_size
        }
    }

    pub const fn num_wires(&self) -> usize {
        DivisionWires::num_wires(U32_MAX, 1) * self.num_ops
    }

    pub const fn num_constants(&self) -> usize {
        DivisionWires::num_constants() * self.num_ops
    }

    pub const fn degree(&self) -> usize {
        DivisionWires::degree()
    }

    pub const fn num_constraints(&self) -> usize {
        self.num_ops * DivisionWires::num_constraints(U32_MAX, 1)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for DivisionU32ByU32Gate {
    fn id(&self) -> String {
        format!("DivisionU32ByU32Gate {{ num_ops: {} }}", self.num_ops)
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.num_ops)?;
        for op in &self.division_ops {
            op.serialize(dst)?;
        }
        Ok(())
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let num_ops = src.read_usize()?;
        let mut division_ops = Vec::with_capacity(num_ops);
        for _ in 0..num_ops {
            division_ops.push(DivisionWires::deserialize(src)?);
        }
        Ok(Self { division_ops, num_ops })
    }

    //note: runs during verification
    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = Vec::with_capacity(self.num_constraints());
        for division_wires in &self.division_ops {
            constraints.extend(division_wires.eval_unfiltered(vars));
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
        for division_wires in &self.division_ops {
            constraints.extend(division_wires.eval_unfiltered_circuit(builder, vars));
        }
        constraints
    }

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<WitnessGeneratorRef<F, D>> {
        (0..self.num_ops)
            .map(|i| {
                WitnessGeneratorRef::new(
                    DivisionU32ByU32Generator {
                        row,
                        division_wires: self.division_ops[i].clone(),
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

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D> for DivisionU32ByU32Gate {
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(&self, vars: EvaluationVarsBasePacked<P>, mut yield_constr: StridedConstraintConsumer<P>) {
        for division_wires in &self.division_ops {
            division_wires.eval_unfiltered_base_packed(vars, &mut yield_constr);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DivisionU32ByU32Generator {
    row: usize,
    division_wires: DivisionWires,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for DivisionU32ByU32Generator {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn dependencies(&self) -> Vec<Target> {
        [self.division_wires.dividend_wire, self.division_wires.divisor_wire]
            .iter()
            .map(|&i| Target::wire(self.row, i))
            .collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        self.division_wires.run_generator(self.row, witness, out_buffer);
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.row)?;
        self.division_wires.serialize(dst)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let row = src.read_usize()?;
        let division_wires = DivisionWires::deserialize(src)?;
        Ok(Self { row, division_wires })
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
        test_low_degree::<F, _, D>(DivisionU32ByU32Gate::new::<F, D>(&config))
    }

    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        test_eval_fns::<F, C, _, D>(DivisionU32ByU32Gate::new::<F, D>(&config))
    }

    #[test]
    fn test_gate_constraint() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type FF = <C as GenericConfig<D>>::FE;

        // Returns the local wires for a comparison gate given the two inputs.
        let get_wires = |gate: &DivisionU32ByU32Gate, dividend: F, divisor: F| -> Vec<FF> {
            let mut wire_values: Vec<F> = vec![F::ZERO; gate.num_wires()];
            for division_wires in &gate.division_ops {
                division_wires.fill_test_wires::<F, D>(dividend, divisor, &mut wire_values);
            }

            wire_values.iter().map(|&x| x.into()).collect()
        };

        let mut rng = OsRng;
        let max: u64 = 1 << 32;
        let dividend_u64 = rng.gen_range(0..max);
        let divisor_u64 = {
            let mut val = rng.gen_range(0..max);
            while val > dividend_u64 {
                val = rng.gen_range(0..max);
            }
            val
        };

        let config = CircuitConfig::standard_recursion_config();
        let dividend = F::from_canonical_u64(dividend_u64);
        let divisor = F::from_canonical_u64(divisor_u64);

        let division_gate = DivisionU32ByU32Gate::new::<F, D>(&config);
        let division_gate_vars = EvaluationVars::<F, D> {
            local_constants: &[],
            local_wires: &get_wires(&division_gate, dividend, divisor)[..],
            public_inputs_hash: &HashOut::rand(),
        };
        assert!(
            division_gate.eval_unfiltered(division_gate_vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied."
        );
    }
}
