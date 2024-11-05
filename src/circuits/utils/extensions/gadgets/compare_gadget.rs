use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::custom_ops::gates::CompareGate;
use crate::custom_ops::wires::compare_wires::CompareType;

pub trait CompareGadgetCircuitBuilder<F: RichField + Extendable<D>, const D: usize> {
    /// Compares a and b and returns if a < b (note: abs(a - b) must be less than 2^62)
    fn less_than_u62(&mut self, a: Target, b: Target) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CompareGadgetCircuitBuilder<F, D> for CircuitBuilder<F, D> {
    /// Compares a and b and returns if a < b (note: abs(a - b) must be less than 2^62)
    fn less_than_u62(&mut self, a: Target, b: Target) -> BoolTarget {
        let gate = CompareGate::new::<F, D>(&self.config, CompareType::LessThan, 62);
        let params = vec![F::from_canonical_usize(CompareType::LessThan as usize), F::from_canonical_usize(62)];
        let (row, i) = self.find_slot(gate.clone(), &params, &[]);

        let target_first_input = Target::wire(row, gate.comparison_ops[i].first_input_wire);
        let target_second_input = Target::wire(row, gate.comparison_ops[i].second_input_wire);

        self.connect(a, target_first_input);
        self.connect(b, target_second_input);

        BoolTarget::new_unsafe(Target::wire(row, gate.comparison_ops[i].result_bool_wire.unwrap()))
    }
}
