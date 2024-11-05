use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::custom_ops::gates::DivisionU32ByU32Gate;
use std::cell::RefCell;
use std::rc::Rc;
thread_local! {
    static DIV_U32_BY_U32_CALL_COUNT: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
}

pub trait DivisionGadgetCircuitBuilder<F: RichField + Extendable<D>, const D: usize> {
    /// Computes the integer based arithmetic generalization of `x / y` (unsafe if x >= 2^32 or y >= 2^32).
    fn div_u32_by_u32(&mut self, x: Target, y: Target) -> (Target, Target);

    /// Fills any unused division gates with dummy values (should be called once only and before building the circuit).
    fn fill_unused_division_gates(&mut self);
}

impl<F: RichField + Extendable<D>, const D: usize> DivisionGadgetCircuitBuilder<F, D> for CircuitBuilder<F, D> {
    /// Computes the integer based arithmetic generalization of `x / y` (unsafe if x >= 2^32 or y >= 2^32).
    fn div_u32_by_u32(&mut self, x: Target, y: Target) -> (Target, Target) {
        DIV_U32_BY_U32_CALL_COUNT.with(|count| {
            *count.borrow_mut() += 1;
        });

        let gate = DivisionU32ByU32Gate::new::<F, D>(&self.config);
        let (row, i) = self.find_slot(gate.clone(), &[], &[]);

        let dividend_input = Target::wire(row, gate.division_ops[i].dividend_wire);
        let divisor_input = Target::wire(row, gate.division_ops[i].divisor_wire);

        self.connect(x, dividend_input);
        self.connect(y, divisor_input);

        let quotient_output = Target::wire(row, gate.division_ops[i].quotient_wire);
        let remainder_output = Target::wire(row, gate.division_ops[i].remainder_wire);
        (quotient_output, remainder_output)
    }

    /// Fills any unused division gates with dummy values (should be called once only and before building the circuit).
    fn fill_unused_division_gates(&mut self) {
        let one = self.one();

        let div_u32_by_u32_call_count = DIV_U32_BY_U32_CALL_COUNT.with(|count| *count.borrow());
        let ops_per_gate = DivisionU32ByU32Gate::num_ops(&self.config);
        let empty_ops = ops_per_gate - (div_u32_by_u32_call_count % ops_per_gate);
        if empty_ops != ops_per_gate {
            for _ in 0..empty_ops {
                self.div_u32_by_u32(one, one);
            }
        }

        DIV_U32_BY_U32_CALL_COUNT.with(|count| {
            *count.borrow_mut() = 0;
        });
    }
}
