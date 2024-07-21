use plonky2::{gates::noop::NoopGate, hash::{hash_types::{HashOut, HashOutTarget}, merkle_proofs::MerkleProofTarget}, iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CommonCircuitData}}};
use plonky2::field::types::Field as Plonky2_Field;

mod sha256;
use sha256::build_sha256_hash;

use crate::{Config, Field, D};

pub trait CircuitBuilderExtended {
    /// Computes the sha256 hash treating each target like a u32.
    fn sha256_hash(&mut self, inputs: Vec<Target>) -> Vec<Target>;

    /// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
    fn xor(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget;

    /// Computes the arithmetic generalization of `x > y`
    //fn greater_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget;

    /// Computes the arithmetic generalization of `x < y`
    fn less_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget;

    /// Selects `x` or `y` based on `b`, i.e., this returns `if b { x } else { y }`.
    fn select_hash(&mut self, b: BoolTarget, x: HashOutTarget, y: HashOutTarget) -> HashOutTarget;

    /// Selects between arrays `x` or `y` based on `b`, i.e., this returns `if b { x } else { y }`.
    fn select_many(&mut self, b: BoolTarget, x: &[Target], y: &[Target]) -> Vec<Target>;
}
impl CircuitBuilderExtended for CircuitBuilder<Field, D> {
    fn sha256_hash(&mut self, inputs: Vec<Target>) -> Vec<Target> {
        build_sha256_hash(self, inputs)
    }

    fn xor(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget {
        let zero = self.zero();
        let x_plus_y = self.add(x.target, y.target);
        let two_x_y = self.arithmetic(Field::TWO, Field::ZERO, x.target, y.target, zero);
        BoolTarget::new_unsafe(self.sub(x_plus_y, two_x_y))
    }
/*
    fn greater_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget {
        let x_bits = self.split_le(x, num_bits);
        let y_bits = self.split_le(y, num_bits);

        //starting with the smallest bit, compute `!y_bit & (x_bit | previous_bit_comparison)`
        let mut previous_bit_comparison = self.constant_bool(false);
        for i in 0..num_bits {
            let x_bit_or_prev_comp = self.or(x_bits[i], previous_bit_comparison);
            let not_y_bit = self.not(y_bits[i]);
            previous_bit_comparison = self.and(not_y_bit, x_bit_or_prev_comp);
        }
        previous_bit_comparison
    }
*/
    fn less_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget {
        let x_bits = self.split_le(x, num_bits);
        let y_bits = self.split_le(y, num_bits);

        //starting with the smallest bit, compute `y_bit & (!x_bit | previous_bit_comparison)`
        let mut previous_bit_comparison = self.constant_bool(false);
        for i in 0..num_bits {
            let not_x_bit = self.not(x_bits[i]);
            let not_x_bit_or_prev_comp = self.or(not_x_bit, previous_bit_comparison);
            previous_bit_comparison = self.and(y_bits[i], not_x_bit_or_prev_comp);
        }
        previous_bit_comparison
    }

    fn select_hash(&mut self, b: BoolTarget, x: HashOutTarget, y: HashOutTarget) -> HashOutTarget {
        HashOutTarget {
            elements: core::array::from_fn(|i| self.select(b, x.elements[i], y.elements[i])),
        }
    }

    fn select_many(&mut self, b: BoolTarget, x: &[Target], y: &[Target]) -> Vec<Target> {
        debug_assert_eq!(x.len(), y.len(), "lengths do not match for select many");
        x.iter().zip(y).map(|(x, y)| {
            self.select(b, *x, *y)
        }).collect()
    }
}

pub trait PartialWitnessExtended {
    fn set_merkle_proof_target(&mut self, target: MerkleProofTarget, value: &[[Field; 4]]);
}
impl PartialWitnessExtended for PartialWitness<Field> {
    fn set_merkle_proof_target(&mut self, target: MerkleProofTarget, value: &[[Field; 4]]) {
        for (t, v) in target.siblings.iter().zip(value.iter()) {
            let hash: HashOut<Field> = HashOut::<Field> { elements: *v };
            self.set_hash_target(*t, hash);
        }
    }
}

pub fn common_data_for_recursion(max_gates: usize) -> CommonCircuitData<Field, D> {
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<Field, D>::new(config);
    let data = builder.build::<Config>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<Field, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<Config>(&proof, &verifier_data, &data.common);
    let data = builder.build::<Config>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<Field, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<Config>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < max_gates {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<Config>().common
}
