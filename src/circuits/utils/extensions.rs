use plonky2::field::types::Field as Plonky2_Field;
use plonky2::{
    gates::noop::NoopGate,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        merkle_proofs::MerkleProofTarget,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData},
        config::AlgebraicHasher,
    },
};

mod sha256;
use sha256::build_sha256_hash;

use crate::{Config, Field, D};

pub trait CircuitBuilderExtended {
    /// Computes the sha256 hash treating each target like a u32.
    fn sha256_hash(&mut self, inputs: Vec<Target>) -> Vec<Target>;

    /// Compresses the given u32 hash output into just 4 field elements.
    fn compress_hash(&mut self, u32_hash: Vec<Target>) -> HashOutTarget;

    /// Returns the big endian representation of the given target in u32s.
    fn to_u32s(&mut self, input: Target) -> Vec<Target>;

    /// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
    fn xor(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget;

    /// Computes the logical AND of the provided [`BoolTarget`]s.
    fn and_many(&mut self, b: &[BoolTarget]) -> BoolTarget;

    /// Checks whether `x` and `y` are equal and outputs the boolean result.
    fn is_equal_many(&mut self, x: &[Target], y: &[Target]) -> BoolTarget;

    /// Computes the arithmetic generalization of `x > y`
    fn greater_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget;

    /// Computes the arithmetic generalization of `x < y`
    fn less_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget;

    /// Asserts that `r` is equal to `x / y` rounded to the nearest whole number (0 if `y == 0`).
    fn div_round_down(&mut self, x: Target, y: Target, r: Target, num_bits: usize);

    /// Asserts that `r` is equal to `sqrt(x)` rounded to the nearest whole number.
    fn sqrt_round_down(&mut self, x: Target, r: Target, num_bits: usize);

    /// Selects `x` or `y` based on `b`, i.e., this returns `if b { x } else { y }`.
    fn select_hash(&mut self, b: BoolTarget, x: HashOutTarget, y: HashOutTarget) -> HashOutTarget;

    /// Selects between arrays `x` or `y` based on `b`, i.e., this returns `if b { x } else { y }`.
    fn select_many(&mut self, b: BoolTarget, x: &[Target], y: &[Target]) -> Vec<Target>;

    /// Uses Plonk's permutation argument to require that two series of elements be equal.
    fn connect_many(&mut self, x: &[Target], y: &[Target]);

    /// Asserts the provided [`BoolTarget`]s are true if `b` is also true.
    fn assert_true_if(&mut self, b: BoolTarget, a: &[BoolTarget]);

    /// Computes the new merkle root given new leaf data, index and previous proof with sibling data.
    fn merkle_root_from_prev_proof<H: AlgebraicHasher<Field>>(
        &mut self,
        new_leaf_data: Vec<Target>,
        leaf_index_bits: &[BoolTarget],
        proof: &MerkleProofTarget,
    ) -> HashOutTarget;

    /// Computes the new merkle root given two instances of new leaf data, indexes and previous proofs with sibling data.
    fn merkle_root_from_prev_two_proofs<H: AlgebraicHasher<Field>>(
        &mut self,
        new_leaf_data1: Vec<Target>,
        leaf_index_bits1: &[BoolTarget],
        proof1: &MerkleProofTarget,
        new_leaf_data2: Vec<Target>,
        leaf_index_bits2: &[BoolTarget],
        proof2: &MerkleProofTarget,
    ) -> HashOutTarget;
}
impl CircuitBuilderExtended for CircuitBuilder<Field, D> {
    fn sha256_hash(&mut self, inputs: Vec<Target>) -> Vec<Target> {
        build_sha256_hash(self, inputs)
    }

    fn to_u32s(&mut self, input: Target) -> Vec<Target> {
        let split = self.split_low_high(input, 32, 64);
        vec![split.1, split.0]
    }

    fn compress_hash(&mut self, u32_hash: Vec<Target>) -> HashOutTarget {
        debug_assert_eq!(u32_hash.len(), 8, "given u32_hash does not have 8 elements");
        let compressed: Vec<Target> = u32_hash
            .chunks(2)
            .map(|e| {
                let low_bits = self.split_le(e[1], 32);
                let high_bits = self.split_le(e[0], 32);

                let mut combined: Vec<BoolTarget> = Vec::new();
                combined.extend(&low_bits[0..32]);
                combined.extend(&high_bits[0..31]);

                self.le_sum(combined.into_iter())
            })
            .collect();

        HashOutTarget {
            elements: [compressed[0], compressed[1], compressed[2], compressed[3]],
        }
    }

    fn xor(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget {
        let zero = self.zero();
        let x_plus_y = self.add(x.target, y.target);
        let two_x_y = self.arithmetic(Field::TWO, Field::ZERO, x.target, y.target, zero);
        BoolTarget::new_unsafe(self.sub(x_plus_y, two_x_y))
    }

    fn and_many(&mut self, b: &[BoolTarget]) -> BoolTarget {
        let terms: Vec<Target> = b.iter().map(|b| b.target).collect();
        BoolTarget::new_unsafe(self.mul_many(terms))
    }

    fn is_equal_many(&mut self, x: &[Target], y: &[Target]) -> BoolTarget {
        debug_assert_eq!(x.len(), y.len(), "lengths do not match for is equal many");
        let one = self.one();
        BoolTarget::new_unsafe(x.iter().zip(y).fold(one, |acc, (x, y)| {
            let eq = self.is_equal(*x, *y);
            self.mul(acc, eq.target)
        }))
    }

    fn greater_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget {
        let or_equal_to = false;
        let x_bits = self.split_le(x, num_bits);
        let y_bits = self.split_le(y, num_bits);

        //starting with the smallest bit, compute `(x_bit & prev_bit_comp) | (x_bit & ~y_bit) | (prev_bit_comp & ~y_bit)`
        let mut previous_bit_comparison = self.constant_bool(or_equal_to);
        for i in 0..num_bits {
            let not_y_bit = self.not(y_bits[i]);
            let x_bit_and_prev_comp = self.and(x_bits[i], previous_bit_comparison);
            let x_bit_and_not_y_bit = self.and(x_bits[i], not_y_bit);
            let prev_comp_and_not_y_bit = self.and(previous_bit_comparison, not_y_bit);
            let x_bit_and_prev_comp_or_x_bit_and_not_y_bit = self.or(x_bit_and_prev_comp, x_bit_and_not_y_bit);
            previous_bit_comparison = self.or(x_bit_and_prev_comp_or_x_bit_and_not_y_bit, prev_comp_and_not_y_bit);
        }
        previous_bit_comparison
    }

    fn less_than(&mut self, x: Target, y: Target, num_bits: usize) -> BoolTarget {
        let or_equal_to = false;
        let x_bits = self.split_le(x, num_bits);
        let y_bits = self.split_le(y, num_bits);

        //starting with the smallest bit, compute `(y_bit & prev_bit_comp) | (y_bit & ~x_bit) | (prev_bit_comp & ~x_bit)`
        let mut previous_bit_comparison = self.constant_bool(or_equal_to);
        for i in 0..num_bits {
            let not_x_bit = self.not(x_bits[i]);
            let y_bit_and_prev_comp = self.and(y_bits[i], previous_bit_comparison);
            let y_bit_and_not_x_bit = self.and(y_bits[i], not_x_bit);
            let prev_comp_and_not_x_bit = self.and(previous_bit_comparison, not_x_bit);
            let y_bit_and_prev_comp_or_y_bit_and_not_x_bit = self.or(y_bit_and_prev_comp, y_bit_and_not_x_bit);
            previous_bit_comparison = self.or(y_bit_and_prev_comp_or_y_bit_and_not_x_bit, prev_comp_and_not_x_bit);
        }
        previous_bit_comparison
    }

    fn div_round_down(&mut self, x: Target, y: Target, r: Target, num_bits: usize) {
        let zero = self.zero();
        let one = self.one();

        let r2 = self.add(r, one);
        let low = self.mul(y, r);
        let high = self.mul(y, r2);
        let low_is_greater = self.greater_than(low, x, num_bits);
        let high_is_greater = self.greater_than(high, x, num_bits);

        let r_is_zero = self.is_equal(r, zero);
        let y_is_zero = self.is_equal(y, zero);
        let y_is_not_zero = self.not(y_is_zero);

        self.assert_zero(low_is_greater.target);
        self.assert_true_if(y_is_not_zero, &[high_is_greater]);
        self.assert_true_if(y_is_zero, &[r_is_zero]);
    }

    fn sqrt_round_down(&mut self, x: Target, r: Target, num_bits: usize) {
        let one = self.one();
        let r2 = self.add(r, one);
        let low = self.mul(r, r);
        let high = self.mul(r2, r2);
        let low_is_greater = self.greater_than(low, x, num_bits);
        let high_is_greater = self.greater_than(high, x, num_bits);

        self.assert_zero(low_is_greater.target);
        self.assert_one(high_is_greater.target);
    }

    fn select_hash(&mut self, b: BoolTarget, x: HashOutTarget, y: HashOutTarget) -> HashOutTarget {
        HashOutTarget {
            elements: core::array::from_fn(|i| self.select(b, x.elements[i], y.elements[i])),
        }
    }

    fn select_many(&mut self, b: BoolTarget, x: &[Target], y: &[Target]) -> Vec<Target> {
        debug_assert_eq!(x.len(), y.len(), "lengths do not match for select many");
        x.iter().zip(y).map(|(x, y)| self.select(b, *x, *y)).collect()
    }

    fn connect_many(&mut self, x: &[Target], y: &[Target]) {
        debug_assert_eq!(x.len(), y.len(), "lengths do not match for select many");
        for (x, y) in x.iter().zip(y) {
            self.connect(*x, *y);
        }
    }

    fn assert_true_if(&mut self, b: BoolTarget, a: &[BoolTarget]) {
        let not_b = self.not(b);
        let terms: Vec<Target> = a.iter().map(|a| a.target).collect();
        let terms_eval = BoolTarget::new_unsafe(self.mul_many(terms));
        let terms_eval_or_irrelevant = self.or(not_b, terms_eval);
        self.assert_one(terms_eval_or_irrelevant.target);
    }

    fn merkle_root_from_prev_proof<H: AlgebraicHasher<Field>>(
        &mut self,
        new_leaf_data: Vec<Target>,
        leaf_index_bits: &[BoolTarget],
        proof: &MerkleProofTarget,
    ) -> HashOutTarget {
        let mut state: HashOutTarget = self.hash_or_noop::<H>(new_leaf_data);
        for (&bit, &sibling) in leaf_index_bits.iter().zip(&proof.siblings) {
            let perm_inputs_a = [&state.elements[..], &sibling.elements[..]].concat();
            let perm_inputs_b = [&sibling.elements[..], &state.elements[..]].concat();
            let perm_inputs = self.select_many(bit, &perm_inputs_b, &perm_inputs_a);
            state = self.hash_n_to_hash_no_pad::<H>(perm_inputs);
        }
        state
    }

    fn merkle_root_from_prev_two_proofs<H: AlgebraicHasher<Field>>(
        &mut self,
        new_leaf_data1: Vec<Target>,
        leaf_index_bits1: &[BoolTarget],
        proof1: &MerkleProofTarget,
        new_leaf_data2: Vec<Target>,
        leaf_index_bits2: &[BoolTarget],
        proof2: &MerkleProofTarget,
    ) -> HashOutTarget {
        let len = leaf_index_bits1.len();
        debug_assert_eq!(
            leaf_index_bits1.len(),
            leaf_index_bits2.len(),
            "lengths do not match for merkle root from prev two proofs"
        );

        //find the bit index where the two proof siblings have the same parent
        let mut proof_siblings_have_same_parent: Vec<BoolTarget> = Vec::new();
        let mut eq = self.constant_bool(true);
        for i in (0..len).rev() {
            let x = self.xor(leaf_index_bits1[i], leaf_index_bits2[i]);
            let e = self.not(x);
            let eq2 = self.and(eq, e);
            proof_siblings_have_same_parent.push(self.xor(eq, eq2));
            eq = eq2;
        }
        proof_siblings_have_same_parent.reverse();

        //compute a new sibling trace using the first given data set
        let mut trace1: Vec<HashOutTarget> = Vec::new();
        let mut state1: HashOutTarget = self.hash_or_noop::<H>(new_leaf_data1);
        for (&bit, &sibling) in leaf_index_bits1.iter().zip(&proof1.siblings) {
            trace1.push(state1);
            let perm_inputs_a = [&state1.elements[..], &sibling.elements[..]].concat();
            let perm_inputs_b = [&sibling.elements[..], &state1.elements[..]].concat();
            let perm_inputs = self.select_many(bit, &perm_inputs_b, &perm_inputs_a);
            state1 = self.hash_n_to_hash_no_pad::<H>(perm_inputs);
        }

        //compute the new root using the second given data set (and the first trace when necessary)
        let mut state2: HashOutTarget = self.hash_or_noop::<H>(new_leaf_data2);
        for i in 0..len {
            let bit = leaf_index_bits2[i];
            let sibling = self.select_hash(proof_siblings_have_same_parent[i], trace1[i], proof2.siblings[i]);

            let perm_inputs_a = [&state2.elements[..], &sibling.elements[..]].concat();
            let perm_inputs_b = [&sibling.elements[..], &state2.elements[..]].concat();
            let perm_inputs = self.select_many(bit, &perm_inputs_b, &perm_inputs_a);
            state2 = self.hash_n_to_hash_no_pad::<H>(perm_inputs);
        }
        state2
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
