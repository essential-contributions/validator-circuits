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

    /// Selects `x` or `y` based on `b`, i.e., this returns `if b { x } else { y }`.
    fn select_hash(&mut self, b: BoolTarget, x: HashOutTarget, y: HashOutTarget) -> HashOutTarget;
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

    fn select_hash(&mut self, b: BoolTarget, x: HashOutTarget, y: HashOutTarget) -> HashOutTarget {
        HashOutTarget {
            elements: core::array::from_fn(|i| self.select(b, x.elements[i], y.elements[i])),
        }
    }
/*
    //TODO: make something like this
    fn select() {
        
        let maybe_skip_root1 = builder.mul(skip.target, skip_root.elements[0]);
        let maybe_skip_root2 = builder.mul(skip.target, skip_root.elements[1]);
        let maybe_skip_root3 = builder.mul(skip.target, skip_root.elements[2]);
        let maybe_skip_root4 = builder.mul(skip.target, skip_root.elements[3]);
        let root1 = builder.mul_add(not_skip.target, commitment_root.elements[0], maybe_skip_root1);
        let root2 = builder.mul_add(not_skip.target, commitment_root.elements[1], maybe_skip_root2);
        let root3 = builder.mul_add(not_skip.target, commitment_root.elements[2], maybe_skip_root3);
        let root4 = builder.mul_add(not_skip.target, commitment_root.elements[3], maybe_skip_root4);
        let merkle_root = HashOutTarget {
            elements: [root1, root2, root3, root4],
        };
    }
*/

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

pub fn common_data_for_recursion() -> CommonCircuitData<Field, D> {
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
    while builder.num_gates() < 1 << 12 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<Config>().common
}
