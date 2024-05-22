use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, Hasher as Plonky2_Hasher};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use anyhow::*;

use crate::{empty_agg2_participation_sub_root, AttestationsAggregator2Circuit, AttestationsAggregator2Proof, Config, Field, AGGREGATION_PASS3_SIZE, AGGREGATION_PASS3_SUB_TREE_HEIGHT, D, PIS_AGG2_BLOCK_SLOT, PIS_AGG2_NUM_PARTICIPANTS, PIS_AGG2_PARTICIPATION_SUB_ROOT, PIS_AGG2_TOTAL_STAKE, PIS_AGG2_VALIDATORS_SUB_ROOT};
use crate::Hash;

pub const VALIDATORS_TREE_AGG3_SUB_HEIGHT: usize = AGGREGATION_PASS3_SUB_TREE_HEIGHT;
pub const ATTESTATION_AGGREGATION_PASS3_SIZE: usize = AGGREGATION_PASS3_SIZE;
pub const PIS_AGG3_VALIDATORS_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_AGG3_PARTICIPATION_ROOT: [usize; 4] = [4, 5, 6, 7];
pub const PIS_AGG3_NUM_PARTICIPANTS: usize = 8;
pub const PIS_AGG3_BLOCK_SLOT: usize = 9;
pub const PIS_AGG3_TOTAL_STAKE: usize = 10;

pub struct AttestationsAggregator3Circuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttsAgg3Targets,
}
struct AttsAgg3Targets {
    block_slot: Target,
    atts_agg2_verifier: VerifierCircuitTarget,
    atts_agg2_data: Vec<AttsAgg3Agg2Targets>,
}
struct AttsAgg3Agg2Targets {
    validators_sub_root: HashOutTarget,
    has_participation: BoolTarget,
    proof: ProofWithPublicInputsTarget<D>
}

impl AttestationsAggregator3Circuit {
    pub fn new(atts_agg2_circuit: &AttestationsAggregator2Circuit) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, atts_agg2_circuit.circuit_data());
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets }
    }
    
    pub fn generate_proof(&self, data: &AttestationsAggregator3Data, atts_agg2_circuit: &AttestationsAggregator2Circuit) -> Result<AttestationsAggregator3Proof> {
        let pw = generate_partial_witness(&self.targets, data, atts_agg2_circuit.circuit_data())?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationsAggregator3Proof { proof })
    }

    pub fn verify_proof(&self, proof: &AttestationsAggregator3Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    pub fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }
}

#[derive(Clone)]
pub struct AttestationsAggregator3Proof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}

impl AttestationsAggregator3Proof {
    pub fn validators_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG3_VALIDATORS_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG3_VALIDATORS_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG3_VALIDATORS_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG3_VALIDATORS_ROOT[3]]]
    }

    pub fn participation_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG3_PARTICIPATION_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG3_PARTICIPATION_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG3_PARTICIPATION_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG3_PARTICIPATION_ROOT[3]]]
    }

    pub fn num_participants(&self) -> usize{
        self.proof.public_inputs[PIS_AGG3_NUM_PARTICIPANTS].to_canonical_u64() as usize
    }

    pub fn block_slot(&self) -> usize{
        self.proof.public_inputs[PIS_AGG3_BLOCK_SLOT].to_canonical_u64() as usize
    }

    pub fn total_stake(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG3_TOTAL_STAKE].to_canonical_u64()
    }

    pub fn raw_proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>, atts_agg2_circuit_data: &CircuitData<Field, Config, D>) -> AttsAgg3Targets {
    let mut atts_agg2_data: Vec<AttsAgg3Agg2Targets> = Vec::new();

    // Global targets
    let empty_participation_root = build_empty_participation_sub_root(builder);
    let block_slot = builder.add_virtual_target();
    let mut total_stake = builder.zero();
    let mut num_participants = builder.zero();

    // Circuit target
    let atts_agg2_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(atts_agg2_circuit_data.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };

    // Verify each agg2 data
    let mut validator_nodes: Vec<HashOutTarget> = Vec::new();
    let mut participation_nodes: Vec<HashOutTarget> = Vec::new();
    for _ in 0..ATTESTATION_AGGREGATION_PASS3_SIZE {
        let validators_sub_root = builder.add_virtual_hash();
        let has_participation = builder.add_virtual_bool_target_safe();
        let no_participation = builder.not(has_participation);
        let proof_target = builder.add_virtual_proof_with_pis(&atts_agg2_circuit_data.common);

        // Verify proof if has participation
        builder.verify_proof::<Config>(&proof_target, &atts_agg2_verifier, &atts_agg2_circuit_data.common);

        // Determine applicable validator node
        let maybe_pi_validators_root1 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[0]]);
        let maybe_pi_validators_root2 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[1]]);
        let maybe_pi_validators_root3 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[2]]);
        let maybe_pi_validators_root4 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[3]]);
        let validators_sub_root1 = builder.mul_add(no_participation.target, validators_sub_root.elements[0], maybe_pi_validators_root1);
        let validators_sub_root2 = builder.mul_add(no_participation.target, validators_sub_root.elements[1], maybe_pi_validators_root2);
        let validators_sub_root3 = builder.mul_add(no_participation.target, validators_sub_root.elements[2], maybe_pi_validators_root3);
        let validators_sub_root4 = builder.mul_add(no_participation.target, validators_sub_root.elements[3], maybe_pi_validators_root4);
        validator_nodes.push(HashOutTarget {
            elements: [validators_sub_root1, validators_sub_root2, validators_sub_root3, validators_sub_root4],
        });

        // Determine applicable participation node
        let maybe_pi_participation_root1 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[0]]);
        let maybe_pi_participation_root2 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[1]]);
        let maybe_pi_participation_root3 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[2]]);
        let maybe_pi_participation_root4 = builder.mul(has_participation.target, proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[3]]);
        let participation_sub_root1 = builder.mul_add(no_participation.target, empty_participation_root.elements[0], maybe_pi_participation_root1);
        let participation_sub_root2 = builder.mul_add(no_participation.target, empty_participation_root.elements[1], maybe_pi_participation_root2);
        let participation_sub_root3 = builder.mul_add(no_participation.target, empty_participation_root.elements[2], maybe_pi_participation_root3);
        let participation_sub_root4 = builder.mul_add(no_participation.target, empty_participation_root.elements[3], maybe_pi_participation_root4);
        participation_nodes.push(HashOutTarget {
            elements: [participation_sub_root1, participation_sub_root2, participation_sub_root3, participation_sub_root4],
        });

        // Make sure each agg2 data has the same block_slot
        builder.connect(proof_target.public_inputs[PIS_AGG2_BLOCK_SLOT], block_slot);

        // Keep running total of stake and num participants
        total_stake = builder.mul_add(has_participation.target, proof_target.public_inputs[PIS_AGG2_TOTAL_STAKE], total_stake);
        num_participants = builder.mul_add(has_participation.target, proof_target.public_inputs[PIS_AGG2_NUM_PARTICIPANTS], num_participants);

        atts_agg2_data.push(AttsAgg3Agg2Targets {
            validators_sub_root,
            has_participation,
            proof: proof_target,
        });
    }

    // Compute the validators sub root
    for h in (0..VALIDATORS_TREE_AGG3_SUB_HEIGHT).rev() {
        let start = validator_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [validator_nodes[start + (i * 2)].elements.to_vec(), validator_nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            validator_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let validators_sub_root = validator_nodes.last().unwrap();

    // Compute the participation sub root
    for h in (0..VALIDATORS_TREE_AGG3_SUB_HEIGHT).rev() {
        let start = participation_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [participation_nodes[start + (i * 2)].elements.to_vec(), participation_nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            participation_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let participation_root = participation_nodes.last().unwrap();

    // Register the public inputs
    builder.register_public_inputs(&validators_sub_root.elements);
    builder.register_public_inputs(&participation_root.elements);
    builder.register_public_input(num_participants);
    builder.register_public_input(block_slot);
    builder.register_public_input(total_stake);

    AttsAgg3Targets {
        block_slot,
        atts_agg2_verifier,
        atts_agg2_data,
    }
}

#[derive(Clone)]pub struct AttestationsAggregator3Data {
    pub block_slot: usize,
    pub agg2_data: Vec<AttestationsAggregator3Agg2Data>,
}
#[derive(Clone)]
pub struct AttestationsAggregator3Agg2Data {
    pub validators_sub_root: [Field; 4],
    pub agg2_proof: Option<AttestationsAggregator2Proof>,
}

fn generate_partial_witness(targets: &AttsAgg3Targets, data: &AttestationsAggregator3Data, atts_agg2_circuit_data: &CircuitData<Field, Config, D>) -> Result<PartialWitness<Field>> {
    if data.agg2_data.len() != ATTESTATION_AGGREGATION_PASS3_SIZE {
        return Err(anyhow!("Must include {} datas in attestation aggregation third pass", ATTESTATION_AGGREGATION_PASS3_SIZE));
    }

    //find a proof to use as a dummy proof
    let mut dummy_proof: Option<AttestationsAggregator2Proof> = None;
    for d in &data.agg2_data {
        if d.agg2_proof.is_some() {
            dummy_proof = d.agg2_proof.clone();
            break;
        }
    }
    if dummy_proof.is_none() {
        return Err(anyhow!("Must include at least one valid proof in attestation aggregation third pass"));
    }
    let dummy_proof = dummy_proof.unwrap();

    //create partial witness
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Plonky2_Field::from_canonical_u64(data.block_slot as u64));

    //TODO: the following can be replaced by: 
    //pw.set_verifier_data_target(&targets.atts_agg2_verifier, &atts_agg2_circuit_data.verifier_only);
    pw.set_cap_target(&targets.atts_agg2_verifier.constants_sigmas_cap, &atts_agg2_circuit_data.verifier_only.constants_sigmas_cap);
    pw.set_hash_target(targets.atts_agg2_verifier.circuit_digest.clone(), atts_agg2_circuit_data.verifier_only.circuit_digest);

    for (t, v) in targets.atts_agg2_data.iter().zip(data.agg2_data.clone()) {
        let validators_sub_root: HashOut<Field> = HashOut::<Field> { elements: v.validators_sub_root };
        pw.set_hash_target(t.validators_sub_root, validators_sub_root);
        match v.agg2_proof {
            Some(proof) => {
                pw.set_bool_target(t.has_participation, true);
                pw.set_proof_with_pis_target(&t.proof, proof.raw_proof());
            },
            None => {
                pw.set_bool_target(t.has_participation, false);
                pw.set_proof_with_pis_target(&t.proof, dummy_proof.raw_proof());
            },
        }
    }

    Ok(pw)
}

fn build_empty_participation_sub_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_agg3_participation_sub_root();
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}

pub fn empty_agg3_participation_sub_root() -> [Field; 4] {
    let mut node = empty_agg2_participation_sub_root();
    for _ in 0..VALIDATORS_TREE_AGG3_SUB_HEIGHT {
        node = field_hash_two(node.clone(), node.clone());
    }
    node
}

fn field_hash_two(left: [Field; 4], right: [Field; 4]) -> [Field; 4] {
    <Hash as Plonky2_Hasher<Field>>::two_to_one(HashOut {elements: left}, HashOut {elements: right}).elements
}
