use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};

use crate::circuits::extensions::CircuitBuilderExtended;
use crate::participation::empty_participation_sub_root;
use crate::{Config, Field, Hash, AGGREGATION_STAGE2_SIZE, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, D};
use crate::circuits::serialization::{deserialize_circuit, read_verifier, serialize_circuit, write_verifier};
use super::{AttestationAggregatorFirstStageCircuit, AttestationAggregatorFirstStageProof, Circuit, Proof, Serializeable, PIS_AGG1_BLOCK_SLOT, PIS_AGG1_PARTICIPATION_COUNT, PIS_AGG1_PARTICIPATION_SUB_ROOT, PIS_AGG1_ATTESTATIONS_STAKE, PIS_AGG1_VALIDATORS_SUB_ROOT};

pub const PIS_AGG2_VALIDATORS_SUB_ROOT: [usize; 4] = [0, 1, 2, 3];
pub const PIS_AGG2_PARTICIPATION_SUB_ROOT: [usize; 4] = [4, 5, 6, 7];
pub const PIS_AGG2_PARTICIPATION_COUNT: usize = 8;
pub const PIS_AGG2_ATTESTATIONS_STAKE: usize = 9;
pub const PIS_AGG2_BLOCK_SLOT: usize = 10;

pub struct AttestationAggregatorSecondStageCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttAgg2Targets,

    atts_agg1_verifier: VerifierOnlyCircuitData<Config, D>,
}
struct AttAgg2Targets {
    block_slot: Target,
    atts_agg1_verifier: VerifierCircuitTarget,
    atts_agg1_data: Vec<AttAgg2Agg1Targets>,
}
struct AttAgg2Agg1Targets {
    validators_sub_root: HashOutTarget,
    has_participation: BoolTarget,
    proof: ProofWithPublicInputsTarget<D>
}
impl AttestationAggregatorSecondStageCircuit {
    pub fn from_subcircuits(atts_agg_first_stage_circuit: &AttestationAggregatorFirstStageCircuit) -> Self {
        let atts_agg1_common_data = &atts_agg_first_stage_circuit.circuit_data().common;
        let atts_agg1_verifier = atts_agg_first_stage_circuit.circuit_data().verifier_only.clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, atts_agg1_common_data);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets, atts_agg1_verifier }
    }

    pub fn generate_proof(&self, data: &AttestationAggregatorSecondStageData) -> Result<AttestationAggregatorSecondStageProof> {
        let pw = generate_partial_witness(&self.targets, data, &self.atts_agg1_verifier)?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationAggregatorSecondStageProof { proof })
    }
}
impl Circuit for AttestationAggregatorSecondStageCircuit {
    type Proof = AttestationAggregatorSecondStageProof;

    fn new() -> Self {
        let atts_agg_first_stage_circuit = AttestationAggregatorFirstStageCircuit::new();
        Self::from_subcircuits(&atts_agg_first_stage_circuit)
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        Ok(proof.proof.to_bytes())
    }

    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof> {
        let common_data = &self.circuit_data.common;
        let proof = ProofWithPublicInputs::<Field, Config, D>::from_bytes(bytes, common_data)?;
        Ok(Self::Proof { proof })
    }

    fn is_wrappable() -> bool {
        false
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        None
    }
}
impl Serializeable for AttestationAggregatorSecondStageCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        if write_verifier(&mut buffer, &self.atts_agg1_verifier).is_err() {
            return Err(anyhow!("Failed to serialize sub circuit verifier"));
        }
        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let (circuit_data, mut buffer) = deserialize_circuit(bytes)?;
        let targets = match read_targets(&mut buffer) {
            Ok(targets) => Ok(targets),
            Err(_) => Err(anyhow!("Failed to deserialize circuit targets")),
        }?;
        let atts_agg1_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        Ok(Self { circuit_data, targets, atts_agg1_verifier })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AttestationAggregatorSecondStageProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl AttestationAggregatorSecondStageProof {
    pub fn validators_sub_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[3]]]
    }

    pub fn participation_sub_root(&self) -> [Field; 4] {
        [self.proof.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[0]], 
        self.proof.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[1]], 
        self.proof.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[2]], 
        self.proof.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[3]]]
    }

    pub fn participation_count(&self) -> usize{
        self.proof.public_inputs[PIS_AGG2_PARTICIPATION_COUNT].to_canonical_u64() as usize
    }

    pub fn attestations_stake(&self) -> u64 {
        self.proof.public_inputs[PIS_AGG2_ATTESTATIONS_STAKE].to_canonical_u64()
    }

    pub fn block_slot(&self) -> usize{
        self.proof.public_inputs[PIS_AGG2_BLOCK_SLOT].to_canonical_u64() as usize
    }
}
impl Proof for AttestationAggregatorSecondStageProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(builder: &mut CircuitBuilder<Field, D>, atts_agg1_common_data: &CommonCircuitData<Field, D>) -> AttAgg2Targets {
    let mut atts_agg1_data: Vec<AttAgg2Agg1Targets> = Vec::new();

    // Global targets
    let empty_participation_root = build_empty_participation_sub_root(builder);
    let block_slot = builder.add_virtual_target();
    let mut attestations_stake = builder.zero();
    let mut participation_count = builder.zero();

    // Circuit target
    let atts_agg1_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(atts_agg1_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };

    // Verify each agg1 data
    let mut validator_nodes: Vec<HashOutTarget> = Vec::new();
    let mut participation_nodes: Vec<HashOutTarget> = Vec::new();
    for _ in 0..AGGREGATION_STAGE2_SIZE {
        let validators_sub_root = builder.add_virtual_hash();
        let has_participation = builder.add_virtual_bool_target_safe();
        let proof_target = builder.add_virtual_proof_with_pis(&atts_agg1_common_data);

        // Verify proof (ignored if not flagged as has participation)
        builder.verify_proof::<Config>(&proof_target, &atts_agg1_verifier, &atts_agg1_common_data);
        
        // Determine applicable validator node
        let proof_validators_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG1_VALIDATORS_SUB_ROOT[3]]
            ]
        };
        validator_nodes.push(builder.select_hash(has_participation, proof_validators_sub_root, validators_sub_root));

        // Determine applicable participation node
        let proof_participation_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG1_PARTICIPATION_SUB_ROOT[3]]
            ]
        };
        participation_nodes.push(builder.select_hash(has_participation, proof_participation_sub_root, empty_participation_root));

        // Make sure each agg1 data has the same block_slot
        builder.connect(proof_target.public_inputs[PIS_AGG1_BLOCK_SLOT], block_slot);

        // Keep running total of stake and num participants
        attestations_stake = builder.mul_add(has_participation.target, proof_target.public_inputs[PIS_AGG1_ATTESTATIONS_STAKE], attestations_stake);
        participation_count = builder.mul_add(has_participation.target, proof_target.public_inputs[PIS_AGG1_PARTICIPATION_COUNT], participation_count);

        atts_agg1_data.push(AttAgg2Agg1Targets {
            validators_sub_root,
            has_participation,
            proof: proof_target,
        });
    }

    // Compute the validators sub root
    for h in (0..AGGREGATION_STAGE2_SUB_TREE_HEIGHT).rev() {
        let start = validator_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [validator_nodes[start + (i * 2)].elements.to_vec(), validator_nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            validator_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let validators_sub_root = validator_nodes.last().unwrap();

    // Compute the participation sub root
    for h in (0..AGGREGATION_STAGE2_SUB_TREE_HEIGHT).rev() {
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
    builder.register_public_input(participation_count);
    builder.register_public_input(attestations_stake);
    builder.register_public_input(block_slot);

    AttAgg2Targets {
        block_slot,
        atts_agg1_verifier,
        atts_agg1_data,
    }
}

#[derive(Clone)]
pub struct AttestationAggregatorSecondStageData {
    pub block_slot: usize,
    pub agg1_data: Vec<AttestationAggregatorSecondStageAgg1Data>,
}
#[derive(Clone)]
pub struct AttestationAggregatorSecondStageAgg1Data {
    pub validators_sub_root: [Field; 4],
    pub agg1_proof: Option<AttestationAggregatorFirstStageProof>,
}

fn generate_partial_witness(targets: &AttAgg2Targets, data: &AttestationAggregatorSecondStageData, atts_agg1_verifier: &VerifierOnlyCircuitData<Config, D>) -> Result<PartialWitness<Field>> {
    if data.agg1_data.len() != AGGREGATION_STAGE2_SIZE {
        return Err(anyhow!("Must include {} datas in attestation aggregation second pass", AGGREGATION_STAGE2_SIZE));
    }

    //find a proof to use as a dummy proof
    let mut dummy_proof: Option<AttestationAggregatorFirstStageProof> = None;
    for d in &data.agg1_data {
        if d.agg1_proof.is_some() {
            dummy_proof = d.agg1_proof.clone();
            break;
        }
    }
    if dummy_proof.is_none() {
        return Err(anyhow!("Must include at least one valid proof in attestation aggregation second pass"));
    }
    let dummy_proof = dummy_proof.unwrap();

    //create partial witness
    let mut pw = PartialWitness::new();
    pw.set_target(targets.block_slot, Field::from_canonical_u64(data.block_slot as u64));
    pw.set_verifier_data_target(&targets.atts_agg1_verifier, &atts_agg1_verifier);

    for (t, v) in targets.atts_agg1_data.iter().zip(data.agg1_data.clone()) {
        let validators_sub_root: HashOut<Field> = HashOut::<Field> { elements: v.validators_sub_root };
        pw.set_hash_target(t.validators_sub_root, validators_sub_root);
        match v.agg1_proof {
            Some(proof) => {
                pw.set_bool_target(t.has_participation, true);
                pw.set_proof_with_pis_target(&t.proof, proof.proof());
            },
            None => {
                pw.set_bool_target(t.has_participation, false);
                pw.set_proof_with_pis_target(&t.proof, dummy_proof.proof());
            },
        }
    }

    Ok(pw)
}

#[inline]
fn write_targets(buffer: &mut Vec<u8>, targets: &AttAgg2Targets) -> IoResult<()> {
    buffer.write_target(targets.block_slot)?;
    buffer.write_target_verifier_circuit(&targets.atts_agg1_verifier)?;
    buffer.write_usize(targets.atts_agg1_data.len())?;
    for d in &targets.atts_agg1_data {
        buffer.write_target_hash(&d.validators_sub_root)?;
        buffer.write_target_bool(d.has_participation)?;
        buffer.write_target_proof_with_public_inputs(&d.proof)?;
    }

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<AttAgg2Targets> {
    let block_slot = buffer.read_target()?;
    let atts_agg1_verifier = buffer.read_target_verifier_circuit()?;
    let mut atts_agg1_data: Vec<AttAgg2Agg1Targets> = Vec::new();
    let atts_agg1_data_length = buffer.read_usize()?;
    for _ in 0..atts_agg1_data_length {
        let validators_sub_root = buffer.read_target_hash()?;
        let has_participation = buffer.read_target_bool()?;
        let proof = buffer.read_target_proof_with_public_inputs()?;
        atts_agg1_data.push(AttAgg2Agg1Targets {
            validators_sub_root,
            has_participation,
            proof,
        });
    }

    Ok(AttAgg2Targets {
        block_slot,
        atts_agg1_verifier,
        atts_agg1_data,
    })
}

fn build_empty_participation_sub_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_sub_root(0);
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}
