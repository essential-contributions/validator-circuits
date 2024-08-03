use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::field::types::{Field as Plonky2_Field, PrimeField64};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use anyhow::{anyhow, Result};

use crate::circuits::extensions::CircuitBuilderExtended;
use crate::circuits::{load_or_create_circuit, VALIDATORS_STATE_CIRCUIT_DIR};
use crate::circuits::validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateProof, PIS_VALIDATORS_STATE_INPUTS_HASH, PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT};
use crate::participation::empty_participation_sub_root;
use crate::{Config, Field, Hash, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, AGGREGATION_STAGE3_SIZE, AGGREGATION_STAGE3_SUB_TREE_HEIGHT, D};
use crate::circuits::serialization::{deserialize_circuit, read_verifier, serialize_circuit, write_verifier};
use super::{AttestationAggregatorSecondStageCircuit, AttestationAggregatorSecondStageProof, Circuit, Proof, Serializeable, PIS_AGG2_BLOCK_SLOT, PIS_AGG2_NUM_PARTICIPANTS, PIS_AGG2_PARTICIPATION_SUB_ROOT, PIS_AGG2_TOTAL_STAKE, PIS_AGG2_VALIDATORS_SUB_ROOT};

pub const PIS_VALIDATOR_INPUTS_HASH: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub const PIS_AGG3_PARTICIPATION_ROOT: [usize; 4] = [8, 9, 10, 11];
pub const PIS_AGG3_NUM_PARTICIPANTS: usize = 12;
pub const PIS_AGG3_BLOCK_SLOT: usize = 13;
pub const PIS_AGG3_TOTAL_STAKE: usize = 14;

pub struct AttestationAggregatorThirdStageCircuit {
    circuit_data: CircuitData<Field, Config, D>,
    targets: AttAgg3Targets,

    atts_agg2_verifier: VerifierOnlyCircuitData<Config, D>,
    validators_state_verifier: VerifierOnlyCircuitData<Config, D>,
}
struct AttAgg3Targets {
    block_slot: Target,
    validators_state_verifier: VerifierCircuitTarget,
    validators_state_proof: ProofWithPublicInputsTarget<D>,
    atts_agg2_verifier: VerifierCircuitTarget,
    atts_agg2_data: Vec<AttAgg3Agg2Targets>,
}
struct AttAgg3Agg2Targets {
    validators_sub_root: HashOutTarget,
    has_participation: BoolTarget,
    proof: ProofWithPublicInputsTarget<D>
}
impl AttestationAggregatorThirdStageCircuit {
    pub fn from_subcircuits(atts_agg_second_stage_circuit: &AttestationAggregatorSecondStageCircuit) -> Self {
        let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
        let validators_state_common_data = &validators_state_circuit.circuit_data().common;
        let validators_state_verifier = validators_state_circuit.circuit_data().verifier_only.clone();
        
        let atts_agg2_common_data = &atts_agg_second_stage_circuit.circuit_data().common;
        let atts_agg2_verifier = atts_agg_second_stage_circuit.circuit_data().verifier_only.clone();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<Config as GenericConfig<D>>::F, D>::new(config);
        let targets = generate_circuit(&mut builder, atts_agg2_common_data, validators_state_common_data);
        let circuit_data = builder.build::<Config>();

        Self { circuit_data, targets, atts_agg2_verifier, validators_state_verifier }
    }

    pub fn generate_proof(&self, data: &AttestationAggregatorThirdStageData) -> Result<AttestationAggregatorThirdStageProof> {
        let pw = generate_partial_witness(
            &self.targets,
            data,
            &self.atts_agg2_verifier,
            &self.validators_state_verifier,
        )?;
        let proof = self.circuit_data.prove(pw)?;
        Ok(AttestationAggregatorThirdStageProof { proof })
    }
}
impl Circuit for AttestationAggregatorThirdStageCircuit {
    type Proof = AttestationAggregatorThirdStageProof;

    fn new() -> Self {
        let atts_agg_second_stage_circuit = AttestationAggregatorSecondStageCircuit::new();
        Self::from_subcircuits(&atts_agg_second_stage_circuit)
    }

    fn verify_proof(&self, proof: &AttestationAggregatorThirdStageProof) -> Result<()> {
        self.circuit_data.verify(proof.proof.clone())
    }
    
    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.circuit_data;
    }

    fn is_wrappable() -> bool {
        false
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        None
    }
}
impl Serializeable for AttestationAggregatorThirdStageCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer = serialize_circuit(&self.circuit_data)?;
        if write_targets(&mut buffer, &self.targets).is_err() {
            return Err(anyhow!("Failed to serialize circuit targets"));
        }
        if write_verifier(&mut buffer, &self.atts_agg2_verifier).is_err() {
            return Err(anyhow!("Failed to serialize sub circuit verifier"));
        }
        if write_verifier(&mut buffer, &self.validators_state_verifier).is_err() {
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
        let atts_agg2_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        let validators_state_verifier = match read_verifier(&mut buffer) {
            Ok(verifier) => Ok(verifier),
            Err(_) => Err(anyhow!("Failed to deserialize sub circuit verifier")),
        }?;
        Ok(Self { circuit_data, targets, atts_agg2_verifier, validators_state_verifier })
    }
}

#[derive(Clone)]
pub struct AttestationAggregatorThirdStageProof {
    proof: ProofWithPublicInputs<Field, Config, D>,
}
impl AttestationAggregatorThirdStageProof {
    pub fn validator_inputs_hash(&self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes = (self.proof.public_inputs[PIS_VALIDATOR_INPUTS_HASH[i]].to_canonical_u64() as u32).to_be_bytes();
            hash[(i * 4)..((i * 4) + 4)].copy_from_slice(&bytes);
        }
        hash
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
}
impl Proof for AttestationAggregatorThirdStageProof {
    fn from_proof(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        Self { proof }
    }
    
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof
    }
}

fn generate_circuit(
    builder: &mut CircuitBuilder<Field, D>, 
    atts_agg2_common_data: &CommonCircuitData<Field, D>, 
    val_state_common_data: &CommonCircuitData<Field, D>
) -> AttAgg3Targets {
    let mut atts_agg2_data: Vec<AttAgg3Agg2Targets> = Vec::new();

    // Global targets
    let empty_participation_root = build_empty_participation_sub_root(builder);
    let block_slot = builder.add_virtual_target();
    let mut total_stake = builder.zero();
    let mut num_participants = builder.zero();

    // Circuit target
    let atts_agg2_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(atts_agg2_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    
    //Verify the validators state proof
    let validators_state_verifier = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(val_state_common_data.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let validators_state_proof = builder.add_virtual_proof_with_pis(val_state_common_data);
    builder.verify_proof::<Config>(&validators_state_proof, &validators_state_verifier, val_state_common_data);
    let validators_state_inputs_hash = vec![
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[0]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[1]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[2]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[3]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[4]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[5]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[6]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_INPUTS_HASH[7]],
    ];
    let validators_state_validators_tree_root = vec![
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[0]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[1]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[2]],
        validators_state_proof.public_inputs[PIS_VALIDATORS_STATE_VALIDATORS_TREE_ROOT[3]],
    ];

    // Verify each agg2 data
    let mut validator_nodes: Vec<HashOutTarget> = Vec::new();
    let mut participation_nodes: Vec<HashOutTarget> = Vec::new();
    for _ in 0..AGGREGATION_STAGE3_SIZE {
        let validators_sub_root = builder.add_virtual_hash();
        let has_participation = builder.add_virtual_bool_target_safe();
        let proof_target = builder.add_virtual_proof_with_pis(&atts_agg2_common_data);

        // Verify proof if has participation
        builder.verify_proof::<Config>(&proof_target, &atts_agg2_verifier, &atts_agg2_common_data);

        // Determine applicable validator node
        let proof_validators_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG2_VALIDATORS_SUB_ROOT[3]]
            ]
        };
        validator_nodes.push(builder.select_hash(has_participation, proof_validators_sub_root, validators_sub_root));

        // Determine applicable participation node
        let proof_participation_sub_root = HashOutTarget {
            elements: [
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[0]],
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[1]],
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[2]],
                proof_target.public_inputs[PIS_AGG2_PARTICIPATION_SUB_ROOT[3]]
            ]
        };
        participation_nodes.push(builder.select_hash(has_participation, proof_participation_sub_root, empty_participation_root));

        // Make sure each agg2 data has the same block_slot
        builder.connect(proof_target.public_inputs[PIS_AGG2_BLOCK_SLOT], block_slot);

        // Keep running total of stake and num participants
        total_stake = builder.mul_add(has_participation.target, proof_target.public_inputs[PIS_AGG2_TOTAL_STAKE], total_stake);
        num_participants = builder.mul_add(has_participation.target, proof_target.public_inputs[PIS_AGG2_NUM_PARTICIPANTS], num_participants);

        atts_agg2_data.push(AttAgg3Agg2Targets {
            validators_sub_root,
            has_participation,
            proof: proof_target,
        });
    }

    // Compute the validators sub root
    for h in (0..AGGREGATION_STAGE3_SUB_TREE_HEIGHT).rev() {
        let start = validator_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [validator_nodes[start + (i * 2)].elements.to_vec(), validator_nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            validator_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let validators_sub_root = validator_nodes.last().unwrap();

    // Connect the validators root to the root from the validators state proof
    for (&c, p) in validators_sub_root.elements.iter().zip(validators_state_validators_tree_root) {
        builder.connect(c, p);
    }

    // Compute the participation sub root
    for h in (0..AGGREGATION_STAGE3_SUB_TREE_HEIGHT).rev() {
        let start = participation_nodes.len() - (1 << (h + 1));
        for i in 0..(1 << h) {
            let data = [participation_nodes[start + (i * 2)].elements.to_vec(), participation_nodes[start + (i * 2) + 1].elements.to_vec()].concat();
            participation_nodes.push(builder.hash_n_to_hash_no_pad::<Hash>(data));
        }
    }
    let participation_root = participation_nodes.last().unwrap();

    // Register the public inputs
    builder.register_public_inputs(&validators_state_inputs_hash);
    builder.register_public_inputs(&participation_root.elements);
    builder.register_public_input(num_participants);
    builder.register_public_input(block_slot);
    builder.register_public_input(total_stake);

    AttAgg3Targets {
        block_slot,
        validators_state_verifier,
        validators_state_proof,
        atts_agg2_verifier,
        atts_agg2_data,
    }
}

#[derive(Clone)]
pub struct AttestationAggregatorThirdStageData {
    pub block_slot: usize,
    pub validators_state_proof: ValidatorsStateProof,
    pub agg2_data: Vec<AttestationAggregatorThirdStageAgg2Data>,
}
#[derive(Clone)]
pub struct AttestationAggregatorThirdStageAgg2Data {
    pub validators_sub_root: [Field; 4],
    pub agg2_proof: Option<AttestationAggregatorSecondStageProof>,
}

fn generate_partial_witness(
    targets: &AttAgg3Targets, 
    data: &AttestationAggregatorThirdStageData, 
    atts_agg2_verifier: &VerifierOnlyCircuitData<Config, D>, 
    validators_state_verifier: &VerifierOnlyCircuitData<Config, D>
) -> Result<PartialWitness<Field>> {
    if data.agg2_data.len() != AGGREGATION_STAGE3_SIZE {
        return Err(anyhow!("Must include {} datas in attestation aggregation third pass", AGGREGATION_STAGE3_SIZE));
    }

    //find a proof to use as a dummy proof
    let mut dummy_proof: Option<AttestationAggregatorSecondStageProof> = None;
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
    pw.set_target(targets.block_slot, Field::from_canonical_u64(data.block_slot as u64));

    pw.set_verifier_data_target(&targets.validators_state_verifier, validators_state_verifier);
    pw.set_proof_with_pis_target(&targets.validators_state_proof, data.validators_state_proof.proof());

    pw.set_verifier_data_target(&targets.atts_agg2_verifier, atts_agg2_verifier);
    for (t, v) in targets.atts_agg2_data.iter().zip(data.agg2_data.clone()) {
        let validators_sub_root: HashOut<Field> = HashOut::<Field> { elements: v.validators_sub_root };
        pw.set_hash_target(t.validators_sub_root, validators_sub_root);
        match v.agg2_proof {
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
fn write_targets(buffer: &mut Vec<u8>, targets: &AttAgg3Targets) -> IoResult<()> {
    buffer.write_target(targets.block_slot)?;

    buffer.write_target_verifier_circuit(&targets.validators_state_verifier)?;
    buffer.write_target_proof_with_public_inputs(&targets.validators_state_proof)?;

    buffer.write_target_verifier_circuit(&targets.atts_agg2_verifier)?;
    buffer.write_usize(targets.atts_agg2_data.len())?;
    for d in &targets.atts_agg2_data {
        buffer.write_target_hash(&d.validators_sub_root)?;
        buffer.write_target_bool(d.has_participation)?;
        buffer.write_target_proof_with_public_inputs(&d.proof)?;
    }

    Ok(())
}

#[inline]
fn read_targets(buffer: &mut Buffer) -> IoResult<AttAgg3Targets> {
    let block_slot = buffer.read_target()?;

    let validators_state_verifier = buffer.read_target_verifier_circuit()?;
    let validators_state_proof = buffer.read_target_proof_with_public_inputs()?;

    let atts_agg2_verifier = buffer.read_target_verifier_circuit()?;
    let mut atts_agg2_data: Vec<AttAgg3Agg2Targets> = Vec::new();
    let atts_agg1_data_length = buffer.read_usize()?;
    for _ in 0..atts_agg1_data_length {
        let validators_sub_root = buffer.read_target_hash()?;
        let has_participation = buffer.read_target_bool()?;
        let proof = buffer.read_target_proof_with_public_inputs()?;
        atts_agg2_data.push(AttAgg3Agg2Targets {
            validators_sub_root,
            has_participation,
            proof,
        });
    }

    Ok(AttAgg3Targets {
        block_slot,
        validators_state_verifier,
        validators_state_proof,
        atts_agg2_verifier,
        atts_agg2_data,
    })
}

fn build_empty_participation_sub_root(builder: &mut CircuitBuilder<Field, D>) -> HashOutTarget {
    let root = empty_participation_sub_root(AGGREGATION_STAGE2_SUB_TREE_HEIGHT);
    HashOutTarget {
        elements: root.map(|f| { builder.constant(f) }),
    }
}
