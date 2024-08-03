mod attestation_aggregator_first_stage_circuit;
mod attestation_aggregator_second_stage_circuit;
mod attestation_aggregator_third_stage_circuit;

pub use attestation_aggregator_first_stage_circuit::*;
pub use attestation_aggregator_second_stage_circuit::*;
pub use attestation_aggregator_third_stage_circuit::*;

use plonky2::{field::types::Field as Plonky2_Field, plonk::circuit_data::CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::{anyhow, Result};
use plonky2::util::serialization::Write;

use crate::{AGGREGATION_STAGE1_SIZE, AGGREGATION_STAGE2_SIZE, AGGREGATION_STAGE3_SIZE};
use crate::{commitment::example_commitment_proof, validators::{example_validator_set, ValidatorCommitmentReveal, ValidatorsTree}, Config, Field, AGGREGATION_STAGE1_SUB_TREE_HEIGHT, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, D};
use super::{Circuit, Proof, Serializeable};

//TODO: implement multi-threading for proof generation

const AGG1_PROOFS_LEN: usize = AGGREGATION_STAGE3_SIZE * AGGREGATION_STAGE2_SIZE;
const AGG2_PROOFS_LEN: usize = AGGREGATION_STAGE3_SIZE;

pub struct AttestationAggregationCircuit {
    attestations_aggregator1: AttestationAggregatorFirstStageCircuit,
    attestations_aggregator2: AttestationAggregatorSecondStageCircuit,
    attestations_aggregator3: AttestationAggregatorThirdStageCircuit,
}
impl AttestationAggregationCircuit {
    pub fn generate_proof(
        &self, 
        reveals: &Vec<ValidatorCommitmentReveal>,
        validators_tree: &ValidatorsTree
    ) -> Result<AttestationAggregatorProof> {
        generate_proof_from_data(&self, reveals, validators_tree)
    }
}
impl Circuit for AttestationAggregationCircuit {
    type Proof = AttestationAggregatorProof;
    
    fn new() -> Self {
        log::info!("Building sub circuit [AttestationAggregatorFirstStageCircuit]");
        let attestations_aggregator1 = AttestationAggregatorFirstStageCircuit::new();
        log::info!("Building sub circuit [AttestationAggregatorSecondStageCircuit]");
        let attestations_aggregator2 = AttestationAggregatorSecondStageCircuit::from_subcircuits(&attestations_aggregator1);
        log::info!("Building sub circuit [AttestationAggregatorThirdStageCircuit]");
        let attestations_aggregator3 = AttestationAggregatorThirdStageCircuit::from_subcircuits(&attestations_aggregator2);

        Self { attestations_aggregator1, attestations_aggregator2, attestations_aggregator3 }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.attestations_aggregator3.verify_proof(&proof.proof)
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.attestations_aggregator3.circuit_data();
    }

    fn is_wrappable() -> bool {
        true
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        log::info!("Generating example sub proof for first stage");
        let proof1 = self.attestations_aggregator1.generate_proof(
            &example_data_agg1(),
        ).unwrap();
        log::info!("Generating example sub proof for second stage");
        let proof2 = self.attestations_aggregator2.generate_proof(
            &example_data_agg2(&proof1),
        ).unwrap();
        log::info!("Generating final aggregate example proof");
        let proof3 = self.attestations_aggregator3.generate_proof(
            &example_data_agg3(&proof2),
        ).unwrap();
        Some(AttestationAggregatorProof { proof: proof3 })
    }
}
impl Serializeable for AttestationAggregationCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::new();
        write_all(&mut buffer, &(0 as u64).to_be_bytes())?;
        write_all(&mut buffer, &(0 as u64).to_be_bytes())?;

        {
            let bytes = self.attestations_aggregator1.to_bytes()?;
            buffer[0..8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
            write_all(&mut buffer, bytes.as_slice())?;
        }
        {
            let bytes = self.attestations_aggregator2.to_bytes()?;
            buffer[8..16].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
            write_all(&mut buffer, bytes.as_slice())?;
        }
        {
            let bytes = self.attestations_aggregator3.to_bytes()?;
            write_all(&mut buffer, bytes.as_slice())?;
        }

        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let mut be_bytes = [0u8; 8];
        let start1 = 16;
        be_bytes.copy_from_slice(&bytes[0..8]);
        let start2 = start1 + (u64::from_be_bytes(be_bytes) as usize);
        be_bytes.copy_from_slice(&bytes[8..16]);
        let start3 = start2 + (u64::from_be_bytes(be_bytes) as usize);

        log::info!("Loading sub circuit from bytes [AttestationAggregatorFirstStageCircuit]");
        let attestations_aggregator1 = AttestationAggregatorFirstStageCircuit::from_bytes(&(&bytes[start1..start2]).to_vec())?;
        log::info!("Loading sub circuit from bytes [AttestationAggregatorSecondStageCircuit]");
        let attestations_aggregator2 = AttestationAggregatorSecondStageCircuit::from_bytes(&(&bytes[start2..start3]).to_vec())?;
        log::info!("Loading sub circuit from bytes [AttestationAggregatorThirdStageCircuit]");
        let attestations_aggregator3 = AttestationAggregatorThirdStageCircuit::from_bytes(&(&bytes[start3..]).to_vec())?;

        Ok(Self { attestations_aggregator1, attestations_aggregator2, attestations_aggregator3 })
    }
}

#[derive(Clone)]
pub struct AttestationAggregatorProof {
    proof: AttestationAggregatorThirdStageProof,
}
impl AttestationAggregatorProof {
    pub fn validators_root(&self) -> [Field; 4] {
        self.proof.validators_root()
    }

    pub fn participation_root(&self) -> [Field; 4] {
        self.proof.participation_root()
    }

    pub fn num_participants(&self) -> usize{
        self.proof.num_participants()
    }

    pub fn block_slot(&self) -> usize{
        self.proof.block_slot()
    }

    pub fn total_stake(&self) -> u64 {
        self.proof.total_stake()
    }
}
impl Proof for AttestationAggregatorProof {
    fn from_proof(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        Self { proof: AttestationAggregatorThirdStageProof::from_proof(proof) }
    }
    
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof.proof()
    }
}

#[derive(Clone)]
enum SecondStageGroupData<'a> {
    ValidatorGroupData(Vec<FirstStageGroupData<'a>>),
    ValidatorGroupRoot([Field; 4]),
}
#[derive(Clone)]
enum FirstStageGroupData<'a> {
    ValidatorGroupData(Vec<ValidatorData<'a>>),
    ValidatorGroupRoot([Field; 4]),
}
#[derive(Clone)]
struct ValidatorData<'a> {
    pub stake: u32,
    pub commitment_root: [Field; 4],
    pub reveal: Option<&'a ValidatorCommitmentReveal>,
}

fn generate_proof_from_data(
    circuits: &AttestationAggregationCircuit,
    reveals: &Vec<ValidatorCommitmentReveal>,
    validators_tree: &ValidatorsTree,
) -> Result<AttestationAggregatorProof> {
    let max_attestations = AGGREGATION_STAGE1_SIZE * AGGREGATION_STAGE2_SIZE * AGGREGATION_STAGE3_SIZE;
    if reveals.len() == 0 {
        return Err(anyhow!("At least one reveal must be provided for the attestations proof"));
    }
    if reveals.len() > max_attestations {
        return Err(anyhow!("Only {} reveals can be proven per attestations proof", max_attestations));
    }
    let block_slot = reveals[0].block_slot;
    for reveal in reveals.iter() {
        if reveal.block_slot != block_slot {
            return Err(anyhow!("All reveals do not have the same block_slot"));
        }
    }

    //organize the reveal data
    let mut validator_data: Vec<SecondStageGroupData> = vec![SecondStageGroupData::ValidatorGroupRoot([Field::ZERO; 4]); AGGREGATION_STAGE3_SIZE];
    for reveal in reveals.iter() {
        let validator_stage2_group_index = reveal.validator_index / (AGGREGATION_STAGE1_SIZE * AGGREGATION_STAGE2_SIZE);
        let stage2_group = &validator_data[validator_stage2_group_index];
        //add full second stage group if it is currently just a root
        if let SecondStageGroupData::ValidatorGroupRoot(_) = stage2_group {
            let validator_group_data: Vec<FirstStageGroupData> = vec![FirstStageGroupData::ValidatorGroupRoot([Field::ZERO; 4]); AGGREGATION_STAGE2_SIZE];
            validator_data[validator_stage2_group_index] = SecondStageGroupData::ValidatorGroupData(validator_group_data);
        }
        let stage2_group = &mut validator_data[validator_stage2_group_index];
        if let SecondStageGroupData::ValidatorGroupData(stage2_group) = stage2_group {
            let validator_stage1_group_index = (reveal.validator_index / AGGREGATION_STAGE1_SIZE) % AGGREGATION_STAGE2_SIZE;
            let stage1_group = &stage2_group[validator_stage1_group_index];
            //add full first stage group if it is currently just a root
            if let FirstStageGroupData::ValidatorGroupRoot(_) = stage1_group {
                let validators: Vec<ValidatorData> = vec![ValidatorData {stake: 0, commitment_root: [Field::ZERO; 4], reveal: None}; AGGREGATION_STAGE1_SIZE];
                stage2_group[validator_stage1_group_index] = FirstStageGroupData::ValidatorGroupData(validators);
            }
            let stage1_group = &mut stage2_group[validator_stage1_group_index];
            if let FirstStageGroupData::ValidatorGroupData(stage1_group) = stage1_group {
                //add the validator reveal data
                let validator_group_index = reveal.validator_index % AGGREGATION_STAGE1_SIZE;
                stage1_group[validator_group_index].reveal = Some(reveal);
            }
        }
    }

    //fill in group roots and validator data
    for (i, stage2_group) in validator_data.iter_mut().enumerate() {
        match stage2_group {
            SecondStageGroupData::ValidatorGroupRoot(ref mut stage2_group_root) => {
                //second stage group root
                let height = AGGREGATION_STAGE1_SUB_TREE_HEIGHT + AGGREGATION_STAGE2_SUB_TREE_HEIGHT;
                let index = i;
                *stage2_group_root = validators_tree.sub_root(height, index);
            },
            SecondStageGroupData::ValidatorGroupData(ref mut stage2_group) => {
                for (j, stage1_group) in stage2_group.iter_mut().enumerate() {
                    match stage1_group {
                        FirstStageGroupData::ValidatorGroupRoot(ref mut stage1_group_root) => {
                            //first stage group root
                            let height = AGGREGATION_STAGE1_SUB_TREE_HEIGHT;
                            let index = (i * AGGREGATION_STAGE2_SUB_TREE_HEIGHT) + j;
                            *stage1_group_root = validators_tree.sub_root(height, index);
                        },
                        FirstStageGroupData::ValidatorGroupData(ref mut stage1_group) => {
                            for (k, validator) in stage1_group.iter_mut().enumerate() {
                                //validator data
                                let index = (i * AGGREGATION_STAGE2_SUB_TREE_HEIGHT * AGGREGATION_STAGE1_SUB_TREE_HEIGHT) + (j * AGGREGATION_STAGE1_SUB_TREE_HEIGHT) + k;
                                let data = validators_tree.validator(index);
                                validator.stake = data.stake;
                                validator.commitment_root = data.commitment_root.clone();
                            }
                        },
                    }
                }
            },
        }
    }

    //generate first stage proofs
    //TODO: parallelize in small groups
    log::info!("Generating sub proofs for first stage");
    let mut agg1_proofs: [Option<AttestationAggregatorFirstStageProof>; AGG1_PROOFS_LEN] = std::array::from_fn(|_| None);
    for (i, stage2_group) in validator_data.iter().enumerate() {
        if let SecondStageGroupData::ValidatorGroupData(stage1_groups) = stage2_group {
            for (j, stage1_group) in stage1_groups.iter().enumerate() {
                if let FirstStageGroupData::ValidatorGroupData(validators) = stage1_group {
                    let agg1_data = AttestationAggregatorFirstStageData {
                        block_slot,
                        validators: validators.into_iter().map(|v| AttestationAggregatorFirstStageValidatorData {
                            stake: v.stake,
                            commitment_root: v.commitment_root,
                            reveal: match &v.reveal {
                                Some(r) => Some(AttestationAggregatorFirstStageRevealData {
                                    reveal: r.reveal,
                                    reveal_proof: r.proof.clone(),
                                }),
                                None => None,
                            },
                        }).collect(),
                    };
                    agg1_proofs[i * AGGREGATION_STAGE3_SIZE + j] = Some(circuits.attestations_aggregator1.generate_proof(&agg1_data)?);
                }
            }
        }
    }

    //generate second stage proofs
    log::info!("Generating sub proofs for second stage");
    let mut agg2_proofs: [Option<AttestationAggregatorSecondStageProof>; AGG2_PROOFS_LEN] = std::array::from_fn(|_| None);
    for (i, stage2_group) in validator_data.iter().enumerate() {
        if let SecondStageGroupData::ValidatorGroupData(stage1_groups) = stage2_group {
            let agg2_data = AttestationAggregatorSecondStageData {
                block_slot,
                agg1_data: stage1_groups.iter().enumerate().map(|(j, stage1_group)| match stage1_group {
                    FirstStageGroupData::ValidatorGroupData(_) => {
                        let agg1_proof = agg1_proofs[i * AGGREGATION_STAGE3_SIZE + j].clone().unwrap();
                        AttestationAggregatorSecondStageAgg1Data {
                            validators_sub_root: agg1_proof.validators_sub_root(),
                            agg1_proof: Some(agg1_proof),
                        }
                    },
                    FirstStageGroupData::ValidatorGroupRoot(root) => {
                        AttestationAggregatorSecondStageAgg1Data {
                            validators_sub_root: root.clone(),
                            agg1_proof: None,
                        }
                    },
                }).collect(),
            };
            agg2_proofs[i] = Some(circuits.attestations_aggregator2.generate_proof(&agg2_data)?);
        }
    }

    //generate the final proof
    log::info!("Generating final aggregate proof");
    let agg3_data = AttestationAggregatorThirdStageData {
        block_slot,
        agg2_data: validator_data.iter().enumerate().map(|(j, stage2_group)| match stage2_group {
            SecondStageGroupData::ValidatorGroupData(_) => {
                let agg2_proof = agg2_proofs[j].clone().unwrap();
                AttestationAggregatorThirdStageAgg2Data {
                    validators_sub_root: agg2_proof.validators_sub_root(),
                    agg2_proof: Some(agg2_proof),
                }
            },
            SecondStageGroupData::ValidatorGroupRoot(root) => {
                AttestationAggregatorThirdStageAgg2Data {
                    validators_sub_root: root.clone(),
                    agg2_proof: None,
                }
            },
        }).collect(),
    };
    let stage3_proof = circuits.attestations_aggregator3.generate_proof(&agg3_data)?;

    return Ok(AttestationAggregatorProof {
        proof: stage3_proof,
    })
}

#[inline]
fn write_all(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let result = buffer.write_all(bytes);
    if result.is_err() {
        return Err(anyhow!("Failed to serialize circuits"));
    }
    Ok(result.unwrap())
}

fn example_data_agg1() -> AttestationAggregatorFirstStageData {
    let num_attestations = 500;
    let validator_set = example_validator_set();
    let validators: Vec<AttestationAggregatorFirstStageValidatorData> = (0..AGGREGATION_STAGE1_SIZE).map(|i| {
        let validator = validator_set.validator(i);
        if i < num_attestations {
            let commitment_proof = example_commitment_proof(i);
            AttestationAggregatorFirstStageValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: Some(AttestationAggregatorFirstStageRevealData {
                    reveal: commitment_proof.reveal,
                    reveal_proof: commitment_proof.proof,
                }),
            }
        } else {
            AttestationAggregatorFirstStageValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: None,
            }
        }
    }).collect();

    AttestationAggregatorFirstStageData {
        block_slot: 100,
        validators,
    }
}

fn example_data_agg2(agg1_proof: &AttestationAggregatorFirstStageProof) -> AttestationAggregatorSecondStageData {
    let validator_set = example_validator_set();
    let agg1_data: Vec<AttestationAggregatorSecondStageAgg1Data> = (0..AGGREGATION_STAGE2_SIZE).map(|i| {
        let validators_sub_root = validator_set.sub_root(AGGREGATION_STAGE1_SUB_TREE_HEIGHT, i);
        if i == 0 {
            AttestationAggregatorSecondStageAgg1Data {
                validators_sub_root,
                agg1_proof: Some(agg1_proof.clone()),
            }
        } else {
            AttestationAggregatorSecondStageAgg1Data {
                validators_sub_root,
                agg1_proof: None,
            }
        }
    }).collect();

    AttestationAggregatorSecondStageData {
        block_slot: 100,
        agg1_data,
    }
}

fn example_data_agg3(agg2_proof: &AttestationAggregatorSecondStageProof) -> AttestationAggregatorThirdStageData {
    let validator_set = example_validator_set();
    let agg2_data: Vec<AttestationAggregatorThirdStageAgg2Data> = (0..AGGREGATION_STAGE3_SIZE).map(|i| {
        let height = AGGREGATION_STAGE1_SUB_TREE_HEIGHT + AGGREGATION_STAGE2_SUB_TREE_HEIGHT;
        let validators_sub_root = validator_set.sub_root(height, i);
        if i == 0 {
            AttestationAggregatorThirdStageAgg2Data {
                validators_sub_root,
                agg2_proof: Some(agg2_proof.clone()),
            }
        } else {
            AttestationAggregatorThirdStageAgg2Data {
                validators_sub_root,
                agg2_proof: None,
            }
        }
    }).collect();

    AttestationAggregatorThirdStageData {
        block_slot: 100,
        agg2_data,
    }
}
