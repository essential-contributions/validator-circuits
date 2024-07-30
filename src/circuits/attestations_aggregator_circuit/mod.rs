mod attestations_aggregator1_circuit;
mod attestations_aggregator2_circuit;
mod attestations_aggregator3_circuit;

pub use attestations_aggregator1_circuit::*;
pub use attestations_aggregator2_circuit::*;
pub use attestations_aggregator3_circuit::*;

use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::{anyhow, Result};
use plonky2::util::serialization::Write;

use crate::{Config, Field, D};
use super::{Circuit, Proof, Serializeable};

//TODO: implement multi-threading for proof generation

const AGG1_PROOFS_LEN: usize = ATTESTATION_AGGREGATION_PASS3_SIZE * ATTESTATION_AGGREGATION_PASS2_SIZE;
const AGG2_PROOFS_LEN: usize = ATTESTATION_AGGREGATION_PASS3_SIZE;

pub struct AttestationsAggregatorCircuit {
    attestations_aggregator1: AttestationsAggregator1Circuit,
    attestations_aggregator2: AttestationsAggregator2Circuit,
    attestations_aggregator3: AttestationsAggregator3Circuit,
}
impl Circuit for AttestationsAggregatorCircuit {
    type Data = AttestationsAggregatorCircuitData;
    type Proof = AttestationsAggregatorProof;
    
    fn new() -> Self {
        log::info!("Building sub circuit [AttestationsAggregator1Circuit]");
        let attestations_aggregator1 = AttestationsAggregator1Circuit::new();
        log::info!("Building sub circuit [AttestationsAggregator2Circuit]");
        let attestations_aggregator2 = AttestationsAggregator2Circuit::new_continuation(&attestations_aggregator1);
        log::info!("Building sub circuit [AttestationsAggregator3Circuit]");
        let attestations_aggregator3 = AttestationsAggregator3Circuit::new_continuation(&attestations_aggregator2);

        Self { attestations_aggregator1, attestations_aggregator2, attestations_aggregator3 }
    }
    
    fn generate_proof(&self, data: &Self::Data) -> Result<Self::Proof> {
        generate_proof_from_data(&self, data)
    }

    fn example_proof(&self) -> Self::Proof {
        log::info!("Generating example sub proof for secondary group");
        let proof1 = self.attestations_aggregator1.example_proof();
        log::info!("Generating example sub proof for primary group");
        let proof2 = self.attestations_aggregator2.example_proof_continuation(&self.attestations_aggregator1, &proof1);
        log::info!("Generating final aggregate example proof");
        let proof3 = self.attestations_aggregator3.example_proof_continuation(&self.attestations_aggregator2, &proof2);
        AttestationsAggregatorProof { proof: proof3 }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.attestations_aggregator3.verify_proof(&proof.proof)
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.attestations_aggregator3.circuit_data();
    }
}
impl Serializeable for AttestationsAggregatorCircuit {
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

        log::info!("Loading sub circuit from bytes [AttestationsAggregator1Circuit]");
        let attestations_aggregator1 = AttestationsAggregator1Circuit::from_bytes(&(&bytes[start1..start2]).to_vec())?;
        log::info!("Loading sub circuit from bytes [AttestationsAggregator2Circuit]");
        let attestations_aggregator2 = AttestationsAggregator2Circuit::from_bytes(&(&bytes[start2..start3]).to_vec())?;
        log::info!("Loading sub circuit from bytes [AttestationsAggregator3Circuit]");
        let attestations_aggregator3 = AttestationsAggregator3Circuit::from_bytes(&(&bytes[start3..]).to_vec())?;

        Ok(Self { attestations_aggregator1, attestations_aggregator2, attestations_aggregator3 })
    }
}

#[derive(Clone)]
pub struct AttestationsAggregatorProof {
    proof: AttestationsAggregator3Proof,
}
impl AttestationsAggregatorProof {
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
impl Proof for AttestationsAggregatorProof {
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof.proof()
    }
}

#[derive(Clone)]
pub struct AttestationsAggregatorCircuitData {
    pub block_slot: usize,
    pub validator_data: Vec<ValidatorPrimaryGroupData>,
}
#[derive(Clone)]
pub enum ValidatorPrimaryGroupData {
    ValidatorGroupData(Vec<ValidatorSecondaryGroupData>),
    ValidatorGroupRoot([Field; 4]),
}
#[derive(Clone)]
pub enum ValidatorSecondaryGroupData {
    ValidatorGroupData(Vec<ValidatorData>),
    ValidatorGroupRoot([Field; 4]),
}
#[derive(Clone)]
pub struct ValidatorData {
    pub stake: u32,
    pub commitment_root: [Field; 4],
    pub reveal: Option<ValidatorRevealData>,
}
#[derive(Clone)]
pub struct ValidatorRevealData {
    pub reveal: [Field; 4],
    pub reveal_proof: Vec<[Field; 4]>,
}

fn generate_proof_from_data(circuits: &AttestationsAggregatorCircuit, data: &AttestationsAggregatorCircuitData) -> Result<AttestationsAggregatorProof> {
    //generate first pass proofs
    //TODO: parallelize in small groups
    log::info!("Generating sub proofs for secondary groups");
    let mut agg1_proofs: [Option<AttestationsAggregator1Proof>; AGG1_PROOFS_LEN] = std::array::from_fn(|_| None);
    for (i, primary_group) in data.validator_data.iter().enumerate() {
        if let ValidatorPrimaryGroupData::ValidatorGroupData(secondary_groups) = primary_group {
            for (j, secondary_group) in secondary_groups.iter().enumerate() {
                if let ValidatorSecondaryGroupData::ValidatorGroupData(validators) = secondary_group {
                    let agg1_data = AttestationsAggregator1Data {
                        block_slot: data.block_slot,
                        validators: validators.into_iter().map(|v| AttestationsAggregator1ValidatorData {
                            stake: v.stake,
                            commitment_root: v.commitment_root,
                            reveal: match &v.reveal {
                                Some(r) => Some(AttestationsAggregator1RevealData {
                                    reveal: r.reveal,
                                    reveal_proof: r.reveal_proof.clone(),
                                }),
                                None => None,
                            },
                        }).collect(),
                    };
                    agg1_proofs[i * ATTESTATION_AGGREGATION_PASS3_SIZE + j] = Some(circuits.attestations_aggregator1.generate_proof(&agg1_data)?);
                }
            }
        }
    }

    //generate second pass proofs
    log::info!("Generating sub proofs for primary groups");
    let mut agg2_proofs: [Option<AttestationsAggregator2Proof>; AGG2_PROOFS_LEN] = std::array::from_fn(|_| None);
    for (i, primary_group) in data.validator_data.iter().enumerate() {
        if let ValidatorPrimaryGroupData::ValidatorGroupData(secondary_groups) = primary_group {
            let agg2_data = AttestationsAggregator2Data {
                block_slot: data.block_slot,
                agg1_data: secondary_groups.iter().enumerate().map(|(j, secondary_group)| match secondary_group {
                    ValidatorSecondaryGroupData::ValidatorGroupData(_) => {
                        let agg1_proof = agg1_proofs[i * ATTESTATION_AGGREGATION_PASS3_SIZE + j].clone().unwrap();
                        AttestationsAggregator2Agg1Data {
                            validators_sub_root: agg1_proof.validators_sub_root(),
                            agg1_proof: Some(agg1_proof),
                        }
                    },
                    ValidatorSecondaryGroupData::ValidatorGroupRoot(root) => {
                        AttestationsAggregator2Agg1Data {
                            validators_sub_root: root.clone(),
                            agg1_proof: None,
                        }
                    },
                }).collect(),
            };
            agg2_proofs[i] = Some(circuits.attestations_aggregator2.generate_proof_continuation(&agg2_data, &circuits.attestations_aggregator1)?);
        }
    }

    //generate the final proof
    log::info!("Generating final aggregate proof");
    let agg3_data = AttestationsAggregator3Data {
        block_slot: data.block_slot,
        agg2_data: data.validator_data.iter().enumerate().map(|(j, primary_group)| match primary_group {
            ValidatorPrimaryGroupData::ValidatorGroupData(_) => {
                let agg2_proof = agg2_proofs[j].clone().unwrap();
                AttestationsAggregator3Agg2Data {
                    validators_sub_root: agg2_proof.validators_sub_root(),
                    agg2_proof: Some(agg2_proof),
                }
            },
            ValidatorPrimaryGroupData::ValidatorGroupRoot(root) => {
                AttestationsAggregator3Agg2Data {
                    validators_sub_root: root.clone(),
                    agg2_proof: None,
                }
            },
        }).collect(),
    };
    let pass3_proof = circuits.attestations_aggregator3.generate_proof_continuation(&agg3_data, &circuits.attestations_aggregator2)?;

    return Ok(AttestationsAggregatorProof {
        proof: pass3_proof,
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
