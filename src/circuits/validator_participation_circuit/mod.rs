mod validator_participation_aggregator_end_circuit;
mod validator_participation_aggregator_circuit;

pub use validator_participation_aggregator_end_circuit::*;
pub use validator_participation_aggregator_circuit::*;

use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use anyhow::{anyhow, Result};
use plonky2::util::serialization::Write;

use crate::{accounts::AccountsTree, commitment::example_commitment_proof, participation::ParticipationRoundsTree, validators::{example_validator_set, ValidatorsTree}, Config, Field, AGGREGATION_PASS1_SUB_TREE_HEIGHT, AGGREGATION_PASS2_SUB_TREE_HEIGHT, D, PARTICIPATION_ROUNDS_PER_STATE_EPOCH};
use super::{participation_state_circuit::ParticipationStateProof, validators_state_circuit::ValidatorsStateProof, Circuit, Proof, Serializeable};

//TODO: proof generation needs to be able to reference validators_tree at specific epochs (see todo in validators.rs)

pub struct ValidatorParticipationCircuit {
    participation_agg: ValidatorParticipationAggCircuit,
    participation_agg_end: ValidatorParticipationAggEndCircuit,
}
impl ValidatorParticipationCircuit {
    pub fn generate_proof(
        &self,
        data: &ValidatorParticipationCircuitData,
        validators_tree: &ValidatorsTree,
        accounts_tree: &AccountsTree,
        participation_rounds_tree: &ParticipationRoundsTree,
    ) -> Result<ValidatorParticipationProof> {
        generate_proof_from_data(&self, data, validators_tree, accounts_tree, participation_rounds_tree)
    }
}
impl Circuit for ValidatorParticipationCircuit {
    type Proof = ValidatorParticipationProof;
    
    fn new() -> Self {
        log::info!("Building sub circuit [ValidatorParticipationAggCircuit]");
        let participation_agg = ValidatorParticipationAggCircuit::new();
        log::info!("Building sub circuit [ValidatorParticipationAggEndCircuit]");
        let participation_agg_end = ValidatorParticipationAggEndCircuit::from_subcircuits(&participation_agg);

        Self { participation_agg, participation_agg_end }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.participation_agg_end.verify_proof(&proof.proof)
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.participation_agg_end.circuit_data();
    }

    fn is_wrappable() -> bool {
        true
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        todo!()
        /*
        log::info!("Generating example sub proof for secondary group");
        let proof1 = self.attestations_aggregator1.generate_proof(
            &example_data_agg1(),
        ).unwrap();
        log::info!("Generating example sub proof for primary group");
        let proof2 = self.attestations_aggregator2.generate_proof_continuation(
            &example_data_agg2(&proof1), 
            &self.attestations_aggregator1,
        ).unwrap();
        log::info!("Generating final aggregate example proof");
        let proof3 = self.attestations_aggregator3.generate_proof_continuation(
            &example_data_agg3(&proof2), 
            &self.attestations_aggregator2,
        ).unwrap();
        Some(ValidatorParticipationProof { proof: proof3 })
        */
    }
}
impl Serializeable for ValidatorParticipationCircuit {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::new();
        write_all(&mut buffer, &(0 as u64).to_be_bytes())?;

        {
            let bytes = self.participation_agg.to_bytes()?;
            buffer[0..8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
            write_all(&mut buffer, bytes.as_slice())?;
        }
        {
            let bytes = self.participation_agg_end.to_bytes()?;
            write_all(&mut buffer, bytes.as_slice())?;
        }

        Ok(buffer)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self> {
        let mut be_bytes = [0u8; 8];
        let start1 = 16;
        be_bytes.copy_from_slice(&bytes[0..8]);
        let start2 = start1 + (u64::from_be_bytes(be_bytes) as usize);

        log::info!("Loading sub circuit from bytes [ValidatorParticipationAggCircuit]");
        let participation_agg = ValidatorParticipationAggCircuit::from_bytes(&(&bytes[start1..start2]).to_vec())?;
        log::info!("Loading sub circuit from bytes [ValidatorParticipationAggEndCircuit]");
        let participation_agg_end = ValidatorParticipationAggEndCircuit::from_bytes(&(&bytes[start2..]).to_vec())?;

        Ok(Self { participation_agg, participation_agg_end })
    }
}

#[derive(Clone)]
pub struct ValidatorParticipationProof {
    proof: ValidatorParticipationAggEndProof,
}
impl ValidatorParticipationProof {
    pub fn participation_inputs_hash(&self) -> [u8; 32] {
        self.proof.participation_inputs_hash()
    }

    pub fn account_address(&self) -> [u8; 20] {
        self.proof.account_address()
    }

    pub fn from_epoch(&self) -> u32 {
        self.proof.from_epoch()
    }

    pub fn to_epoch(&self) -> u32 {
        self.proof.to_epoch()
    }

    pub fn withdraw_max(&self) -> u64 {
        self.proof.withdraw_max()
    }

    pub fn withdraw_unearned(&self) -> u64 {
        self.proof.withdraw_unearned()
    }

    pub fn param_rf(&self) -> u64 {
        self.proof.param_rf()
    }

    pub fn param_st(&self) -> u64 {
        self.proof.param_st()
    }
}
impl Proof for ValidatorParticipationProof {
    fn from_proof(proof: ProofWithPublicInputs<Field, Config, D>) -> Self {
        Self { proof: ValidatorParticipationAggEndProof::from_proof(proof) }
    }
    
    fn proof(&self) -> &ProofWithPublicInputs<Field, Config, D> {
        &self.proof.proof()
    }
}

#[derive(Clone)]
pub struct ValidatorParticipationCircuitData {
    pub account_address: [u8; 20],
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub rf: u64,
    pub st: u64,

    pub validators_state_proof: ValidatorsStateProof,
    pub participation_state_proof: ParticipationStateProof,
}

fn generate_proof_from_data(
    circuits: &ValidatorParticipationCircuit, 
    data: &ValidatorParticipationCircuitData,
    validators_tree: &ValidatorsTree,
    accounts_tree: &AccountsTree,
    participation_rounds_tree: &ParticipationRoundsTree,
) -> Result<ValidatorParticipationProof> {
    if data.validators_state_proof.validators_tree_root() != validators_tree.root() {
        return Err(anyhow!("Validators tree root does not match the given validators state proof."));
    }
    if data.validators_state_proof.accounts_tree_root() != accounts_tree.root() {
        return Err(anyhow!("Accounts tree root does not match the given validators state proof."));
    }
    if data.participation_state_proof.participation_rounds_tree_root() != participation_rounds_tree.root() {
        return Err(anyhow!("Participation rounds tree root does not match the given participation state proof."));
    }

    //generate cyclical proof for each epoch
    let mut cyclical_proof = None;
    for epoch in data.from_epoch..data.to_epoch {
        log::info!("Generating proof for epoch {}", epoch);
        let account = accounts_tree.account(data.account_address);
        let validator = match account.validator_index {
            Some(index) => {
                let validator = validators_tree.validator(index);
                Some(ValidatorParticipationValidatorData {
                    index,
                    stake: validator.stake,
                    commitment: validator.commitment_root,
                    proof: validators_tree.merkle_proof(index),
                })
            },
            None => None,
        };
        let participation_rounds = (0..PARTICIPATION_ROUNDS_PER_STATE_EPOCH).map(|n| {
            let round_num = ((epoch as usize) * PARTICIPATION_ROUNDS_PER_STATE_EPOCH) + n;
            let round = participation_rounds_tree.round(round_num);
            ValidatorPartAggRoundData {
                participation_root: round.participation_root,
                participation_count: round.participation_count,
                participation_round_proof: participation_rounds_tree.merkle_proof(round_num),
                participation_bits: round.participation_bits,
            }
        }).collect();
        let previous_data = match cyclical_proof {
            Some(proof) => ValidatorPartAggPrevData::Continue(proof),
            None => ValidatorPartAggPrevData::Start(ValidatorPartAggStartData {
                pr_tree_root: participation_rounds_tree.root(),
                account: data.account_address,
                epoch: epoch as u32,
                param_rf: data.rf,
                param_st: data.st,
            }),
        };
        let data = ValidatorParticipationAggCircuitData {
            validator,
            account_validator_proof: accounts_tree.merkle_proof(data.account_address),
            validators_state_proof: data.validators_state_proof.clone(),
            participation_rounds,
            previous_data,
        };
        cyclical_proof = Some(circuits.participation_agg.generate_proof(&data)?);
    }
    
    //generate final end proof
    log::info!("Generating final proof");
    let data = ValidatorParticipationAggEndCircuitData {
        participation_agg_proof: cyclical_proof.unwrap(),
        participation_state_proof: data.participation_state_proof.clone(),
    };
    let proof = circuits.participation_agg_end.generate_proof(&data).unwrap();
    
    Ok(ValidatorParticipationProof { proof })
}

#[inline]
fn write_all(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let result = buffer.write_all(bytes);
    if result.is_err() {
        return Err(anyhow!("Failed to serialize circuits"));
    }
    Ok(result.unwrap())
}

/*
fn example_data_agg1() -> ValidatorParticipation1Data {
    let num_attestations = 500;
    let validator_set = example_validator_set();
    let validators: Vec<ValidatorParticipation1ValidatorData> = (0..ATTESTATION_AGGREGATION_PASS1_SIZE).map(|i| {
        let validator = validator_set.validator(i);
        if i < num_attestations {
            let commitment_proof = example_commitment_proof(i);
            ValidatorParticipation1ValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: Some(ValidatorParticipation1RevealData {
                    reveal: commitment_proof.reveal,
                    reveal_proof: commitment_proof.proof,
                }),
            }
        } else {
            ValidatorParticipation1ValidatorData {
                stake: validator.stake,
                commitment_root: validator.commitment_root,
                reveal: None,
            }
        }
    }).collect();

    ValidatorParticipation1Data {
        block_slot: 100,
        validators,
    }
}

fn example_data_agg2(agg1_proof: &ValidatorParticipation1Proof) -> ValidatorParticipation2Data {
    let validator_set = example_validator_set();
    let agg1_data: Vec<ValidatorParticipation2Agg1Data> = (0..ATTESTATION_AGGREGATION_PASS2_SIZE).map(|i| {
        let validators_sub_root = validator_set.sub_root(AGGREGATION_PASS1_SUB_TREE_HEIGHT, i);
        if i == 0 {
            ValidatorParticipation2Agg1Data {
                validators_sub_root,
                agg1_proof: Some(agg1_proof.clone()),
            }
        } else {
            ValidatorParticipation2Agg1Data {
                validators_sub_root,
                agg1_proof: None,
            }
        }
    }).collect();

    ValidatorParticipation2Data {
        block_slot: 100,
        agg1_data,
    }
}

fn example_data_agg3(agg2_proof: &ValidatorParticipation2Proof) -> ValidatorParticipation3Data {
    let validator_set = example_validator_set();
    let agg2_data: Vec<ValidatorParticipation3Agg2Data> = (0..ATTESTATION_AGGREGATION_PASS3_SIZE).map(|i| {
        let height = AGGREGATION_PASS1_SUB_TREE_HEIGHT + AGGREGATION_PASS2_SUB_TREE_HEIGHT;
        let validators_sub_root = validator_set.sub_root(height, i);
        if i == 0 {
            ValidatorParticipation3Agg2Data {
                validators_sub_root,
                agg2_proof: Some(agg2_proof.clone()),
            }
        } else {
            ValidatorParticipation3Agg2Data {
                validators_sub_root,
                agg2_proof: None,
            }
        }
    }).collect();

    ValidatorParticipation3Data {
        block_slot: 100,
        agg2_data,
    }
}
*/