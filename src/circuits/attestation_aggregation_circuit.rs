mod subcircuits;

pub use subcircuits::*;

use anyhow::{anyhow, Result};
use plonky2::util::serialization::Write;
use plonky2::{field::types::Field as Plonky2_Field, plonk::circuit_data::CircuitData};

use super::validators_state_circuit::{ValidatorsStateCircuitData, ValidatorsStateProof};
use super::{Circuit, Serializeable};
use crate::accounts::{initial_accounts_tree, null_account_address, Account, AccountsTree};
use crate::circuits::validators_state_circuit::ValidatorsStateCircuit;
use crate::circuits::{load_or_create_circuit, load_or_create_init_proof, VALIDATORS_STATE_CIRCUIT_DIR};
use crate::commitment::example_commitment_root;
use crate::validators::{initial_validators_tree, Validator};
use crate::{
    commitment::example_commitment_proof,
    validators::{ValidatorCommitmentReveal, ValidatorsTree},
    Config, Field, AGGREGATION_STAGE1_SUB_TREE_HEIGHT, AGGREGATION_STAGE2_SUB_TREE_HEIGHT, D,
};
use crate::{AGGREGATION_STAGE1_SIZE, AGGREGATION_STAGE2_SIZE, AGGREGATION_STAGE3_SIZE};

//TODO: implement multi-threading for proof generation

const AGG1_PROOFS_LEN: usize = AGGREGATION_STAGE3_SIZE * AGGREGATION_STAGE2_SIZE;
const AGG2_PROOFS_LEN: usize = AGGREGATION_STAGE3_SIZE;

pub type AttestationAggregatorProof = AttestationAggregatorThirdStageProof;

pub struct AttestationAggregationCircuit {
    attestations_aggregator1: AttestationAggregatorFirstStageCircuit,
    attestations_aggregator2: AttestationAggregatorSecondStageCircuit,
    attestations_aggregator3: AttestationAggregatorThirdStageCircuit,
}

impl AttestationAggregationCircuit {
    pub fn generate_proof(
        &self,
        validators_state_proof: &ValidatorsStateProof,
        reveals: &Vec<ValidatorCommitmentReveal>,
        validators_tree: &ValidatorsTree,
    ) -> Result<AttestationAggregatorProof> {
        generate_proof_from_data(&self, validators_state_proof, reveals, validators_tree)
    }
}

impl Circuit for AttestationAggregationCircuit {
    type Proof = AttestationAggregatorProof;

    fn new() -> Self {
        log::info!("Building sub circuit [AttestationAggregatorFirstStageCircuit]");
        let attestations_aggregator1 = AttestationAggregatorFirstStageCircuit::new();
        log::info!("Building sub circuit [AttestationAggregatorSecondStageCircuit]");
        let attestations_aggregator2 =
            AttestationAggregatorSecondStageCircuit::from_subcircuits(&attestations_aggregator1);
        log::info!("Building sub circuit [AttestationAggregatorThirdStageCircuit]");
        let attestations_aggregator3 =
            AttestationAggregatorThirdStageCircuit::from_subcircuits(&attestations_aggregator2);

        Self {
            attestations_aggregator1,
            attestations_aggregator2,
            attestations_aggregator3,
        }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.attestations_aggregator3.verify_proof(proof)
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.attestations_aggregator3.circuit_data();
    }

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        Ok(self.attestations_aggregator3.proof_to_bytes(proof)?)
    }

    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof> {
        Ok(self.attestations_aggregator3.proof_from_bytes(bytes)?)
    }

    fn is_cyclical() -> bool {
        false
    }

    fn cyclical_init_proof(&self) -> Option<Self::Proof> {
        None
    }

    fn is_wrappable() -> bool {
        true
    }

    fn wrappable_example_proof(&self) -> Option<Self::Proof> {
        //load sub circuits
        let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);

        //create prerequisite data
        let accounts = [[11u8; 20]];
        let validator_indexes = [21];
        let stakes = [64];
        let (validators_tree, validators_state_proof) =
            example_validators_state(&validators_state_circuit, &accounts, &validator_indexes, &stakes);

        //generate proof
        let block_slot = 100;
        let reveals = validator_indexes
            .iter()
            .map(|&validator_index| {
                let commitment_proof = example_commitment_proof(validator_index);
                ValidatorCommitmentReveal {
                    validator_index,
                    block_slot,
                    reveal: commitment_proof.reveal,
                    proof: commitment_proof.proof,
                }
            })
            .collect();
        Some(generate_proof_from_data(&self, &validators_state_proof, &reveals, &validators_tree).unwrap())
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
        let attestations_aggregator1 =
            AttestationAggregatorFirstStageCircuit::from_bytes(&(&bytes[start1..start2]).to_vec())?;
        log::info!("Loading sub circuit from bytes [AttestationAggregatorSecondStageCircuit]");
        let attestations_aggregator2 =
            AttestationAggregatorSecondStageCircuit::from_bytes(&(&bytes[start2..start3]).to_vec())?;
        log::info!("Loading sub circuit from bytes [AttestationAggregatorThirdStageCircuit]");
        let attestations_aggregator3 =
            AttestationAggregatorThirdStageCircuit::from_bytes(&(&bytes[start3..]).to_vec())?;

        Ok(Self {
            attestations_aggregator1,
            attestations_aggregator2,
            attestations_aggregator3,
        })
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
    validators_state_proof: &ValidatorsStateProof,
    reveals: &Vec<ValidatorCommitmentReveal>,
    validators_tree: &ValidatorsTree,
) -> Result<AttestationAggregatorProof> {
    let max_attestations = AGGREGATION_STAGE1_SIZE * AGGREGATION_STAGE2_SIZE * AGGREGATION_STAGE3_SIZE;
    if reveals.len() == 0 {
        return Err(anyhow!(
            "At least one reveal must be provided for the attestations proof"
        ));
    }
    if reveals.len() > max_attestations {
        return Err(anyhow!(
            "Only {} reveals can be proven per attestations proof",
            max_attestations
        ));
    }
    let block_slot = reveals[0].block_slot;
    for reveal in reveals.iter() {
        if reveal.block_slot != block_slot {
            return Err(anyhow!("All reveals do not have the same block_slot"));
        }
    }

    //organize the reveal data
    let mut validator_data: Vec<SecondStageGroupData> =
        vec![SecondStageGroupData::ValidatorGroupRoot([Field::ZERO; 4]); AGGREGATION_STAGE3_SIZE];
    for reveal in reveals.iter() {
        let validator_stage2_group_index = reveal.validator_index / (AGGREGATION_STAGE1_SIZE * AGGREGATION_STAGE2_SIZE);
        let stage2_group = &validator_data[validator_stage2_group_index];
        //add full second stage group if it is currently just a root
        if let SecondStageGroupData::ValidatorGroupRoot(_) = stage2_group {
            let validator_group_data: Vec<FirstStageGroupData> =
                vec![FirstStageGroupData::ValidatorGroupRoot([Field::ZERO; 4]); AGGREGATION_STAGE2_SIZE];
            validator_data[validator_stage2_group_index] =
                SecondStageGroupData::ValidatorGroupData(validator_group_data);
        }
        let stage2_group = &mut validator_data[validator_stage2_group_index];
        if let SecondStageGroupData::ValidatorGroupData(stage2_group) = stage2_group {
            let validator_stage1_group_index =
                (reveal.validator_index / AGGREGATION_STAGE1_SIZE) % AGGREGATION_STAGE2_SIZE;
            let stage1_group = &stage2_group[validator_stage1_group_index];
            //add full first stage group if it is currently just a root
            if let FirstStageGroupData::ValidatorGroupRoot(_) = stage1_group {
                let validators: Vec<ValidatorData> = vec![
                    ValidatorData {
                        stake: 0,
                        commitment_root: [Field::ZERO; 4],
                        reveal: None
                    };
                    AGGREGATION_STAGE1_SIZE
                ];
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
            }
            SecondStageGroupData::ValidatorGroupData(ref mut stage2_group) => {
                for (j, stage1_group) in stage2_group.iter_mut().enumerate() {
                    match stage1_group {
                        FirstStageGroupData::ValidatorGroupRoot(ref mut stage1_group_root) => {
                            //first stage group root
                            let height = AGGREGATION_STAGE1_SUB_TREE_HEIGHT;
                            let index = (i * AGGREGATION_STAGE2_SUB_TREE_HEIGHT) + j;
                            *stage1_group_root = validators_tree.sub_root(height, index);
                        }
                        FirstStageGroupData::ValidatorGroupData(ref mut stage1_group) => {
                            for (k, validator) in stage1_group.iter_mut().enumerate() {
                                //validator data
                                let index =
                                    (i * AGGREGATION_STAGE2_SUB_TREE_HEIGHT * AGGREGATION_STAGE1_SUB_TREE_HEIGHT)
                                        + (j * AGGREGATION_STAGE1_SUB_TREE_HEIGHT)
                                        + k;
                                let data = validators_tree.validator(index);
                                validator.stake = data.stake;
                                validator.commitment_root = data.commitment_root.clone();
                            }
                        }
                    }
                }
            }
        }
    }

    //generate first stage proofs
    //TODO: parallelize in small groups
    log::info!("Generating sub proofs for first stage");
    let mut agg1_proofs: [Option<AttestationAggregatorFirstStageProof>; AGG1_PROOFS_LEN] =
        std::array::from_fn(|_| None);
    for (i, stage2_group) in validator_data.iter().enumerate() {
        if let SecondStageGroupData::ValidatorGroupData(stage1_groups) = stage2_group {
            for (j, stage1_group) in stage1_groups.iter().enumerate() {
                if let FirstStageGroupData::ValidatorGroupData(validators) = stage1_group {
                    let agg1_data = AttestationAggregatorFirstStageData {
                        block_slot,
                        validators: validators
                            .into_iter()
                            .map(|v| AttestationAggregatorFirstStageValidatorData {
                                stake: v.stake,
                                commitment_root: v.commitment_root,
                                reveal: match &v.reveal {
                                    Some(r) => Some(AttestationAggregatorFirstStageRevealData {
                                        reveal: r.reveal,
                                        reveal_proof: r.proof.clone(),
                                    }),
                                    None => None,
                                },
                            })
                            .collect(),
                    };
                    agg1_proofs[i * AGGREGATION_STAGE3_SIZE + j] =
                        Some(circuits.attestations_aggregator1.generate_proof(&agg1_data)?);
                }
            }
        }
    }

    //generate second stage proofs
    log::info!("Generating sub proofs for second stage");
    let mut agg2_proofs: [Option<AttestationAggregatorSecondStageProof>; AGG2_PROOFS_LEN] =
        std::array::from_fn(|_| None);
    for (i, stage2_group) in validator_data.iter().enumerate() {
        if let SecondStageGroupData::ValidatorGroupData(stage1_groups) = stage2_group {
            let agg2_data = AttestationAggregatorSecondStageData {
                block_slot,
                agg1_data: stage1_groups
                    .iter()
                    .enumerate()
                    .map(|(j, stage1_group)| match stage1_group {
                        FirstStageGroupData::ValidatorGroupData(_) => {
                            let agg1_proof = agg1_proofs[i * AGGREGATION_STAGE3_SIZE + j].clone().unwrap();
                            AttestationAggregatorSecondStageAgg1Data {
                                validators_sub_root: agg1_proof.validators_sub_root(),
                                agg1_proof: Some(agg1_proof),
                            }
                        }
                        FirstStageGroupData::ValidatorGroupRoot(root) => AttestationAggregatorSecondStageAgg1Data {
                            validators_sub_root: root.clone(),
                            agg1_proof: None,
                        },
                    })
                    .collect(),
            };
            agg2_proofs[i] = Some(circuits.attestations_aggregator2.generate_proof(&agg2_data)?);
        }
    }

    //generate the final proof
    log::info!("Generating final aggregate proof");
    let agg3_data = AttestationAggregatorThirdStageData {
        block_slot,
        validators_state_proof: validators_state_proof.clone(),
        agg2_data: validator_data
            .iter()
            .enumerate()
            .map(|(j, stage2_group)| match stage2_group {
                SecondStageGroupData::ValidatorGroupData(_) => {
                    let agg2_proof = agg2_proofs[j].clone().unwrap();
                    AttestationAggregatorThirdStageAgg2Data {
                        validators_sub_root: agg2_proof.validators_sub_root(),
                        agg2_proof: Some(agg2_proof),
                    }
                }
                SecondStageGroupData::ValidatorGroupRoot(root) => AttestationAggregatorThirdStageAgg2Data {
                    validators_sub_root: root.clone(),
                    agg2_proof: None,
                },
            })
            .collect(),
    };
    let stage3_proof = circuits.attestations_aggregator3.generate_proof(&agg3_data)?;

    return Ok(stage3_proof);
}

fn example_validators_state(
    validators_state_circuit: &ValidatorsStateCircuit,
    accounts: &[[u8; 20]],
    validator_indexes: &[usize],
    stakes: &[u32],
) -> (
    ValidatorsTree,       //validators_tree
    ValidatorsStateProof, //validators_state_proof
) {
    log::info!("Generating example accounts");
    let mut validators_tree = initial_validators_tree();
    let mut accounts_tree = initial_accounts_tree();

    log::info!("Generating example validator state sub proof");
    let mut previous_proof: Option<ValidatorsStateProof> = Some(load_or_create_init_proof::<ValidatorsStateCircuit>(
        VALIDATORS_STATE_CIRCUIT_DIR,
    ));
    for ((&account, &validator_index), &stake) in accounts.iter().zip(validator_indexes).zip(stakes) {
        let commitment = example_commitment_root(validator_index);
        let data = compile_data_for_validators_state_circuit(
            &accounts_tree,
            &validators_tree,
            validator_index,
            stake,
            commitment,
            account,
            null_account_address(validator_index),
            account,
            previous_proof,
        );
        let proof = validators_state_circuit.generate_proof(&data).unwrap();
        assert!(
            validators_state_circuit.verify_proof(&proof).is_ok(),
            "Validators state proof verification failed."
        );
        validators_tree.set_validator(
            validator_index,
            Validator {
                commitment_root: commitment,
                stake,
            },
        );
        accounts_tree.set_account(Account {
            address: account,
            validator_index: Some(validator_index),
        });
        previous_proof = Some(proof);
    }
    let validators_state_proof = previous_proof.unwrap();

    (
        validators_tree,        //validators_tree
        validators_state_proof, //validators_state_proof
    )
}

fn compile_data_for_validators_state_circuit(
    accounts_tree: &AccountsTree,
    validators_tree: &ValidatorsTree,
    index: usize,
    stake: u32,
    commitment: [Field; 4],
    account: [u8; 20],
    from_account: [u8; 20],
    to_account: [u8; 20],
    previous_proof: Option<ValidatorsStateProof>,
) -> ValidatorsStateCircuitData {
    let curr_validator = validators_tree.validator(index);
    ValidatorsStateCircuitData {
        index,
        stake,
        commitment,
        account,

        validator_index: index,
        validator_stake: curr_validator.stake,
        validator_commitment: curr_validator.commitment_root,
        validator_proof: validators_tree.merkle_proof(index),

        from_account,
        from_acc_index: accounts_tree.account(from_account).validator_index,
        from_acc_proof: accounts_tree.merkle_proof(from_account),

        to_account,
        to_acc_index: accounts_tree.account(to_account).validator_index,
        to_acc_proof: accounts_tree.merkle_proof(to_account),

        previous_proof,
    }
}

#[inline]
fn write_all(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let result = buffer.write_all(bytes);
    if result.is_err() {
        return Err(anyhow!("Failed to serialize circuits"));
    }
    Ok(result.unwrap())
}
