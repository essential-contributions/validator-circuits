mod subcircuits;
use subcircuits::*;

use anyhow::{anyhow, Result};
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::util::serialization::Write;

use super::{
    participation_state_circuit::{ParticipationStateCircuit, ParticipationStateProof},
    validators_state_circuit::{
        ValidatorsStateCircuit, ValidatorsStateCircuitData, ValidatorsStateProof,
    },
    Circuit, Serializeable,
};
use crate::{
    accounts::{initial_accounts_tree, null_account_address, Account, AccountsTree},
    circuits::{
        load_or_create_circuit, load_or_create_init_proof,
        participation_state_circuit::ParticipationStateCircuitData,
        PARTICIPATION_STATE_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR,
    },
    commitment::example_commitment_root,
    epochs::{initial_validator_epochs_tree, ValidatorEpochsTree},
    participation::{
        initial_participation_rounds_tree, participation_root, ParticipationRound,
        ParticipationRoundsTree, PARTICIPATION_BITS_BYTE_SIZE,
    },
    validators::{initial_validators_tree, Validator, ValidatorsTree},
    Config, Field, D, PARTICIPATION_ROUNDS_PER_STATE_EPOCH,
};

pub type ValidatorParticipationProof = ValidatorParticipationAggEndProof;

pub struct ValidatorParticipationCircuit {
    participation_agg: ValidatorParticipationAggCircuit,
    participation_agg_end: ValidatorParticipationAggEndCircuit,
}

impl ValidatorParticipationCircuit {
    pub fn generate_proof(
        &self,
        data: &ValidatorParticipationCircuitData,
        validator_epochs_tree: &ValidatorEpochsTree,
        participation_rounds_tree: &ParticipationRoundsTree,
    ) -> Result<ValidatorParticipationProof> {
        generate_proof_from_data(
            &self,
            data,
            validator_epochs_tree,
            participation_rounds_tree,
        )
    }
}

impl Circuit for ValidatorParticipationCircuit {
    type Proof = ValidatorParticipationProof;

    fn new() -> Self {
        log::info!("Building sub circuit [ValidatorParticipationAggCircuit]");
        let participation_agg = ValidatorParticipationAggCircuit::new();
        log::info!("Building sub circuit [ValidatorParticipationAggEndCircuit]");
        let participation_agg_end =
            ValidatorParticipationAggEndCircuit::from_subcircuits(&participation_agg);

        Self {
            participation_agg,
            participation_agg_end,
        }
    }

    fn verify_proof(&self, proof: &Self::Proof) -> Result<()> {
        self.participation_agg_end.verify_proof(proof)
    }

    fn circuit_data(&self) -> &CircuitData<Field, Config, D> {
        return &self.participation_agg_end.circuit_data();
    }

    fn proof_to_bytes(&self, proof: &Self::Proof) -> Result<Vec<u8>> {
        Ok(self.participation_agg_end.proof_to_bytes(proof)?)
    }

    fn proof_from_bytes(&self, bytes: Vec<u8>) -> Result<Self::Proof> {
        Ok(self.participation_agg_end.proof_from_bytes(bytes)?)
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
        let validators_state_circuit =
            load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
        let participation_state_circuit =
            load_or_create_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR);

        //create prerequisite data
        let accounts = [[77u8; 20]];
        let validator_indexes = [77];
        let stakes = [64];
        let rounds = [32];
        let (validators_tree, accounts_tree, validators_state_proof) = example_validators_state(
            &validators_state_circuit,
            &accounts,
            &validator_indexes,
            &stakes,
        );
        let (validator_epochs_tree, participation_rounds_tree, participation_state_proof) =
            example_participation_state(
                &participation_state_circuit,
                &validators_state_proof,
                &validators_tree,
                &accounts_tree,
                &rounds,
            );

        //generate proof
        let data = ValidatorParticipationCircuitData {
            account_address: accounts[0],
            from_epoch: 0,
            to_epoch: 1,
            rf: 13093,
            st: 84,
            participation_state_proof: participation_state_proof.clone(),
        };
        Some(
            generate_proof_from_data(
                &self,
                &data,
                &validator_epochs_tree,
                &participation_rounds_tree,
            )
            .unwrap(),
        )
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
        let start1 = 8;
        be_bytes.copy_from_slice(&bytes[0..8]);
        let start2 = start1 + (u64::from_be_bytes(be_bytes) as usize);

        log::info!("Loading sub circuit from bytes [ValidatorParticipationAggCircuit]");
        let participation_agg =
            ValidatorParticipationAggCircuit::from_bytes(&(&bytes[start1..start2]).to_vec())?;
        log::info!("Loading sub circuit from bytes [ValidatorParticipationAggEndCircuit]");
        let participation_agg_end =
            ValidatorParticipationAggEndCircuit::from_bytes(&(&bytes[start2..]).to_vec())?;

        Ok(Self {
            participation_agg,
            participation_agg_end,
        })
    }
}

#[derive(Clone)]
pub struct ValidatorParticipationCircuitData {
    pub account_address: [u8; 20],
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub rf: u32,
    pub st: u32,

    pub participation_state_proof: ParticipationStateProof,
}

fn generate_proof_from_data(
    circuits: &ValidatorParticipationCircuit,
    data: &ValidatorParticipationCircuitData,
    validator_epochs_tree: &ValidatorEpochsTree,
    participation_rounds_tree: &ParticipationRoundsTree,
) -> Result<ValidatorParticipationProof> {
    if data.participation_state_proof.validator_epochs_tree_root() != validator_epochs_tree.root() {
        return Err(anyhow!(
            "Validator epochs tree root does not match the given participation state proof."
        ));
    }
    if data
        .participation_state_proof
        .participation_rounds_tree_root()
        != participation_rounds_tree.root()
    {
        return Err(anyhow!(
            "Participation rounds tree root does not match the given participation state proof."
        ));
    }

    //generate cyclical proof for each epoch
    let mut cyclical_proof = None;
    for epoch_num in (data.from_epoch as usize)..(data.to_epoch as usize) {
        log::info!("Generating proof for epoch {}", epoch_num);
        let validators_state_proof =
            match validator_epochs_tree.epoch_validators_state_proof(epoch_num) {
                Some(proof) => proof,
                None => load_or_create_init_proof::<ValidatorsStateCircuit>(
                    VALIDATORS_STATE_CIRCUIT_DIR,
                ),
            };
        let validators_tree = match validator_epochs_tree.epoch_validators_tree(epoch_num) {
            Some(proof) => proof,
            None => initial_validators_tree(),
        };
        let accounts_tree = match validator_epochs_tree.epoch_accounts_tree(epoch_num) {
            Some(proof) => proof,
            None => initial_accounts_tree(),
        };

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
            }
            None => None,
        };
        let participation_rounds = (0..PARTICIPATION_ROUNDS_PER_STATE_EPOCH)
            .map(|n| {
                let round_num = (epoch_num * PARTICIPATION_ROUNDS_PER_STATE_EPOCH) + n;
                let round = participation_rounds_tree.round(round_num);
                ValidatorPartAggRoundData {
                    participation_root: round.participation_root,
                    participation_count: round.participation_count,
                    participation_round_proof: participation_rounds_tree.merkle_proof(round_num),
                    participation_bits: participation_rounds_tree
                        .round_participation_bits(round_num),
                }
            })
            .collect();
        let previous_data = match cyclical_proof {
            Some(proof) => ValidatorPartAggPrevData::Continue(proof),
            None => ValidatorPartAggPrevData::Start(ValidatorPartAggStartData {
                val_epochs_tree_root: validator_epochs_tree.root(),
                pr_tree_root: participation_rounds_tree.root(),
                account: data.account_address,
                epoch: epoch_num as u32,
                param_rf: data.rf,
                param_st: data.st,
            }),
        };
        let data = ValidatorParticipationAggCircuitData {
            validator,
            account_validator_proof: accounts_tree.merkle_proof(data.account_address),
            validators_state_proof,
            validator_epochs_proof: validator_epochs_tree.merkle_proof(epoch_num),
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
    let proof = circuits
        .participation_agg_end
        .generate_proof(&data)
        .unwrap();

    Ok(proof)
}

fn example_validators_state(
    validators_state_circuit: &ValidatorsStateCircuit,
    accounts: &[[u8; 20]],
    validator_indexes: &[usize],
    stakes: &[u32],
) -> (
    ValidatorsTree,       //validators_tree
    AccountsTree,         //accounts_tree
    ValidatorsStateProof, //validators_state_proof
) {
    log::info!("Generating example accounts");
    let mut validators_tree = initial_validators_tree();
    let mut accounts_tree = initial_accounts_tree();

    log::info!("Generating example validator state sub proof");
    let mut previous_proof: Option<ValidatorsStateProof> = Some(load_or_create_init_proof::<
        ValidatorsStateCircuit,
    >(VALIDATORS_STATE_CIRCUIT_DIR));
    for ((&account, &validator_index), &stake) in accounts.iter().zip(validator_indexes).zip(stakes)
    {
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
        accounts_tree,          //accounts_tree
        validators_state_proof, //validators_state_proof
    )
}

fn example_participation_state(
    participation_state_circuit: &ParticipationStateCircuit,
    validators_state_proof: &ValidatorsStateProof,
    validators_tree: &ValidatorsTree,
    accounts_tree: &AccountsTree,
    rounds: &[usize],
) -> (
    ValidatorEpochsTree,     //validator_epochs_tree
    ParticipationRoundsTree, //participation_rounds_tree
    ParticipationStateProof, //participation_state_proof
) {
    let mut validator_epochs_tree = initial_validator_epochs_tree();
    let mut participation_rounds_tree = initial_participation_rounds_tree();

    let mut validator_indexes: Vec<usize> = Vec::new();
    for (i, v) in validators_tree.validators().iter().enumerate() {
        if v.stake > 0 {
            validator_indexes.push(i);
        }
    }

    let mut bit_flags: Vec<u8> = vec![0u8; PARTICIPATION_BITS_BYTE_SIZE];
    for validator_index in &validator_indexes {
        bit_flags[validator_index / 8] += 0x80 >> (validator_index % 8);
    }

    log::info!("Generating example participation state sub proof");
    let mut previous_proof: Option<ParticipationStateProof> =
        Some(load_or_create_init_proof::<ParticipationStateCircuit>(
            PARTICIPATION_STATE_CIRCUIT_DIR,
        ));
    for num in rounds {
        let epoch_num = num / PARTICIPATION_ROUNDS_PER_STATE_EPOCH;
        let round = ParticipationRound {
            num: *num,
            participation_root: participation_root(&bit_flags),
            participation_count: validator_indexes.len() as u32,
        };
        let current_epoch_data = validator_epochs_tree.epoch(epoch_num);
        let current_round_data = participation_rounds_tree.round(round.num);
        let proof = participation_state_circuit
            .generate_proof(&ParticipationStateCircuitData {
                round_num: round.num,
                val_state_inputs_hash: validators_state_proof.inputs_hash(),
                participation_root: round.participation_root,
                participation_count: round.participation_count,
                current_val_state_inputs_hash: current_epoch_data.validators_state_inputs_hash,
                validator_epoch_proof: validator_epochs_tree.merkle_proof(epoch_num),
                current_participation_root: current_round_data.participation_root,
                current_participation_count: current_round_data.participation_count,
                participation_round_proof: participation_rounds_tree.merkle_proof(round.num),
                previous_proof,
            })
            .unwrap();
        assert!(
            participation_state_circuit.verify_proof(&proof).is_ok(),
            "Participation state proof verification failed."
        );
        validator_epochs_tree.update_epoch(
            epoch_num,
            validators_state_proof,
            validators_tree,
            accounts_tree,
        );
        participation_rounds_tree.update_round(round.clone(), Some(bit_flags.clone()));
        previous_proof = Some(proof);
    }
    let participation_state_proof = previous_proof.unwrap();

    (
        validator_epochs_tree,     //validator_epochs_tree
        participation_rounds_tree, //participation_rounds_tree
        participation_state_proof, //participation_state_proof
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
