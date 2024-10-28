use std::time::Instant;

use blake3::Hasher as Blake3_Hasher;
use clap::{arg, command, Parser};
use env_logger::{Builder, Env};
use jemallocator::Jemalloc;
use plonky2::field::types::PrimeField64;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use validator_circuits::{
    accounts::{Account, AccountsTree},
    circuits::{
        load_or_create_circuit, load_or_create_init_proof, load_proof, save_proof,
        validators_state_circuit::{ValidatorsStateCircuit, ValidatorsStateCircuitData},
        VALIDATORS_STATE_CIRCUIT_DIR,
    },
    commitment::{example_commitment_reveal, example_commitment_root},
    file_exists,
    validators::{Validator, ValidatorCommitmentReveal, ValidatorsTree},
};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const VALIDATORS_PROOF_INTERVAL: usize = 512;
const VALIDATORS_PROOF_DIR: [&str; 3] = ["data", "large_setup", "validators_state_proofs"];

fn validators_proof_filename(iteration: usize) -> String {
    format!("validators_{}.proof", iteration)
}

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = "Constructs large sample environment data for benchmarking at full scale"
)]
struct Args {
    #[arg(
        short,
        long,
        default_value_t = 1048576,
        help = "Number of validators to build into validator state"
    )]
    validators: usize,

    #[arg(
        short,
        long,
        default_value_t = 384,
        help = "Number of epochs to build participation for"
    )]
    participation: usize,
}

fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    //scan for proof files
    println!("Searching Already Generated Proofs...");
    let mut iteration = 0;
    for i in (0..args.validators).step_by(VALIDATORS_PROOF_INTERVAL) {
        let j = i + VALIDATORS_PROOF_INTERVAL;
        let filename = validators_proof_filename(j);
        let exists = file_exists(&VALIDATORS_PROOF_DIR, &filename);
        if exists {
            iteration = j;
        } else {
            break;
        }
    }
    if iteration >= args.validators {
        println!("Proofs already generated for all {} validators", args.validators);
        return;
    }
    println!("latest proof found for iteration {}", iteration);
    println!();

    //load the validators state circuit
    println!("Building Validators State Circuit... ");
    let start = Instant::now();
    let validators_state_circuit = load_or_create_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
    println!("(finished in {:?})", start.elapsed());
    println!();

    //get the starting proof
    let mut proof = if iteration == 0 {
        println!("Building Initial Proof...");
        let start = Instant::now();
        let p = load_or_create_init_proof::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR);
        println!("(finished in {:?})", start.elapsed());
        println!();
        p
    } else {
        let filename = validators_proof_filename(iteration);
        load_proof(&validators_state_circuit, &VALIDATORS_PROOF_DIR, &filename).unwrap()
    };

    //build account tree from last iteration
    println!("Building Account Tree...");
    let start = std::time::Instant::now();
    let mut accounts_tree = accounts_tree_at(iteration);
    println!("finished: {:?}", start.elapsed());
    println!();

    //build validators tree from last iteration
    println!("Building Validator Tree...");
    let start = std::time::Instant::now();
    let mut validators_tree = validators_tree_at(iteration);
    println!("finished: {:?}", start.elapsed());
    let total_staked = total_validator_stake(iteration);
    println!("total staked: {}", total_staked);
    println!();

    //resume proof generation from where it left off
    println!("Generating Proofs...");
    for i in iteration..args.validators {
        //generate proof
        let curr_validator = validators_tree.validator(i);
        let new_validator = Validator {
            commitment_root: example_commitment_root(i),
            stake: validator_stake(i),
        };
        let new_validator_address = account_address(i);
        let from_account = accounts_tree.account_with_index(i);
        let to_account = accounts_tree.account(new_validator_address);
        let data = ValidatorsStateCircuitData {
            index: i,
            stake: new_validator.stake,
            commitment: new_validator.commitment_root,
            account: new_validator_address,

            validator_index: i,
            validator_stake: curr_validator.stake,
            validator_commitment: curr_validator.commitment_root,
            validator_proof: validators_tree.merkle_proof(i),

            from_account: from_account.address,
            from_acc_index: from_account.validator_index,
            from_acc_proof: accounts_tree.merkle_proof(from_account.address),

            to_account: to_account.address,
            to_acc_index: to_account.validator_index,
            to_acc_proof: accounts_tree.merkle_proof(to_account.address),

            previous_proof: Some(proof),
        };
        proof = validators_state_circuit.generate_proof(&data).unwrap();
        println!("finished proof {}", (i + 1));

        //update trees
        validators_tree.set_validator(i, new_validator);
        accounts_tree.set_account(Account {
            address: new_validator_address,
            validator_index: Some(i),
        });

        //save proof
        if (i + 1) % VALIDATORS_PROOF_INTERVAL == 0 {
            let filename = validators_proof_filename(i + 1);
            save_proof(&validators_state_circuit, &proof, &VALIDATORS_PROOF_DIR, &filename).unwrap();
            println!("saved proof to file: {}", filename);
        }
    }
    println!();

    /*
    println!("Gathering Attestations");
    let start = std::time::Instant::now();
    let attestations = validators_attestation_at(iterations, 0, total_staked);
    println!("finished: {:?}", start.elapsed());
    println!("attestations: {}", attestations.len());
    println!();

    println!("Verify Attestations");
    let start = std::time::Instant::now();
    validators_tree.verify_attestations(attestations).unwrap();
    println!("finished: {:?}", start.elapsed());
    println!();
    */
}

fn accounts_tree_at(iteration: usize) -> AccountsTree {
    let accounts = (0..iteration)
        .into_par_iter()
        .map(|i| Account {
            address: account_address(i),
            validator_index: Some(i),
        })
        .collect::<Vec<Account>>();
    AccountsTree::from_accounts(&accounts)
}

fn validators_tree_at(iteration: usize) -> ValidatorsTree {
    let validators = (0..iteration)
        .into_par_iter()
        .map(|i| Validator {
            commitment_root: example_commitment_root(i),
            stake: validator_stake(i),
        })
        .collect::<Vec<Validator>>();
    ValidatorsTree::from_validators(&validators)
}

fn validators_attestation_at(
    iteration: usize,
    block_slot: usize,
    desired_stake: u32,
) -> Vec<ValidatorCommitmentReveal> {
    let mut rng = rand::thread_rng();
    let mut validator_indexes = (0..iteration).collect::<Vec<usize>>();
    validator_indexes.shuffle(&mut rng);
    let mut total_stake = 0;
    let mut selected_validators = Vec::new();
    for i in 0..iteration {
        if total_stake >= desired_stake {
            break;
        }
        total_stake += validator_stake(i);
        selected_validators.push(i);
    }

    let attestations = selected_validators
        .into_par_iter()
        .map(|i| {
            let proof = example_commitment_reveal(i, block_slot);
            ValidatorCommitmentReveal {
                validator_index: i,
                block_slot,
                reveal: proof.reveal,
                proof: proof.proof,
            }
        })
        .collect::<Vec<ValidatorCommitmentReveal>>();
    attestations
}

fn total_validator_stake(iterations: usize) -> u32 {
    (0..iterations).map(validator_stake).sum()
}

fn validator_stake(validator_index: usize) -> u32 {
    let mut hasher = Blake3_Hasher::new();
    hasher.update(&validator_index.to_be_bytes());
    hasher.update(&[12u8; 32]); //salt
    let h: [u8; 32] = hasher.finalize().into();

    let stakes: [u32; 8] = [8, 16, 24, 32, 48, 64, 96, 128];
    stakes[h[0] as usize % 8]
}

fn account_address(validator_index: usize) -> [u8; 20] {
    let mut hasher = Blake3_Hasher::new();
    hasher.update(&validator_index.to_be_bytes());
    hasher.update(&[78u8; 32]); //salt
    let result = hasher.finalize();
    let hash: [u8; 32] = result.into();

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[0..20]);
    address
}

fn next_inputs_hash(previous_hash: [u8; 32], data: ValidatorsStateCircuitData) -> [u8; 32] {
    let mut to_hash = [0u8; 92];
    to_hash[0..32].copy_from_slice(&previous_hash);
    to_hash[32..36].copy_from_slice(&(data.index as u32).to_be_bytes());
    to_hash[36..40].copy_from_slice(&(data.stake as u32).to_be_bytes());
    to_hash[40..48].copy_from_slice(&data.commitment[0].to_canonical_u64().to_be_bytes());
    to_hash[48..56].copy_from_slice(&data.commitment[1].to_canonical_u64().to_be_bytes());
    to_hash[56..64].copy_from_slice(&data.commitment[2].to_canonical_u64().to_be_bytes());
    to_hash[64..72].copy_from_slice(&data.commitment[3].to_canonical_u64().to_be_bytes());
    to_hash[72..92].copy_from_slice(&data.account);

    let mut hasher = Sha256::new();
    hasher.update(&to_hash);
    let result = hasher.finalize();
    let hash: [u8; 32] = result.into();
    hash
}
