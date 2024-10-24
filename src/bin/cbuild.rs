use clap::{arg, command, Parser};
use env_logger::{Builder, Env};
use jemallocator::Jemalloc;
use validator_circuits::{
    circuits::wrappers::{
        bn128_wrapper_circuit_data_exists, bn128_wrapper_circuit_proof_exists, bn128_wrapper_clear_data_and_proof,
        load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof,
    },
    circuits::wrappers::{
        create_groth16_wrapper_circuit, groth16_wrapper_circuit_data_exists, groth16_wrapper_circuit_proof_exists,
        groth16_wrapper_clear_data_and_proof,
    },
    circuits::{
        attestation_aggregation_circuit::AttestationAggregationCircuit, circuit_data_exists, circuit_init_proof_exists,
        clear_data_and_proof, load_or_create_circuit, load_or_create_init_proof,
        participation_state_circuit::ParticipationStateCircuit,
        validator_participation_circuit::ValidatorParticipationCircuit,
        validators_state_circuit::ValidatorsStateCircuit, Circuit, Proof, Serializeable,
        ATTESTATION_AGGREGATION_CIRCUIT_DIR, PARTICIPATION_STATE_CIRCUIT_DIR, VALIDATORS_STATE_CIRCUIT_DIR,
        VALIDATOR_PARTICIPATION_CIRCUIT_DIR,
    },
};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Builds the circuits related to validator activities")]
struct Args {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "Build full circuits including wrappers"
    )]
    full: bool,

    #[arg(
        short,
        long,
        default_value_t = false,
        help = "Clear out existing circuits before building"
    )]
    clear: bool,

    #[arg(
        long,
        help = "Option to build a single circuit by name (state/attestations/participation)"
    )]
    circuit: Option<String>,
}

fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    match args.circuit {
        Some(circuit_name) => {
            if circuit_name.eq("state") {
                build_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR, args.full, args.clear);
                build_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR, args.full, args.clear);
            } else if circuit_name.eq("attestations") {
                build_circuit::<AttestationAggregationCircuit>(
                    ATTESTATION_AGGREGATION_CIRCUIT_DIR,
                    args.full,
                    args.clear,
                );
            } else if circuit_name.eq("participation") {
                build_circuit::<ValidatorParticipationCircuit>(
                    VALIDATOR_PARTICIPATION_CIRCUIT_DIR,
                    args.full,
                    args.clear,
                );
            } else {
                log::error!("Invalid circuit name [{}]", circuit_name);
            }
        }
        None => {
            build_circuit::<ValidatorsStateCircuit>(VALIDATORS_STATE_CIRCUIT_DIR, args.full, args.clear);
            build_circuit::<ParticipationStateCircuit>(PARTICIPATION_STATE_CIRCUIT_DIR, args.full, args.clear);
            build_circuit::<AttestationAggregationCircuit>(ATTESTATION_AGGREGATION_CIRCUIT_DIR, args.full, args.clear);
            build_circuit::<ValidatorParticipationCircuit>(VALIDATOR_PARTICIPATION_CIRCUIT_DIR, args.full, args.clear);
        }
    }
}

pub fn build_circuit<C>(dir: &str, full: bool, clear: bool)
where
    C: Circuit + Serializeable,
{
    //clear old data
    if clear {
        clear_data_and_proof(dir);
        bn128_wrapper_clear_data_and_proof(dir);
        groth16_wrapper_clear_data_and_proof(dir);
    }

    //check current build artifacts
    let cyclical = C::is_cyclical();
    let wrappable = C::is_wrappable();
    let no_data = !circuit_data_exists(dir);
    let no_proof = cyclical && !circuit_init_proof_exists(dir);
    let no_bn128_wrapper_data = full && wrappable && !bn128_wrapper_circuit_data_exists(dir);
    let no_bn128_wrapper_proof = full && wrappable && !bn128_wrapper_circuit_proof_exists(dir);
    let no_groth16_wrapper_data = full && wrappable && !groth16_wrapper_circuit_data_exists(dir);
    let no_groth16_wrapper_proof = full && wrappable && !groth16_wrapper_circuit_proof_exists(dir);
    if no_data || no_proof || no_bn128_wrapper_data || no_bn128_wrapper_proof {
        //base circuit
        if no_data {
            log::info!("Building circuit [/{}]", dir);
        } else {
            log::info!("Loading circuit [/{}]", dir);
        }
        let circuit = load_or_create_circuit::<C>(dir);

        //initial proof for cyclical circuits
        if no_proof {
            load_or_create_init_proof::<C>(dir);
        }

        //log that circuits are not for wrapping
        if full && !wrappable {
            log::info!("Skipping wrapped proof generation for internal proof (only used recursively in other proofs).");
        }

        //bn128 wrapper
        if no_bn128_wrapper_data || no_bn128_wrapper_proof {
            if no_bn128_wrapper_data {
                log::info!("Building bn128 wrapper circuit [/{}]", dir);
            } else {
                log::info!("Loading bn128 wrapper circuit for example proof generation [/{}]", dir);
            }
            let bn128_wrapper_circuit = load_or_create_bn128_wrapper_circuit(circuit.circuit_data(), dir);
            if no_bn128_wrapper_proof {
                log::info!("Generating bn128 wrapper example proof [/{}]", dir);
                let example_proof = circuit.wrappable_example_proof().unwrap();
                let bn128_wrapper_proof =
                    bn128_wrapper_circuit.generate_proof(circuit.circuit_data(), &example_proof.proof());
                save_bn128_wrapper_proof(&bn128_wrapper_proof.unwrap(), dir);
            }
        }
    }

    //groth16 wrapper
    if no_groth16_wrapper_data || no_groth16_wrapper_proof {
        if no_groth16_wrapper_data {
            log::info!("Building groth16 wrapper circuit [/{}] (this can take a while...)", dir);
            create_groth16_wrapper_circuit(dir);
        }
    }
}
