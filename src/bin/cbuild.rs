use clap::{arg, command, Parser};
use env_logger::{Builder, Env};
use validator_circuits::{bn128_wrapper::{bn128_wrapper_circuit_data_exists, bn128_wrapper_circuit_proof_exists, bn128_wrapper_clear_data_and_proof, load_or_create_bn128_wrapper_circuit, save_bn128_wrapper_proof}, circuits::{attestations_aggregator_circuit::AttestationsAggregatorCircuit, circuit_data_exists, circuit_proof_exists, clear_data_and_proof, load_or_create_circuit, load_or_create_example_proof, participation_circuit::ParticipationCircuit, Circuit, Serializeable, ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR, PARTICIPATION_CIRCUIT_DIR}, groth16_wrapper::{create_groth16_wrapper_circuit, groth16_wrapper_circuit_data_exists, groth16_wrapper_circuit_proof_exists, groth16_wrapper_clear_data_and_proof}};
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Builds the circuits related to validator activities")]
struct Args {
    #[arg(short, long, default_value_t = false, help = "Build full circuits including wrappers")]
    full: bool,

    #[arg(short, long, default_value_t = false, help = "Clear out existing circuits before building")]
    clear: bool,

    #[arg(long, help = "Option to build a single circuit by name (state/attestations/participation)")]
    circuit: Option<String>,
}

fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    match args.circuit {
        Some(circuit_name) => {
            if circuit_name.eq("state")  {
                //TODO
            } else if circuit_name.eq("attestations")  {
                build_circuit::<AttestationsAggregatorCircuit>(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR, args.full, args.clear);
            } else if circuit_name.eq("participation")  {
                build_circuit::<ParticipationCircuit>(PARTICIPATION_CIRCUIT_DIR, args.full, args.clear);
            } else {
                log::error!("Invalid circuit name [{}]", circuit_name);
            }
        },
        None => {
            build_circuit::<AttestationsAggregatorCircuit>(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR, args.full, args.clear);
            build_circuit::<ParticipationCircuit>(PARTICIPATION_CIRCUIT_DIR, args.full, args.clear);
        },
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
    let no_data = !circuit_data_exists(dir);
    let no_proof = !circuit_proof_exists(dir);
    let no_bn128_wrapper_data = !full || !bn128_wrapper_circuit_data_exists(dir);
    let no_bn128_wrapper_proof = !full || !bn128_wrapper_circuit_proof_exists(dir);
    let no_groth16_wrapper_data = !full || !groth16_wrapper_circuit_data_exists(dir);
    let no_groth16_wrapper_proof = !full || !groth16_wrapper_circuit_proof_exists(dir);
    if no_data || no_proof || no_bn128_wrapper_data || no_bn128_wrapper_proof {

        //base circuit
        if no_data {
            log::info!("Building circuit [/{}]", dir);
        } else {
            log::info!("Loading circuit [/{}]", dir);
        }
        let circuit = load_or_create_circuit::<C>(dir);

        //base circuit example proof
        if no_proof {
            log::info!("Generating example proof [/{}]", dir);
        } else {
            log::info!("Loading example proof [/{}]", dir);
        }
        let example_proof = load_or_create_example_proof(&circuit, dir);

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
                let bn128_wrapper_proof = bn128_wrapper_circuit.generate_proof(circuit.circuit_data(), &example_proof);
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
