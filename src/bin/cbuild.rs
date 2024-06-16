use clap::{arg, command, Parser};
use env_logger::{Builder, Env};
use validator_circuits::circuits::{attestations_aggregator_circuit::AttestationsAggregatorCircuit, circuit_data_exists, circuit_proof_exists, load_or_create_circuit, participation_circuit::ParticipationCircuit, save_proof, validators_update_circuit::ValidatorsUpdateCircuit, Circuit, Serializeable, ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR, PARTICIPATION_CIRCUIT_DIR, VALIDATORS_UPDATE_CIRCUIT_DIR};

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Builds the circuits related to validator activities")]
struct Args {
    #[arg(short, long, default_value_t = false, help = "Build full circuits including wrappers")]
    full: bool,

    #[arg(short, long, default_value_t = false, help = "Clear out existing circuits before building")]
    clear: bool,

    #[arg(long, help = "Option to build a single circuit by name (attestations/participation/update)")]
    circuit: Option<String>,
}

fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if args.full {
        compile_groth16_wrapper();
    }

    match args.circuit {
        Some(circuit_name) => {
            if circuit_name.eq("attestations")  {
                build_circuit::<AttestationsAggregatorCircuit>(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR, args.full);
            } else if circuit_name.eq("participation")  {
                build_circuit::<ParticipationCircuit>(PARTICIPATION_CIRCUIT_DIR, args.full);
            } else if circuit_name.eq("update")  {
                build_circuit::<ValidatorsUpdateCircuit>(VALIDATORS_UPDATE_CIRCUIT_DIR, args.full);
            } else {
                log::error!("Invalid circuit name [{}]", circuit_name);
            }
        },
        None => {
            build_circuit::<ParticipationCircuit>(PARTICIPATION_CIRCUIT_DIR, args.full);
            build_circuit::<ValidatorsUpdateCircuit>(VALIDATORS_UPDATE_CIRCUIT_DIR, args.full);
            build_circuit::<AttestationsAggregatorCircuit>(ATTESTATIONS_AGGREGATOR_CIRCUIT_DIR, args.full);
        },
    }
}

fn compile_groth16_wrapper() {

}


pub fn build_circuit<C>(dir: &str, full: bool)
where
    C: Circuit + Serializeable,
{
    let no_data = !circuit_data_exists(dir);
    let no_proof = !circuit_proof_exists(dir);
    if no_data || no_proof {
        if no_data {
            log::info!("Building circuit [/{}]", dir);
        } else {
            log::info!("Loading circuit for example proof generation [/{}]", dir);
        }

        let participation_circuit = load_or_create_circuit::<C>(dir);
        if no_proof {
            log::info!("Generating example proof [/{}]", dir);
            save_proof(&participation_circuit.example_proof(), dir);
        }
    }






}
