mod actions;

use clap::{arg, command, Parser};
use env_logger::{Builder, Env};
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(help = "The action to benchmark (commitment/attestations/participation/update)")]
    action: String,

    #[arg(short, long, default_value_t = false, help = "Build full circuits including wrappers")]
    full: bool,
}

fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    
    let args = Args::parse();
    if args.action.eq("commitment")  {
        actions::benchmark_commitment_generation();
    } else if args.action.eq("attestations")  {
        actions::benchmark_prove_attestations_aggregation(args.full);
    } else if args.action.eq("participation")  {
        actions::benchmark_prove_participation(args.full);
    } else if args.action.eq("update")  {
        actions::benchmark_prove_validators_update(args.full);
    } else {
        log::error!("Invalid action [{}]", args.action);
    }
}
