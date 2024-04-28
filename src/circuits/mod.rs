mod aggregator_circuit;
mod batch_circuit;
mod update_circuit;

//pub use aggregator_circuit::*;
pub use batch_circuit::*;
//pub use update_circuit::*;

//TODO: create function to get already compiled circuits

pub const REVEAL_BATCH_MAX_SIZE: usize = batch_circuit::REVEAL_BATCH_MAX_SIZE;

pub struct ValidatorCircuits {
    pub batch_circuit: BatchCircuit,
}

pub fn build_circuits() -> ValidatorCircuits {
    ValidatorCircuits {
        batch_circuit: BatchCircuit::new(),
    }
}
