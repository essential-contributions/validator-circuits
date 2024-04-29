mod aggregator_circuit;
mod batch_circuit;
mod update_circuit;

use anyhow::Result;

pub use aggregator_circuit::*;
pub use batch_circuit::*;

//TODO: create function to get already compiled circuits

pub const REVEAL_BATCH_SIZE: usize = batch_circuit::REVEAL_BATCH_SIZE;
pub const AGGREGATOR_BATCH_SIZE: usize = aggregator_circuit::AGGREGATOR_BATCH_SIZE;

pub struct ValidatorCircuits {
    batch_circuit: BatchCircuit,
    aggregator_circuit: AggregatorCircuit,
}

impl ValidatorCircuits {
    pub fn build() -> Self {
        let batch_circuit = BatchCircuit::new();
        let aggregator_circuit = AggregatorCircuit::new(&batch_circuit);

        ValidatorCircuits {
            batch_circuit,
            aggregator_circuit,
        }
    }

    pub fn generate_batch_proof(&self, data: &BatchCircuitData) -> Result<BatchProof> {
        self.batch_circuit.generate_proof(data)
    }

    pub fn verify_batch_proof(&self, proof: &BatchProof) -> Result<()> {
        self.batch_circuit.verify_proof(proof)
    }

    pub fn generate_aggregate_proof(&self, data: &AggregatorCircuitData) -> Result<AggregateProof> {
        self.aggregator_circuit.generate_proof(data, &self.batch_circuit)
    }

    pub fn verify_aggregate_proof(&self, proof: &AggregateProof) -> Result<()> {
        self.aggregator_circuit.verify_proof(proof)
    }
}
