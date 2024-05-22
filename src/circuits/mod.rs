mod attestations_aggregator1_circuit;
mod attestations_aggregator2_circuit;
mod attestations_aggregator3_circuit;

use anyhow::*;

pub use attestations_aggregator1_circuit::*;
pub use attestations_aggregator2_circuit::*;
pub use attestations_aggregator3_circuit::*;

//TODO: create function to get already compiled circuits

pub struct ValidatorCircuits {
    attestations_aggregator1: AttestationsAggregator1Circuit,
    attestations_aggregator2: AttestationsAggregator2Circuit,
    attestations_aggregator3: AttestationsAggregator3Circuit,
}

impl ValidatorCircuits {
    pub fn build() -> Self {
        let attestations_aggregator1 = AttestationsAggregator1Circuit::new();
        let attestations_aggregator2 = AttestationsAggregator2Circuit::new(&attestations_aggregator1);
        let attestations_aggregator3 = AttestationsAggregator3Circuit::new(&attestations_aggregator2);

        ValidatorCircuits {
            attestations_aggregator1,
            attestations_aggregator2,
            attestations_aggregator3,
        }
    }

    pub fn generate_attestations_aggregator1_proof(&self, data: &AttestationsAggregator1Data) -> Result<AttestationsAggregator1Proof> {
        self.attestations_aggregator1.generate_proof(data)
    }
    pub fn verify_attestations_aggregator1_proof(&self, proof: &AttestationsAggregator1Proof) -> Result<()> {
        self.attestations_aggregator1.verify_proof(proof)
    }

    pub fn generate_attestations_aggregator2_proof(&self, data: &AttestationsAggregator2Data) -> Result<AttestationsAggregator2Proof> {
        self.attestations_aggregator2.generate_proof(data, &self.attestations_aggregator1)
    }
    pub fn verify_attestations_aggregator2_proof(&self, proof: &AttestationsAggregator2Proof) -> Result<()> {
        self.attestations_aggregator2.verify_proof(proof)
    }

    pub fn generate_attestations_aggregator3_proof(&self, data: &AttestationsAggregator3Data) -> Result<AttestationsAggregator3Proof> {
        self.attestations_aggregator3.generate_proof(data, &self.attestations_aggregator2)
    }
    pub fn verify_attestations_aggregator3_proof(&self, proof: &AttestationsAggregator3Proof) -> Result<()> {
        self.attestations_aggregator3.verify_proof(proof)
    }
}
