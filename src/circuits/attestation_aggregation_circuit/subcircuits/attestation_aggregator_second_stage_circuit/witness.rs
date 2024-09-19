use anyhow::{anyhow, Result};
use plonky2::field::types::Field as Plonky2_Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;

use super::{AttAgg2Targets, AttestationAggregatorFirstStageProof};
use crate::circuits::Proof;
use crate::{Config, Field, AGGREGATION_STAGE2_SIZE, D};

#[derive(Clone)]
pub struct AttestationAggregatorSecondStageData {
    pub block_slot: usize,
    pub agg1_data: Vec<AttestationAggregatorSecondStageAgg1Data>,
}

#[derive(Clone)]
pub struct AttestationAggregatorSecondStageAgg1Data {
    pub validators_sub_root: [Field; 4],
    pub agg1_proof: Option<AttestationAggregatorFirstStageProof>,
}

pub fn generate_partial_witness(
    targets: &AttAgg2Targets,
    data: &AttestationAggregatorSecondStageData,
    atts_agg1_verifier: &VerifierOnlyCircuitData<Config, D>,
) -> Result<PartialWitness<Field>> {
    if data.agg1_data.len() != AGGREGATION_STAGE2_SIZE {
        return Err(anyhow!(
            "Must include {} datas in attestation aggregation second pass",
            AGGREGATION_STAGE2_SIZE
        ));
    }

    //find a proof to use as a dummy proof
    let mut dummy_proof: Option<AttestationAggregatorFirstStageProof> = None;
    for d in &data.agg1_data {
        if d.agg1_proof.is_some() {
            dummy_proof = d.agg1_proof.clone();
            break;
        }
    }
    if dummy_proof.is_none() {
        return Err(anyhow!(
            "Must include at least one valid proof in attestation aggregation second pass"
        ));
    }
    let dummy_proof = dummy_proof.unwrap();

    //create partial witness
    let mut pw = PartialWitness::new();
    pw.set_target(
        targets.block_slot,
        Field::from_canonical_u64(data.block_slot as u64),
    );
    pw.set_verifier_data_target(&targets.atts_agg1_verifier, &atts_agg1_verifier);

    for (t, v) in targets.atts_agg1_data.iter().zip(data.agg1_data.clone()) {
        let validators_sub_root: HashOut<Field> = HashOut::<Field> {
            elements: v.validators_sub_root,
        };
        pw.set_hash_target(t.validators_sub_root, validators_sub_root);
        match v.agg1_proof {
            Some(proof) => {
                pw.set_bool_target(t.has_participation, true);
                pw.set_proof_with_pis_target(&t.proof, proof.proof());
            }
            None => {
                pw.set_bool_target(t.has_participation, false);
                pw.set_proof_with_pis_target(&t.proof, dummy_proof.proof());
            }
        }
    }

    Ok(pw)
}
