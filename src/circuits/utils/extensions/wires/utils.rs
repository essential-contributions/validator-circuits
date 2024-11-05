use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::GeneratedValues,
        target::Target,
        witness::{PartitionWitness, Witness},
    },
};

#[cfg(test)]
use plonky2::iop::witness::WitnessWrite;

pub fn get_wire<F: RichField + Extendable<D>, const D: usize>(row: usize, wire: usize, witness: &PartitionWitness<F>, out_buffer: &GeneratedValues<F>) -> F {
    for v in out_buffer.target_values.iter() {
        if v.0 == Target::wire(row, wire) {
            return v.1;
        }
    }
    witness.get_target(Target::wire(row, wire))
}

#[cfg(test)]
pub fn values_to_witness<F: RichField + Extendable<D>, const D: usize>(wire_values: &[F], witness: &mut PartitionWitness<F>) {
    for (i, value) in wire_values.iter().enumerate() {
        witness.set_target(Target::wire(0, i), *value);
    }
}

#[cfg(test)]
pub fn output_to_values<F: RichField + Extendable<D>, const D: usize>(out_buffer: &GeneratedValues<F>, wire_values: &mut [F]) {
    for (target, value) in out_buffer.target_values.iter() {
        wire_values[target.index(wire_values.len(), 1)] = *value;
    }
}
