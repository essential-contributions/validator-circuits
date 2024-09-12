use std::borrow::Borrow;

use plonky2::field::types::Field as Plonky2_Field;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::CircuitBuilderExtended;
use crate::{Field, D};

const H256_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn build_sha256_hash(
    builder: &mut CircuitBuilder<Field, D>,
    inputs: Vec<Target>,
) -> Vec<Target> {
    let mut state = [
        builder.constant(Field::from_canonical_u32(H256_256[0])),
        builder.constant(Field::from_canonical_u32(H256_256[1])),
        builder.constant(Field::from_canonical_u32(H256_256[2])),
        builder.constant(Field::from_canonical_u32(H256_256[3])),
        builder.constant(Field::from_canonical_u32(H256_256[4])),
        builder.constant(Field::from_canonical_u32(H256_256[5])),
        builder.constant(Field::from_canonical_u32(H256_256[6])),
        builder.constant(Field::from_canonical_u32(H256_256[7])),
    ];

    // Process each 512-bit (64-byte, 16-word) chunk of the input message
    let mut i = 0;
    while i + 16 <= inputs.len() {
        sha256_transform(builder, &mut state, &inputs[i..i + 16]);
        i += 16;
    }

    // Process the remaining words and bit length of the input message
    let bit_len = (inputs.len() * 32) as u64;
    let remaining_words = inputs.len() - i;
    if remaining_words > 0 {
        if remaining_words >= 14 {
            // Process the remainder first and then the length
            let mut buffer: Vec<Target> = Vec::new();
            for j in 0..16 {
                if j < remaining_words {
                    buffer.push(inputs[i + j]);
                } else if j == remaining_words {
                    buffer.push(builder.constant(Field::from_canonical_u32(0x80000000)));
                } else {
                    buffer.push(builder.zero());
                }
            }
            sha256_transform(builder, &mut state, &buffer);

            // Process the length by itself
            let w = generate_w(bit_len as u64, false)
                .map(|w| builder.constant(Field::from_canonical_u32(w)));
            sha256_compress(builder, &mut state, &w);
        } else {
            // Process the remainder and the bit length in a single pass
            let mut buffer: Vec<Target> = Vec::new();
            for j in 0..14 {
                if j < remaining_words {
                    buffer.push(inputs[i + j]);
                } else if j == remaining_words {
                    buffer.push(builder.constant(Field::from_canonical_u32(0x80000000)));
                } else {
                    buffer.push(builder.zero());
                }
            }
            buffer.push(builder.constant(Field::from_canonical_u32((bit_len >> 32) as u32)));
            buffer.push(builder.constant(Field::from_canonical_u32(bit_len as u32)));
            sha256_transform(builder, &mut state, &buffer);
        }
    } else {
        // Process the bit length with a more optimized method,
        // since we know the full buffer at circuit build time
        let w = generate_w(bit_len as u64, true)
            .map(|w| builder.constant(Field::from_canonical_u32(w)));
        sha256_compress(builder, &mut state, &w);
    }

    //return the final state
    state.to_vec()
}

fn sha256_transform(
    builder: &mut CircuitBuilder<Field, D>,
    state: &mut [Target],
    block: &[Target],
) {
    let mut w: Vec<Target> = Vec::new();
    for i in 0..16 {
        w.push(block[i]);
    }

    let mut w_bits: Vec<Vec<BoolTarget>> = Vec::new();
    for i in 0..16 {
        let bits = builder.split_le(w[i], 32);
        w_bits.push(bits);
    }

    // Extend the first 16 words into the remaining 48 words w[16..63]
    for i in 16..64 {
        let s0 = sigma(builder, w_bits[i - 15].clone(), 7, 18, 3);
        let s1 = sigma(builder, w_bits[i - 2].clone(), 17, 19, 10);
        let add = builder.add_many([w[i - 16], s0, w[i - 7], s1]);
        let wrapped_add = builder.split_low_high(add, 32, 34).0;

        w.push(wrapped_add);
        w_bits.push(builder.split_le(wrapped_add, 32));
    }

    // Run the compress loop
    sha256_compress(builder, state, &w);
}

fn sha256_compress(builder: &mut CircuitBuilder<Field, D>, state: &mut [Target], w: &[Target]) {
    // Initialize working variables to current hash value
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Compression function main loop
    for i in 0..64 {
        let k = builder.constant(Field::from_canonical_u32(K[i]));
        let s1 = big_sigma(builder, e, 6, 11, 25); //rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        let ch = ch(builder, e, f, g); //(e & f) ^ (!e & g);
        let temp1 = wrapping_add(builder, [h, s1, ch, k, w[i]]);
        let s0 = big_sigma(builder, a, 2, 13, 22); //rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        let maj = maj(builder, a, b, c); //(a & b) ^ (a & c) ^ (b & c);
        let temp2 = wrapping_add(builder, [s0, maj]);

        h = g;
        g = f;
        f = e;
        e = wrapping_add(builder, [d, temp1]);
        d = c;
        c = b;
        b = a;
        a = wrapping_add(builder, [temp1, temp2]);
    }

    // Add the compressed chunk to the current hash value
    state[0] = wrapping_add(builder, [state[0], a]);
    state[1] = wrapping_add(builder, [state[1], b]);
    state[2] = wrapping_add(builder, [state[2], c]);
    state[3] = wrapping_add(builder, [state[3], d]);
    state[4] = wrapping_add(builder, [state[4], e]);
    state[5] = wrapping_add(builder, [state[5], f]);
    state[6] = wrapping_add(builder, [state[6], g]);
    state[7] = wrapping_add(builder, [state[7], h]);
}

// (a rrot r1) xor (a rrot r2) xor (a rsh s3)
fn sigma(
    builder: &mut CircuitBuilder<Field, D>,
    a_bits: Vec<BoolTarget>,
    r1: u8,
    r2: u8,
    s3: u8,
) -> Target {
    let mut s_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..32 {
        let r1_bit = a_bits[(i + (r1 as usize)) % 32];
        let r2_bit = a_bits[(i + (r2 as usize)) % 32];
        let s3_bit = if (i + (s3 as usize)) < 32 {
            a_bits[i + (s3 as usize)]
        } else {
            builder.constant_bool(false)
        };

        let xor1 = builder.xor(r1_bit, r2_bit);
        s_bits.push(builder.xor(xor1, s3_bit));
    }

    builder.le_sum(s_bits.clone().into_iter())
}

// (a rrot r1) xor (a rrot r2) xor (a rrot r3)
fn big_sigma(builder: &mut CircuitBuilder<Field, D>, a: Target, r1: u8, r2: u8, r3: u8) -> Target {
    let a_bits = builder.split_le(a, 32);
    let mut s_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..32 {
        let r1_bit = a_bits[(i + (r1 as usize)) % 32];
        let r2_bit = a_bits[(i + (r2 as usize)) % 32];
        let r3_bit = a_bits[(i + (r3 as usize)) % 32];

        let xor1 = builder.xor(r1_bit, r2_bit);
        s_bits.push(builder.xor(xor1, r3_bit));
    }

    builder.le_sum(s_bits.clone().into_iter())
}

// (e and f) xor ((not e) and g)
fn ch(builder: &mut CircuitBuilder<Field, D>, e: Target, f: Target, g: Target) -> Target {
    let e_bits = builder.split_le(e, 32);
    let f_bits = builder.split_le(f, 32);
    let g_bits = builder.split_le(g, 32);
    let mut ch_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..32 {
        let e_and_f = builder.and(e_bits[i], f_bits[i]);
        let not_e = builder.not(e_bits[i]);
        let not_e_and_g = builder.and(not_e, g_bits[i]);
        ch_bits.push(builder.xor(e_and_f, not_e_and_g));
    }

    builder.le_sum(ch_bits.clone().into_iter())
}

//(a and b) xor (a and c) xor (b and c);
fn maj(builder: &mut CircuitBuilder<Field, D>, a: Target, b: Target, c: Target) -> Target {
    let a_bits = builder.split_le(a, 32);
    let b_bits = builder.split_le(b, 32);
    let c_bits = builder.split_le(c, 32);
    let mut maj_bits: Vec<BoolTarget> = Vec::new();
    for i in 0..32 {
        let a_and_b = builder.and(a_bits[i], b_bits[i]);
        let a_and_c = builder.and(a_bits[i], c_bits[i]);
        let b_and_c = builder.and(b_bits[i], c_bits[i]);

        let xor1 = builder.xor(a_and_b, a_and_c);
        maj_bits.push(builder.xor(xor1, b_and_c));
    }

    builder.le_sum(maj_bits.clone().into_iter())
}

fn wrapping_add<T>(
    builder: &mut CircuitBuilder<Field, D>,
    terms: impl IntoIterator<Item = T>,
) -> Target
where
    T: Borrow<Target>,
{
    let add = builder.add_many(terms);
    builder.split_low_high(add, 32, 48).0
}

fn generate_w(bit_len: u64, include_byte_flag: bool) -> [u32; 64] {
    let mut block = [0u8; 64];
    if include_byte_flag {
        block[0] = 0x80;
    }
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = ((block[4 * i] as u32) << 24)
            | ((block[4 * i + 1] as u32) << 16)
            | ((block[4 * i + 2] as u32) << 8)
            | (block[4 * i + 3] as u32);
    }

    for i in 16..64 {
        let s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    w
}

fn rotate_right(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}
