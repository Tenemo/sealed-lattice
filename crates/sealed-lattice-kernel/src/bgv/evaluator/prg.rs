use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    encoding::{append_bytes, append_varuint},
    hashing::HASH512_PREIMAGE_PREFIX,
};

// Deterministic SHAKE256 sampler used only for the development evaluation key
// set and development encryptions that exercise the evaluator. The preimage is
// framed exactly like `hash512` so the stream is domain-separated and
// byte-identical across native and WASM builds. This is development key/seed
// material, never production-grade entropy.
pub(crate) struct DeterministicSampler {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl DeterministicSampler {
    pub(crate) fn new(domain: &str, parts: &[&[u8]]) -> Self {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(HASH512_PREIMAGE_PREFIX);
        append_bytes(&mut preimage, domain.as_bytes());
        append_varuint(&mut preimage, parts.len() as u64);
        for part in parts {
            append_bytes(&mut preimage, part);
        }
        let mut hasher = Shake256::default();
        hasher.update(&preimage);

        Self {
            reader: hasher.finalize_xof(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.reader.read(&mut bytes);

        u64::from_le_bytes(bytes)
    }

    fn next_byte(&mut self) -> u8 {
        let mut byte = [0_u8; 1];
        self.reader.read(&mut byte);

        byte[0]
    }

    // Raw stream bytes, used for development commitment salts.
    pub(crate) fn bytes(&mut self, count: usize) -> Vec<u8> {
        let mut output = vec![0_u8; count];
        self.reader.read(&mut output);

        output
    }

    // Rejection-sampled uniform residues in [0, modulus). The rejection zone
    // removes modulo bias; for the selected ~47-bit primes the rejection rate is
    // negligible.
    pub(crate) fn uniform_residues(&mut self, modulus: u64, count: usize) -> Vec<u64> {
        let zone = (u64::MAX / modulus) * modulus;
        let mut output = Vec::with_capacity(count);
        while output.len() < count {
            let candidate = self.next_u64();
            if candidate < zone {
                output.push(candidate % modulus);
            }
        }

        output
    }

    // Ternary secret/randomizer coefficients in {-1, 0, 1}. Two bits per draw,
    // rejecting the unused fourth value to stay unbiased.
    pub(crate) fn ternary(&mut self, count: usize) -> Vec<i64> {
        let mut output = Vec::with_capacity(count);
        while output.len() < count {
            let byte = self.next_byte();
            for shift in [0_u8, 2, 4, 6] {
                if output.len() == count {
                    break;
                }
                let two_bits = (byte >> shift) & 0b11;
                if two_bits < 3 {
                    output.push(i64::from(two_bits) - 1);
                }
            }
        }

        output
    }

    // Centered binomial error coefficients with parameter eta = 2, giving values
    // in {-2, -1, 0, 1, 2}. Four bits per draw: (a0 + a1) - (b0 + b1).
    pub(crate) fn centered_binomial_eta2(&mut self, count: usize) -> Vec<i64> {
        let mut output = Vec::with_capacity(count);
        while output.len() < count {
            let byte = self.next_byte();
            for shift in [0_u8, 4] {
                if output.len() == count {
                    break;
                }
                let nibble = (byte >> shift) & 0b1111;
                let positive = i64::from((nibble & 1) + ((nibble >> 1) & 1));
                let negative = i64::from(((nibble >> 2) & 1) + ((nibble >> 3) & 1));
                output.push(positive - negative);
            }
        }

        output
    }
}
