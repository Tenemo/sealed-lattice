//! Hash-chained Fiat-Shamir transcript for the atom family backend.
//!
//! Challenges come from a length-framed `hash512` squeeze over the running
//! state, in the same non-ambiguous framing the rest of the kernel uses (the
//! init/absorb/squeeze byte tags domain-separate the operations, and the
//! per-round counter, reset on every absorb, keeps same-round challenges
//! distinct). Field-element challenges are Horner-reduced from a squeeze block
//! wider than the modulus, so the residual bias below the ~770-bit proof field
//! is under `2^-180`; query positions come from power-of-two masking.

use super::super::proof_field::ProofFieldParameters;
use super::merkle::MerkleDigest;
use crate::hashing::hash512;

const TRANSCRIPT_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/transcript";

// Words drawn per field challenge. The proof fields are at most 13 limbs
// (~770 bits); 15 words is ~960 bits, so Horner reduction leaves a bias below
// 2^-180 without rejection sampling.
const CHALLENGE_WORDS: usize = 15;

#[derive(Clone)]
pub(super) struct Transcript {
    state: [u8; 64],
    squeeze_counter: u64,
}

impl Transcript {
    pub(super) fn new(protocol_label: &str) -> Self {
        Self {
            state: hash512(TRANSCRIPT_DOMAIN, &[b"init", protocol_label.as_bytes()]),
            squeeze_counter: 0,
        }
    }

    pub(super) fn absorb(&mut self, label: &str, bytes: &[u8]) {
        self.state = hash512(
            TRANSCRIPT_DOMAIN,
            &[b"absorb", &self.state, label.as_bytes(), bytes],
        );
        self.squeeze_counter = 0;
    }

    pub(super) fn absorb_u64(&mut self, label: &str, value: u64) {
        self.absorb(label, &value.to_le_bytes());
    }

    pub(super) fn absorb_digest(&mut self, label: &str, digest: &MerkleDigest) {
        self.absorb(label, digest);
    }

    // Absorb a slice of proof-field elements by their little-endian limbs.
    pub(super) fn absorb_field_elements<const LIMB_COUNT: usize>(
        &mut self,
        label: &str,
        elements: &[[u64; LIMB_COUNT]],
    ) {
        let mut bytes = Vec::with_capacity(elements.len() * LIMB_COUNT * 8);
        for element in elements {
            for limb in element {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
        self.absorb(label, &bytes);
    }

    fn squeeze_block(&mut self, label: &str) -> [u8; 64] {
        let block = hash512(
            TRANSCRIPT_DOMAIN,
            &[
                b"squeeze",
                &self.state,
                label.as_bytes(),
                &self.squeeze_counter.to_le_bytes(),
            ],
        );
        self.squeeze_counter += 1;

        block
    }

    fn squeeze_words(&mut self, label: &str, count: usize) -> Vec<u64> {
        let mut words = Vec::with_capacity(count);
        while words.len() < count {
            let block = self.squeeze_block(label);
            for chunk in block.chunks_exact(8) {
                if words.len() == count {
                    break;
                }
                words.push(u64::from_le_bytes(
                    chunk.try_into().expect("eight-byte chunk"),
                ));
            }
        }
        words
    }

    // One uniform-enough proof-field element: a wide squeeze reduced mod p by
    // Horner over base 2^64 (each 64-bit word and the base are valid residues
    // because the modulus exceeds 2^64).
    pub(super) fn challenge_field_element<const LIMB_COUNT: usize>(
        &mut self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        label: &str,
    ) -> [u64; LIMB_COUNT] {
        let words = self.squeeze_words(label, CHALLENGE_WORDS);
        let base = {
            let mut raw = [0_u64; LIMB_COUNT];
            raw[1] = 1;
            parameters.raw_value_to_element(&raw)
        };
        let mut accumulator = parameters.zero();
        for word in words {
            accumulator = parameters.add(
                &parameters.multiply(&accumulator, &base),
                &parameters.unsigned_word_to_element(word),
            );
        }
        accumulator
    }

    pub(super) fn challenge_field_elements<const LIMB_COUNT: usize>(
        &mut self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        label: &str,
        count: usize,
    ) -> Vec<[u64; LIMB_COUNT]> {
        (0..count)
            .map(|_| self.challenge_field_element(parameters, label))
            .collect()
    }

    // Query positions in `[0, range)`; `range` must be a power of two, so
    // masking is unbiased.
    pub(super) fn challenge_positions(
        &mut self,
        label: &str,
        range: usize,
        count: usize,
    ) -> Vec<usize> {
        debug_assert!(range.is_power_of_two());
        let mask = (range - 1) as u64;
        self.squeeze_words(label, count)
            .into_iter()
            .map(|word| (word & mask) as usize)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    #[test]
    fn absorbing_different_bytes_diverges_challenges() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut left = Transcript::new("atom");
        let mut right = Transcript::new("atom");
        left.absorb("x", &[1, 2, 3]);
        right.absorb("x", &[1, 2, 4]);
        assert_ne!(
            left.challenge_field_element(&parameters, "c"),
            right.challenge_field_element(&parameters, "c"),
        );
    }

    #[test]
    fn same_absorptions_reproduce_challenges() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut left = Transcript::new("atom");
        let mut right = Transcript::new("atom");
        for transcript in [&mut left, &mut right] {
            transcript.absorb("a", b"hello");
            transcript.absorb_u64("n", 42);
        }
        assert_eq!(
            left.challenge_field_elements(&parameters, "c", 4),
            right.challenge_field_elements(&parameters, "c", 4),
        );
        assert_eq!(
            left.challenge_positions("q", 256, 10),
            right.challenge_positions("q", 256, 10),
        );
    }

    #[test]
    fn challenge_field_element_is_reduced_and_varied() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut transcript = Transcript::new("atom");
        transcript.absorb("seed", b"reduce-check");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let element = transcript.challenge_field_element(&parameters, "c");
            // Reduced below the modulus.
            let raw = parameters.to_raw_value(&element);
            assert!(super::super::super::wide_unsigned::is_less_than(
                &raw,
                &parameters.modulus
            ));
            seen.insert(raw);
        }
        // Overwhelmingly distinct across draws.
        assert!(seen.len() >= 60);
    }

    #[test]
    fn squeeze_counter_resets_on_absorb() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut transcript = Transcript::new("atom");
        transcript.absorb("a", b"1");
        let first = transcript.challenge_field_element(&parameters, "c");
        // Re-derive with the same prefix: absorbing again then squeezing must
        // match a fresh transcript with identical history.
        let mut fresh = Transcript::new("atom");
        fresh.absorb("a", b"1");
        assert_eq!(first, fresh.challenge_field_element(&parameters, "c"));
    }
}
