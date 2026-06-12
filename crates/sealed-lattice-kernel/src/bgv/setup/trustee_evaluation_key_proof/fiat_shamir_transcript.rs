use super::extension_field::{CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement};
use crate::hashing::hash512;

const TRANSCRIPT_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/transcript-v1";

// Hash-chained Fiat-Shamir transcript over the kernel hash. Challenges are
// derived from labelled squeeze blocks with a counter, so prover and verifier
// stay in lockstep as long as they absorb the same byte sequences.
#[derive(Clone)]
pub(super) struct FiatShamirTranscript {
    state: [u8; 64],
    squeeze_counter: u64,
}

impl FiatShamirTranscript {
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

    pub(super) fn absorb_u64_slice(&mut self, label: &str, values: &[u64]) {
        let mut bytes = Vec::with_capacity(values.len() * 8);
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.absorb(label, &bytes);
    }

    // Deterministic fork for per-limb sub-transcripts.
    pub(super) fn fork(&self, label: &str, index: u64) -> Self {
        let mut forked = self.clone();
        forked.absorb("fork", label.as_bytes());
        forked.absorb_u64("fork-index", index);

        forked
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

    fn squeeze_u64(&mut self, label: &str) -> u64 {
        let block = self.squeeze_block(label);
        u64::from_le_bytes(block[..8].try_into().expect("block prefix is eight bytes"))
    }

    // Unbiased uniform residues below the modulus via rejection sampling.
    pub(super) fn challenge_field_elements(
        &mut self,
        label: &str,
        modulus: u64,
        count: usize,
    ) -> Vec<u64> {
        let rejection_zone = (u64::MAX / modulus) * modulus;
        let mut elements = Vec::with_capacity(count);
        while elements.len() < count {
            let block = self.squeeze_block(label);
            for chunk in block.chunks_exact(8) {
                if elements.len() == count {
                    break;
                }
                let candidate = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
                if candidate < rejection_zone {
                    elements.push(candidate % modulus);
                }
            }
        }

        elements
    }

    // Uniform degree-four challenge extension elements: four base-field
    // coordinates per element, rejection-sampled like every base challenge.
    pub(super) fn challenge_extension_elements(
        &mut self,
        label: &str,
        modulus: u64,
        count: usize,
    ) -> Vec<ChallengeExtensionElement> {
        self.challenge_field_elements(label, modulus, count * CHALLENGE_EXTENSION_DEGREE)
            .chunks_exact(CHALLENGE_EXTENSION_DEGREE)
            .map(|coordinates| {
                coordinates
                    .try_into()
                    .expect("chunks are extension-degree wide")
            })
            .collect()
    }

    // A nonzero uniform challenge extension element.
    pub(super) fn challenge_nonzero_extension_element(
        &mut self,
        label: &str,
        modulus: u64,
    ) -> ChallengeExtensionElement {
        loop {
            let element = self.challenge_extension_elements(label, modulus, 1)[0];
            if element.iter().any(|coordinate| *coordinate != 0) {
                return element;
            }
        }
    }

    // Fixed-width unsigned integers below 2^bit_count, shared across limb
    // fields, used for the bounded cross-limb consistency combinations.
    pub(super) fn challenge_bounded_integers(
        &mut self,
        label: &str,
        bit_count: u32,
        count: usize,
    ) -> Vec<u64> {
        debug_assert!(bit_count <= 63);
        let mask = (1_u64 << bit_count) - 1;
        let mut integers = Vec::with_capacity(count);
        while integers.len() < count {
            let block = self.squeeze_block(label);
            for chunk in block.chunks_exact(8) {
                if integers.len() == count {
                    break;
                }
                let candidate = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
                integers.push(candidate & mask);
            }
        }

        integers
    }

    // Query positions in [0, range).
    pub(super) fn challenge_positions(
        &mut self,
        label: &str,
        range: usize,
        count: usize,
    ) -> Vec<usize> {
        debug_assert!(range.is_power_of_two());
        let mask = (range - 1) as u64;
        let mut positions = Vec::with_capacity(count);
        while positions.len() < count {
            let value = self.squeeze_u64(label);
            positions.push((value & mask) as usize);
        }

        positions
    }
}
