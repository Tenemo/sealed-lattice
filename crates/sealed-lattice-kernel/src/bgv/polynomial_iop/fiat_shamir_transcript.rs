use super::extension_field::{CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement};
use crate::hashing::hash512;

const TRANSCRIPT_DOMAIN: &str = "sealed-lattice/internal/polynomial-iop/transcript-v1";

// Hash-chained Fiat-Shamir transcript over the kernel hash. Challenges are
// derived from labelled squeeze blocks with a counter, so prover and verifier
// stay in lockstep as long as they absorb the same byte sequences.
#[derive(Clone)]
pub(in crate::bgv) struct FiatShamirTranscript {
    state: [u8; 64],
    squeeze_counter: u64,
}

impl FiatShamirTranscript {
    pub(in crate::bgv) fn new(protocol_label: &str) -> Self {
        Self {
            state: hash512(TRANSCRIPT_DOMAIN, &[b"init", protocol_label.as_bytes()]),
            squeeze_counter: 0,
        }
    }

    pub(in crate::bgv) fn absorb(&mut self, label: &str, bytes: &[u8]) {
        self.state = hash512(
            TRANSCRIPT_DOMAIN,
            &[b"absorb", &self.state, label.as_bytes(), bytes],
        );
        self.squeeze_counter = 0;
    }

    pub(in crate::bgv) fn absorb_u64(&mut self, label: &str, value: u64) {
        self.absorb(label, &value.to_le_bytes());
    }

    pub(in crate::bgv) fn absorb_u64_slice(&mut self, label: &str, values: &[u64]) {
        let mut bytes = Vec::with_capacity(values.len() * 8);
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.absorb(label, &bytes);
    }

    // Deterministic fork for per-limb sub-transcripts.
    pub(in crate::bgv) fn fork(&self, label: &str, index: u64) -> Self {
        let mut forked = self.clone();
        forked.absorb("fork", label.as_bytes());
        forked.absorb_u64("fork-index", index);

        forked
    }

    // The init, absorb, squeeze, and fork byte tags domain-separate the four
    // operations so a squeeze output can never be replayed as an absorbed
    // message, and the per-round counter (reset on absorb) keeps same-round
    // challenges distinct.
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
    pub(in crate::bgv) fn challenge_field_elements(
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
    pub(in crate::bgv) fn challenge_extension_elements(
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
    pub(in crate::bgv) fn challenge_nonzero_extension_element(
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

    // Query positions in [0, range).
    pub(in crate::bgv) fn challenge_positions(
        &mut self,
        label: &str,
        range: usize,
        count: usize,
    ) -> Vec<usize> {
        // Masking is unbiased only because FRI domain sizes are powers of two
        // (debug-asserted); base-field challenges differ and must
        // rejection-sample against the non-power-of-two modulus.
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
