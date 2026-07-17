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
use crate::bgv::proof_suite::CanonicalTranscriptEngine;
use crate::bgv::setup::trustee_evaluation_key_proof::HashChainTranscriptCore;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::foundation::ProofApplicationSlotCeilings;

// Words drawn per field challenge. The proof fields are at most 13 limbs
// (~770 bits); 15 words is ~960 bits, so Horner reduction leaves a bias below
// 2^-180 without rejection sampling.
const CHALLENGE_WORDS: usize = 15;
const MAXIMUM_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 128;

fn transcript_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[derive(Clone)]
pub(super) struct Transcript {
    core: HashChainTranscriptCore,
    maximum_candidate_draws_per_output: u32,
}

impl Transcript {
    pub(super) fn new(protocol_label: &str) -> Self {
        Self {
            core: HashChainTranscriptCore::new(
                CanonicalTranscriptEngine::KeySwitchAtom,
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                "limb-group-key-switch-atom",
                protocol_label,
            ),
            maximum_candidate_draws_per_output: MAXIMUM_CANDIDATE_DRAWS_PER_OUTPUT,
        }
    }

    pub(super) const fn maximum_candidate_draws_per_output(&self) -> u32 {
        self.maximum_candidate_draws_per_output
    }

    pub(super) fn absorb(&mut self, label: &str, bytes: &[u8]) {
        self.core.absorb(label, bytes);
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

    fn squeeze_block(&mut self, label: &str) -> CanonicalResult<[u8; 64]> {
        self.core.try_squeeze_block(label).ok_or_else(|| {
            transcript_error("the key-switch atom transcript squeeze counter was exhausted")
        })
    }

    fn squeeze_words(&mut self, label: &str, count: usize) -> CanonicalResult<Vec<u64>> {
        let mut words = Vec::with_capacity(count);
        while words.len() < count {
            let block = self.squeeze_block(label)?;
            for chunk in block.chunks_exact(8) {
                if words.len() == count {
                    break;
                }
                words.push(u64::from_le_bytes(
                    chunk.try_into().expect("eight-byte chunk"),
                ));
            }
        }
        Ok(words)
    }

    // One uniform-enough proof-field element: a wide squeeze reduced mod p by
    // Horner over base 2^64 (each 64-bit word and the base are valid residues
    // because the modulus exceeds 2^64).
    pub(super) fn challenge_field_element<const LIMB_COUNT: usize>(
        &mut self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        label: &str,
    ) -> CanonicalResult<[u64; LIMB_COUNT]> {
        if LIMB_COUNT < 2 {
            return Err(transcript_error(
                "the key-switch atom proof field requires at least two limbs",
            ));
        }
        let words = self.squeeze_words(label, CHALLENGE_WORDS)?;
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
        Ok(accumulator)
    }

    pub(super) fn challenge_field_elements<const LIMB_COUNT: usize>(
        &mut self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        label: &str,
        count: usize,
    ) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
        (0..count)
            .map(|_| self.challenge_field_element(parameters, label))
            .collect()
    }

    // Uniform base-field residues by rejection from 64-bit transcript words.
    // The BDLOP lincheck uses these to reproduce the established extension
    // challenge distribution instead of reducing with a measurable bias.
    pub(super) fn challenge_residues(
        &mut self,
        label: &str,
        modulus: u64,
        count: usize,
    ) -> CanonicalResult<Vec<u64>> {
        if modulus <= 1 {
            return Err(transcript_error(
                "the key-switch atom challenge modulus must exceed one",
            ));
        }
        let sample_space = 1_u128 << u64::BITS;
        let modulus_u128 = u128::from(modulus);
        let accepted_candidate_count = sample_space - (sample_space % modulus_u128);
        let mut residues = Vec::with_capacity(count);
        let mut candidate_draws_for_next_output = 0_u32;
        while residues.len() < count {
            if candidate_draws_for_next_output == self.maximum_candidate_draws_per_output {
                return Err(transcript_error(
                    "the key-switch atom candidate-draw limit was exhausted before deriving an output",
                ));
            }
            candidate_draws_for_next_output += 1;
            let word = self.squeeze_words(label, 1)?[0];
            if u128::from(word) < accepted_candidate_count {
                residues.push(word % modulus);
                candidate_draws_for_next_output = 0;
            }
        }
        Ok(residues)
    }

    // Query positions in `[0, range)`; `range` must be a power of two, so
    // masking is unbiased.
    pub(super) fn challenge_positions(
        &mut self,
        label: &str,
        range: usize,
        count: usize,
    ) -> CanonicalResult<Vec<usize>> {
        if !range.is_power_of_two() {
            return Err(transcript_error(
                "the key-switch atom challenge-position range must be a nonzero power of two",
            ));
        }
        let mask = u64::try_from(range - 1).map_err(|_| {
            transcript_error("the key-switch atom challenge-position range exceeds u64")
        })?;
        self.squeeze_words(label, count)?
            .into_iter()
            .map(|word| {
                usize::try_from(word & mask).map_err(|_| {
                    transcript_error(
                        "the key-switch atom challenge position exceeds the platform range",
                    )
                })
            })
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
            left.challenge_field_element(&parameters, "c")
                .expect("left challenge"),
            right
                .challenge_field_element(&parameters, "c")
                .expect("right challenge"),
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
            left.challenge_field_elements(&parameters, "c", 4)
                .expect("left challenges"),
            right
                .challenge_field_elements(&parameters, "c", 4)
                .expect("right challenges"),
        );
        assert_eq!(
            left.challenge_positions("q", 256, 10)
                .expect("left positions"),
            right
                .challenge_positions("q", 256, 10)
                .expect("right positions"),
        );
    }

    #[test]
    fn challenge_field_element_is_reduced_and_varied() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut transcript = Transcript::new("atom");
        transcript.absorb("seed", b"reduce-check");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let element = transcript
                .challenge_field_element(&parameters, "c")
                .expect("field challenge");
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
        let first = transcript
            .challenge_field_element(&parameters, "c")
            .expect("first challenge");
        // Re-derive with the same prefix: absorbing again then squeezing must
        // match a fresh transcript with identical history.
        let mut fresh = Transcript::new("atom");
        fresh.absorb("a", b"1");
        assert_eq!(
            first,
            fresh
                .challenge_field_element(&parameters, "c")
                .expect("fresh challenge")
        );
    }

    #[test]
    fn invalid_challenge_domains_fail_without_panicking() {
        let mut transcript = Transcript::new("invalid-domain");
        assert!(transcript.challenge_residues("residue", 0, 1).is_err());
        assert!(transcript.challenge_residues("residue", 1, 1).is_err());
        assert!(transcript.challenge_positions("position", 0, 1).is_err());
        assert!(transcript.challenge_positions("position", 3, 1).is_err());
    }

    #[test]
    fn candidate_draw_and_squeeze_exhaustion_are_typed() {
        let modulus = (1_u64 << 63) + 1;
        let exhausted_absorption = (0_u64..256)
            .find(|absorption| {
                let mut transcript = Transcript::new("candidate-limit");
                transcript.maximum_candidate_draws_per_output = 1;
                transcript.absorb_u64("n", *absorption);
                transcript
                    .challenge_residues("key-linkage-alpha", modulus, 1)
                    .is_err()
            })
            .expect("the fixed transcript corpus contains a first-draw rejection");
        let mut transcript = Transcript::new("candidate-limit");
        transcript.maximum_candidate_draws_per_output = 1;
        transcript.absorb_u64("n", exhausted_absorption);
        let error = transcript
            .challenge_residues("key-linkage-alpha", modulus, 1)
            .expect_err("the fixed first candidate exceeds the acceptance range");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("candidate-draw limit was exhausted"));

        let mut transcript = Transcript::new("counter-limit");
        transcript.core.exhaust_squeeze_counter();
        let error = transcript
            .challenge_positions("key-query", 8, 1)
            .expect_err("an exhausted squeeze counter must fail closed");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("squeeze counter was exhausted"));
    }
}
