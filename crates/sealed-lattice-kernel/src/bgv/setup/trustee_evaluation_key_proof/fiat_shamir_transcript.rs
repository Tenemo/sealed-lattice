use super::extension_field::{CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement};
use crate::bgv::proof_suite::{
    CanonicalProofTranscript, CanonicalTranscriptEngine, common_proof_transcript_domain_id,
};
#[cfg(test)]
use crate::bgv::setup::transcript_order_audit::{
    TranscriptOrderAuditRecorder, active_transcript_order_audit_recorder,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

fn transcript_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[derive(Clone)]
pub(in crate::bgv::setup) struct HashChainTranscriptCore {
    transcript: CanonicalProofTranscript,
    engine: CanonicalTranscriptEngine,
    squeeze_counter: u64,
    #[cfg(test)]
    audit: Option<TranscriptOrderAuditRecorder>,
}

impl HashChainTranscriptCore {
    pub(in crate::bgv::setup) fn new(
        engine: CanonicalTranscriptEngine,
        application_statement_schema_identifier: u16,
        audit_label: &'static str,
        protocol_label: &str,
    ) -> Self {
        let core = Self {
            transcript: CanonicalProofTranscript::new(
                1,
                common_proof_transcript_domain_id(),
                application_statement_schema_identifier,
                protocol_label.as_bytes(),
            ),
            engine,
            squeeze_counter: 0,
            #[cfg(test)]
            audit: active_transcript_order_audit_recorder(audit_label, protocol_label),
        };
        #[cfg(test)]
        {
            let mut core = core;
            if let Some(audit) = core.audit.as_mut() {
                audit.record_initialize(protocol_label, protocol_label.len());
            }
            core
        }
        #[cfg(not(test))]
        {
            let _ = audit_label;
            core
        }
    }

    pub(in crate::bgv::setup) fn absorb(&mut self, label: &str, bytes: &[u8]) {
        #[cfg(test)]
        if let Some(audit) = self.audit.as_mut() {
            audit.record_absorb(label, bytes.len());
        }
        self.transcript
            .absorb_engine_round(self.engine, label, bytes)
            .unwrap_or_else(|_| panic!("proof engine round tag `{label}` is not canonical"));
        self.squeeze_counter = 0;
    }

    pub(in crate::bgv::setup) fn fork(&self, label: &str, index: u64) -> Self {
        let forked = self.clone();
        #[cfg(test)]
        {
            let mut forked = forked;
            forked.audit = self.audit.as_ref().map(|audit| audit.fork(label, index));
            forked
        }
        #[cfg(not(test))]
        {
            let _ = (label, index);
            forked
        }
    }

    pub(in crate::bgv::setup) fn try_squeeze_block(&mut self, label: &str) -> Option<[u8; 64]> {
        let squeeze_counter = self.squeeze_counter;
        self.squeeze_counter = squeeze_counter.checked_add(1)?;
        #[cfg(test)]
        if let Some(audit) = self.audit.as_mut() {
            audit.record_squeeze(label, squeeze_counter);
        }
        Some(
            self.transcript
                .squeeze_engine_challenge(self.engine, label, squeeze_counter)
                .unwrap_or_else(|_| {
                    panic!("proof engine challenge tag `{label}` is not canonical")
                }),
        )
    }

    #[cfg(test)]
    fn exhaust_squeeze_counter(&mut self) {
        self.squeeze_counter = u64::MAX;
    }
}

// Hash-chained Fiat-Shamir transcript over the kernel hash. Challenges are
// derived from labelled squeeze blocks with a counter, so prover and verifier
// stay in lockstep as long as they absorb the same byte sequences.
#[derive(Clone)]
pub(super) struct FiatShamirTranscript {
    core: HashChainTranscriptCore,
    maximum_candidate_draws_per_output: u32,
}

impl FiatShamirTranscript {
    #[cfg(test)]
    pub(super) fn new(
        protocol_label: &str,
        maximum_candidate_draws_per_output: u32,
    ) -> CanonicalResult<Self> {
        Self::new_for_schema(protocol_label, 0x1216, maximum_candidate_draws_per_output)
    }

    pub(super) fn new_for_schema(
        protocol_label: &str,
        application_statement_schema_identifier: u16,
        maximum_candidate_draws_per_output: u32,
    ) -> CanonicalResult<Self> {
        if maximum_candidate_draws_per_output == 0 {
            return Err(transcript_error(
                "the trustee proof candidate-draw limit must be positive",
            ));
        }
        Ok(Self {
            core: HashChainTranscriptCore::new(
                CanonicalTranscriptEngine::TrusteeEvaluationKey,
                application_statement_schema_identifier,
                "trustee-evaluation-key",
                protocol_label,
            ),
            maximum_candidate_draws_per_output,
        })
    }

    pub(super) fn maximum_candidate_draws_per_output(&self) -> u32 {
        self.maximum_candidate_draws_per_output
    }

    pub(super) fn absorb(&mut self, label: &str, bytes: &[u8]) {
        self.core.absorb(label, bytes);
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
        forked.core = self.core.fork(label, index);
        forked.absorb("fork", label.as_bytes());
        forked.absorb_u64("fork-index", index);

        forked
    }

    // The init, absorb, squeeze, and fork byte tags domain-separate the four
    // operations so a squeeze output can never be replayed as an absorbed
    // message, and the per-round counter (reset on absorb) keeps same-round
    // challenges distinct.
    fn squeeze_block(&mut self, label: &str) -> CanonicalResult<[u8; 64]> {
        self.core.try_squeeze_block(label).ok_or_else(|| {
            transcript_error("the trustee proof transcript squeeze counter was exhausted")
        })
    }

    // Unbiased uniform residues below the modulus via rejection sampling.
    pub(super) fn challenge_field_elements(
        &mut self,
        label: &str,
        modulus: u64,
        count: usize,
    ) -> CanonicalResult<Vec<u64>> {
        if modulus <= 1 {
            return Err(transcript_error(
                "the trustee proof challenge modulus must exceed one",
            ));
        }
        let modulus_u128 = u128::from(modulus);
        let accepted_candidate_count = ((1_u128 << 64) / modulus_u128) * modulus_u128;
        let mut elements = Vec::with_capacity(count);
        let mut candidate_draws_for_next_output = 0_u32;
        while elements.len() < count {
            let block = self.squeeze_block(label)?;
            for chunk in block.chunks_exact(8) {
                if elements.len() == count {
                    break;
                }
                if candidate_draws_for_next_output == self.maximum_candidate_draws_per_output {
                    return Err(transcript_error(
                        "the trustee proof candidate-draw limit was exhausted before deriving an output",
                    ));
                }
                candidate_draws_for_next_output += 1;
                let candidate = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
                if u128::from(candidate) < accepted_candidate_count {
                    elements.push(candidate % modulus);
                    candidate_draws_for_next_output = 0;
                }
            }
        }

        Ok(elements)
    }

    // Uniform degree-four challenge extension elements: four base-field
    // coordinates per element, rejection-sampled like every base challenge.
    pub(super) fn challenge_extension_elements(
        &mut self,
        label: &str,
        modulus: u64,
        count: usize,
    ) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
        let coordinate_count = count
            .checked_mul(CHALLENGE_EXTENSION_DEGREE)
            .ok_or_else(|| {
                transcript_error(
                    "the trustee proof challenge output count exceeds the supported range",
                )
            })?;
        Ok(self
            .challenge_field_elements(label, modulus, coordinate_count)?
            .chunks_exact(CHALLENGE_EXTENSION_DEGREE)
            .map(|coordinates| {
                coordinates
                    .try_into()
                    .expect("chunks are extension-degree wide")
            })
            .collect())
    }

    // A nonzero uniform challenge extension element.
    pub(super) fn challenge_nonzero_extension_element(
        &mut self,
        label: &str,
        modulus: u64,
    ) -> CanonicalResult<ChallengeExtensionElement> {
        for _ in 0..self.maximum_candidate_draws_per_output {
            let element = self.challenge_extension_elements(label, modulus, 1)?[0];
            if element.iter().any(|coordinate| *coordinate != 0) {
                return Ok(element);
            }
        }

        Err(transcript_error(
            "the trustee proof candidate-draw limit was exhausted before deriving an output",
        ))
    }

    // Fixed-width unsigned integers below 2^bit_count, shared across limb
    // fields, used for the bounded cross-limb consistency combinations.
    pub(super) fn challenge_bounded_integers(
        &mut self,
        label: &str,
        bit_count: u32,
        count: usize,
    ) -> CanonicalResult<Vec<u64>> {
        // Bounded-integer combination: the collision probability over the
        // integers is at most 2^-bit_count per repetition independent of the
        // field, so masking (not rejection) yields the exact uniform target
        // [0, 2^bits).
        if bit_count == 0 || bit_count > 63 {
            return Err(transcript_error(
                "the trustee proof bounded-integer challenge width must be in 1..=63",
            ));
        }
        let mask = (1_u64 << bit_count) - 1;
        let mut integers = Vec::with_capacity(count);
        while integers.len() < count {
            let block = self.squeeze_block(label)?;
            for chunk in block.chunks_exact(8) {
                if integers.len() == count {
                    break;
                }
                let candidate = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
                integers.push(candidate & mask);
            }
        }

        Ok(integers)
    }

    // Query positions in [0, range), sampled independently with replacement.
    // Repeated positions remain separate query ordinals; transport may still
    // deduplicate the corresponding Merkle openings.
    pub(super) fn challenge_positions(
        &mut self,
        label: &str,
        range: usize,
        count: usize,
    ) -> CanonicalResult<Vec<usize>> {
        if !range.is_power_of_two() {
            return Err(transcript_error(
                "the trustee proof challenge-position range must be a nonzero power of two",
            ));
        }
        let position_mask = u64::try_from(range - 1).map_err(|_| {
            transcript_error("the trustee proof challenge-position range exceeds u64")
        })?;
        let mut positions = Vec::with_capacity(count);
        while positions.len() < count {
            let block = self.squeeze_block(label)?;
            for chunk in block.chunks_exact(8) {
                if positions.len() == count {
                    break;
                }
                let candidate = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
                positions.push(usize::try_from(candidate & position_mask).map_err(|_| {
                    transcript_error(
                        "the trustee proof challenge position exceeds the platform range",
                    )
                })?);
            }
        }
        Ok(positions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_draw_limit_exhaustion_is_deterministic_and_typed() {
        let modulus = (1_u64 << 63) + 1;
        let exhausted_label = (0_u64..256)
            .find_map(|label_index| {
                let label = format!("candidate-{label_index}");
                let mut transcript = FiatShamirTranscript::new("candidate-limit", 1)
                    .expect("positive candidate-draw limit is valid");
                matches!(
                    transcript.challenge_field_elements(&label, modulus, 1),
                    Err(error) if error.message.contains("candidate-draw limit was exhausted")
                )
                .then_some(label)
            })
            .expect("the fixed transcript corpus contains a first-draw rejection");
        let mut transcript = FiatShamirTranscript::new("candidate-limit", 1)
            .expect("positive candidate-draw limit is valid");

        let error = transcript
            .challenge_field_elements(&exhausted_label, modulus, 1)
            .expect_err("the fixed first candidate exceeds the acceptance range");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("candidate-draw limit was exhausted"));
    }

    #[test]
    fn nonzero_extension_challenge_exhaustion_is_deterministic() {
        let exhausted_label = (0_u64..256)
            .find_map(|label_index| {
                let label = format!("nonzero-{label_index}");
                let mut transcript = FiatShamirTranscript::new("nonzero-limit", 1)
                    .expect("positive candidate-draw limit is valid");
                matches!(
                    transcript.challenge_nonzero_extension_element(&label, 2),
                    Err(error) if error.message.contains("candidate-draw limit was exhausted")
                )
                .then_some(label)
            })
            .expect("the fixed transcript corpus contains an all-zero extension draw");
        let mut transcript = FiatShamirTranscript::new("nonzero-limit", 1)
            .expect("positive candidate-draw limit is valid");

        let error = transcript
            .challenge_nonzero_extension_element(&exhausted_label, 2)
            .expect_err("the fixed first extension challenge is zero");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("candidate-draw limit was exhausted"));
    }

    #[test]
    fn invalid_limits_and_domains_fail_without_panicking() {
        let invalid_limit_error = FiatShamirTranscript::new("invalid-limit", 0)
            .err()
            .expect("zero candidate-draw limit must be rejected");
        assert_eq!(
            invalid_limit_error.code,
            CanonicalErrorCode::InvalidProtocolObject
        );
        let mut transcript = FiatShamirTranscript::new("invalid-domain", 1)
            .expect("positive candidate-draw limit is valid");
        assert!(transcript.challenge_field_elements("field", 1, 1).is_err());
        assert!(
            transcript
                .challenge_bounded_integers("integer", 64, 1)
                .is_err()
        );
        assert!(transcript.challenge_positions("position", 3, 1).is_err());
        assert_eq!(
            transcript
                .challenge_positions("position", 1, 3)
                .expect("the singleton domain is valid"),
            vec![0, 0, 0]
        );
    }

    #[test]
    fn query_positions_are_bounded_repeatable_and_deterministic() {
        let mut first = FiatShamirTranscript::new("query-positions", 64)
            .expect("positive candidate-draw limit is valid");
        let mut second = first.clone();
        let first_positions = first
            .challenge_positions("position", 8, 24)
            .expect("query ordinals may repeat positions");
        let second_positions = second
            .challenge_positions("position", 8, 24)
            .expect("deterministic replay derives the same positions");
        assert_eq!(first_positions, second_positions);
        assert_eq!(first_positions.len(), 24);
        assert!(first_positions.iter().all(|position| *position < 8));
        assert!(
            first_positions
                .iter()
                .enumerate()
                .any(|(index, position)| first_positions[..index].contains(position)),
            "more query ordinals than domain positions must produce a repeat"
        );
    }

    #[test]
    fn sequential_squeeze_counter_exhaustion_is_typed() {
        let mut transcript = FiatShamirTranscript::new("counter-limit", 1)
            .expect("positive candidate-draw limit is valid");
        transcript.core.exhaust_squeeze_counter();

        let error = transcript
            .challenge_field_elements("field", 17, 1)
            .expect_err("an exhausted squeeze counter must fail closed");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("squeeze counter was exhausted"));
    }
}
