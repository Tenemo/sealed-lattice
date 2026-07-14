#[cfg(test)]
use std::collections::BTreeSet;

use crate::hashing::hash_framed_parts_512 as hash512;

const TRANSCRIPT_INITIAL_DOMAIN: &str = "sealed-lattice/proof/transcript/v1";
const TRANSCRIPT_ABSORB_DOMAIN: &str = "sealed-lattice/proof/transcript/absorb/v1";
const TRANSCRIPT_SQUEEZE_DOMAIN: &str = "sealed-lattice/proof/transcript/squeeze/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TranscriptError {
    InvalidTag,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum DistinctQuerySamplingError {
    InvalidQueryDomain,
    QueryCountExceedsDomain,
    CandidateDrawsExhausted { output_index: usize },
    ChallengeBlockUnavailable { output_index: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalTranscriptEngine {
    TrusteeEvaluationKey,
    KeySwitchAtom,
}

impl CanonicalTranscriptEngine {
    fn wire_label(self) -> &'static str {
        match self {
            Self::TrusteeEvaluationKey => "trustee-evaluation-key",
            Self::KeySwitchAtom => "key-switch-atom",
        }
    }

    fn accepts_round_label(self, label: &str) -> bool {
        (match self {
            Self::TrusteeEvaluationKey => matches!(
                label,
                "statement"
                    | "fork"
                    | "fork-index"
                    | "witness-tree-root"
                    | "quotient-tree-root"
                    | "masked-consistency-claims"
                    | "deep-evaluations"
                    | "low-degree-purpose"
                    | "fold-layer-root"
                    | "final-coefficients"
            ),
            Self::KeySwitchAtom => matches!(
                label,
                "key-statement-binding"
                    | "key-schedule-index"
                    | "key-source"
                    | "galois-element"
                    | "ring-degree"
                    | "digit-count"
                    | "group-modulus"
                    | "plaintext-modulus"
                    | "digit-sample"
                    | "digit-gadget"
                    | "round-two-aggregate"
                    | "key-linkage-present"
                    | "linkage-seed-hash"
                    | "linkage-source-limb"
                    | "linkage-source-modulus"
                    | "linkage-commitment-root"
                    | "key-base-root"
                    | "key-material-root"
                    | "key-aux-root"
                    | "key-lookup-terminal"
                    | "key-table-terminals"
                    | "key-quotient-root"
                    | "fri-layer-root"
                    | "fri-final"
            ),
        }) || cfg!(test) && matches!(label, "a" | "n" | "seed" | "x")
    }

    fn accepts_challenge_label(self, label: &str) -> bool {
        match self {
            Self::TrusteeEvaluationKey => {
                matches!(
                    label,
                    "gamma"
                        | "lincheck-u"
                        | "lincheck-alpha"
                        | "same-secret-bridge-alpha"
                        | "private-vss-relation-alpha"
                        | "vss-share-linkage-alpha"
                        | "target-decryption-share-alpha"
                        | "same-secret-source-linkage-alpha"
                        | "linkage-alpha"
                        | "consistency-alpha"
                        | "consistency-vector"
                        | "beta"
                        | "deep-point"
                        | "lambda"
                        | "fold-challenge"
                        | "shared-query-position"
                ) || cfg!(test)
                    && (matches!(label, "field" | "position")
                        || dynamic_indexed_label(label, "shared-query-position")
                        || dynamic_decimal_suffix(label, "candidate-")
                        || dynamic_decimal_suffix(label, "nonzero-"))
            }
            Self::KeySwitchAtom => {
                matches!(
                    label,
                    "key-gamma"
                        | "key-delta"
                        | "key-lookup-mu"
                        | "key-linkage-alpha"
                        | "key-linkage-lincheck"
                        | "key-linkage-omega"
                        | "key-sum-batch"
                        | "key-support-alpha"
                        | "key-combination"
                        | "key-query"
                        | "fri-fold"
                        | "fri-query"
                ) || cfg!(test) && matches!(label, "c" | "q")
            }
        }
    }
}

fn dynamic_indexed_label(label: &str, prefix: &str) -> bool {
    label
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .is_some_and(|suffix| {
            suffix.len() == 8
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn dynamic_decimal_suffix(label: &str, prefix: &str) -> bool {
    label.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[derive(Clone)]
pub(crate) struct CanonicalProofTranscript {
    application_statement_schema_identifier: u16,
    state: [u8; 64],
}

impl CanonicalProofTranscript {
    pub(crate) fn new(
        protocol_version: u16,
        suite_id: [u8; 64],
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
    ) -> Self {
        Self {
            application_statement_schema_identifier,
            state: hash512(
                TRANSCRIPT_INITIAL_DOMAIN,
                &[
                    &protocol_version.to_le_bytes(),
                    &suite_id,
                    &application_statement_schema_identifier.to_le_bytes(),
                    canonical_proof_object_header_bytes,
                ],
            ),
        }
    }

    pub(crate) fn absorb_engine_round(
        &mut self,
        engine: CanonicalTranscriptEngine,
        round_label: &str,
        canonical_round_message_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if !engine.accepts_round_label(round_label) {
            return Err(TranscriptError::InvalidTag);
        }
        let round_tag = format!(
            "proof/{:04x}/engine/{}/{}",
            self.application_statement_schema_identifier,
            engine.wire_label(),
            round_label,
        );
        self.state = hash512(
            TRANSCRIPT_ABSORB_DOMAIN,
            &[
                &self.state,
                round_tag.as_bytes(),
                canonical_round_message_bytes,
            ],
        );
        Ok(())
    }

    pub(crate) fn squeeze_engine_challenge(
        &self,
        engine: CanonicalTranscriptEngine,
        challenge_label: &str,
        squeeze_counter: u64,
    ) -> Result<[u8; 64], TranscriptError> {
        if !engine.accepts_challenge_label(challenge_label) {
            return Err(TranscriptError::InvalidTag);
        }
        let challenge_tag = format!(
            "proof/{:04x}/engine/{}/{}",
            self.application_statement_schema_identifier,
            engine.wire_label(),
            challenge_label,
        );
        Ok(hash512(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            &[
                &self.state,
                challenge_tag.as_bytes(),
                &squeeze_counter.to_le_bytes(),
            ],
        ))
    }
}

/// Shared distinct-query sampler used while the live proof families migrate to
/// the common profile. The caller supplies a deterministic 64-byte challenge
/// block for one logical output and counter. Every output starts at counter
/// zero, and rejected or duplicate candidates consume its draw ceiling.
#[cfg(test)]
pub(crate) fn sample_distinct_query_positions_with_blocks(
    query_orbit_count: usize,
    query_count: usize,
    maximum_candidate_draws_per_output: u32,
    mut challenge_block: impl FnMut(usize, u64) -> Option<[u8; 64]>,
) -> Result<Vec<usize>, DistinctQuerySamplingError> {
    if query_orbit_count == 0 {
        return Err(DistinctQuerySamplingError::InvalidQueryDomain);
    }
    if query_count > query_orbit_count {
        return Err(DistinctQuerySamplingError::QueryCountExceedsDomain);
    }
    if maximum_candidate_draws_per_output == 0 {
        return Err(DistinctQuerySamplingError::CandidateDrawsExhausted { output_index: 0 });
    }

    let modulus = u64::try_from(query_orbit_count)
        .map_err(|_| DistinctQuerySamplingError::InvalidQueryDomain)?;
    let candidate_byte_length = usize::try_from((64 - modulus.leading_zeros()).div_ceil(8))
        .map_err(|_| DistinctQuerySamplingError::InvalidQueryDomain)?;
    let candidate_space = 1_u128 << (8 * candidate_byte_length);
    let acceptance_limit = candidate_space / u128::from(modulus) * u128::from(modulus);
    let mut positions = BTreeSet::new();
    for output_index in 0..query_count {
        let mut block = [0_u8; 64];
        let mut block_offset = block.len();
        let mut squeeze_counter = 0_u64;
        let mut selected = None;
        for _ in 0..maximum_candidate_draws_per_output {
            let mut candidate_bytes = [0_u8; 8];
            for candidate_byte in &mut candidate_bytes[..candidate_byte_length] {
                if block_offset == block.len() {
                    block = challenge_block(output_index, squeeze_counter).ok_or(
                        DistinctQuerySamplingError::ChallengeBlockUnavailable { output_index },
                    )?;
                    squeeze_counter = squeeze_counter.checked_add(1).ok_or(
                        DistinctQuerySamplingError::ChallengeBlockUnavailable { output_index },
                    )?;
                    block_offset = 0;
                }
                *candidate_byte = block[block_offset];
                block_offset += 1;
            }
            let candidate = u128::from(u64::from_le_bytes(candidate_bytes));
            if candidate >= acceptance_limit {
                continue;
            }
            let candidate = usize::try_from(candidate % u128::from(modulus))
                .map_err(|_| DistinctQuerySamplingError::InvalidQueryDomain)?;
            if positions.insert(candidate) {
                selected = Some(candidate);
                break;
            }
        }
        if selected.is_none() {
            return Err(DistinctQuerySamplingError::CandidateDrawsExhausted { output_index });
        }
    }
    Ok(positions.into_iter().collect())
}

#[cfg(test)]
pub(super) fn sample_distinct_query_positions_from_values(
    values: &[u64],
    query_orbit_count: usize,
    query_count: usize,
    maximum_candidate_draws_per_output: u32,
) -> Result<Vec<usize>, DistinctQuerySamplingError> {
    if query_orbit_count == 0 {
        return Err(DistinctQuerySamplingError::InvalidQueryDomain);
    }
    if query_count > query_orbit_count {
        return Err(DistinctQuerySamplingError::QueryCountExceedsDomain);
    }
    let mut value_position = 0_usize;
    let mut positions = BTreeSet::new();
    for output_index in 0..query_count {
        let mut selected = false;
        for _ in 0..maximum_candidate_draws_per_output {
            let candidate = *values
                .get(value_position)
                .ok_or(DistinctQuerySamplingError::CandidateDrawsExhausted { output_index })?;
            value_position += 1;
            let candidate = usize::try_from(candidate % query_orbit_count as u64)
                .map_err(|_| DistinctQuerySamplingError::InvalidQueryDomain)?;
            if positions.insert(candidate) {
                selected = true;
                break;
            }
        }
        if !selected {
            return Err(DistinctQuerySamplingError::CandidateDrawsExhausted { output_index });
        }
    }
    Ok(positions.into_iter().collect())
}
