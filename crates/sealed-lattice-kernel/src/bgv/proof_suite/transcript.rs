use std::collections::BTreeSet;

use num_bigint::BigUint;
use num_traits::One;

use crate::foundation::{
    CanonicalItem, CanonicalItemType, Hash512, StreamingFoundationHashError,
    StreamingFoundationTupleHash512, fill_foundation_tuple_xof, hash_foundation_tuple_512,
};

use super::field::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement,
};

const TRANSCRIPT_INITIAL_DOMAIN: &str = "sealed-lattice/proof/transcript/v1";
const TRANSCRIPT_ABSORB_DOMAIN: &str = "sealed-lattice/proof/transcript/absorb/v1";
const TRANSCRIPT_SQUEEZE_DOMAIN: &str = "sealed-lattice/proof/transcript/squeeze/v1";

fn transcript_hash(domain: &str, items: Vec<CanonicalItem>) -> Result<[u8; 64], TranscriptError> {
    hash_foundation_tuple_512(domain, &items)
        .map(|digest| digest.into_bytes())
        .map_err(|_| TranscriptError::CanonicalEncoding)
}

fn transcript_xof(
    domain: &str,
    items: Vec<CanonicalItem>,
    output: &mut [u8],
) -> Result<(), TranscriptError> {
    fill_foundation_tuple_xof(domain, &items, output)
        .map_err(|_| TranscriptError::CanonicalEncoding)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TranscriptError {
    CanonicalEncoding,
    InvalidTag,
    InvalidCommonProofSchedule,
    UnexpectedCommonProofRound,
    UnexpectedCommonProofChallenge,
    InvalidCommonProofMessage,
    InvalidChallengeModulus,
    CommonChallengeDrawsExhausted,
    ChallengeCounterOverflow,
    IncompleteCommonProofTranscript,
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
    pending_common_challenge: Option<PendingCommonChallenge>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingCommonChallenge {
    candidate_seed: [u8; 64],
    challenge_tag: String,
    canonical_output_bytes: Vec<u8>,
}

impl CanonicalProofTranscript {
    pub(crate) fn try_new(
        protocol_version: u16,
        suite_id: [u8; 64],
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
    ) -> Result<Self, TranscriptError> {
        Ok(Self {
            application_statement_schema_identifier,
            state: transcript_hash(
                TRANSCRIPT_INITIAL_DOMAIN,
                vec![
                    CanonicalItem::unsigned16(protocol_version),
                    CanonicalItem::hash512(suite_id),
                    CanonicalItem::unsigned16(application_statement_schema_identifier),
                    CanonicalItem::variable_bytes(canonical_proof_object_header_bytes.to_vec())
                        .map_err(|_| TranscriptError::CanonicalEncoding)?,
                ],
            )?,
            pending_common_challenge: None,
        })
    }

    /// Compatibility constructor for the two pre-common proof engines.  Their
    /// header is an internal bounded protocol label, never hostile proof data.
    pub(crate) fn new(
        protocol_version: u16,
        suite_id: [u8; 64],
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
    ) -> Self {
        Self::try_new(
            protocol_version,
            suite_id,
            application_statement_schema_identifier,
            canonical_proof_object_header_bytes,
        )
        .expect("an internal proof-engine protocol label has a canonical transcript header")
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
        self.state = transcript_hash(
            TRANSCRIPT_ABSORB_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&round_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::variable_bytes(canonical_round_message_bytes.to_vec())
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            ],
        )?;
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
        transcript_hash(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(squeeze_counter),
            ],
        )
    }

    fn absorb_common_round(
        &mut self,
        round: CommonProofRound,
        canonical_round_message_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if round.requires_hash512_message() && canonical_round_message_bytes.len() != 64 {
            return Err(TranscriptError::InvalidCommonProofMessage);
        }
        let round_tag = round.tag(self.application_statement_schema_identifier);
        let response_context = self.common_response_context(&round_tag)?;
        let mut response_items = vec![
            CanonicalItem::hash512(response_context.challenge_seed),
            CanonicalItem::nonempty_ascii(&round_tag)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        ];
        if let Some(canonical_challenge_output_bytes) =
            response_context.canonical_challenge_output_bytes
        {
            response_items.push(
                CanonicalItem::variable_bytes(canonical_challenge_output_bytes)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            );
        }
        response_items.push(
            CanonicalItem::variable_bytes(canonical_round_message_bytes.to_vec())
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        );
        self.state = transcript_hash(TRANSCRIPT_ABSORB_DOMAIN, response_items)?;
        self.pending_common_challenge = None;
        Ok(())
    }

    fn begin_streamed_common_round(
        &self,
        round: CommonProofRound,
        canonical_round_message_byte_length: usize,
    ) -> Result<CommonProofRoundMessageAbsorber, TranscriptError> {
        if round.requires_hash512_message() || canonical_round_message_byte_length == 0 {
            return Err(TranscriptError::InvalidCommonProofMessage);
        }
        let round_tag = round.tag(self.application_statement_schema_identifier);
        let response_context = self.common_response_context(&round_tag)?;
        let mut prefix_items = vec![
            CanonicalItem::hash512(response_context.challenge_seed),
            CanonicalItem::nonempty_ascii(&round_tag)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        ];
        if let Some(canonical_challenge_output_bytes) =
            response_context.canonical_challenge_output_bytes
        {
            prefix_items.push(
                CanonicalItem::variable_bytes(canonical_challenge_output_bytes)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            );
        }
        let streaming_hash = StreamingFoundationTupleHash512::new_variable_bytes(
            TRANSCRIPT_ABSORB_DOMAIN,
            &prefix_items,
            canonical_round_message_byte_length,
        )
        .map_err(transcript_streaming_hash_error)?;
        Ok(CommonProofRoundMessageAbsorber {
            starting_transcript_state: self.state,
            starting_pending_challenge: self.pending_common_challenge.clone(),
            streaming_hash,
        })
    }

    fn finish_streamed_common_round(
        &mut self,
        absorber: CommonProofRoundMessageAbsorber,
    ) -> Result<(), TranscriptError> {
        if absorber.starting_transcript_state != self.state
            || absorber.starting_pending_challenge != self.pending_common_challenge
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.state = absorber
            .streaming_hash
            .finalize()
            .map_err(transcript_streaming_hash_error)?
            .into_bytes();
        self.pending_common_challenge = None;
        Ok(())
    }

    fn absorb_common_extension_value_list(
        &mut self,
        round: CommonProofRound,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        let value_count =
            u32::try_from(values.len()).map_err(|_| TranscriptError::InvalidCommonProofMessage)?;
        let value_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
            .checked_mul(8)
            .ok_or(TranscriptError::InvalidCommonProofMessage)?;
        let message_byte_length = values
            .len()
            .checked_mul(value_byte_length)
            .and_then(|length| length.checked_add(6))
            .ok_or(TranscriptError::InvalidCommonProofMessage)?;
        let mut absorber = self.begin_streamed_common_round(round, message_byte_length)?;
        absorber
            .streaming_hash
            .absorb(
                &CanonicalItemType::ChallengeExtensionElement
                    .canonical_code()
                    .to_le_bytes(),
            )
            .map_err(transcript_streaming_hash_error)?;
        absorber
            .streaming_hash
            .absorb(&value_count.to_le_bytes())
            .map_err(transcript_streaming_hash_error)?;
        for value in values {
            for coordinate in value.canonical_coordinates() {
                absorber
                    .streaming_hash
                    .absorb(&coordinate.to_le_bytes())
                    .map_err(transcript_streaming_hash_error)?;
            }
        }
        self.finish_streamed_common_round(absorber)
    }

    fn begin_common_challenge(
        &mut self,
        challenge: CommonProofChallenge,
    ) -> Result<CommonChallengeStream, TranscriptError> {
        self.close_pending_common_challenge()?;
        let challenge_tag = challenge.tag(self.application_statement_schema_identifier);
        let challenge_seed = transcript_hash(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(0),
            ],
        )?;
        Ok(CommonChallengeStream::new(challenge_seed, challenge_tag))
    }

    /// Begins one logical verifier message backed by one SHAKE256 XOF
    /// evaluation. The first 512 output bits are the chain handle; the rest
    /// are verifier coins consumed locally by the schedule-bounded sampler.
    fn begin_common_xof_challenge(
        &mut self,
        challenge: CommonProofChallenge,
        random_byte_length: usize,
    ) -> Result<(CommonChallengeStream, Vec<u8>), TranscriptError> {
        self.close_pending_common_challenge()?;
        let challenge_tag = challenge.tag(self.application_statement_schema_identifier);
        let output_byte_length = Hash512::BYTE_LENGTH
            .checked_add(random_byte_length)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        output.resize(output_byte_length, 0);
        transcript_xof(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(0),
            ],
            &mut output,
        )?;
        let mut chain_handle = [0_u8; Hash512::BYTE_LENGTH];
        chain_handle.copy_from_slice(&output[..Hash512::BYTE_LENGTH]);
        let verifier_randomness = output.split_off(Hash512::BYTE_LENGTH);
        Ok((
            CommonChallengeStream::new(chain_handle, challenge_tag),
            verifier_randomness,
        ))
    }

    fn finish_common_challenge(
        &mut self,
        stream: CommonChallengeStream,
        canonical_output_bytes: Vec<u8>,
    ) -> Result<(), TranscriptError> {
        if canonical_output_bytes.is_empty() || self.pending_common_challenge.is_some() {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        self.pending_common_challenge = Some(PendingCommonChallenge {
            candidate_seed: stream.current_candidate_seed,
            challenge_tag: stream.challenge_tag,
            canonical_output_bytes,
        });
        Ok(())
    }

    fn close_pending_common_challenge(&mut self) -> Result<(), TranscriptError> {
        let Some(pending) = self.pending_common_challenge.take() else {
            return Ok(());
        };
        let response_tag = format!("{}/accepted", pending.challenge_tag);
        self.state = transcript_hash(
            TRANSCRIPT_ABSORB_DOMAIN,
            vec![
                CanonicalItem::hash512(pending.candidate_seed),
                CanonicalItem::nonempty_ascii(&response_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::variable_bytes(pending.canonical_output_bytes)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            ],
        )?;
        Ok(())
    }

    fn common_response_context(
        &self,
        round_tag: &str,
    ) -> Result<CommonResponseContext, TranscriptError> {
        if let Some(pending) = &self.pending_common_challenge {
            return Ok(CommonResponseContext {
                challenge_seed: pending.candidate_seed,
                canonical_challenge_output_bytes: Some(pending.canonical_output_bytes.clone()),
            });
        }
        let virtual_challenge_tag = format!("{round_tag}/response-binding");
        let challenge_seed = transcript_hash(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&virtual_challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(0),
            ],
        )?;
        Ok(CommonResponseContext {
            challenge_seed,
            canonical_challenge_output_bytes: None,
        })
    }
}

struct CommonResponseContext {
    challenge_seed: [u8; 64],
    canonical_challenge_output_bytes: Option<Vec<u8>>,
}

fn transcript_streaming_hash_error(_error: StreamingFoundationHashError) -> TranscriptError {
    TranscriptError::InvalidCommonProofMessage
}

/// Incremental transcript absorption for the complete canonical query-opening
/// and authentication-frontier sequence.  It owns only SHAKE state and the
/// starting transcript digest, never the proof bytes.
pub(crate) struct CommonProofQueryOpeningAbsorber {
    round_message_absorber: CommonProofRoundMessageAbsorber,
}

impl CommonProofQueryOpeningAbsorber {
    pub(crate) fn absorb(
        &mut self,
        canonical_query_opening_fragment: &[u8],
    ) -> Result<(), TranscriptError> {
        self.round_message_absorber
            .streaming_hash
            .absorb(canonical_query_opening_fragment)
            .map_err(transcript_streaming_hash_error)
    }
}

struct CommonProofRoundMessageAbsorber {
    starting_transcript_state: [u8; 64],
    starting_pending_challenge: Option<PendingCommonChallenge>,
    streaming_hash: StreamingFoundationTupleHash512,
}

/// Closed round tags for the common transparent proof.  Callers never supply
/// free-form labels on this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRound {
    BaseRoot { tree_ordinal: u16 },
    AuxiliaryRoot { tree_ordinal: u16 },
    QuotientRoot { component_ordinal: u16 },
    DeepValues,
    OpeningBatchMaskRoot,
    FriLayerRoot { fold_ordinal: u16 },
    FriTerminal,
    QueryOpenings,
}

impl CommonProofRound {
    fn tag(self, application_statement_schema_identifier: u16) -> String {
        let prefix = format!("proof/{application_statement_schema_identifier:04x}");
        match self {
            Self::BaseRoot { tree_ordinal } => {
                format!("{prefix}/base-root/{tree_ordinal:04x}")
            }
            Self::AuxiliaryRoot { tree_ordinal } => {
                format!("{prefix}/auxiliary-root/{tree_ordinal:04x}")
            }
            Self::QuotientRoot { component_ordinal } => {
                format!("{prefix}/quotient-root/{component_ordinal:04x}")
            }
            Self::DeepValues => format!("{prefix}/deep-values"),
            Self::OpeningBatchMaskRoot => {
                format!("{prefix}/opening-batch-mask-root")
            }
            Self::FriLayerRoot { fold_ordinal } => {
                format!("{prefix}/fri-layer-root/{fold_ordinal:04x}")
            }
            Self::FriTerminal => format!("{prefix}/fri-terminal"),
            Self::QueryOpenings => format!("{prefix}/query-openings"),
        }
    }

    fn requires_hash512_message(self) -> bool {
        matches!(
            self,
            Self::BaseRoot { .. }
                | Self::AuxiliaryRoot { .. }
                | Self::QuotientRoot { .. }
                | Self::OpeningBatchMaskRoot
                | Self::FriLayerRoot { .. }
        )
    }
}

/// Closed Fiat-Shamir challenge tags for the common transparent proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CommonProofChallenge {
    Theta { modulus_ordinal: u16 },
    Alpha { modulus_ordinal: u16 },
    Composition { constraint_ordinal: u16 },
    DeepPoint { point_ordinal: u16 },
    OpeningBatch { claim_ordinal: u16 },
    FriFold { fold_ordinal: u16 },
    QueryVector,
}

impl CommonProofChallenge {
    fn tag(self, application_statement_schema_identifier: u16) -> String {
        let prefix = format!("proof/{application_statement_schema_identifier:04x}");
        match self {
            Self::Theta { modulus_ordinal } => {
                format!("{prefix}/theta-vector/{modulus_ordinal:04x}")
            }
            Self::Alpha { modulus_ordinal } => {
                format!("{prefix}/alpha-vector/{modulus_ordinal:04x}")
            }
            Self::Composition { constraint_ordinal } => {
                format!("{prefix}/composition/{constraint_ordinal:04x}")
            }
            Self::DeepPoint { point_ordinal } => {
                format!("{prefix}/deep-point/{point_ordinal:04x}")
            }
            Self::OpeningBatch { claim_ordinal } => {
                format!("{prefix}/opening-batch/{claim_ordinal:04x}")
            }
            Self::FriFold { fold_ordinal } => {
                format!("{prefix}/fri-fold/{fold_ordinal:04x}")
            }
            Self::QueryVector => format!("{prefix}/query-vector"),
        }
    }

    fn is_application_challenge(self) -> bool {
        matches!(self, Self::Theta { .. } | Self::Alpha { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofPrivacyMode {
    PublicOnly,
    SecretBearing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofApplicationChallengeGroup {
    challenge: CommonProofChallenge,
    modulus: u64,
    coordinate_count: u16,
}

impl CommonProofApplicationChallengeGroup {
    pub(crate) fn new(
        challenge: CommonProofChallenge,
        modulus: u64,
        coordinate_count: u16,
    ) -> Result<Self, TranscriptError> {
        if !challenge.is_application_challenge()
            || modulus <= 1
            || modulus >= PROOF_BASE_FIELD_MODULUS
            || coordinate_count == 0
            || BigUint::from(modulus).pow(u32::from(coordinate_count))
                >= (BigUint::one() << 512_usize)
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        Ok(Self {
            challenge,
            modulus,
            coordinate_count,
        })
    }

    pub(crate) fn challenge(self) -> CommonProofChallenge {
        self.challenge
    }

    pub(crate) fn modulus(self) -> u64 {
        self.modulus
    }

    pub(crate) fn coordinate_count(self) -> u16 {
        self.coordinate_count
    }
}

/// Exact plan-derived schedule needed to reject omitted, reordered, repeated,
/// or mode-incompatible common-proof messages before algebraic verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofTranscriptSchedule {
    ordered_base_tree_ordinals: Vec<u16>,
    ordered_application_challenge_groups: Vec<CommonProofApplicationChallengeGroup>,
    ordered_auxiliary_tree_ordinals: Vec<u16>,
    composition_challenge_count: u16,
    quotient_component_count: u16,
    deep_point_count: u16,
    opening_claim_count: u16,
    fri_fold_count: u16,
    terminal_coefficient_count: u32,
    unique_query_count: u32,
    query_orbit_count: u64,
    maximum_candidate_draws_per_output: u32,
    privacy_mode: CommonProofPrivacyMode,
}

impl CommonProofTranscriptSchedule {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ordered_base_tree_ordinals: Vec<u16>,
        ordered_application_challenge_groups: Vec<CommonProofApplicationChallengeGroup>,
        ordered_auxiliary_tree_ordinals: Vec<u16>,
        composition_challenge_count: u16,
        quotient_component_count: u16,
        deep_point_count: u16,
        opening_claim_count: u16,
        fri_fold_count: u16,
        terminal_coefficient_count: u32,
        unique_query_count: u32,
        query_orbit_count: u64,
        maximum_candidate_draws_per_output: u32,
        privacy_mode: CommonProofPrivacyMode,
    ) -> Result<Self, TranscriptError> {
        let schedule = Self {
            ordered_base_tree_ordinals,
            ordered_application_challenge_groups,
            ordered_auxiliary_tree_ordinals,
            composition_challenge_count,
            quotient_component_count,
            deep_point_count,
            opening_claim_count,
            fri_fold_count,
            terminal_coefficient_count,
            unique_query_count,
            query_orbit_count,
            maximum_candidate_draws_per_output,
            privacy_mode,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    fn validate(&self) -> Result<(), TranscriptError> {
        if !strictly_increasing(&self.ordered_base_tree_ordinals)
            || !strictly_increasing(&self.ordered_auxiliary_tree_ordinals)
            || self
                .ordered_application_challenge_groups
                .windows(2)
                .any(|pair| pair[0].challenge >= pair[1].challenge)
            || self
                .ordered_application_challenge_groups
                .iter()
                .any(|entry| {
                    !entry.challenge.is_application_challenge()
                        || entry.modulus <= 1
                        || entry.modulus >= PROOF_BASE_FIELD_MODULUS
                        || entry.coordinate_count == 0
                        || BigUint::from(entry.modulus).pow(u32::from(entry.coordinate_count))
                            >= (BigUint::one() << 512_usize)
                })
            || self.composition_challenge_count == 0
            || self.quotient_component_count == 0
            || self.deep_point_count == 0
            || self.opening_claim_count == 0
            || self.fri_fold_count == 0
            || self.terminal_coefficient_count == 0
            || self.unique_query_count == 0
            || u64::from(self.unique_query_count) > self.query_orbit_count
            || !self.query_orbit_count.is_power_of_two()
            || self.maximum_candidate_draws_per_output == 0
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        Ok(())
    }

    pub(crate) fn ordered_base_tree_ordinals(&self) -> &[u16] {
        &self.ordered_base_tree_ordinals
    }

    pub(crate) fn ordered_auxiliary_tree_ordinals(&self) -> &[u16] {
        &self.ordered_auxiliary_tree_ordinals
    }

    pub(crate) fn ordered_application_challenge_groups(
        &self,
    ) -> &[CommonProofApplicationChallengeGroup] {
        &self.ordered_application_challenge_groups
    }

    pub(crate) const fn composition_challenge_count(&self) -> u16 {
        self.composition_challenge_count
    }

    pub(crate) const fn quotient_component_count(&self) -> u16 {
        self.quotient_component_count
    }

    pub(crate) const fn opening_claim_count(&self) -> u16 {
        self.opening_claim_count
    }

    pub(crate) const fn deep_point_count(&self) -> u16 {
        self.deep_point_count
    }

    pub(crate) const fn fri_fold_count(&self) -> u16 {
        self.fri_fold_count
    }

    pub(crate) const fn terminal_coefficient_count(&self) -> u32 {
        self.terminal_coefficient_count
    }

    pub(crate) const fn unique_query_count(&self) -> u32 {
        self.unique_query_count
    }

    pub(crate) const fn query_orbit_count(&self) -> u64 {
        self.query_orbit_count
    }

    pub(crate) const fn privacy_mode(&self) -> CommonProofPrivacyMode {
        self.privacy_mode
    }

    /// Exact maximum number of typed transcript-hash invocations made while
    /// verifying an accepted proof under this schedule. The bound follows the
    /// same challenge/response state machine as `CommonProofTranscript` and
    /// includes every rejection-sampling expansion block. It deliberately
    /// excludes Merkle authentication, whose cost is derived from the checked
    /// tree catalog and opening geometry.
    pub(crate) fn maximum_transcript_hash_query_count(&self) -> Result<u64, TranscriptError> {
        self.validate()?;
        let mut counter = TranscriptHashQueryCounter::new();

        for _ in &self.ordered_base_tree_ordinals {
            counter.absorb_response()?;
        }
        for challenge in &self.ordered_application_challenge_groups {
            counter.begin_challenge(maximum_product_residue_challenge_hash_count(
                challenge.modulus,
                challenge.coordinate_count,
                self.maximum_candidate_draws_per_output,
            )?)?;
        }
        for _ in &self.ordered_auxiliary_tree_ordinals {
            counter.absorb_response()?;
        }
        for _ in 0..self.composition_challenge_count {
            counter.begin_challenge(maximum_extension_challenge_hash_count(
                self.maximum_candidate_draws_per_output,
            )?)?;
        }
        for _ in 0..self.quotient_component_count {
            counter.absorb_response()?;
        }
        for _ in 0..self.deep_point_count {
            counter.begin_challenge(maximum_extension_challenge_hash_count(
                self.maximum_candidate_draws_per_output,
            )?)?;
        }
        counter.absorb_response()?;
        if self.privacy_mode == CommonProofPrivacyMode::SecretBearing {
            counter.absorb_response()?;
        }
        for _ in 0..self.opening_claim_count {
            counter.begin_challenge(maximum_extension_challenge_hash_count(
                self.maximum_candidate_draws_per_output,
            )?)?;
        }
        for fold_ordinal in 0..self.fri_fold_count {
            counter.begin_challenge(maximum_extension_challenge_hash_count(
                self.maximum_candidate_draws_per_output,
            )?)?;
            if fold_ordinal + 1 < self.fri_fold_count {
                counter.absorb_response()?;
            }
        }
        counter.absorb_response()?;
        // The entire without-replacement query vector is one extended XOF
        // verifier message and therefore one random-oracle query.
        counter.begin_challenge(1)?;
        counter.absorb_response()?;
        counter.finish()
    }
}

struct TranscriptHashQueryCounter {
    hash_query_count: u64,
    pending_challenge: bool,
}

impl TranscriptHashQueryCounter {
    fn new() -> Self {
        Self {
            // The instance-, suite-, family-, and header-bound initial state.
            hash_query_count: 1,
            pending_challenge: false,
        }
    }

    fn begin_challenge(&mut self, challenge_hash_count: u64) -> Result<(), TranscriptError> {
        if challenge_hash_count == 0 {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        if self.pending_challenge {
            self.add_hash_queries(1)?;
        }
        self.add_hash_queries(challenge_hash_count)?;
        self.pending_challenge = true;
        Ok(())
    }

    fn absorb_response(&mut self) -> Result<(), TranscriptError> {
        if self.pending_challenge {
            self.add_hash_queries(1)?;
        } else {
            // A response without an operative preceding challenge receives a
            // typed virtual response-binding challenge before absorption.
            self.add_hash_queries(2)?;
        }
        self.pending_challenge = false;
        Ok(())
    }

    fn add_hash_queries(&mut self, count: u64) -> Result<(), TranscriptError> {
        self.hash_query_count = self
            .hash_query_count
            .checked_add(count)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        Ok(())
    }

    fn finish(self) -> Result<u64, TranscriptError> {
        if self.pending_challenge {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        Ok(self.hash_query_count)
    }
}

fn maximum_product_residue_challenge_hash_count(
    modulus: u64,
    coordinate_count: u16,
    maximum_candidate_draws: u32,
) -> Result<u64, TranscriptError> {
    if modulus <= 1
        || coordinate_count == 0
        || BigUint::from(modulus).pow(u32::from(coordinate_count)) >= (BigUint::one() << 512_usize)
        || maximum_candidate_draws == 0
    {
        return Err(TranscriptError::InvalidChallengeModulus);
    }
    maximum_rejection_chain_hash_count(maximum_candidate_draws)
}

fn maximum_extension_challenge_hash_count(
    maximum_candidate_draws: u32,
) -> Result<u64, TranscriptError> {
    if maximum_candidate_draws == 0 {
        return Err(TranscriptError::InvalidChallengeModulus);
    }
    maximum_rejection_chain_hash_count(maximum_candidate_draws)
}

fn maximum_rejection_chain_hash_count(
    maximum_candidate_draws: u32,
) -> Result<u64, TranscriptError> {
    u64::from(maximum_candidate_draws)
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(TranscriptError::ChallengeCounterOverflow)
}

fn strictly_increasing(values: &[u16]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofProgress {
    BaseRoots(usize),
    ApplicationChallenges(usize),
    AuxiliaryRoots(usize),
    CompositionChallenges(u16),
    QuotientRoots(u16),
    DeepPoints(u16),
    DeepValues,
    OpeningBatchMaskRoot,
    OpeningBatchChallenges(u16),
    FriFoldChallenge(u16),
    FriLayerRoot(u16),
    FriTerminal,
    QueryRepresentatives(u32),
    QueryOpenings,
    Complete,
}

/// Stateful exact common-proof transcript.  The schedule is fixed by the
/// checked relation plan and proof profile; bytes cannot choose a round, tag,
/// modulus, count, or privacy-mode branch.
#[derive(Clone)]
pub(crate) struct CommonProofTranscript {
    transcript: CanonicalProofTranscript,
    schedule: CommonProofTranscriptSchedule,
    progress: CommonProofProgress,
    accepted_deep_points: Vec<ProofChallengeExtensionElement>,
    accepted_query_representatives: Vec<u64>,
}

impl CommonProofTranscript {
    pub(crate) fn new(
        protocol_version: u16,
        suite_id: [u8; 64],
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
        schedule: CommonProofTranscriptSchedule,
    ) -> Result<Self, TranscriptError> {
        schedule.validate()?;
        let mut result = Self {
            transcript: CanonicalProofTranscript::try_new(
                protocol_version,
                suite_id,
                application_statement_schema_identifier,
                canonical_proof_object_header_bytes,
            )?,
            schedule,
            progress: CommonProofProgress::BaseRoots(0),
            accepted_deep_points: Vec::new(),
            accepted_query_representatives: Vec::new(),
        };
        result.skip_empty_prefix_phases();
        Ok(result)
    }

    pub(crate) fn absorb_base_root(
        &mut self,
        tree_ordinal: u16,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        let CommonProofProgress::BaseRoots(next_index) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        };
        if self.schedule.ordered_base_tree_ordinals.get(next_index) != Some(&tree_ordinal) {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::BaseRoot { tree_ordinal }, &root)?;
        self.progress = CommonProofProgress::BaseRoots(next_index + 1);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_application_challenge_group(
        &mut self,
        challenge: CommonProofChallenge,
    ) -> Result<Vec<u64>, TranscriptError> {
        let CommonProofProgress::ApplicationChallenges(next_index) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        let Some(expected) = self
            .schedule
            .ordered_application_challenge_groups
            .get(next_index)
            .copied()
        else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if expected.challenge != challenge {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let mut stream = self.transcript.begin_common_challenge(challenge)?;
        let sampled = stream.sample_residue_vector(
            expected.modulus,
            expected.coordinate_count,
            self.schedule.maximum_candidate_draws_per_output,
        )?;
        let mut canonical_output_bytes = Vec::with_capacity(
            sampled
                .len()
                .checked_mul(std::mem::size_of::<u64>())
                .ok_or(TranscriptError::ChallengeCounterOverflow)?,
        );
        for coordinate in &sampled {
            canonical_output_bytes.extend_from_slice(&coordinate.to_le_bytes());
        }
        self.transcript
            .finish_common_challenge(stream, canonical_output_bytes)?;
        self.progress = CommonProofProgress::ApplicationChallenges(next_index + 1);
        self.skip_empty_prefix_phases();
        Ok(sampled)
    }

    pub(crate) fn absorb_auxiliary_root(
        &mut self,
        tree_ordinal: u16,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        let CommonProofProgress::AuxiliaryRoots(next_index) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        };
        if self
            .schedule
            .ordered_auxiliary_tree_ordinals
            .get(next_index)
            != Some(&tree_ordinal)
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::AuxiliaryRoot { tree_ordinal }, &root)?;
        self.progress = CommonProofProgress::AuxiliaryRoots(next_index + 1);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_composition_challenge(
        &mut self,
        constraint_ordinal: u16,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        let CommonProofProgress::CompositionChallenges(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if next_ordinal != constraint_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let challenge = CommonProofChallenge::Composition { constraint_ordinal };
        let sampled = self.sample_extension(challenge, |_| false)?;
        self.progress = CommonProofProgress::CompositionChallenges(next_ordinal + 1);
        self.skip_empty_prefix_phases();
        Ok(sampled)
    }

    pub(crate) fn absorb_quotient_root(
        &mut self,
        component_ordinal: u16,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        let CommonProofProgress::QuotientRoots(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        };
        if next_ordinal != component_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::QuotientRoot { component_ordinal }, &root)?;
        self.progress = CommonProofProgress::QuotientRoots(next_ordinal + 1);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_deep_point<F>(
        &mut self,
        point_ordinal: u16,
        mut is_forbidden: F,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError>
    where
        F: FnMut(ProofChallengeExtensionElement) -> bool,
    {
        let CommonProofProgress::DeepPoints(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if next_ordinal != point_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let already_accepted = self.accepted_deep_points.clone();
        let sampled = self.sample_extension(
            CommonProofChallenge::DeepPoint { point_ordinal },
            |candidate| {
                candidate.is_zero()
                    || already_accepted.contains(&candidate)
                    || is_forbidden(candidate)
            },
        )?;
        self.accepted_deep_points.push(sampled);
        self.progress = CommonProofProgress::DeepPoints(next_ordinal + 1);
        self.skip_empty_prefix_phases();
        Ok(sampled)
    }

    #[cfg(test)]
    pub(crate) fn absorb_deep_values(
        &mut self,
        canonical_deep_values_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::DeepValues
            || canonical_deep_values_bytes.is_empty()
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::DeepValues, canonical_deep_values_bytes)?;
        self.progress = match self.schedule.privacy_mode {
            CommonProofPrivacyMode::PublicOnly => CommonProofProgress::OpeningBatchChallenges(0),
            CommonProofPrivacyMode::SecretBearing => CommonProofProgress::OpeningBatchMaskRoot,
        };
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn absorb_deep_evaluations(
        &mut self,
        deep_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::DeepValues
            || deep_evaluations.len() != usize::from(self.schedule.opening_claim_count)
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_extension_value_list(CommonProofRound::DeepValues, deep_evaluations)?;
        self.progress = match self.schedule.privacy_mode {
            CommonProofPrivacyMode::PublicOnly => CommonProofProgress::OpeningBatchChallenges(0),
            CommonProofPrivacyMode::SecretBearing => CommonProofProgress::OpeningBatchMaskRoot,
        };
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn absorb_opening_batch_mask_root(
        &mut self,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::OpeningBatchMaskRoot {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::OpeningBatchMaskRoot, &root)?;
        self.progress = CommonProofProgress::OpeningBatchChallenges(0);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_opening_batch_challenge(
        &mut self,
        claim_ordinal: u16,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        let CommonProofProgress::OpeningBatchChallenges(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if next_ordinal != claim_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let sampled = self
            .sample_extension(CommonProofChallenge::OpeningBatch { claim_ordinal }, |_| {
                false
            })?;
        self.progress = CommonProofProgress::OpeningBatchChallenges(next_ordinal + 1);
        self.skip_empty_prefix_phases();
        Ok(sampled)
    }

    pub(crate) fn sample_fri_fold_challenge(
        &mut self,
        fold_ordinal: u16,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        let CommonProofProgress::FriFoldChallenge(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if next_ordinal != fold_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let sampled =
            self.sample_extension(CommonProofChallenge::FriFold { fold_ordinal }, |_| false)?;
        self.progress = if fold_ordinal + 1 < self.schedule.fri_fold_count {
            CommonProofProgress::FriLayerRoot(fold_ordinal)
        } else {
            CommonProofProgress::FriTerminal
        };
        Ok(sampled)
    }

    pub(crate) fn absorb_fri_layer_root(
        &mut self,
        fold_ordinal: u16,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        let CommonProofProgress::FriLayerRoot(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        };
        if next_ordinal != fold_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::FriLayerRoot { fold_ordinal }, &root)?;
        self.progress = CommonProofProgress::FriFoldChallenge(fold_ordinal + 1);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn absorb_fri_terminal(
        &mut self,
        canonical_terminal_coefficients_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::FriTerminal
            || canonical_terminal_coefficients_bytes.is_empty()
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript.absorb_common_round(
            CommonProofRound::FriTerminal,
            canonical_terminal_coefficients_bytes,
        )?;
        self.progress = CommonProofProgress::QueryRepresentatives(0);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn absorb_fri_terminal_coefficients(
        &mut self,
        terminal_coefficients: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::FriTerminal
            || terminal_coefficients.len()
                != usize::try_from(self.schedule.terminal_coefficient_count)
                    .map_err(|_| TranscriptError::InvalidCommonProofSchedule)?
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript.absorb_common_extension_value_list(
            CommonProofRound::FriTerminal,
            terminal_coefficients,
        )?;
        self.progress = CommonProofProgress::QueryRepresentatives(0);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    /// Samples the complete ordered query vector from one typed SHAKE256 XOF
    /// verifier message. The evaluation orbit is a power of two, so every
    /// fixed-width candidate maps uniformly; duplicate candidates are retried
    /// inside this one message. Conditional on the checked draw ceiling not
    /// being exhausted, the result is uniform without replacement.
    pub(crate) fn sample_query_representatives(&mut self) -> Result<Vec<u64>, TranscriptError> {
        let CommonProofProgress::QueryRepresentatives(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if next_ordinal != 0
            || !self.accepted_query_representatives.is_empty()
            || !self.schedule.query_orbit_count.is_power_of_two()
        {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let candidate_bit_length = 64_u32
            .checked_sub((self.schedule.query_orbit_count - 1).leading_zeros())
            .ok_or(TranscriptError::InvalidChallengeModulus)?;
        let candidate_byte_length = usize::try_from(candidate_bit_length.div_ceil(8))
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let candidate_count = usize::try_from(self.schedule.unique_query_count)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
            .checked_mul(
                usize::try_from(self.schedule.maximum_candidate_draws_per_output)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let random_byte_length = candidate_count
            .checked_mul(candidate_byte_length)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let (stream, verifier_randomness) = self
            .transcript
            .begin_common_xof_challenge(CommonProofChallenge::QueryVector, random_byte_length)?;
        let mut selected = BTreeSet::new();
        let mut randomness_offset = 0_usize;
        for _ in 0..self.schedule.unique_query_count {
            let mut accepted = None;
            for _ in 0..self.schedule.maximum_candidate_draws_per_output {
                let candidate_end = randomness_offset
                    .checked_add(candidate_byte_length)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                let candidate_bytes = verifier_randomness
                    .get(randomness_offset..candidate_end)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                randomness_offset = candidate_end;
                let mut canonical_candidate = [0_u8; std::mem::size_of::<u64>()];
                canonical_candidate[..candidate_byte_length].copy_from_slice(candidate_bytes);
                let candidate =
                    u64::from_le_bytes(canonical_candidate) % self.schedule.query_orbit_count;
                if selected.insert(candidate) {
                    accepted = Some(candidate);
                    break;
                }
            }
            self.accepted_query_representatives
                .push(accepted.ok_or(TranscriptError::CommonChallengeDrawsExhausted)?);
        }
        let mut canonical_output_bytes = Vec::new();
        canonical_output_bytes
            .try_reserve_exact(
                self.accepted_query_representatives
                    .len()
                    .checked_mul(std::mem::size_of::<u64>())
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?,
            )
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        for representative in &self.accepted_query_representatives {
            canonical_output_bytes.extend_from_slice(&representative.to_le_bytes());
        }
        self.transcript
            .finish_common_challenge(stream, canonical_output_bytes)?;
        self.progress = CommonProofProgress::QueryRepresentatives(self.schedule.unique_query_count);
        self.skip_empty_prefix_phases();
        Ok(self.accepted_query_representatives.clone())
    }

    pub(crate) fn sorted_query_representatives(&self) -> Result<Vec<u64>, TranscriptError> {
        if !matches!(
            self.progress,
            CommonProofProgress::QueryOpenings | CommonProofProgress::Complete
        ) {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        let mut sorted = self.accepted_query_representatives.clone();
        sorted.sort_unstable();
        Ok(sorted)
    }

    #[cfg(test)]
    pub(crate) fn absorb_query_openings(
        &mut self,
        canonical_query_openings_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        let mut absorber = self.begin_query_openings(canonical_query_openings_bytes.len())?;
        absorber.absorb(canonical_query_openings_bytes)?;
        self.finish_query_openings(absorber)
    }

    pub(crate) fn begin_query_openings(
        &self,
        canonical_query_openings_byte_length: usize,
    ) -> Result<CommonProofQueryOpeningAbsorber, TranscriptError> {
        if self.progress != CommonProofProgress::QueryOpenings {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        Ok(CommonProofQueryOpeningAbsorber {
            round_message_absorber: self.transcript.begin_streamed_common_round(
                CommonProofRound::QueryOpenings,
                canonical_query_openings_byte_length,
            )?,
        })
    }

    pub(crate) fn finish_query_openings(
        &mut self,
        absorber: CommonProofQueryOpeningAbsorber,
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::QueryOpenings {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .finish_streamed_common_round(absorber.round_message_absorber)?;
        self.progress = CommonProofProgress::Complete;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::Complete
            || self.transcript.pending_common_challenge.is_some()
        {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) const fn transcript_state_for_test(&self) -> [u8; 64] {
        self.transcript.state
    }

    fn sample_extension<F>(
        &mut self,
        challenge: CommonProofChallenge,
        mut is_forbidden: F,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError>
    where
        F: FnMut(ProofChallengeExtensionElement) -> bool,
    {
        let mut stream = self.transcript.begin_common_challenge(challenge)?;
        for draw_ordinal in 0..self.schedule.maximum_candidate_draws_per_output {
            if let Some(candidate) = stream.sample_extension_candidate()?
                && !is_forbidden(candidate)
            {
                let mut canonical_output_bytes = Vec::with_capacity(
                    PROOF_CHALLENGE_EXTENSION_DEGREE * std::mem::size_of::<u64>(),
                );
                for coordinate in candidate.canonical_coordinates() {
                    canonical_output_bytes.extend_from_slice(&coordinate.to_le_bytes());
                }
                self.transcript
                    .finish_common_challenge(stream, canonical_output_bytes)?;
                return Ok(candidate);
            }
            if draw_ordinal + 1 < self.schedule.maximum_candidate_draws_per_output {
                stream.reject_current_candidate()?;
            }
        }
        Err(TranscriptError::CommonChallengeDrawsExhausted)
    }

    fn skip_empty_prefix_phases(&mut self) {
        loop {
            self.progress = match self.progress {
                CommonProofProgress::BaseRoots(next)
                    if next == self.schedule.ordered_base_tree_ordinals.len() =>
                {
                    CommonProofProgress::ApplicationChallenges(0)
                }
                CommonProofProgress::ApplicationChallenges(next)
                    if next == self.schedule.ordered_application_challenge_groups.len() =>
                {
                    CommonProofProgress::AuxiliaryRoots(0)
                }
                CommonProofProgress::AuxiliaryRoots(next)
                    if next == self.schedule.ordered_auxiliary_tree_ordinals.len() =>
                {
                    CommonProofProgress::CompositionChallenges(0)
                }
                CommonProofProgress::CompositionChallenges(next)
                    if next == self.schedule.composition_challenge_count =>
                {
                    CommonProofProgress::QuotientRoots(0)
                }
                CommonProofProgress::QuotientRoots(next)
                    if next == self.schedule.quotient_component_count =>
                {
                    CommonProofProgress::DeepPoints(0)
                }
                CommonProofProgress::DeepPoints(next) if next == self.schedule.deep_point_count => {
                    CommonProofProgress::DeepValues
                }
                CommonProofProgress::OpeningBatchChallenges(next)
                    if next == self.schedule.opening_claim_count =>
                {
                    CommonProofProgress::FriFoldChallenge(0)
                }
                CommonProofProgress::QueryRepresentatives(next)
                    if next == self.schedule.unique_query_count =>
                {
                    CommonProofProgress::QueryOpenings
                }
                _ => break,
            };
        }
    }
}

struct CommonChallengeStream {
    current_candidate_seed: [u8; 64],
    challenge_tag: String,
    next_draw_ordinal: Option<u64>,
}

impl CommonChallengeStream {
    fn new(challenge_seed: [u8; 64], challenge_tag: String) -> Self {
        Self {
            current_candidate_seed: challenge_seed,
            challenge_tag,
            next_draw_ordinal: Some(1),
        }
    }

    /// Samples one uniform vector from `Z_modulus^coordinate_count` with one
    /// random-oracle draw.  The accepted integer is reduced modulo the full
    /// product cardinality and only then decoded into base-`modulus` digits;
    /// the coordinates are not separate Fiat-Shamir verifier messages.
    fn sample_residue_vector(
        &mut self,
        modulus: u64,
        coordinate_count: u16,
        maximum_candidate_draws: u32,
    ) -> Result<Vec<u64>, TranscriptError> {
        if modulus <= 1 || coordinate_count == 0 || maximum_candidate_draws == 0 {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        let sample_space = BigUint::one() << 512_usize;
        let modulus_big = BigUint::from(modulus);
        let product_cardinality = modulus_big.pow(u32::from(coordinate_count));
        if product_cardinality >= sample_space {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        let acceptance_limit = (&sample_space / &product_cardinality) * &product_cardinality;
        for draw_ordinal in 0..maximum_candidate_draws {
            let candidate = BigUint::from_bytes_le(&self.current_candidate_seed);
            if candidate < acceptance_limit {
                let mut encoded_vector = candidate % &product_cardinality;
                let mut coordinates = Vec::new();
                coordinates
                    .try_reserve_exact(usize::from(coordinate_count))
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
                for _ in 0..coordinate_count {
                    coordinates.push(
                        u64::try_from(&encoded_vector % &modulus_big)
                            .map_err(|_| TranscriptError::InvalidChallengeModulus)?,
                    );
                    encoded_vector /= &modulus_big;
                }
                if encoded_vector != BigUint::default() {
                    return Err(TranscriptError::InvalidChallengeModulus);
                }
                return Ok(coordinates);
            }
            if draw_ordinal + 1 < maximum_candidate_draws {
                self.reject_current_candidate()?;
            }
        }
        Err(TranscriptError::CommonChallengeDrawsExhausted)
    }

    /// Samples one uniformly distributed element of the complete challenge
    /// extension. One draw uses the complete 512-bit candidate seed and
    /// rejection is performed once against the extension cardinality. A
    /// caller's draw ceiling therefore bounds the whole logical output.
    fn sample_extension_candidate(
        &self,
    ) -> Result<Option<ProofChallengeExtensionElement>, TranscriptError> {
        let base_field_modulus = BigUint::from(PROOF_BASE_FIELD_MODULUS);
        let extension_cardinality = base_field_modulus.pow(
            u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                .map_err(|_| TranscriptError::InvalidChallengeModulus)?,
        );
        let sample_space = BigUint::one() << 512_usize;
        let acceptance_limit = (&sample_space / &extension_cardinality) * &extension_cardinality;
        let candidate = BigUint::from_bytes_le(&self.current_candidate_seed);
        if candidate >= acceptance_limit {
            return Ok(None);
        }

        let mut residue = candidate % &extension_cardinality;
        let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coordinate in &mut coordinates {
            *coordinate = u64::try_from(&residue % &base_field_modulus)
                .map_err(|_| TranscriptError::InvalidChallengeModulus)?;
            residue /= &base_field_modulus;
        }
        if residue != BigUint::default() {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
            .map(Some)
            .map_err(|_| TranscriptError::InvalidChallengeModulus)
    }

    fn reject_current_candidate(&mut self) -> Result<(), TranscriptError> {
        let response_tag = format!("{}/rejected", self.challenge_tag);
        let rejection_state = transcript_hash(
            TRANSCRIPT_ABSORB_DOMAIN,
            vec![
                CanonicalItem::hash512(self.current_candidate_seed),
                CanonicalItem::nonempty_ascii(&response_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            ],
        )?;
        let draw_ordinal = self
            .next_draw_ordinal
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        self.current_candidate_seed = transcript_hash(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512(rejection_state),
                CanonicalItem::nonempty_ascii(&self.challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(draw_ordinal),
            ],
        )?;
        self.next_draw_ordinal = draw_ordinal.checked_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod common_challenge_chain_tests {
    use num_bigint::BigUint;

    use crate::bgv::proof_suite::field::{
        PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    };

    use super::{
        CanonicalProofTranscript, CommonChallengeStream, CommonProofChallenge,
        CommonProofPrivacyMode, CommonProofRound, CommonProofTranscriptSchedule,
    };

    fn transcript() -> CanonicalProofTranscript {
        CanonicalProofTranscript::try_new(1, [0x5a; 64], 0x1211, b"header")
            .expect("the test transcript header is canonical")
    }

    fn theta_challenge() -> CommonProofChallenge {
        CommonProofChallenge::Theta { modulus_ordinal: 0 }
    }

    fn alpha_challenge() -> CommonProofChallenge {
        CommonProofChallenge::Alpha { modulus_ordinal: 0 }
    }

    #[test]
    fn accepted_challenge_output_changes_the_next_challenge_seed() {
        let mut first = transcript();
        let mut second = transcript();

        let first_stream = first
            .begin_common_challenge(theta_challenge())
            .expect("the first challenge starts");
        first
            .finish_common_challenge(first_stream, vec![0x01])
            .expect("the first accepted output is recorded");

        let second_stream = second
            .begin_common_challenge(theta_challenge())
            .expect("the second challenge starts");
        second
            .finish_common_challenge(second_stream, vec![0x02])
            .expect("the changed accepted output is recorded");

        let first_next_seed = first
            .begin_common_challenge(alpha_challenge())
            .expect("the first downstream challenge starts")
            .current_candidate_seed;
        let second_next_seed = second
            .begin_common_challenge(alpha_challenge())
            .expect("the second downstream challenge starts")
            .current_candidate_seed;

        assert_ne!(first_next_seed, second_next_seed);
    }

    #[test]
    fn accepted_challenge_output_is_bound_into_the_immediate_response() {
        let mut first = transcript();
        let mut second = transcript();

        let first_stream = first
            .begin_common_challenge(theta_challenge())
            .expect("the first challenge starts");
        first
            .finish_common_challenge(first_stream, vec![0x01])
            .expect("the first accepted output is recorded");
        let second_stream = second
            .begin_common_challenge(theta_challenge())
            .expect("the second challenge starts");
        second
            .finish_common_challenge(second_stream, vec![0x02])
            .expect("the changed accepted output is recorded");

        first
            .absorb_common_round(
                CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 },
                &[7; 64],
            )
            .expect("the first response is absorbed");
        second
            .absorb_common_round(
                CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 },
                &[7; 64],
            )
            .expect("the second response is absorbed");

        assert_ne!(first.state, second.state);
    }

    #[test]
    fn rejected_candidate_advances_the_alternating_hash_chain() {
        let initial_seed = [0x5a; 64];
        let mut stream = CommonChallengeStream::new(initial_seed, "test-rejection".to_owned());

        stream
            .reject_current_candidate()
            .expect("the rejected candidate advances the challenge chain");

        assert_ne!(stream.current_candidate_seed, initial_seed);
        assert_eq!(stream.next_draw_ordinal, Some(2));
    }

    #[test]
    fn changing_challenge_order_changes_the_downstream_response_state() {
        let mut first = transcript();
        let mut second = transcript();

        let first_theta = first
            .begin_common_challenge(theta_challenge())
            .expect("theta starts");
        first
            .finish_common_challenge(first_theta, vec![0x31])
            .expect("theta output is recorded");
        let first_alpha = first
            .begin_common_challenge(alpha_challenge())
            .expect("alpha follows theta");
        first
            .finish_common_challenge(first_alpha, vec![0x32])
            .expect("alpha output is recorded");

        let second_alpha = second
            .begin_common_challenge(alpha_challenge())
            .expect("alpha starts");
        second
            .finish_common_challenge(second_alpha, vec![0x32])
            .expect("alpha output is recorded");
        let second_theta = second
            .begin_common_challenge(theta_challenge())
            .expect("theta follows alpha");
        second
            .finish_common_challenge(second_theta, vec![0x31])
            .expect("theta output is recorded");

        first
            .absorb_common_round(
                CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 },
                &[7; 64],
            )
            .expect("the first response is bound to the pending challenge");
        second
            .absorb_common_round(
                CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 },
                &[7; 64],
            )
            .expect("the second response is bound to the pending challenge");

        assert_ne!(first.state, second.state);
        assert!(first.pending_common_challenge.is_none());
        assert!(second.pending_common_challenge.is_none());
    }

    #[test]
    fn extended_query_vector_is_one_deterministic_xof_message() {
        let mut first = transcript();
        let mut second = transcript();

        let (first_stream, first_randomness) = first
            .begin_common_xof_challenge(CommonProofChallenge::QueryVector, 4_096)
            .expect("the first extended verifier message derives");
        let (second_stream, second_randomness) = second
            .begin_common_xof_challenge(CommonProofChallenge::QueryVector, 4_096)
            .expect("the repeated extended verifier message derives");

        assert_eq!(
            first_stream.current_candidate_seed,
            second_stream.current_candidate_seed
        );
        assert_eq!(first_randomness, second_randomness);
        assert_eq!(first_randomness.len(), 4_096);
        assert!(first_randomness.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn transcript_hash_budget_is_derived_from_the_exact_round_chain() {
        let schedule = |maximum_candidate_draws_per_output| {
            CommonProofTranscriptSchedule::new(
                vec![0],
                Vec::new(),
                Vec::new(),
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                2,
                maximum_candidate_draws_per_output,
                CommonProofPrivacyMode::PublicOnly,
            )
            .expect("the minimal schedule is valid")
        };

        assert_eq!(
            schedule(1)
                .maximum_transcript_hash_query_count()
                .expect("the exact hash budget derives"),
            13,
        );
        assert_eq!(
            schedule(2)
                .maximum_transcript_hash_query_count()
                .expect("the larger rejection ceiling derives"),
            21,
        );
    }

    #[test]
    fn extension_sampler_decodes_one_uniform_full_field_candidate() {
        let modulus = BigUint::from(PROOF_BASE_FIELD_MODULUS);
        let expected_coordinates = [1_u64, 2, 3, 4, 5];
        let mut candidate = BigUint::default();
        let mut place = BigUint::from(1_u8);
        for coordinate in expected_coordinates {
            candidate += &place * BigUint::from(coordinate);
            place *= &modulus;
        }
        let encoded = candidate.to_bytes_le();
        let mut block = [0_u8; 64];
        block[..encoded.len()].copy_from_slice(&encoded);
        let stream = CommonChallengeStream::new(block, "test-extension".to_owned());

        let sampled = stream
            .sample_extension_candidate()
            .expect("the full-extension draw is well formed")
            .expect("the canonical candidate is accepted");

        assert_eq!(sampled.canonical_coordinates(), expected_coordinates);
        assert_eq!(stream.current_candidate_seed, block);
    }

    #[test]
    fn product_residue_sampler_decodes_one_uniform_vector_candidate() {
        let modulus = 65_537_u64;
        let expected_coordinates = [0_u64, 1, 65_536, 17, 9, 42, 7];
        let mut candidate = BigUint::default();
        let mut place = BigUint::from(1_u8);
        for coordinate in expected_coordinates {
            candidate += &place * BigUint::from(coordinate);
            place *= BigUint::from(modulus);
        }
        let encoded = candidate.to_bytes_le();
        let mut block = [0_u8; 64];
        block[..encoded.len()].copy_from_slice(&encoded);
        let mut stream = CommonChallengeStream::new(block, "test-product".to_owned());

        let sampled = stream
            .sample_residue_vector(modulus, 7, 1)
            .expect("the product-space candidate is accepted");

        assert_eq!(sampled, expected_coordinates);
        assert_eq!(stream.current_candidate_seed, block);
    }

    #[test]
    fn product_residue_sampler_rejects_an_oversized_product_space() {
        let mut stream = CommonChallengeStream::new([0_u8; 64], "test-product".to_owned());

        assert_eq!(
            stream.sample_residue_vector(2, 512, 1),
            Err(super::TranscriptError::InvalidChallengeModulus),
        );
    }

    #[test]
    fn extension_sampler_rejects_the_first_out_of_range_candidate() {
        let modulus = BigUint::from(PROOF_BASE_FIELD_MODULUS);
        let extension_cardinality = modulus.pow(
            u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE).expect("the extension degree fits u32"),
        );
        let sample_space = BigUint::from(1_u8) << 512_usize;
        let acceptance_limit = (&sample_space / &extension_cardinality) * extension_cardinality;
        let encoded = acceptance_limit.to_bytes_le();
        let mut block = [0_u8; 64];
        block[..encoded.len()].copy_from_slice(&encoded);
        let stream = CommonChallengeStream::new(block, "test-extension".to_owned());

        assert_eq!(
            stream
                .sample_extension_candidate()
                .expect("the rejection boundary is well formed"),
            None,
        );
        assert_eq!(stream.current_candidate_seed, block);
    }
}

/// Shared distinct-query sampler for proof transcript tests. The caller
/// supplies a deterministic 64-byte challenge
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
