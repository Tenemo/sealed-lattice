use std::collections::BTreeSet;

use num_bigint::BigUint;
use num_traits::One;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalItemType,
    CanonicalTuple, Hash512, StreamingFoundationHashError, StreamingFoundationTupleHash512,
    fill_foundation_tuple_xof, hash_foundation_tuple_512,
};

use super::field::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement,
};
use super::relation_plan::RelationApplicationChallengeAssignment;

const TRANSCRIPT_INITIAL_DOMAIN: &str = "sealed-lattice/proof/transcript/v1";
const TRANSCRIPT_ABSORB_DOMAIN: &str = "sealed-lattice/proof/transcript/absorb/v1";
const TRANSCRIPT_SQUEEZE_DOMAIN: &str = "sealed-lattice/proof/transcript/squeeze/v1";
const PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE: &str = "sealed-lattice/proof/product-residue-vector/v1";

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
    InvalidCommonProofSchedule,
    UnexpectedCommonProofRound,
    UnexpectedCommonProofChallenge,
    InvalidCommonProofMessage,
    InvalidChallengeModulus,
    CommonChallengeDrawsExhausted,
    ChallengeCounterOverflow,
    IncompleteCommonProofTranscript,
    UnexpectedRowCodeWhirRound,
    UnexpectedRowCodeWhirChallenge,
    IncompleteRowCodeWhirTranscript,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum DistinctQuerySamplingError {
    InvalidQueryDomain,
    QueryCountExceedsDomain,
    CandidateDrawsExhausted { output_index: usize },
    ChallengeBlockUnavailable { output_index: usize },
}

#[derive(Clone, Debug)]
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
    fn try_new(
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
                    CanonicalItem::variable_bytes(canonical_proof_object_header_bytes)
                        .map_err(|_| TranscriptError::CanonicalEncoding)?,
                ],
            )?,
            pending_common_challenge: None,
        })
    }

    fn absorb_common_round(
        &mut self,
        round: CommonProofRound,
        canonical_round_message_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        self.absorb_typed_round(
            round.tag(self.application_statement_schema_identifier),
            round.requires_hash512_message(),
            canonical_round_message_bytes,
        )
    }

    fn absorb_typed_round(
        &mut self,
        round_tag: String,
        requires_hash512_message: bool,
        canonical_round_message_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if requires_hash512_message && canonical_round_message_bytes.len() != 64 {
            return Err(TranscriptError::InvalidCommonProofMessage);
        }
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
            CanonicalItem::variable_bytes(canonical_round_message_bytes)
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
        self.begin_streamed_typed_round(
            round.tag(self.application_statement_schema_identifier),
            round.requires_hash512_message(),
            canonical_round_message_byte_length,
        )
    }

    fn begin_streamed_typed_round(
        &self,
        round_tag: String,
        requires_hash512_message: bool,
        canonical_round_message_byte_length: usize,
    ) -> Result<CommonProofRoundMessageAbsorber, TranscriptError> {
        if requires_hash512_message || canonical_round_message_byte_length == 0 {
            return Err(TranscriptError::InvalidCommonProofMessage);
        }
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
        self.absorb_typed_extension_value_list(
            round.tag(self.application_statement_schema_identifier),
            values,
        )
    }

    fn absorb_typed_extension_value_list(
        &mut self,
        round_tag: String,
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
        let mut absorber =
            self.begin_streamed_typed_round(round_tag, false, message_byte_length)?;
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
        self.begin_typed_challenge(challenge.tag(self.application_statement_schema_identifier))
    }

    fn begin_typed_challenge(
        &mut self,
        challenge_tag: String,
    ) -> Result<CommonChallengeStream, TranscriptError> {
        self.close_pending_common_challenge()?;
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

    /// Begins one typed product-space verifier message. The fixed-width chain
    /// handle and every variable-length rejection candidate bind the sampler
    /// geometry. Candidate ordinals are separate XOF inputs under that handle.
    fn begin_common_product_residue_challenge(
        &mut self,
        group: CommonProofApplicationChallengeGroup,
    ) -> Result<(CommonChallengeStream, Vec<u8>), TranscriptError> {
        self.close_pending_common_challenge()?;
        if !group.challenge.is_application_challenge() {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let challenge_tag = group
            .challenge
            .tag(self.application_statement_schema_identifier);
        let candidate_byte_length = usize::try_from(group.candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let chain_handle = transcript_hash(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::nonempty_ascii(PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(group.modulus),
                CanonicalItem::unsigned16(group.coordinate_count),
                CanonicalItem::unsigned64(group.candidate_byte_length),
                CanonicalItem::unsigned64(
                    u64::try_from(Hash512::BYTE_LENGTH)
                        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
                ),
            ],
        )?;
        let mut first_candidate = Vec::new();
        first_candidate
            .try_reserve_exact(candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        first_candidate.resize(candidate_byte_length, 0);
        transcript_xof(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            product_residue_candidate_xof_input(
                chain_handle,
                &challenge_tag,
                group.modulus,
                group.coordinate_count,
                0,
                candidate_byte_length,
                candidate_byte_length,
            )?,
            &mut first_candidate,
        )?;
        Ok((
            CommonChallengeStream::new(chain_handle, challenge_tag),
            first_candidate,
        ))
    }

    /// Begins one logical verifier message backed by one SHAKE256 XOF
    /// evaluation. The first 512 output bits are the chain handle; the rest
    /// are verifier coins consumed locally by the schedule-bounded sampler.
    fn begin_common_xof_challenge(
        &mut self,
        challenge: CommonProofChallenge,
        random_byte_length: usize,
    ) -> Result<(CommonChallengeStream, Vec<u8>), TranscriptError> {
        self.begin_typed_xof_challenge(
            challenge.tag(self.application_statement_schema_identifier),
            random_byte_length,
        )
    }

    fn begin_typed_xof_challenge(
        &mut self,
        challenge_tag: String,
        random_byte_length: usize,
    ) -> Result<(CommonChallengeStream, Vec<u8>), TranscriptError> {
        self.close_pending_common_challenge()?;
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
        output.copy_within(Hash512::BYTE_LENGTH.., 0);
        output.truncate(random_byte_length);
        Ok((
            CommonChallengeStream::new(chain_handle, challenge_tag),
            output,
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
    Composition { constraint_ordinal: u32 },
    DeepPoint { point_ordinal: u16 },
    OpeningBatch { claim_ordinal: u32 },
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

    fn accepts_application_modulus(self, modulus: u64) -> bool {
        match self {
            Self::Theta { .. } => modulus == PROOF_BASE_FIELD_MODULUS,
            Self::Alpha { .. } => modulus > 1 && modulus < PROOF_BASE_FIELD_MODULUS,
            _ => false,
        }
    }

    fn is_application_challenge(self) -> bool {
        matches!(self, Self::Theta { .. } | Self::Alpha { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowCodeWhirPhase {
    Base,
    Auxiliary,
}

impl RowCodeWhirPhase {
    const fn tag(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Auxiliary => "auxiliary",
        }
    }
}

/// Closed verifier-message roles between the common relation prefix and WHIR.
/// The verifier chooses every role and ordinal from checked production geometry;
/// proof bytes never provide a free-form transcript label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowCodeWhirChallenge {
    PointSelectorWeight {
        opening_point_ordinal: u16,
        selector_ordinal: u16,
    },
    PhaseRowWeight {
        opening_point_ordinal: u16,
        phase: RowCodeWhirPhase,
        row_ordinal: u32,
    },
    QuotientComponentWeight,
    OpeningBatchMaskWeight,
    BoundOpeningWeight {
        column_ordinal: u32,
    },
    OuterQueryVector,
    BoundQueryVector,
    BoundDegreeCoordinate {
        block_ordinal: u16,
        degree_test_ordinal: u16,
        coordinate_ordinal: u16,
    },
}

impl RowCodeWhirChallenge {
    fn tag(self) -> String {
        let prefix = "row-code-whir";
        match self {
            Self::PointSelectorWeight {
                opening_point_ordinal,
                selector_ordinal,
            } => format!(
                "{prefix}/point/{opening_point_ordinal:04x}/selector/{selector_ordinal:04x}"
            ),
            Self::PhaseRowWeight {
                opening_point_ordinal,
                phase,
                row_ordinal,
            } => format!(
                "{prefix}/point/{opening_point_ordinal:04x}/{}/row/{row_ordinal:08x}",
                phase.tag()
            ),
            Self::QuotientComponentWeight => {
                format!("{prefix}/quotient-component-weight")
            }
            Self::OpeningBatchMaskWeight => format!("{prefix}/opening-batch-mask-weight"),
            Self::BoundOpeningWeight { column_ordinal } => {
                format!("{prefix}/bound-opening-weight/{column_ordinal:08x}")
            }
            Self::OuterQueryVector => format!("{prefix}/outer-query-vector"),
            Self::BoundQueryVector => format!("{prefix}/bound-query-vector"),
            Self::BoundDegreeCoordinate {
                block_ordinal,
                degree_test_ordinal,
                coordinate_ordinal,
            } => format!(
                "{prefix}/bound-degree/{block_ordinal:04x}/{degree_test_ordinal:04x}/{coordinate_ordinal:04x}"
            ),
        }
    }

    const fn stage(self) -> RowCodeWhirChallengeStage {
        match self {
            Self::PointSelectorWeight { .. }
            | Self::PhaseRowWeight { .. }
            | Self::QuotientComponentWeight
            | Self::OpeningBatchMaskWeight
            | Self::BoundOpeningWeight { .. } => RowCodeWhirChallengeStage::BeforeCommitment,
            Self::OuterQueryVector
            | Self::BoundQueryVector
            | Self::BoundDegreeCoordinate { .. } => RowCodeWhirChallengeStage::AfterCommitment,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirChallengeStage {
    BeforeCommitment,
    AfterCommitment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirRound {
    OpeningBatchMaskEvaluations,
    ProtocolSchedule,
    AggregateCommitment,
    WhirCommitment { commitment_ordinal: u32 },
    WhirValues { observation_ordinal: u32 },
    FinalProofOpenings,
}

impl RowCodeWhirRound {
    fn tag(self) -> String {
        let prefix = "row-code-whir";
        match self {
            Self::OpeningBatchMaskEvaluations => {
                format!("{prefix}/opening-batch-mask-evaluations")
            }
            Self::ProtocolSchedule => format!("{prefix}/protocol-schedule"),
            Self::AggregateCommitment => format!("{prefix}/aggregate-commitment"),
            Self::WhirCommitment { commitment_ordinal } => {
                format!("{prefix}/whir-commitment/{commitment_ordinal:08x}")
            }
            Self::WhirValues {
                observation_ordinal,
            } => format!("{prefix}/whir-values/{observation_ordinal:08x}"),
            Self::FinalProofOpenings => format!("{prefix}/final-proof-openings"),
        }
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
    candidate_byte_length: u64,
}

impl CommonProofApplicationChallengeGroup {
    pub(crate) fn new(
        challenge: CommonProofChallenge,
        modulus: u64,
        coordinate_count: u16,
    ) -> Result<Self, TranscriptError> {
        if !challenge.accepts_application_modulus(modulus) || coordinate_count == 0 {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let candidate_byte_length =
            product_residue_candidate_byte_length(modulus, coordinate_count).and_then(
                |length| {
                    u64::try_from(length).map_err(|_| TranscriptError::ChallengeCounterOverflow)
                },
            )?;
        Ok(Self {
            challenge,
            modulus,
            coordinate_count,
            candidate_byte_length,
        })
    }

    pub(crate) fn challenge(self) -> CommonProofChallenge {
        self.challenge
    }

    #[cfg(test)]
    pub(crate) const fn modulus(self) -> u64 {
        self.modulus
    }

    pub(crate) fn coordinate_count(self) -> u16 {
        self.coordinate_count
    }

    #[cfg(test)]
    pub(crate) const fn candidate_byte_length(self) -> u64 {
        self.candidate_byte_length
    }
}

/// Source-owned accounting for one typed theta or alpha product-vector
/// sampler. It is ordinary verifier state and is never serialized or accepted
/// from proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofApplicationChallengeSamplerAccounting {
    challenge: CommonProofChallenge,
    modulus: u64,
    coordinate_count: u16,
    candidate_byte_length: u64,
    maximum_candidate_draw_count: u32,
    accepted_vector_byte_length: u64,
    chain_handle_xof_query_count: u64,
    candidate_xof_query_count_ceiling: u64,
    total_xof_query_count_ceiling: u64,
}

impl CommonProofApplicationChallengeSamplerAccounting {
    pub(crate) const fn challenge(self) -> CommonProofChallenge {
        self.challenge
    }

    pub(crate) const fn modulus(self) -> u64 {
        self.modulus
    }

    pub(crate) const fn coordinate_count(self) -> u16 {
        self.coordinate_count
    }

    pub(crate) const fn candidate_byte_length(self) -> u64 {
        self.candidate_byte_length
    }

    pub(crate) const fn maximum_candidate_draw_count(self) -> u32 {
        self.maximum_candidate_draw_count
    }

    pub(crate) const fn accepted_vector_byte_length(self) -> u64 {
        self.accepted_vector_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn chain_handle_xof_query_count(self) -> u64 {
        self.chain_handle_xof_query_count
    }

    #[cfg(test)]
    pub(crate) const fn candidate_xof_query_count_ceiling(self) -> u64 {
        self.candidate_xof_query_count_ceiling
    }

    pub(crate) const fn total_xof_query_count_ceiling(self) -> u64 {
        self.total_xof_query_count_ceiling
    }

    /// The sampler reuses one candidate allocation across every bounded draw.
    pub(crate) const fn reusable_candidate_buffer_byte_length(self) -> u64 {
        self.candidate_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn maximum_xof_output_byte_length(self) -> u64 {
        if self.candidate_byte_length > Hash512::BYTE_LENGTH as u64 {
            self.candidate_byte_length
        } else {
            Hash512::BYTE_LENGTH as u64
        }
    }
}

/// Exact source-owned live payload of one typed foundation-tuple hash or XOF
/// call. The caller-owned typed input, the domain-framed clone, and the encoded
/// tuple are simultaneously live while SHAKE absorbs the canonical preimage.
/// Allocator bookkeeping and allocator-selected excess capacity are runtime
/// measurements rather than protocol-derived payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommonProofTypedXofMemoryAccounting {
    typed_input_item_storage_byte_length: u64,
    typed_input_payload_byte_length: u64,
    framed_item_storage_byte_length: u64,
    framed_payload_byte_length: u64,
    encoded_tuple_byte_length: u64,
    total_byte_length: u64,
}

impl CommonProofTypedXofMemoryAccounting {
    pub(crate) const fn total_byte_length(self) -> u64 {
        self.total_byte_length
    }
}

/// Source-owned live-payload accounting for one bounded product-residue vector draw.
/// The accepted coordinate vector is a distinct owner from the reusable
/// candidate buffer, and the BigUint term covers the live 32-bit limb payloads
/// used by the exact product-space rejection and radix decode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommonProofProductSamplerMemoryAccounting {
    challenge_tag_byte_length: u64,
    #[cfg(test)]
    reusable_candidate_buffer_byte_length: u64,
    accepted_coordinate_vector_byte_length: u64,
    big_integer_limb_working_set_byte_length: u64,
    typed_xof_memory_accounting: CommonProofTypedXofMemoryAccounting,
    xof_draw_peak_byte_length: u64,
    accepted_decode_peak_byte_length: u64,
    maximum_peak_byte_length: u64,
}

impl CommonProofProductSamplerMemoryAccounting {
    pub(crate) const fn challenge_tag_byte_length(self) -> u64 {
        self.challenge_tag_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn reusable_candidate_buffer_byte_length(self) -> u64 {
        self.reusable_candidate_buffer_byte_length
    }

    pub(crate) const fn accepted_coordinate_vector_byte_length(self) -> u64 {
        self.accepted_coordinate_vector_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn big_integer_limb_working_set_byte_length(self) -> u64 {
        self.big_integer_limb_working_set_byte_length
    }

    pub(crate) const fn typed_xof_memory_accounting(self) -> CommonProofTypedXofMemoryAccounting {
        self.typed_xof_memory_accounting
    }

    #[cfg(test)]
    pub(crate) const fn accepted_decode_peak_byte_length(self) -> u64 {
        self.accepted_decode_peak_byte_length
    }

    pub(crate) const fn maximum_peak_byte_length(self) -> u64 {
        self.maximum_peak_byte_length
    }
}

/// Complete source-derived transcript live-payload owners used by the common
/// prover's resident-memory plan. This is development accounting only; none of
/// these values is serialized into a proof or interpreted as a verification
/// result. Allocator metadata remains an empirical runtime measurement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommonProofTranscriptMemoryAccounting {
    schedule_catalog_byte_length: u64,
    accepted_deep_point_catalog_byte_length: u64,
    accepted_query_catalog_byte_length: u64,
    pending_challenge_tag_byte_length: u64,
    pending_challenge_output_byte_length: u64,
    product_sampler_memory_accounting: CommonProofProductSamplerMemoryAccounting,
    extension_sampler_big_integer_limb_working_set_byte_length: u64,
    deep_point_prior_catalog_clone_byte_length: u64,
    query_xof_output_buffer_byte_length: u64,
    maximum_transcript_codec_overlap_byte_length: u64,
    maximum_output_overlap_byte_length: u64,
    persistent_transcript_byte_length: u64,
    maximum_transient_byte_length: u64,
}

impl CommonProofTranscriptMemoryAccounting {
    pub(crate) const fn schedule_catalog_byte_length(self) -> u64 {
        self.schedule_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn accepted_deep_point_catalog_byte_length(self) -> u64 {
        self.accepted_deep_point_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn accepted_query_catalog_byte_length(self) -> u64 {
        self.accepted_query_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn pending_challenge_tag_byte_length(self) -> u64 {
        self.pending_challenge_tag_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn pending_challenge_output_byte_length(self) -> u64 {
        self.pending_challenge_output_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn product_sampler_memory_accounting(
        self,
    ) -> CommonProofProductSamplerMemoryAccounting {
        self.product_sampler_memory_accounting
    }

    #[cfg(test)]
    pub(crate) const fn deep_point_prior_catalog_clone_byte_length(self) -> u64 {
        self.deep_point_prior_catalog_clone_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn query_xof_output_buffer_byte_length(self) -> u64 {
        self.query_xof_output_buffer_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn maximum_transcript_codec_overlap_byte_length(self) -> u64 {
        self.maximum_transcript_codec_overlap_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn maximum_output_overlap_byte_length(self) -> u64 {
        self.maximum_output_overlap_byte_length
    }

    pub(crate) const fn persistent_transcript_byte_length(self) -> u64 {
        self.persistent_transcript_byte_length
    }

    pub(crate) const fn maximum_transient_byte_length(self) -> u64 {
        self.maximum_transient_byte_length
    }
}

fn checked_memory_add(left: u64, right: u64) -> Result<u64, TranscriptError> {
    left.checked_add(right)
        .ok_or(TranscriptError::ChallengeCounterOverflow)
}

fn checked_memory_multiply(left: u64, right: u64) -> Result<u64, TranscriptError> {
    left.checked_mul(right)
        .ok_or(TranscriptError::ChallengeCounterOverflow)
}

fn usize_memory_byte_length(value: usize) -> Result<u64, TranscriptError> {
    u64::try_from(value).map_err(|_| TranscriptError::ChallengeCounterOverflow)
}

fn typed_foundation_tuple_memory_accounting(
    domain: &str,
    typed_input_items: Vec<CanonicalItem>,
) -> Result<CommonProofTypedXofMemoryAccounting, TranscriptError> {
    let canonical_item_byte_length =
        usize_memory_byte_length(std::mem::size_of::<CanonicalItem>())?;
    let typed_input_item_storage_byte_length = checked_memory_multiply(
        usize_memory_byte_length(typed_input_items.capacity())?,
        canonical_item_byte_length,
    )?;
    let typed_input_payload_byte_length =
        typed_input_items.iter().try_fold(0_u64, |total, item| {
            checked_memory_add(
                total,
                usize_memory_byte_length(item.canonical_bytes().len())?,
            )
        })?;
    let mut framed_items = Vec::with_capacity(
        typed_input_items
            .len()
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?,
    );
    framed_items.push(
        CanonicalItem::nonempty_ascii(domain).map_err(|_| TranscriptError::CanonicalEncoding)?,
    );
    framed_items.extend_from_slice(&typed_input_items);
    let framed_item_storage_byte_length = checked_memory_multiply(
        usize_memory_byte_length(framed_items.capacity())?,
        canonical_item_byte_length,
    )?;
    let framed_payload_byte_length = framed_items.iter().try_fold(0_u64, |total, item| {
        checked_memory_add(
            total,
            usize_memory_byte_length(item.canonical_bytes().len())?,
        )
    })?;
    let encoded_tuple_byte_length = usize_memory_byte_length(
        CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            framed_items,
        )
        .encode()
        .map_err(|_| TranscriptError::CanonicalEncoding)?
        .len(),
    )?;
    let total_byte_length = [
        typed_input_item_storage_byte_length,
        typed_input_payload_byte_length,
        framed_item_storage_byte_length,
        framed_payload_byte_length,
        encoded_tuple_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_memory_add)?;
    Ok(CommonProofTypedXofMemoryAccounting {
        typed_input_item_storage_byte_length,
        typed_input_payload_byte_length,
        framed_item_storage_byte_length,
        framed_payload_byte_length,
        encoded_tuple_byte_length,
        total_byte_length,
    })
}

fn big_integer_limb_payload_byte_length(value: &BigUint) -> Result<u64, TranscriptError> {
    checked_memory_multiply(
        value
            .bits()
            .checked_add(31)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?
            .div_ceil(32),
        usize_memory_byte_length(std::mem::size_of::<u32>())?,
    )
}

fn product_sampler_memory_accounting(
    group: CommonProofApplicationChallengeGroup,
    maximum_candidate_draws: u32,
    application_statement_schema_identifier: u16,
) -> Result<CommonProofProductSamplerMemoryAccounting, TranscriptError> {
    let sampler = application_challenge_sampler_accounting(group, maximum_candidate_draws)?;
    let candidate_byte_length = usize::try_from(sampler.candidate_byte_length())
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
    let challenge_tag = group.challenge.tag(application_statement_schema_identifier);
    let candidate_xof_memory_accounting = typed_foundation_tuple_memory_accounting(
        TRANSCRIPT_SQUEEZE_DOMAIN,
        product_residue_candidate_xof_input(
            [0_u8; Hash512::BYTE_LENGTH],
            &challenge_tag,
            group.modulus,
            group.coordinate_count,
            u64::from(maximum_candidate_draws.saturating_sub(1)),
            candidate_byte_length,
            candidate_byte_length,
        )?,
    )?;
    let chain_handle_memory_accounting = typed_foundation_tuple_memory_accounting(
        TRANSCRIPT_SQUEEZE_DOMAIN,
        vec![
            CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
            CanonicalItem::nonempty_ascii(&challenge_tag)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
            CanonicalItem::nonempty_ascii(PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
            CanonicalItem::unsigned64(group.modulus),
            CanonicalItem::unsigned16(group.coordinate_count),
            CanonicalItem::unsigned64(sampler.candidate_byte_length()),
            CanonicalItem::unsigned64(Hash512::BYTE_LENGTH as u64),
        ],
    )?;
    let typed_xof_memory_accounting = if chain_handle_memory_accounting.total_byte_length()
        > candidate_xof_memory_accounting.total_byte_length()
    {
        chain_handle_memory_accounting
    } else {
        candidate_xof_memory_accounting
    };

    let modulus = BigUint::from(group.modulus);
    let product_cardinality = modulus.pow(u32::from(group.coordinate_count));
    let sample_space = BigUint::one()
        << candidate_byte_length
            .checked_mul(8)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    let acceptance_quotient = &sample_space / &product_cardinality;
    let acceptance_limit = &acceptance_quotient * &product_cardinality;
    let maximum_candidate = &sample_space - BigUint::one();
    let maximum_encoded_vector = &maximum_candidate % &product_cardinality;
    let persistent_big_integer_limb_byte_length = [
        &modulus,
        &product_cardinality,
        &sample_space,
        &acceptance_limit,
    ]
    .into_iter()
    .try_fold(0_u64, |total, value| {
        checked_memory_add(total, big_integer_limb_payload_byte_length(value)?)
    })?;
    let acceptance_construction_transient_byte_length =
        big_integer_limb_payload_byte_length(&acceptance_quotient)?;
    let accepted_decode_transient_byte_length = checked_memory_add(
        big_integer_limb_payload_byte_length(&maximum_candidate)?,
        big_integer_limb_payload_byte_length(&maximum_encoded_vector)?,
    )?;
    let big_integer_limb_working_set_byte_length = checked_memory_add(
        persistent_big_integer_limb_byte_length,
        acceptance_construction_transient_byte_length.max(accepted_decode_transient_byte_length),
    )?;
    let reusable_candidate_buffer_byte_length = sampler.reusable_candidate_buffer_byte_length();
    let accepted_coordinate_vector_byte_length = sampler.accepted_vector_byte_length();
    let challenge_tag_byte_length = usize_memory_byte_length(challenge_tag.capacity())?;
    let xof_draw_peak_byte_length = [
        challenge_tag_byte_length,
        reusable_candidate_buffer_byte_length,
        persistent_big_integer_limb_byte_length,
        typed_xof_memory_accounting.total_byte_length(),
    ]
    .into_iter()
    .try_fold(0_u64, checked_memory_add)?;
    let accepted_decode_peak_byte_length = [
        challenge_tag_byte_length,
        reusable_candidate_buffer_byte_length,
        persistent_big_integer_limb_byte_length,
        accepted_decode_transient_byte_length,
        accepted_coordinate_vector_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_memory_add)?;
    Ok(CommonProofProductSamplerMemoryAccounting {
        challenge_tag_byte_length,
        #[cfg(test)]
        reusable_candidate_buffer_byte_length,
        accepted_coordinate_vector_byte_length,
        big_integer_limb_working_set_byte_length,
        typed_xof_memory_accounting,
        xof_draw_peak_byte_length,
        accepted_decode_peak_byte_length,
        maximum_peak_byte_length: xof_draw_peak_byte_length.max(accepted_decode_peak_byte_length),
    })
}

fn extension_sampler_big_integer_limb_working_set_byte_length() -> Result<u64, TranscriptError> {
    let base_field_modulus = BigUint::from(PROOF_BASE_FIELD_MODULUS);
    let extension_cardinality = base_field_modulus.pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
    );
    let sample_space = BigUint::one() << 512_usize;
    let acceptance_quotient = &sample_space / &extension_cardinality;
    let acceptance_limit = &acceptance_quotient * &extension_cardinality;
    let maximum_candidate = &sample_space - BigUint::one();
    let maximum_residue = &maximum_candidate % &extension_cardinality;
    let persistent_byte_length = [
        &base_field_modulus,
        &extension_cardinality,
        &sample_space,
        &acceptance_limit,
    ]
    .into_iter()
    .try_fold(0_u64, |total, value| {
        checked_memory_add(total, big_integer_limb_payload_byte_length(value)?)
    })?;
    let construction_transient_byte_length =
        big_integer_limb_payload_byte_length(&acceptance_quotient)?;
    let accepted_transient_byte_length = checked_memory_add(
        big_integer_limb_payload_byte_length(&maximum_candidate)?,
        big_integer_limb_payload_byte_length(&maximum_residue)?,
    )?;
    checked_memory_add(
        persistent_byte_length,
        construction_transient_byte_length.max(accepted_transient_byte_length),
    )
}

/// Exact plan-derived schedule needed to reject omitted, reordered, repeated,
/// or mode-incompatible common-proof messages before algebraic verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofTranscriptSchedule {
    ordered_base_tree_ordinals: Vec<u16>,
    ordered_application_challenge_groups: Vec<CommonProofApplicationChallengeGroup>,
    ordered_auxiliary_tree_ordinals: Vec<u16>,
    composition_challenge_count: u32,
    quotient_component_count: u16,
    deep_point_count: u16,
    opening_claim_count: u32,
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
        composition_challenge_count: u32,
        quotient_component_count: u16,
        deep_point_count: u16,
        opening_claim_count: u32,
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
                    !entry.challenge.accepts_application_modulus(entry.modulus)
                        || entry.coordinate_count == 0
                        || entry.candidate_byte_length == 0
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

    pub(crate) fn ordered_application_challenge_sampler_accounting(
        &self,
    ) -> Result<Vec<CommonProofApplicationChallengeSamplerAccounting>, TranscriptError> {
        self.ordered_application_challenge_groups
            .iter()
            .copied()
            .map(|group| {
                application_challenge_sampler_accounting(
                    group,
                    self.maximum_candidate_draws_per_output,
                )
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) const fn maximum_candidate_draws_per_output(&self) -> u32 {
        self.maximum_candidate_draws_per_output
    }

    #[cfg(test)]
    pub(crate) fn maximum_application_challenge_sampler_scratch_byte_length(
        &self,
    ) -> Result<u64, TranscriptError> {
        Ok(self
            .ordered_application_challenge_sampler_accounting()?
            .into_iter()
            .map(|row| row.reusable_candidate_buffer_byte_length())
            .max()
            .unwrap_or(0))
    }

    /// Derives every dynamically owned transcript payload from the checked
    /// production schedule and the canonical tuple codec used by the runtime.
    /// The result is a live-payload ceiling; the one fixed WebAssembly stack is
    /// accounted by the build evidence rather than repeated here.
    pub(crate) fn live_payload_memory_accounting(
        &self,
        application_statement_schema_identifier: u16,
    ) -> Result<CommonProofTranscriptMemoryAccounting, TranscriptError> {
        let schedule_catalog_byte_length = [
            checked_memory_multiply(
                usize_memory_byte_length(self.ordered_base_tree_ordinals.capacity())?,
                usize_memory_byte_length(std::mem::size_of::<u16>())?,
            )?,
            checked_memory_multiply(
                usize_memory_byte_length(self.ordered_application_challenge_groups.capacity())?,
                usize_memory_byte_length(
                    std::mem::size_of::<CommonProofApplicationChallengeGroup>(),
                )?,
            )?,
            checked_memory_multiply(
                usize_memory_byte_length(self.ordered_auxiliary_tree_ordinals.capacity())?,
                usize_memory_byte_length(std::mem::size_of::<u16>())?,
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_memory_add)?;

        let mut maximum_product_sampler_memory_accounting =
            CommonProofProductSamplerMemoryAccounting::default();
        let mut maximum_application_output_byte_length = 0_u64;
        for (group, sampler) in self
            .ordered_application_challenge_groups
            .iter()
            .copied()
            .zip(self.ordered_application_challenge_sampler_accounting()?)
        {
            let memory = product_sampler_memory_accounting(
                group,
                self.maximum_candidate_draws_per_output,
                application_statement_schema_identifier,
            )?;
            if memory.maximum_peak_byte_length()
                > maximum_product_sampler_memory_accounting.maximum_peak_byte_length()
            {
                maximum_product_sampler_memory_accounting = memory;
            }
            maximum_application_output_byte_length =
                maximum_application_output_byte_length.max(sampler.accepted_vector_byte_length());
        }

        let extension_output_byte_length = checked_memory_multiply(
            usize_memory_byte_length(PROOF_CHALLENGE_EXTENSION_DEGREE)?,
            usize_memory_byte_length(std::mem::size_of::<u64>())?,
        )?;
        let accepted_deep_point_catalog_byte_length = checked_memory_multiply(
            u64::from(self.deep_point_count),
            usize_memory_byte_length(std::mem::size_of::<ProofChallengeExtensionElement>())?,
        )?;
        let accepted_query_catalog_byte_length = checked_memory_multiply(
            u64::from(self.unique_query_count),
            usize_memory_byte_length(std::mem::size_of::<u64>())?,
        )?;
        let deep_point_prior_catalog_clone_byte_length = checked_memory_multiply(
            u64::from(self.deep_point_count.saturating_sub(1)),
            usize_memory_byte_length(std::mem::size_of::<ProofChallengeExtensionElement>())?,
        )?;

        let mut challenge_tags = self
            .ordered_application_challenge_groups
            .iter()
            .map(|group| group.challenge.tag(application_statement_schema_identifier))
            .collect::<Vec<_>>();
        challenge_tags.extend([
            CommonProofChallenge::Composition {
                constraint_ordinal: self.composition_challenge_count - 1,
            }
            .tag(application_statement_schema_identifier),
            CommonProofChallenge::DeepPoint {
                point_ordinal: self.deep_point_count - 1,
            }
            .tag(application_statement_schema_identifier),
            CommonProofChallenge::OpeningBatch {
                claim_ordinal: self.opening_claim_count - 1,
            }
            .tag(application_statement_schema_identifier),
            CommonProofChallenge::FriFold {
                fold_ordinal: self.fri_fold_count - 1,
            }
            .tag(application_statement_schema_identifier),
            CommonProofChallenge::QueryVector.tag(application_statement_schema_identifier),
        ]);
        let pending_challenge_tag_byte_length = challenge_tags
            .iter()
            .map(|tag| usize_memory_byte_length(tag.capacity()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let maximum_challenge_tag = challenge_tags
            .into_iter()
            .max_by_key(String::capacity)
            .ok_or(TranscriptError::InvalidCommonProofSchedule)?;
        let pending_challenge_output_byte_length = maximum_application_output_byte_length
            .max(extension_output_byte_length)
            .max(accepted_query_catalog_byte_length);

        let query_xof_output_buffer_byte_length =
            usize_memory_byte_length(query_vector_xof_output_byte_length(
                self.query_orbit_count,
                self.unique_query_count,
                self.maximum_candidate_draws_per_output,
            )?)?;
        let query_tag =
            CommonProofChallenge::QueryVector.tag(application_statement_schema_identifier);
        let query_xof_codec = typed_foundation_tuple_memory_accounting(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
                CanonicalItem::nonempty_ascii(&query_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(0),
            ],
        )?;

        let extension_initial_codec = typed_foundation_tuple_memory_accounting(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            vec![
                CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
                CanonicalItem::nonempty_ascii(&maximum_challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(0),
            ],
        )?;
        let rejected_tag = format!("{maximum_challenge_tag}/rejected");
        let extension_rejection_codec = typed_foundation_tuple_memory_accounting(
            TRANSCRIPT_ABSORB_DOMAIN,
            vec![
                CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
                CanonicalItem::nonempty_ascii(&rejected_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            ],
        )?;

        let round_tags = [
            CommonProofRound::BaseRoot { tree_ordinal: 0 },
            CommonProofRound::AuxiliaryRoot { tree_ordinal: 0 },
            CommonProofRound::QuotientRoot {
                component_ordinal: self.quotient_component_count - 1,
            },
            CommonProofRound::DeepValues,
            CommonProofRound::OpeningBatchMaskRoot,
            CommonProofRound::FriLayerRoot {
                fold_ordinal: self.fri_fold_count - 1,
            },
            CommonProofRound::FriTerminal,
            CommonProofRound::QueryOpenings,
        ]
        .map(|round| round.tag(application_statement_schema_identifier));
        let maximum_round_tag = round_tags
            .into_iter()
            .max_by_key(String::capacity)
            .ok_or(TranscriptError::InvalidCommonProofSchedule)?;
        let response_codec = typed_foundation_tuple_memory_accounting(
            TRANSCRIPT_ABSORB_DOMAIN,
            vec![
                CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
                CanonicalItem::nonempty_ascii(&maximum_round_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::variable_bytes(vec![
                    0_u8;
                    usize::try_from(
                        pending_challenge_output_byte_length,
                    )
                    .map_err(|_| {
                        TranscriptError::ChallengeCounterOverflow
                    },)?
                ])
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::variable_bytes(vec![0_u8; Hash512::BYTE_LENGTH])
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
            ],
        )?;
        let accepted_tag = format!("{maximum_challenge_tag}/accepted");
        let close_pending_codec = typed_foundation_tuple_memory_accounting(
            TRANSCRIPT_ABSORB_DOMAIN,
            vec![
                CanonicalItem::hash512([0_u8; Hash512::BYTE_LENGTH]),
                CanonicalItem::nonempty_ascii(&accepted_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::variable_bytes(vec![
                    0_u8;
                    usize::try_from(
                        pending_challenge_output_byte_length,
                    )
                    .map_err(|_| {
                        TranscriptError::ChallengeCounterOverflow
                    },)?
                ])
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
            ],
        )?;
        let maximum_transcript_codec_overlap_byte_length = [
            maximum_product_sampler_memory_accounting
                .typed_xof_memory_accounting()
                .total_byte_length(),
            query_xof_codec.total_byte_length(),
            extension_initial_codec.total_byte_length(),
            extension_rejection_codec.total_byte_length(),
            response_codec.total_byte_length(),
            close_pending_codec.total_byte_length(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        let query_tag_byte_length = usize_memory_byte_length(query_tag.capacity())?;
        let query_xof_draw_overlap_byte_length = [
            query_tag_byte_length,
            query_xof_output_buffer_byte_length,
            query_xof_codec.total_byte_length(),
        ]
        .into_iter()
        .try_fold(0_u64, checked_memory_add)?;
        let query_decode_overlap_byte_length = [
            query_tag_byte_length,
            query_xof_output_buffer_byte_length,
            checked_memory_multiply(accepted_query_catalog_byte_length, 2)?,
        ]
        .into_iter()
        .try_fold(0_u64, checked_memory_add)?;
        let query_return_overlap_byte_length = checked_memory_add(
            query_tag_byte_length,
            checked_memory_multiply(accepted_query_catalog_byte_length, 2)?,
        )?;
        let product_output_overlap_byte_length = checked_memory_add(
            maximum_product_sampler_memory_accounting.challenge_tag_byte_length(),
            checked_memory_multiply(
                maximum_product_sampler_memory_accounting.accepted_coordinate_vector_byte_length(),
                2,
            )?,
        )?;
        let maximum_output_overlap_byte_length = [
            query_xof_draw_overlap_byte_length,
            query_decode_overlap_byte_length,
            query_return_overlap_byte_length,
            product_output_overlap_byte_length,
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        let extension_sampler_big_integer_limb_working_set_byte_length =
            extension_sampler_big_integer_limb_working_set_byte_length()?;
        let extension_sampler_transient_byte_length = [
            pending_challenge_tag_byte_length,
            deep_point_prior_catalog_clone_byte_length,
            extension_sampler_big_integer_limb_working_set_byte_length.max(
                extension_initial_codec
                    .total_byte_length()
                    .max(extension_rejection_codec.total_byte_length()),
            ),
        ]
        .into_iter()
        .try_fold(0_u64, checked_memory_add)?;
        let persistent_transcript_byte_length = [
            schedule_catalog_byte_length,
            accepted_deep_point_catalog_byte_length,
            accepted_query_catalog_byte_length,
            pending_challenge_tag_byte_length,
            pending_challenge_output_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_memory_add)?;
        let maximum_transient_byte_length = maximum_product_sampler_memory_accounting
            .maximum_peak_byte_length()
            .max(extension_sampler_transient_byte_length)
            .max(maximum_transcript_codec_overlap_byte_length)
            .max(maximum_output_overlap_byte_length);

        Ok(CommonProofTranscriptMemoryAccounting {
            schedule_catalog_byte_length,
            accepted_deep_point_catalog_byte_length,
            accepted_query_catalog_byte_length,
            pending_challenge_tag_byte_length,
            pending_challenge_output_byte_length,
            product_sampler_memory_accounting: maximum_product_sampler_memory_accounting,
            extension_sampler_big_integer_limb_working_set_byte_length,
            deep_point_prior_catalog_clone_byte_length,
            query_xof_output_buffer_byte_length,
            maximum_transcript_codec_overlap_byte_length,
            maximum_output_overlap_byte_length,
            persistent_transcript_byte_length,
            maximum_transient_byte_length,
        })
    }

    pub(crate) const fn composition_challenge_count(&self) -> u32 {
        self.composition_challenge_count
    }

    pub(crate) const fn quotient_component_count(&self) -> u16 {
        self.quotient_component_count
    }

    pub(crate) const fn opening_claim_count(&self) -> u32 {
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

    /// Exact transcript-hash ceiling through the row-code successor handoff.
    /// The returned state includes the opening-mask evaluations as an
    /// unchallenged typed prover round with its response-binding hash. It
    /// excludes the successor protocol schedule and every later row-code or
    /// WHIR message.
    #[cfg(test)]
    pub(crate) fn maximum_row_code_whir_handoff_hash_query_count(
        &self,
    ) -> Result<u64, TranscriptError> {
        if self.privacy_mode != CommonProofPrivacyMode::SecretBearing {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let mut counter = TranscriptHashQueryCounter::new();

        for _ in &self.ordered_base_tree_ordinals {
            counter.absorb_response()?;
        }
        for challenge in &self.ordered_application_challenge_groups {
            counter.begin_challenge(
                application_challenge_sampler_accounting(
                    *challenge,
                    self.maximum_candidate_draws_per_output,
                )?
                .total_xof_query_count_ceiling(),
            )?;
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
        counter.absorb_response()?;
        // The row-code successor absorbs the checked opening-mask evaluations
        // as an ordinary typed prover round. No opening-batch challenge is
        // sampled or pending at this handoff.
        counter.absorb_response()?;
        counter.finish()
    }

    #[cfg(test)]
    pub(crate) fn maximum_row_code_whir_handoff_logical_verifier_message_count(
        &self,
    ) -> Result<u64, TranscriptError> {
        if self.privacy_mode != CommonProofPrivacyMode::SecretBearing {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        u64::try_from(self.ordered_application_challenge_groups.len())
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
            .checked_add(u64::from(self.composition_challenge_count))
            .and_then(|count| count.checked_add(u64::from(self.deep_point_count)))
            .ok_or(TranscriptError::ChallengeCounterOverflow)
    }

    /// Exact maximum number of typed transcript-hash invocations made while
    /// verifying an accepted proof under this schedule. The bound follows the
    /// same challenge/response state machine as `CommonProofTranscript` and
    /// includes every extension-field rejection-sampling expansion block and
    /// every bounded typed product-vector candidate. An application vector
    /// also consumes one chain-handle query; the complete query vector consumes
    /// one extended XOF answer. It deliberately excludes Merkle authentication,
    /// whose cost is derived from the checked tree catalog and opening geometry.
    #[cfg(test)]
    pub(crate) fn maximum_transcript_hash_query_count(&self) -> Result<u64, TranscriptError> {
        let mut counter = TranscriptHashQueryCounter::new();

        for _ in &self.ordered_base_tree_ordinals {
            counter.absorb_response()?;
        }
        for challenge in &self.ordered_application_challenge_groups {
            counter.begin_challenge(
                application_challenge_sampler_accounting(
                    *challenge,
                    self.maximum_candidate_draws_per_output,
                )?
                .total_xof_query_count_ceiling(),
            )?;
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

    /// Largest finite SHAKE256 answer read by the accepted verifier path.
    /// This is the concrete `L_max` input to the shared ideal-XOF model, not a
    /// transport or proof-byte ceiling.
    #[cfg(test)]
    pub(crate) fn maximum_transcript_xof_output_byte_length(
        &self,
    ) -> Result<usize, TranscriptError> {
        let mut maximum_output_byte_length = Hash512::BYTE_LENGTH;
        for sampler in self.ordered_application_challenge_sampler_accounting()? {
            maximum_output_byte_length = maximum_output_byte_length.max(
                usize::try_from(sampler.maximum_xof_output_byte_length())
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            );
        }
        maximum_output_byte_length =
            maximum_output_byte_length.max(query_vector_xof_output_byte_length(
                self.query_orbit_count,
                self.unique_query_count,
                self.maximum_candidate_draws_per_output,
            )?);
        Ok(maximum_output_byte_length)
    }
}

pub(crate) fn sample_relation_application_challenges(
    transcript: &mut CommonProofTranscript,
    schedule: &CommonProofTranscriptSchedule,
) -> Result<Vec<RelationApplicationChallengeAssignment>, TranscriptError> {
    let assignment_count = schedule
        .ordered_application_challenge_groups()
        .iter()
        .try_fold(0_usize, |count, group| {
            count.checked_add(usize::from(group.coordinate_count()))
        })
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(assignment_count)
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
    for group in schedule.ordered_application_challenge_groups() {
        let challenge = group.challenge();
        let values = transcript.sample_application_challenge_group(challenge)?;
        if values.len() != usize::from(group.coordinate_count()) {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        for (repetition_index, value) in values.into_iter().enumerate() {
            assignments.push(
                RelationApplicationChallengeAssignment::new(
                    challenge,
                    u16::try_from(repetition_index)
                        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
                    value,
                )
                .map_err(|_| TranscriptError::InvalidCommonProofSchedule)?,
            );
        }
    }
    Ok(assignments)
}

#[derive(Clone, Debug)]
struct TranscriptHashQueryCounter {
    hash_query_count: u64,
    logical_verifier_message_count: u64,
    pending_challenge: bool,
}

impl TranscriptHashQueryCounter {
    fn new() -> Self {
        Self {
            // The instance-, suite-, family-, and header-bound initial state.
            hash_query_count: 1,
            logical_verifier_message_count: 0,
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
        self.logical_verifier_message_count = self
            .logical_verifier_message_count
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
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

    const fn logical_verifier_message_count(&self) -> u64 {
        self.logical_verifier_message_count
    }
}

fn application_challenge_sampler_accounting(
    group: CommonProofApplicationChallengeGroup,
    maximum_candidate_draws: u32,
) -> Result<CommonProofApplicationChallengeSamplerAccounting, TranscriptError> {
    if maximum_candidate_draws == 0 {
        return Err(TranscriptError::InvalidChallengeModulus);
    }
    let chain_handle_xof_query_count = 1_u64;
    let candidate_xof_query_count_ceiling = u64::from(maximum_candidate_draws);
    let total_xof_query_count_ceiling = candidate_xof_query_count_ceiling
        .checked_add(chain_handle_xof_query_count)
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    let accepted_vector_byte_length = u64::from(group.coordinate_count)
        .checked_mul(
            u64::try_from(std::mem::size_of::<u64>())
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        )
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    Ok(CommonProofApplicationChallengeSamplerAccounting {
        challenge: group.challenge,
        modulus: group.modulus,
        coordinate_count: group.coordinate_count,
        candidate_byte_length: group.candidate_byte_length,
        maximum_candidate_draw_count: maximum_candidate_draws,
        accepted_vector_byte_length,
        chain_handle_xof_query_count,
        candidate_xof_query_count_ceiling,
        total_xof_query_count_ceiling,
    })
}

fn product_residue_candidate_byte_length(
    modulus: u64,
    coordinate_count: u16,
) -> Result<usize, TranscriptError> {
    if modulus <= 1 || coordinate_count == 0 {
        return Err(TranscriptError::InvalidChallengeModulus);
    }
    let product_cardinality = BigUint::from(modulus).pow(u32::from(coordinate_count));
    let maximum_candidate = &product_cardinality - BigUint::one();
    let candidate_bit_length = maximum_candidate.bits().max(1);
    usize::try_from(
        candidate_bit_length
            .checked_add(7)
            .and_then(|length| length.checked_div(8))
            .ok_or(TranscriptError::ChallengeCounterOverflow)?,
    )
    .map_err(|_| TranscriptError::ChallengeCounterOverflow)
}

fn product_residue_candidate_xof_input(
    transcript_chain_handle: [u8; Hash512::BYTE_LENGTH],
    challenge_tag: &str,
    modulus: u64,
    coordinate_count: u16,
    candidate_ordinal: u64,
    candidate_byte_length: usize,
    output_byte_length: usize,
) -> Result<Vec<CanonicalItem>, TranscriptError> {
    Ok(vec![
        CanonicalItem::hash512(transcript_chain_handle),
        CanonicalItem::nonempty_ascii(challenge_tag)
            .map_err(|_| TranscriptError::CanonicalEncoding)?,
        CanonicalItem::nonempty_ascii(PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE)
            .map_err(|_| TranscriptError::CanonicalEncoding)?,
        CanonicalItem::unsigned64(modulus),
        CanonicalItem::unsigned16(coordinate_count),
        CanonicalItem::unsigned64(candidate_ordinal),
        CanonicalItem::unsigned64(
            u64::try_from(candidate_byte_length)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        ),
        CanonicalItem::unsigned64(
            u64::try_from(output_byte_length)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        ),
    ])
}

fn query_vector_xof_output_byte_length(
    query_orbit_count: u64,
    unique_query_count: u32,
    maximum_candidate_draws_per_output: u32,
) -> Result<usize, TranscriptError> {
    if query_orbit_count == 0
        || !query_orbit_count.is_power_of_two()
        || unique_query_count == 0
        || u64::from(unique_query_count) > query_orbit_count
        || maximum_candidate_draws_per_output == 0
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    let candidate_byte_length = query_vector_candidate_byte_length(query_orbit_count)?;
    let candidate_count = usize::try_from(unique_query_count)
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
        .checked_mul(
            usize::try_from(maximum_candidate_draws_per_output)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        )
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    Hash512::BYTE_LENGTH
        .checked_add(
            candidate_count
                .checked_mul(candidate_byte_length)
                .ok_or(TranscriptError::ChallengeCounterOverflow)?,
        )
        .ok_or(TranscriptError::ChallengeCounterOverflow)
}

fn query_vector_candidate_byte_length(query_orbit_count: u64) -> Result<usize, TranscriptError> {
    if query_orbit_count == 0 || !query_orbit_count.is_power_of_two() {
        return Err(TranscriptError::InvalidChallengeModulus);
    }
    let candidate_bit_length = 64_u32
        .checked_sub((query_orbit_count - 1).leading_zeros())
        .ok_or(TranscriptError::InvalidChallengeModulus)?;
    usize::try_from(candidate_bit_length.div_ceil(8))
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)
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
    CompositionChallenges(u32),
    QuotientRoots(u16),
    DeepPoints(u16),
    DeepValues,
    OpeningBatchMaskRoot,
    OpeningBatchChallenges(u32),
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
    hash_query_counter: TranscriptHashQueryCounter,
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
        let mut accepted_deep_points = Vec::new();
        accepted_deep_points
            .try_reserve_exact(usize::from(schedule.deep_point_count))
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let mut accepted_query_representatives = Vec::new();
        accepted_query_representatives
            .try_reserve_exact(
                usize::try_from(schedule.unique_query_count)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let mut result = Self {
            transcript: CanonicalProofTranscript::try_new(
                protocol_version,
                suite_id,
                application_statement_schema_identifier,
                canonical_proof_object_header_bytes,
            )?,
            hash_query_counter: TranscriptHashQueryCounter::new(),
            schedule,
            progress: CommonProofProgress::BaseRoots(0),
            accepted_deep_points,
            accepted_query_representatives,
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
        self.hash_query_counter.absorb_response()?;
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
        let (stream, first_candidate) = self
            .transcript
            .begin_common_product_residue_challenge(expected)?;
        let sampled = stream.sample_residue_vector(
            first_candidate,
            expected,
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
        self.hash_query_counter.begin_challenge(
            application_challenge_sampler_accounting(
                expected,
                self.schedule.maximum_candidate_draws_per_output,
            )?
            .total_xof_query_count_ceiling(),
        )?;
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
        self.hash_query_counter.absorb_response()?;
        self.progress = CommonProofProgress::AuxiliaryRoots(next_index + 1);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_composition_challenge(
        &mut self,
        constraint_ordinal: u32,
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
        self.hash_query_counter.absorb_response()?;
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
        self.hash_query_counter.absorb_response()?;
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
            || u32::try_from(deep_evaluations.len()).ok() != Some(self.schedule.opening_claim_count)
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_extension_value_list(CommonProofRound::DeepValues, deep_evaluations)?;
        self.hash_query_counter.absorb_response()?;
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
        self.hash_query_counter.absorb_response()?;
        self.progress = CommonProofProgress::OpeningBatchChallenges(0);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_opening_batch_challenge(
        &mut self,
        claim_ordinal: u32,
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
        self.hash_query_counter.absorb_response()?;
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
        self.hash_query_counter.absorb_response()?;
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
        self.hash_query_counter.absorb_response()?;
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
        let candidate_byte_length =
            query_vector_candidate_byte_length(self.schedule.query_orbit_count)?;
        let random_byte_length = query_vector_xof_output_byte_length(
            self.schedule.query_orbit_count,
            self.schedule.unique_query_count,
            self.schedule.maximum_candidate_draws_per_output,
        )?
        .checked_sub(Hash512::BYTE_LENGTH)
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let (stream, verifier_randomness) = self
            .transcript
            .begin_common_xof_challenge(CommonProofChallenge::QueryVector, random_byte_length)?;
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
                if !self.accepted_query_representatives.contains(&candidate) {
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
        self.hash_query_counter.begin_challenge(1)?;
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
        self.hash_query_counter.absorb_response()?;
        self.progress = CommonProofProgress::Complete;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::Complete
            || self.transcript.pending_common_challenge.is_some()
        {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        self.hash_query_counter.finish()?;
        Ok(())
    }

    pub(crate) fn into_row_code_whir_transcript(
        self,
        opening_batch_mask_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<RowCodeWhirTranscript, TranscriptError> {
        if self.schedule.privacy_mode != CommonProofPrivacyMode::SecretBearing
            || self.progress != CommonProofProgress::OpeningBatchChallenges(0)
            || self.transcript.pending_common_challenge.is_some()
            || self.hash_query_counter.pending_challenge
        {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        RowCodeWhirTranscript::from_common_prefix(
            self.transcript,
            self.hash_query_counter,
            self.schedule.maximum_candidate_draws_per_output,
            opening_batch_mask_evaluations,
        )
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
                self.hash_query_counter
                    .begin_challenge(maximum_extension_challenge_hash_count(
                        self.schedule.maximum_candidate_draws_per_output,
                    )?)?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirProgress {
    AwaitingMaskEvaluations,
    AwaitingProtocolSchedule,
    BeforeAggregateCommitment,
    AfterAggregateCommitment,
    Whir,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RowCodeWhirTranscriptSummary {
    maximum_hash_query_count: u64,
    logical_verifier_message_count: u64,
}

impl RowCodeWhirTranscriptSummary {
    pub(crate) const fn maximum_hash_query_count(self) -> u64 {
        self.maximum_hash_query_count
    }

    pub(crate) const fn logical_verifier_message_count(self) -> u64 {
        self.logical_verifier_message_count
    }
}

/// The sole typed Fiat-Shamir state for the row-code construction. It consumes
/// the live common-proof prefix instead of hashing a digest into a second
/// challenger. The checked mask evaluations enter as an ordinary typed prover
/// round with no preceding opening-batch challenge.
#[derive(Clone, Debug)]
pub(crate) struct RowCodeWhirTranscript {
    transcript: CanonicalProofTranscript,
    hash_query_counter: TranscriptHashQueryCounter,
    maximum_candidate_draws_per_output: u32,
    progress: RowCodeWhirProgress,
    next_whir_commitment_ordinal: u32,
    next_whir_observation_ordinal: u32,
    next_whir_challenge_ordinal: u32,
    next_whir_bit_challenge_ordinal: u32,
}

impl RowCodeWhirTranscript {
    fn from_common_prefix(
        transcript: CanonicalProofTranscript,
        hash_query_counter: TranscriptHashQueryCounter,
        maximum_candidate_draws_per_output: u32,
        opening_batch_mask_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<Self, TranscriptError> {
        let mut result = Self {
            transcript,
            hash_query_counter,
            maximum_candidate_draws_per_output,
            progress: RowCodeWhirProgress::AwaitingMaskEvaluations,
            next_whir_commitment_ordinal: 0,
            next_whir_observation_ordinal: 0,
            next_whir_challenge_ordinal: 0,
            next_whir_bit_challenge_ordinal: 0,
        };
        result.absorb_opening_batch_mask_evaluations(opening_batch_mask_evaluations)?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(statement: &[u8]) -> Result<Self, TranscriptError> {
        Ok(Self {
            transcript: CanonicalProofTranscript::try_new(
                1,
                [0_u8; Hash512::BYTE_LENGTH],
                u16::MAX,
                statement,
            )?,
            hash_query_counter: TranscriptHashQueryCounter::new(),
            maximum_candidate_draws_per_output:
                super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            progress: RowCodeWhirProgress::AwaitingProtocolSchedule,
            next_whir_commitment_ordinal: 0,
            next_whir_observation_ordinal: 0,
            next_whir_challenge_ordinal: 0,
            next_whir_bit_challenge_ordinal: 0,
        })
    }

    fn absorb_opening_batch_mask_evaluations(
        &mut self,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if self.progress != RowCodeWhirProgress::AwaitingMaskEvaluations || values.is_empty() {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        self.transcript.absorb_typed_extension_value_list(
            RowCodeWhirRound::OpeningBatchMaskEvaluations.tag(),
            values,
        )?;
        self.hash_query_counter.absorb_response()?;
        self.progress = RowCodeWhirProgress::AwaitingProtocolSchedule;
        Ok(())
    }

    pub(crate) fn absorb_protocol_schedule(
        &mut self,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if self.progress != RowCodeWhirProgress::AwaitingProtocolSchedule || values.is_empty() {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        self.transcript
            .absorb_typed_extension_value_list(RowCodeWhirRound::ProtocolSchedule.tag(), values)?;
        self.hash_query_counter.absorb_response()?;
        self.progress = RowCodeWhirProgress::BeforeAggregateCommitment;
        Ok(())
    }

    pub(crate) fn sample_direct_extension(
        &mut self,
        challenge: RowCodeWhirChallenge,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        let expected_progress = match challenge.stage() {
            RowCodeWhirChallengeStage::BeforeCommitment => {
                RowCodeWhirProgress::BeforeAggregateCommitment
            }
            RowCodeWhirChallengeStage::AfterCommitment => {
                RowCodeWhirProgress::AfterAggregateCommitment
            }
        };
        if self.progress != expected_progress
            || matches!(
                challenge,
                RowCodeWhirChallenge::OuterQueryVector | RowCodeWhirChallenge::BoundQueryVector
            )
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        self.sample_extension_with_tag(challenge.tag())
    }

    pub(crate) fn sample_direct_distinct_indices(
        &mut self,
        challenge: RowCodeWhirChallenge,
        upper_bound: usize,
        output_count: usize,
    ) -> Result<Vec<usize>, TranscriptError> {
        if self.progress != RowCodeWhirProgress::AfterAggregateCommitment
            || !matches!(
                challenge,
                RowCodeWhirChallenge::OuterQueryVector | RowCodeWhirChallenge::BoundQueryVector
            )
            || upper_bound == 0
            || !upper_bound.is_power_of_two()
            || output_count == 0
            || output_count > upper_bound
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let candidate_byte_length = std::mem::size_of::<u64>();
        let random_byte_length = output_count
            .checked_mul(
                usize::try_from(self.maximum_candidate_draws_per_output)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .and_then(|count| count.checked_mul(candidate_byte_length))
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let upper_bound_u64 =
            u64::try_from(upper_bound).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let output_count_u64 =
            u64::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let challenge_tag = format!(
            "{}/{upper_bound_u64:016x}/{output_count_u64:016x}",
            challenge.tag()
        );
        let (stream, randomness) = self
            .transcript
            .begin_typed_xof_challenge(challenge_tag, random_byte_length)?;
        let domain_mask = upper_bound_u64 - 1;
        let mut randomness_offset = 0_usize;
        let mut accepted_set = BTreeSet::new();
        let mut accepted_indices = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let mut accepted_index = None;
            for _ in 0..self.maximum_candidate_draws_per_output {
                let candidate_end = randomness_offset
                    .checked_add(candidate_byte_length)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                let candidate_bytes: [u8; std::mem::size_of::<u64>()] = randomness
                    .get(randomness_offset..candidate_end)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?
                    .try_into()
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
                randomness_offset = candidate_end;
                let candidate = usize::try_from(u64::from_le_bytes(candidate_bytes) & domain_mask)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
                if accepted_set.insert(candidate) {
                    accepted_index = Some(candidate);
                    break;
                }
            }
            accepted_indices
                .push(accepted_index.ok_or(TranscriptError::CommonChallengeDrawsExhausted)?);
        }
        drop(randomness);
        drop(accepted_set);
        let mut canonical_output_bytes = Vec::new();
        canonical_output_bytes
            .try_reserve_exact(
                accepted_indices
                    .len()
                    .checked_mul(candidate_byte_length)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?,
            )
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        for index in &accepted_indices {
            canonical_output_bytes.extend_from_slice(
                &u64::try_from(*index)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
                    .to_le_bytes(),
            );
        }
        self.transcript
            .finish_common_challenge(stream, canonical_output_bytes)?;
        self.hash_query_counter.begin_challenge(1)?;
        Ok(accepted_indices)
    }

    pub(crate) fn observe_commitment(
        &mut self,
        canonical_commitment_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if canonical_commitment_bytes.len() != Hash512::BYTE_LENGTH {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        let round = match self.progress {
            RowCodeWhirProgress::BeforeAggregateCommitment => {
                self.progress = RowCodeWhirProgress::AfterAggregateCommitment;
                RowCodeWhirRound::AggregateCommitment
            }
            RowCodeWhirProgress::AfterAggregateCommitment | RowCodeWhirProgress::Whir => {
                let commitment_ordinal = self.next_whir_commitment_ordinal;
                self.next_whir_commitment_ordinal = commitment_ordinal
                    .checked_add(1)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                self.progress = RowCodeWhirProgress::Whir;
                RowCodeWhirRound::WhirCommitment { commitment_ordinal }
            }
            _ => return Err(TranscriptError::UnexpectedRowCodeWhirRound),
        };
        self.transcript
            .absorb_typed_round(round.tag(), true, canonical_commitment_bytes)?;
        self.hash_query_counter.absorb_response()
    }

    pub(crate) fn observe_whir_values(
        &mut self,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if values.is_empty() {
            return Ok(());
        }
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregateCommitment | RowCodeWhirProgress::Whir
        ) {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        let observation_ordinal = self.next_whir_observation_ordinal;
        self.next_whir_observation_ordinal = observation_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        self.transcript.absorb_typed_extension_value_list(
            RowCodeWhirRound::WhirValues {
                observation_ordinal,
            }
            .tag(),
            values,
        )?;
        self.hash_query_counter.absorb_response()?;
        self.progress = RowCodeWhirProgress::Whir;
        Ok(())
    }

    pub(crate) fn sample_whir_extension(
        &mut self,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregateCommitment | RowCodeWhirProgress::Whir
        ) {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let challenge_ordinal = self.next_whir_challenge_ordinal;
        self.next_whir_challenge_ordinal = challenge_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        self.progress = RowCodeWhirProgress::Whir;
        self.sample_extension_with_tag(format!(
            "row-code-whir/whir-challenge/{challenge_ordinal:08x}"
        ))
    }

    pub(crate) fn sample_whir_bits(&mut self, bits: usize) -> Result<usize, TranscriptError> {
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregateCommitment | RowCodeWhirProgress::Whir
        ) || bits >= usize::BITS as usize
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let challenge_ordinal = self.next_whir_bit_challenge_ordinal;
        self.next_whir_bit_challenge_ordinal = challenge_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let tag = format!("row-code-whir/whir-bits/{challenge_ordinal:08x}/{bits:04x}");
        let (stream, randomness) = self
            .transcript
            .begin_typed_xof_challenge(tag, std::mem::size_of::<u64>())?;
        let bytes: [u8; std::mem::size_of::<u64>()] = randomness
            .as_slice()
            .try_into()
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let mask = if bits == 0 { 0 } else { (1_u64 << bits) - 1 };
        let sampled = usize::try_from(u64::from_le_bytes(bytes) & mask)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        self.transcript
            .finish_common_challenge(stream, (sampled as u64).to_le_bytes().to_vec())?;
        self.hash_query_counter.begin_challenge(1)?;
        self.progress = RowCodeWhirProgress::Whir;
        Ok(sampled)
    }

    pub(crate) fn sample_whir_query_vector(
        &mut self,
        bits: usize,
        epoch_ordinal: u32,
        output_count: usize,
    ) -> Result<Vec<usize>, TranscriptError> {
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregateCommitment | RowCodeWhirProgress::Whir
        ) || bits >= usize::BITS as usize
            || output_count == 0
            || output_count > (1_usize << bits)
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let random_byte_length = output_count
            .checked_mul(
                usize::try_from(self.maximum_candidate_draws_per_output)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let output_count_u64 =
            u64::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let tag = format!(
            "row-code-whir/whir-query-vector/{epoch_ordinal:08x}/{bits:04x}/{output_count_u64:016x}"
        );
        let (stream, randomness) = self
            .transcript
            .begin_typed_xof_challenge(tag, random_byte_length)?;
        let mask = if bits == 0 { 0 } else { (1_u64 << bits) - 1 };
        let mut randomness_chunks = randomness.chunks_exact(std::mem::size_of::<u64>());
        let mut accepted_set = BTreeSet::new();
        let mut accepted_indices = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let mut accepted_index = None;
            for _ in 0..self.maximum_candidate_draws_per_output {
                let candidate_bytes = randomness_chunks
                    .next()
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                let candidate = usize::try_from(
                    u64::from_le_bytes(
                        candidate_bytes
                            .try_into()
                            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
                    ) & mask,
                )
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
                if accepted_set.insert(candidate) {
                    accepted_index = Some(candidate);
                    break;
                }
            }
            accepted_indices
                .push(accepted_index.ok_or(TranscriptError::CommonChallengeDrawsExhausted)?);
        }
        let mut canonical_output_bytes =
            Vec::with_capacity(accepted_indices.len() * std::mem::size_of::<u64>());
        for index in &accepted_indices {
            canonical_output_bytes.extend_from_slice(
                &u64::try_from(*index)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
                    .to_le_bytes(),
            );
        }
        self.transcript
            .finish_common_challenge(stream, canonical_output_bytes)?;
        self.hash_query_counter.begin_challenge(1)?;
        self.progress = RowCodeWhirProgress::Whir;
        Ok(accepted_indices)
    }

    pub(crate) fn finish(
        mut self,
        canonical_proof_bytes: &[u8],
    ) -> Result<RowCodeWhirTranscriptSummary, TranscriptError> {
        if self.progress != RowCodeWhirProgress::Whir || canonical_proof_bytes.is_empty() {
            return Err(TranscriptError::IncompleteRowCodeWhirTranscript);
        }
        let mut absorber = self.transcript.begin_streamed_typed_round(
            RowCodeWhirRound::FinalProofOpenings.tag(),
            false,
            canonical_proof_bytes.len(),
        )?;
        absorber
            .streaming_hash
            .absorb(canonical_proof_bytes)
            .map_err(transcript_streaming_hash_error)?;
        self.transcript.finish_streamed_common_round(absorber)?;
        self.hash_query_counter.absorb_response()?;
        self.progress = RowCodeWhirProgress::Complete;
        if self.transcript.pending_common_challenge.is_some() {
            return Err(TranscriptError::IncompleteRowCodeWhirTranscript);
        }
        let logical_verifier_message_count =
            self.hash_query_counter.logical_verifier_message_count();
        Ok(RowCodeWhirTranscriptSummary {
            maximum_hash_query_count: self.hash_query_counter.finish()?,
            logical_verifier_message_count,
        })
    }

    fn sample_extension_with_tag(
        &mut self,
        challenge_tag: String,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        let mut stream = self.transcript.begin_typed_challenge(challenge_tag)?;
        for draw_ordinal in 0..self.maximum_candidate_draws_per_output {
            if let Some(candidate) = stream.sample_extension_candidate()? {
                let mut canonical_output_bytes = Vec::with_capacity(
                    PROOF_CHALLENGE_EXTENSION_DEGREE * std::mem::size_of::<u64>(),
                );
                for coordinate in candidate.canonical_coordinates() {
                    canonical_output_bytes.extend_from_slice(&coordinate.to_le_bytes());
                }
                self.transcript
                    .finish_common_challenge(stream, canonical_output_bytes)?;
                self.hash_query_counter
                    .begin_challenge(maximum_extension_challenge_hash_count(
                        self.maximum_candidate_draws_per_output,
                    )?)?;
                return Ok(candidate);
            }
            if draw_ordinal + 1 < self.maximum_candidate_draws_per_output {
                stream.reject_current_candidate()?;
            }
        }
        Err(TranscriptError::CommonChallengeDrawsExhausted)
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

    /// Samples one uniform vector from `Z_modulus^coordinate_count` as one
    /// verifier message. Every bounded candidate is a separately typed XOF
    /// input under the fixed transcript chain handle. Rejection occurs against
    /// the complete product cardinality before the accepted residue is decoded
    /// into base-`modulus` coordinates.
    fn sample_residue_vector(
        &self,
        mut candidate_bytes: Vec<u8>,
        group: CommonProofApplicationChallengeGroup,
        maximum_candidate_draws: u32,
    ) -> Result<Vec<u64>, TranscriptError> {
        if group.modulus <= 1 || group.coordinate_count == 0 || maximum_candidate_draws == 0 {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        let modulus_big = BigUint::from(group.modulus);
        let product_cardinality = modulus_big.pow(u32::from(group.coordinate_count));
        let candidate_byte_length = usize::try_from(group.candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        if candidate_bytes.len() != candidate_byte_length {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        let candidate_bit_length = candidate_byte_length
            .checked_mul(8)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let sample_space = BigUint::one() << candidate_bit_length;
        let acceptance_limit = (&sample_space / &product_cardinality) * &product_cardinality;
        for candidate_ordinal in 0..maximum_candidate_draws {
            if candidate_ordinal != 0 {
                transcript_xof(
                    TRANSCRIPT_SQUEEZE_DOMAIN,
                    product_residue_candidate_xof_input(
                        self.current_candidate_seed,
                        &self.challenge_tag,
                        group.modulus,
                        group.coordinate_count,
                        u64::from(candidate_ordinal),
                        candidate_byte_length,
                        candidate_byte_length,
                    )?,
                    &mut candidate_bytes,
                )?;
            }
            let candidate = BigUint::from_bytes_le(&candidate_bytes);
            if candidate < acceptance_limit {
                let mut encoded_vector = candidate % &product_cardinality;
                let mut coordinates = Vec::new();
                coordinates
                    .try_reserve_exact(usize::from(group.coordinate_count))
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
                for _ in 0..group.coordinate_count {
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

#[cfg(test)]
mod row_code_whir_transcript_tests {
    use std::collections::BTreeSet;

    use crate::bgv::proof_suite::field::ProofChallengeExtensionElement;
    use crate::foundation::Hash512;

    use super::{RowCodeWhirChallenge, RowCodeWhirTranscript, TranscriptError};

    fn transcript_before_aggregate_commitment(statement: &[u8]) -> RowCodeWhirTranscript {
        let mut transcript = RowCodeWhirTranscript::new_for_test(statement)
            .expect("the fixed test statement is canonical");
        transcript
            .absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE])
            .expect("the nonempty protocol schedule is accepted in its typed phase");
        transcript
    }

    fn transcript_after_aggregate_commitment(statement: &[u8]) -> RowCodeWhirTranscript {
        let mut transcript = transcript_before_aggregate_commitment(statement);
        transcript
            .observe_commitment(&[0x5a; Hash512::BYTE_LENGTH])
            .expect("the fixed-width aggregate commitment advances the transcript");
        transcript
    }

    fn assert_distinct_acceptance_order(indices: &[usize], expected_count: usize) {
        assert_eq!(indices.len(), expected_count);
        assert_eq!(
            indices.iter().copied().collect::<BTreeSet<_>>().len(),
            expected_count,
            "every accepted query index must be distinct",
        );
        let mut sorted_indices = indices.to_vec();
        sorted_indices.sort_unstable();
        assert_ne!(
            indices, sorted_indices,
            "the transcript must return acceptance order instead of sorting verifier coins",
        );
    }

    #[test]
    fn row_code_whir_typestate_rejects_out_of_order_messages() {
        let mut transcript = RowCodeWhirTranscript::new_for_test(b"typed-order")
            .expect("the fixed test statement is canonical");

        assert_eq!(
            transcript.sample_direct_extension(RowCodeWhirChallenge::PointSelectorWeight {
                opening_point_ordinal: 0,
                selector_ordinal: 0,
            }),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        assert_eq!(
            transcript.observe_commitment(&[0x31; Hash512::BYTE_LENGTH]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(
            transcript.observe_whir_values(&[ProofChallengeExtensionElement::ONE]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(
            transcript.absorb_protocol_schedule(&[]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );

        transcript
            .absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE])
            .expect("the protocol schedule is accepted exactly once");
        assert_eq!(
            transcript.absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(
            transcript.sample_direct_extension(RowCodeWhirChallenge::BoundDegreeCoordinate {
                block_ordinal: 0,
                degree_test_ordinal: 0,
                coordinate_ordinal: 0,
            }),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        assert_eq!(
            transcript
                .sample_direct_distinct_indices(RowCodeWhirChallenge::OuterQueryVector, 8, 2,),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );

        transcript
            .observe_commitment(&[0x31; Hash512::BYTE_LENGTH])
            .expect("the aggregate commitment is accepted after the schedule");
        assert_eq!(
            transcript.sample_direct_extension(RowCodeWhirChallenge::OpeningBatchMaskWeight),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        assert_eq!(
            transcript.absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
    }

    #[test]
    fn row_code_whir_distinct_samplers_validate_geometry_and_preserve_acceptance_order() {
        let mut challenged = transcript_after_aggregate_commitment(b"distinct-acceptance-order");
        for (upper_bound, output_count) in [(0, 1), (3, 1), (4, 0), (4, 5)] {
            assert_eq!(
                challenged.sample_direct_distinct_indices(
                    RowCodeWhirChallenge::BoundQueryVector,
                    upper_bound,
                    output_count,
                ),
                Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
            );
        }
        for (bits, output_count) in [(2, 0), (2, 5), (usize::BITS as usize, 1)] {
            assert_eq!(
                challenged.sample_whir_query_vector(bits, 7, output_count),
                Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
            );
        }

        let direct_indices = challenged
            .sample_direct_distinct_indices(RowCodeWhirChallenge::BoundQueryVector, 16, 8)
            .expect("the bounded direct query vector samples");
        let whir_indices = challenged
            .sample_whir_query_vector(4, 7, 8)
            .expect("the bounded WHIR query vector samples");

        let mut replay = transcript_after_aggregate_commitment(b"distinct-acceptance-order");
        let replayed_direct_indices = replay
            .sample_direct_distinct_indices(RowCodeWhirChallenge::BoundQueryVector, 16, 8)
            .expect("the direct query vector replays deterministically");
        let replayed_whir_indices = replay
            .sample_whir_query_vector(4, 7, 8)
            .expect("the WHIR query vector replays deterministically");

        assert_eq!(direct_indices, replayed_direct_indices);
        assert_eq!(whir_indices, replayed_whir_indices);
        assert_distinct_acceptance_order(&direct_indices, 8);
        assert_distinct_acceptance_order(&whir_indices, 8);
    }

    #[test]
    fn row_code_whir_finish_requires_whir_activity_and_a_nonempty_final_response() {
        let before_whir = transcript_after_aggregate_commitment(b"finish-before-whir");
        assert_eq!(
            before_whir.finish(b"final proof openings"),
            Err(TranscriptError::IncompleteRowCodeWhirTranscript),
        );

        let mut missing_response =
            transcript_after_aggregate_commitment(b"finish-without-response");
        missing_response
            .observe_whir_values(&[ProofChallengeExtensionElement::ONE])
            .expect("one WHIR observation starts the WHIR phase");
        assert_eq!(
            missing_response.finish(&[]),
            Err(TranscriptError::IncompleteRowCodeWhirTranscript),
        );

        let mut pending_challenge =
            transcript_after_aggregate_commitment(b"finish-pending-challenge");
        pending_challenge
            .sample_whir_extension()
            .expect("the fixed WHIR challenge samples within the bounded draw ceiling");
        let summary = pending_challenge
            .finish(b"final proof openings")
            .expect("the final proof response answers the pending verifier challenge");
        assert!(summary.maximum_hash_query_count() > 0);
    }
}

#[cfg(test)]
mod common_challenge_chain_tests {
    use num_bigint::BigUint;

    use crate::bgv::parameters::DATA_PRIMES;
    use crate::bgv::proof_suite::PROOF_NON_NATIVE_THETA_REPETITION_COUNT;
    use crate::bgv::proof_suite::field::{
        PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement,
    };

    use super::{
        CanonicalProofTranscript, CommonChallengeStream, CommonProofApplicationChallengeGroup,
        CommonProofChallenge, CommonProofPrivacyMode, CommonProofRound, CommonProofTranscript,
        CommonProofTranscriptSchedule, TRANSCRIPT_SQUEEZE_DOMAIN, TranscriptError,
        product_residue_candidate_byte_length, product_residue_candidate_xof_input, transcript_xof,
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

    fn transcript_after_deep_values(privacy_mode: CommonProofPrivacyMode) -> CommonProofTranscript {
        let schedule = CommonProofTranscriptSchedule::new(
            Vec::new(),
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
            128,
            privacy_mode,
        )
        .expect("the minimal transcript schedule is valid");
        let mut transcript = CommonProofTranscript::new(1, [0x5a; 64], 0x1211, b"header", schedule)
            .expect("the minimal transcript starts");
        transcript
            .sample_composition_challenge(0)
            .expect("the composition challenge samples");
        transcript
            .absorb_quotient_root(0, [0x31; 64])
            .expect("the quotient root is absorbed");
        transcript
            .sample_deep_point(0, |_| false)
            .expect("the nonzero deep point samples");
        transcript
            .absorb_deep_evaluations(&[ProofChallengeExtensionElement::ONE])
            .expect("the deep evaluation list is absorbed");
        transcript
    }

    #[test]
    fn row_code_handoff_requires_the_unchallenged_secret_bearing_mask_round() {
        let public_transcript = transcript_after_deep_values(CommonProofPrivacyMode::PublicOnly);
        assert!(matches!(
            public_transcript.into_row_code_whir_transcript(&[ProofChallengeExtensionElement::ONE]),
            Err(TranscriptError::IncompleteCommonProofTranscript)
        ));

        let mut secret_transcript =
            transcript_after_deep_values(CommonProofPrivacyMode::SecretBearing);
        secret_transcript
            .absorb_opening_batch_mask_root([0x42; 64])
            .expect("the secret-bearing mask root is absorbed");

        let mut challenged_transcript = secret_transcript.clone();
        challenged_transcript
            .sample_opening_batch_challenge(0)
            .expect("the incumbent FRI opening challenge remains available");
        assert!(matches!(
            challenged_transcript
                .into_row_code_whir_transcript(&[ProofChallengeExtensionElement::ONE]),
            Err(TranscriptError::IncompleteCommonProofTranscript)
        ));

        let mut row_code_transcript = secret_transcript
            .into_row_code_whir_transcript(&[ProofChallengeExtensionElement::ONE])
            .expect("the row-code handoff consumes the unchallenged mask round");
        row_code_transcript
            .absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE])
            .expect("the mask round leaves no pending challenge before the protocol schedule");
    }

    fn removed_theta_domain_polynomial(point: u64) -> u64 {
        (0_u64..=256).fold(1_u64, |product, root| {
            let difference = if point >= root {
                point - root
            } else {
                PROOF_BASE_FIELD_MODULUS - (root - point)
            };
            u64::try_from(
                (u128::from(product) * u128::from(difference))
                    % u128::from(PROOF_BASE_FIELD_MODULUS),
            )
            .expect("the reduced base-field product fits u64")
        })
    }

    fn typed_product_candidate(
        chain_handle: [u8; 64],
        challenge_tag: &str,
        modulus: u64,
        coordinate_count: u16,
        candidate_ordinal: u64,
        candidate_byte_length: usize,
        output_byte_length: usize,
    ) -> Vec<u8> {
        let mut output = vec![0_u8; output_byte_length];
        transcript_xof(
            TRANSCRIPT_SQUEEZE_DOMAIN,
            product_residue_candidate_xof_input(
                chain_handle,
                challenge_tag,
                modulus,
                coordinate_count,
                candidate_ordinal,
                candidate_byte_length,
                output_byte_length,
            )
            .expect("the typed product candidate input is canonical"),
            &mut output,
        )
        .expect("the typed product candidate derives");
        output
    }

    #[test]
    fn composition_challenge_schedule_covers_u32_constraint_ordinals() {
        let first_ordinal_above_u16 = u32::from(u16::MAX) + 1;
        let challenge_count_including_first_ordinal_above_u16 = first_ordinal_above_u16 + 1;
        let schedule = CommonProofTranscriptSchedule::new(
            vec![0],
            Vec::new(),
            Vec::new(),
            challenge_count_including_first_ordinal_above_u16,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            128,
            CommonProofPrivacyMode::PublicOnly,
        )
        .expect("a selected-size composition catalog fits the transcript schedule");

        assert_eq!(
            schedule.composition_challenge_count(),
            challenge_count_including_first_ordinal_above_u16
        );
        assert_eq!(
            CommonProofChallenge::Composition {
                constraint_ordinal: u32::from(u16::MAX),
            }
            .tag(0x1211),
            "proof/1211/composition/ffff"
        );
        assert_eq!(
            CommonProofChallenge::Composition {
                constraint_ordinal: first_ordinal_above_u16,
            }
            .tag(0x1211),
            "proof/1211/composition/10000"
        );
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
    fn transcript_hash_budget_counts_typed_product_candidates() {
        let schedule = |maximum_candidate_draws_per_output, includes_product_vector| {
            CommonProofTranscriptSchedule::new(
                vec![0],
                if includes_product_vector {
                    vec![
                        CommonProofApplicationChallengeGroup::new(alpha_challenge(), 2, 513)
                            .expect("the above-512-bit product vector is valid"),
                    ]
                } else {
                    Vec::new()
                },
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
            .expect("the product-vector accounting schedule is valid")
        };

        for maximum_candidate_draws_per_output in [1_u32, 2, 128] {
            let without_product = schedule(maximum_candidate_draws_per_output, false)
                .maximum_transcript_hash_query_count()
                .expect("the baseline hash budget derives");
            let with_product = schedule(maximum_candidate_draws_per_output, true)
                .maximum_transcript_hash_query_count()
                .expect("the product-vector hash budget derives");
            assert_eq!(
                with_product - without_product,
                u64::from(maximum_candidate_draws_per_output) + 2,
            );
            assert_eq!(
                schedule(maximum_candidate_draws_per_output, true)
                    .maximum_transcript_xof_output_byte_length()
                    .expect("the exact maximum XOF output length derives"),
                64 + usize::try_from(maximum_candidate_draws_per_output)
                    .expect("the draw count fits usize"),
            );
        }
    }

    #[test]
    fn application_product_sampler_accounting_is_schedule_owned() {
        let schedule = CommonProofTranscriptSchedule::new(
            vec![0],
            vec![
                CommonProofApplicationChallengeGroup::new(alpha_challenge(), 2, 513)
                    .expect("the above-512-bit product vector is valid"),
            ],
            Vec::new(),
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            2,
            128,
            CommonProofPrivacyMode::PublicOnly,
        )
        .expect("the sampler-accounting schedule is valid");
        let rows = schedule
            .ordered_application_challenge_sampler_accounting()
            .expect("the sampler rows derive");

        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(row.challenge(), alpha_challenge());
        assert_eq!(row.modulus(), 2);
        assert_eq!(row.coordinate_count(), 513);
        assert_eq!(row.candidate_byte_length(), 65);
        assert_eq!(row.maximum_candidate_draw_count(), 128);
        assert_eq!(row.accepted_vector_byte_length(), 513 * 8);
        assert_eq!(row.chain_handle_xof_query_count(), 1);
        assert_eq!(row.candidate_xof_query_count_ceiling(), 128);
        assert_eq!(row.total_xof_query_count_ceiling(), 129);
        assert_eq!(row.reusable_candidate_buffer_byte_length(), 65);
        assert_eq!(row.maximum_xof_output_byte_length(), 65);
        assert_eq!(schedule.maximum_candidate_draws_per_output(), 128);
        assert_eq!(
            schedule
                .maximum_application_challenge_sampler_scratch_byte_length()
                .expect("the sampler scratch derives"),
            65,
        );

        let memory = schedule
            .live_payload_memory_accounting(0x1302)
            .expect("the complete transcript payload ledger derives");
        let product_memory = memory.product_sampler_memory_accounting();
        assert_eq!(product_memory.reusable_candidate_buffer_byte_length(), 65);
        assert_eq!(
            product_memory.accepted_coordinate_vector_byte_length(),
            513 * 8
        );
        assert!(product_memory.challenge_tag_byte_length() > 0);
        assert!(product_memory.big_integer_limb_working_set_byte_length() > 65);
        assert!(
            product_memory.maximum_peak_byte_length()
                >= product_memory.accepted_decode_peak_byte_length()
        );
        assert_eq!(
            memory.accepted_deep_point_catalog_byte_length(),
            std::mem::size_of::<ProofChallengeExtensionElement>() as u64,
        );
        assert_eq!(memory.accepted_query_catalog_byte_length(), 8);
        assert_eq!(memory.query_xof_output_buffer_byte_length(), 64 + 128);
        assert_eq!(memory.deep_point_prior_catalog_clone_byte_length(), 0);
        assert!(memory.schedule_catalog_byte_length() > 0);
        assert!(memory.pending_challenge_tag_byte_length() > 0);
        assert_eq!(memory.pending_challenge_output_byte_length(), 513 * 8);
        assert!(memory.maximum_transcript_codec_overlap_byte_length() > 513 * 8);
        assert!(memory.maximum_output_overlap_byte_length() >= 2 * 513 * 8);
        assert!(
            memory.maximum_transient_byte_length() >= product_memory.maximum_peak_byte_length()
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
        let group = CommonProofApplicationChallengeGroup::new(alpha_challenge(), modulus, 7)
            .expect("the product-space group derives");
        let mut candidate = BigUint::default();
        let mut place = BigUint::from(1_u8);
        for coordinate in expected_coordinates {
            candidate += &place * BigUint::from(coordinate);
            place *= BigUint::from(modulus);
        }
        let candidate_byte_length = usize::try_from(group.candidate_byte_length())
            .expect("the exact candidate width fits usize");
        let mut encoded = candidate.to_bytes_le();
        encoded.resize(candidate_byte_length, 0);
        let chain_handle = [0x47; 64];
        let stream = CommonChallengeStream::new(chain_handle, "test-product".to_owned());

        let sampled = stream
            .sample_residue_vector(encoded, group, 1)
            .expect("the product-space candidate is accepted");

        assert_eq!(sampled, expected_coordinates);
        assert_eq!(sampled.len(), 7);
        assert!(sampled.iter().all(|coordinate| *coordinate < modulus));
        assert_eq!(stream.current_candidate_seed, chain_handle);
    }

    #[test]
    fn product_residue_sampler_round_trips_an_above_512_bit_vector() {
        let modulus = DATA_PRIMES[0];
        let coordinate_count = 17_u16;
        let expected_coordinates = vec![modulus - 1; usize::from(coordinate_count)];
        let group =
            CommonProofApplicationChallengeGroup::new(alpha_challenge(), modulus, coordinate_count)
                .expect("the selected product-space group derives");
        assert!(group.candidate_byte_length() > 64);

        let product_cardinality = BigUint::from(modulus).pow(u32::from(coordinate_count));
        let mut encoded = (&product_cardinality - BigUint::from(1_u8)).to_bytes_le();
        encoded.resize(
            usize::try_from(group.candidate_byte_length())
                .expect("the exact candidate width fits usize"),
            0,
        );
        let sampled = CommonChallengeStream::new([0x48; 64], "test-product".to_owned())
            .sample_residue_vector(encoded, group, 1)
            .expect("the above-512-bit product-space candidate is accepted");

        assert_eq!(sampled, expected_coordinates);
        assert!(sampled.iter().all(|coordinate| *coordinate < modulus));
    }

    #[test]
    fn product_residue_sampler_crosses_the_old_512_bit_boundary() {
        assert_eq!(
            product_residue_candidate_byte_length(2, 511)
                .expect("the below-boundary product derives"),
            64,
        );
        assert_eq!(
            product_residue_candidate_byte_length(2, 512)
                .expect("the exact-boundary product derives"),
            64,
        );
        assert_eq!(
            product_residue_candidate_byte_length(2, 513)
                .expect("the above-boundary product derives"),
            65,
        );
        assert!(CommonProofApplicationChallengeGroup::new(alpha_challenge(), 2, 513,).is_ok(),);
    }

    #[test]
    fn product_residue_sampler_rejects_the_exact_acceptance_boundary() {
        let modulus = 65_537_u64;
        let coordinate_count = 7_u16;
        let group =
            CommonProofApplicationChallengeGroup::new(alpha_challenge(), modulus, coordinate_count)
                .expect("the product-space group derives");
        let candidate_byte_length = usize::try_from(group.candidate_byte_length())
            .expect("the exact candidate width fits usize");
        let product_cardinality = BigUint::from(modulus).pow(u32::from(coordinate_count));
        let sample_space = BigUint::from(1_u8) << (8 * candidate_byte_length);
        let acceptance_limit = (&sample_space / &product_cardinality) * product_cardinality;
        let mut rejected_candidate = acceptance_limit.to_bytes_le();
        rejected_candidate.resize(candidate_byte_length, 0);
        let stream = CommonChallengeStream::new([0x48; 64], "test-product".to_owned());

        assert_eq!(
            stream.sample_residue_vector(rejected_candidate, group, 1),
            Err(TranscriptError::CommonChallengeDrawsExhausted),
        );
    }

    #[test]
    fn typed_product_candidates_bind_every_sampler_coordinate() {
        let chain_handle = [0x49; 64];
        let challenge_tag = "proof/1211/theta-vector/0000";
        let modulus = 65_537_u64;
        let coordinate_count = 7_u16;
        let candidate_byte_length =
            product_residue_candidate_byte_length(modulus, coordinate_count)
                .expect("the exact candidate width derives");
        let baseline = typed_product_candidate(
            chain_handle,
            challenge_tag,
            modulus,
            coordinate_count,
            1,
            candidate_byte_length,
            candidate_byte_length,
        );
        let changed_inputs = [
            typed_product_candidate(
                [0x4a; 64],
                challenge_tag,
                modulus,
                coordinate_count,
                1,
                candidate_byte_length,
                candidate_byte_length,
            ),
            typed_product_candidate(
                chain_handle,
                "proof/1211/alpha-vector/0000",
                modulus,
                coordinate_count,
                1,
                candidate_byte_length,
                candidate_byte_length,
            ),
            typed_product_candidate(
                chain_handle,
                challenge_tag,
                modulus + 2,
                coordinate_count,
                1,
                candidate_byte_length,
                candidate_byte_length,
            ),
            typed_product_candidate(
                chain_handle,
                challenge_tag,
                modulus,
                coordinate_count + 1,
                1,
                candidate_byte_length,
                candidate_byte_length,
            ),
            typed_product_candidate(
                chain_handle,
                challenge_tag,
                modulus,
                coordinate_count,
                2,
                candidate_byte_length,
                candidate_byte_length,
            ),
            typed_product_candidate(
                chain_handle,
                challenge_tag,
                modulus,
                coordinate_count,
                1,
                candidate_byte_length,
                candidate_byte_length + 1,
            ),
        ];
        assert!(
            changed_inputs
                .iter()
                .all(|candidate| candidate != &baseline)
        );
    }

    #[test]
    fn product_residue_sampler_binds_transcript_context() {
        let mut first = transcript();
        let mut second =
            CanonicalProofTranscript::try_new(1, [0x5a; 64], 0x1212, b"changed-header")
                .expect("the changed transcript header is canonical");
        let modulus = 65_537_u64;
        let group = CommonProofApplicationChallengeGroup::new(alpha_challenge(), modulus, 7)
            .expect("the product-space group derives");
        let (first_stream, first_candidate) = first
            .begin_common_product_residue_challenge(group)
            .expect("the first product challenge derives");
        let (second_stream, second_candidate) = second
            .begin_common_product_residue_challenge(group)
            .expect("the changed product challenge derives");

        assert_ne!(
            first_stream.current_candidate_seed,
            second_stream.current_candidate_seed,
        );
        assert_ne!(first_candidate, second_candidate);
    }

    #[test]
    fn selected_roles_sample_independent_product_vectors() {
        let theta_group = CommonProofApplicationChallengeGroup::new(
            theta_challenge(),
            PROOF_BASE_FIELD_MODULUS,
            PROOF_NON_NATIVE_THETA_REPETITION_COUNT,
        )
        .expect("the selected theta group derives");
        assert_eq!(PROOF_NON_NATIVE_THETA_REPETITION_COUNT, 5);
        assert_eq!(theta_group.candidate_byte_length(), 40);
        let theta_product_cardinality =
            BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(u32::from(theta_group.coordinate_count()));
        let mut maximum_theta_candidate =
            (&theta_product_cardinality - BigUint::from(1_u8)).to_bytes_le();
        maximum_theta_candidate.resize(
            usize::try_from(theta_group.candidate_byte_length())
                .expect("the selected theta candidate width fits usize"),
            0,
        );
        let maximum_theta_vector =
            CommonChallengeStream::new([0x5a; 64], "selected-theta-product".to_owned())
                .sample_residue_vector(maximum_theta_candidate, theta_group, 1)
                .expect("the complete selected theta endpoint is accepted");
        assert_eq!(
            maximum_theta_vector,
            vec![
                PROOF_BASE_FIELD_MODULUS - 1;
                usize::from(PROOF_NON_NATIVE_THETA_REPETITION_COUNT)
            ]
        );

        let mut theta_transcript = transcript();
        let (theta_stream, theta_candidate) = theta_transcript
            .begin_common_product_residue_challenge(theta_group)
            .expect("the selected theta challenge derives");
        let theta_coordinates = theta_stream
            .sample_residue_vector(theta_candidate, theta_group, 128)
            .expect("the selected theta vector samples");
        assert_eq!(
            theta_coordinates.len(),
            usize::from(PROOF_NON_NATIVE_THETA_REPETITION_COUNT)
        );
        assert!(
            theta_coordinates
                .iter()
                .all(|coordinate| *coordinate < PROOF_BASE_FIELD_MODULUS)
        );
        let fixed_full_field_theta = theta_coordinates
            .iter()
            .copied()
            .find(|coordinate| *coordinate > 256)
            .expect("the fixed full-field theta is outside the removed 257-value domain");
        assert!((0_u64..=256).all(|point| removed_theta_domain_polynomial(point) == 0));
        assert_ne!(removed_theta_domain_polynomial(fixed_full_field_theta), 0);

        for (modulus_ordinal, modulus) in DATA_PRIMES.iter().copied().take(8).enumerate() {
            let mut transcript = CanonicalProofTranscript::try_new(
                1,
                [0x5b; 64],
                0x1211,
                &u64::try_from(modulus_ordinal)
                    .expect("the selected modulus ordinal fits u64")
                    .to_le_bytes(),
            )
            .expect("the selected-modulus transcript derives");
            let challenge = CommonProofChallenge::Alpha {
                modulus_ordinal: u16::try_from(modulus_ordinal)
                    .expect("the selected modulus ordinal fits u16"),
            };
            let group = CommonProofApplicationChallengeGroup::new(challenge, modulus, 7)
                .expect("the selected product-space group derives");
            assert_eq!(group.candidate_byte_length(), 28);
            let (stream, first_candidate) = transcript
                .begin_common_product_residue_challenge(group)
                .expect("the seven-coordinate alpha challenge derives");
            let coordinates = stream
                .sample_residue_vector(first_candidate, group, 128)
                .expect("the seven-coordinate alpha vector samples");
            assert_eq!(coordinates.len(), 7);
            assert!(coordinates.iter().all(|coordinate| *coordinate < modulus));
        }
    }

    #[test]
    fn application_challenge_groups_enforce_role_specific_fields() {
        assert!(
            CommonProofApplicationChallengeGroup::new(
                theta_challenge(),
                PROOF_BASE_FIELD_MODULUS,
                4,
            )
            .is_ok()
        );
        assert_eq!(
            CommonProofApplicationChallengeGroup::new(theta_challenge(), 257, 4),
            Err(TranscriptError::InvalidCommonProofSchedule)
        );
        assert!(
            CommonProofApplicationChallengeGroup::new(alpha_challenge(), DATA_PRIMES[0], 7).is_ok()
        );
        assert_eq!(
            CommonProofApplicationChallengeGroup::new(
                alpha_challenge(),
                PROOF_BASE_FIELD_MODULUS,
                7,
            ),
            Err(TranscriptError::InvalidCommonProofSchedule)
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
