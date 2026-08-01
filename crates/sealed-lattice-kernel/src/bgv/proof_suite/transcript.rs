use std::collections::BTreeSet;

use num_bigint::BigUint;
use num_traits::One;

#[cfg(test)]
use super::relation_plan::OutOfDomainPointSamplerCardinalityBound;

use crate::foundation::{
    CanonicalItem, CanonicalItemType, Hash512, StreamingFoundationHashError,
    StreamingFoundationTupleHash512, hash_foundation_tuple_512,
};

use super::field::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement,
};
use super::relation_plan::RelationApplicationChallengeAssignment;
use super::row_code_whir::construction_plan::{
    RowCodeWhirCommitmentRole, RowCodeWhirConstructionPlan, RowCodeWhirExtensionRole,
    RowCodeWhirObservationRole, RowCodeWhirQueryRole, RowCodeWhirTranscriptOperation,
};

pub(crate) const TRANSCRIPT_INITIAL_DOMAIN: &str = "sealed-lattice/proof/transcript/v2";
pub(crate) const TRANSCRIPT_ABSORB_DOMAIN: &str = "sealed-lattice/proof/transcript/absorb/v2";
pub(crate) const TRANSCRIPT_RESPONSE_ROOT_DOMAIN: &str =
    "sealed-lattice/proof/transcript/response-root/v1";
pub(crate) const TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN: &str =
    "sealed-lattice/proof/transcript/challenge-handle/v2";
pub(crate) const TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/proof/transcript/accepted-challenge/v2";
pub(crate) const TRANSCRIPT_RESPONSE_BINDING_DOMAIN: &str =
    "sealed-lattice/proof/transcript/response-binding/v2";
pub(crate) const TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN: &str =
    "sealed-lattice/proof/transcript/challenge-expansion-accumulator/v1";
const TRANSCRIPT_INITIAL_HEADER_TAG: &str = "proof/initial-header/0000";

pub(crate) const TRANSCRIPT_INITIAL_DOMAIN_BYTES: &[u8] = TRANSCRIPT_INITIAL_DOMAIN.as_bytes();
pub(crate) const TRANSCRIPT_ABSORB_DOMAIN_BYTES: &[u8] = TRANSCRIPT_ABSORB_DOMAIN.as_bytes();
pub(crate) const TRANSCRIPT_RESPONSE_ROOT_DOMAIN_BYTES: &[u8] =
    TRANSCRIPT_RESPONSE_ROOT_DOMAIN.as_bytes();
pub(crate) const TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN_BYTES: &[u8] =
    TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN.as_bytes();
pub(crate) const TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN_BYTES: &[u8] =
    TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN.as_bytes();
pub(crate) const TRANSCRIPT_RESPONSE_BINDING_DOMAIN_BYTES: &[u8] =
    TRANSCRIPT_RESPONSE_BINDING_DOMAIN.as_bytes();
pub(crate) const TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN_BYTES: &[u8] =
    TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN.as_bytes();

pub(crate) const PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE: &str =
    "sealed-lattice/proof/product-residue-vector/v1";
pub(crate) const DISTINCT_QUERY_VECTOR_SAMPLER_TYPE: &str =
    "sealed-lattice/proof/distinct-query-vector/v1";
pub(crate) const FIXED_CHALLENGE_BLOCK_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
const COMMON_PROOF_RELATION_PREFIX_SCHEDULE_IDENTITY_ENCODING_VERSION: u16 = 1;

fn transcript_hash(domain: &str, items: Vec<CanonicalItem>) -> Result<[u8; 64], TranscriptError> {
    hash_foundation_tuple_512(domain, &items)
        .map(|digest| digest.into_bytes())
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

/// Extension-sampler kinds needed by the test trace.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicSamplerKind {
    Extension,
    OutOfDomain,
}

/// Test marker for one successful call through a typed, bounded public sampler.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservedPublicSamplerRow;

#[cfg(test)]
impl ObservedPublicSamplerRow {
    fn product(
        _challenge_tag: String,
        modulus: u64,
        coordinate_count: u16,
        candidate_byte_length: u64,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<Self, TranscriptError> {
        if modulus <= 1
            || coordinate_count == 0
            || candidate_byte_length == 0
            || !candidate_byte_length.is_multiple_of(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH as u64)
            || maximum_candidate_draws_per_output == 0
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let candidate_bit_length = u32::try_from(
            candidate_byte_length
                .checked_mul(8)
                .ok_or(TranscriptError::ChallengeCounterOverflow)?,
        )
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let target_cardinality = BigUint::from(modulus).pow(u32::from(coordinate_count));
        let candidate_space_cardinality = BigUint::one()
            << usize::try_from(candidate_bit_length)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        if target_cardinality > candidate_space_cardinality {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        Ok(Self)
    }

    pub(crate) fn extension(
        _challenge_tag: String,
        sampler_kind: PublicSamplerKind,
        maximum_candidate_draws_per_output: u32,
        forbidden_cardinality_ceiling: Option<BigUint>,
    ) -> Result<Self, TranscriptError> {
        if !matches!(
            sampler_kind,
            PublicSamplerKind::Extension | PublicSamplerKind::OutOfDomain
        ) || maximum_candidate_draws_per_output == 0
            || (sampler_kind == PublicSamplerKind::OutOfDomain)
                != forbidden_cardinality_ceiling.is_some()
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let target_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
            u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        );
        if let Some(forbidden_cardinality_ceiling) = &forbidden_cardinality_ceiling
            && forbidden_cardinality_ceiling >= &target_cardinality
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        Ok(Self)
    }

    pub(crate) fn distinct(
        _challenge_tag: String,
        domain_cardinality: usize,
        output_count: usize,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<Self, TranscriptError> {
        if domain_cardinality == 0
            || !domain_cardinality.is_power_of_two()
            || output_count == 0
            || output_count > domain_cardinality
            || maximum_candidate_draws_per_output == 0
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        u64::try_from(domain_cardinality).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        u32::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        Ok(Self)
    }
}

/// Test-only trace populated by successful calls through the production
/// transcript samplers. Out-of-domain cardinality ceilings are installed from the
/// checked relation before the first sampled verifier message.
#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ObservedPublicSamplerTrace {
    rows: Vec<ObservedPublicSamplerRow>,
    out_of_domain_forbidden_cardinality_ceilings: Vec<BigUint>,
}

#[derive(Clone, Debug)]
pub(crate) struct CanonicalProofTranscript {
    application_statement_schema_identifier: u16,
    row_code_whir_construction_plan_identity_hash: [u8; 64],
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
    fn try_new_row_code_whir(
        protocol_version: u16,
        suite_id: [u8; 64],
        row_code_whir_construction_plan_identity_hash: [u8; 64],
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
    ) -> Result<Self, TranscriptError> {
        let initial_items = vec![
            CanonicalItem::unsigned16(protocol_version),
            CanonicalItem::hash512(suite_id),
            CanonicalItem::hash512(row_code_whir_construction_plan_identity_hash),
            CanonicalItem::unsigned16(application_statement_schema_identifier),
            CanonicalItem::variable_bytes(canonical_proof_object_header_bytes)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        ];
        let header_root = transcript_hash(TRANSCRIPT_INITIAL_DOMAIN, initial_items)?;
        Ok(Self {
            application_statement_schema_identifier,
            row_code_whir_construction_plan_identity_hash,
            state: response_absorption_state(
                [0_u8; Hash512::BYTE_LENGTH],
                TRANSCRIPT_INITIAL_HEADER_TAG,
                header_root,
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
        self.prepare_typed_response(&round_tag)?;
        let response_root = if requires_hash512_message {
            canonical_round_message_bytes
                .try_into()
                .map_err(|_| TranscriptError::InvalidCommonProofMessage)?
        } else {
            canonical_response_root(&round_tag, canonical_round_message_bytes)?
        };
        self.state = response_absorption_state(self.state, &round_tag, response_root)?;
        Ok(())
    }

    fn begin_streamed_typed_round(
        &mut self,
        round_tag: String,
        requires_hash512_message: bool,
        canonical_round_message_byte_length: usize,
    ) -> Result<CommonProofRoundMessageAbsorber, TranscriptError> {
        if requires_hash512_message || canonical_round_message_byte_length == 0 {
            return Err(TranscriptError::InvalidCommonProofMessage);
        }
        self.prepare_typed_response(&round_tag)?;
        let prefix_items = vec![
            CanonicalItem::nonempty_ascii(&round_tag)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
            CanonicalItem::unsigned64(
                u64::try_from(canonical_round_message_byte_length)
                    .map_err(|_| TranscriptError::InvalidCommonProofMessage)?,
            ),
        ];
        let streaming_hash = StreamingFoundationTupleHash512::new_variable_bytes(
            TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
            &prefix_items,
            canonical_round_message_byte_length,
        )
        .map_err(transcript_streaming_hash_error)?;
        Ok(CommonProofRoundMessageAbsorber {
            starting_transcript_state: self.state,
            round_tag,
            streaming_hash,
        })
    }

    fn finish_streamed_common_round(
        &mut self,
        absorber: CommonProofRoundMessageAbsorber,
    ) -> Result<(), TranscriptError> {
        if absorber.starting_transcript_state != self.state
            || self.pending_common_challenge.is_some()
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        let response_root = absorber
            .streaming_hash
            .finalize()
            .map_err(transcript_streaming_hash_error)?
            .into_bytes();
        self.state = response_absorption_state(self.state, &absorber.round_tag, response_root)?;
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
            TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
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
    /// handle binds the sampler geometry. Every candidate block advances one
    /// typed predecessor chain and supplies the bytes for the next draw.
    fn begin_common_product_residue_challenge(
        &mut self,
        group: CommonProofApplicationChallengeGroup,
        maximum_candidate_draws: u32,
    ) -> Result<CommonChallengeStream, TranscriptError> {
        self.close_pending_common_challenge()?;
        if !group.challenge.is_application_challenge() || maximum_candidate_draws == 0 {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let challenge_tag = group
            .challenge
            .tag(self.application_statement_schema_identifier);
        let candidate_byte_length = usize::try_from(group.candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let chain_handle = transcript_hash(
            TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::nonempty_ascii(PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(group.modulus),
                CanonicalItem::unsigned16(group.coordinate_count),
                CanonicalItem::unsigned64(group.candidate_byte_length),
                CanonicalItem::unsigned32(maximum_candidate_draws),
                CanonicalItem::unsigned64(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH as u64),
            ],
        )?;
        let candidate_block_count = candidate_byte_length
            .checked_div(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)
            .filter(|block_count| {
                *block_count > 0
                    && candidate_byte_length.is_multiple_of(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)
            })
            .ok_or(TranscriptError::InvalidCommonProofSchedule)?;
        Ok(CommonChallengeStream::new_product(
            chain_handle,
            challenge_tag,
            group,
            maximum_candidate_draws,
            u64::try_from(candidate_block_count)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        ))
    }

    fn begin_distinct_query_challenge(
        &mut self,
        challenge_tag: String,
        query_domain_cardinality: u64,
        output_count: u32,
        maximum_candidate_draws_per_output: u32,
    ) -> Result<CommonChallengeStream, TranscriptError> {
        self.close_pending_common_challenge()?;
        if query_domain_cardinality == 0
            || !query_domain_cardinality.is_power_of_two()
            || output_count == 0
            || u64::from(output_count) > query_domain_cardinality
            || maximum_candidate_draws_per_output == 0
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let chain_handle = transcript_hash(
            TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::nonempty_ascii(DISTINCT_QUERY_VECTOR_SAMPLER_TYPE)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(query_domain_cardinality),
                CanonicalItem::unsigned32(output_count),
                CanonicalItem::unsigned32(maximum_candidate_draws_per_output),
                CanonicalItem::unsigned64(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH as u64),
            ],
        )?;
        let candidates_per_block = FIXED_CHALLENGE_BLOCK_BYTE_LENGTH
            .checked_div(std::mem::size_of::<u64>())
            .filter(|candidate_count| *candidate_count > 0)
            .ok_or(TranscriptError::InvalidCommonProofSchedule)?;
        let maximum_block_count_per_output = usize::try_from(maximum_candidate_draws_per_output)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
            .div_ceil(candidates_per_block);
        Ok(CommonChallengeStream::new_distinct(
            chain_handle,
            challenge_tag,
            query_domain_cardinality,
            output_count,
            maximum_candidate_draws_per_output,
            u64::try_from(maximum_block_count_per_output)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
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
        let (accepted_terminal_seed, challenge_tag) = stream.into_accepted_terminal_seed()?;
        self.pending_common_challenge = Some(PendingCommonChallenge {
            candidate_seed: accepted_terminal_seed,
            challenge_tag,
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
            TRANSCRIPT_ACCEPTED_CHALLENGE_DOMAIN,
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

    fn prepare_typed_response(&mut self, round_tag: &str) -> Result<(), TranscriptError> {
        if self.pending_common_challenge.is_some() {
            return self.close_pending_common_challenge();
        }
        let virtual_challenge_tag = format!("{round_tag}/response-binding");
        self.state = transcript_hash(
            TRANSCRIPT_RESPONSE_BINDING_DOMAIN,
            vec![
                CanonicalItem::hash512(self.state),
                CanonicalItem::nonempty_ascii(&virtual_challenge_tag)
                    .map_err(|_| TranscriptError::CanonicalEncoding)?,
                CanonicalItem::unsigned64(0),
            ],
        )?;
        Ok(())
    }
}

fn canonical_response_root(
    round_tag: &str,
    canonical_round_message_bytes: &[u8],
) -> Result<[u8; Hash512::BYTE_LENGTH], TranscriptError> {
    transcript_hash(
        TRANSCRIPT_RESPONSE_ROOT_DOMAIN,
        vec![
            CanonicalItem::nonempty_ascii(round_tag)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
            CanonicalItem::unsigned64(
                u64::try_from(canonical_round_message_bytes.len())
                    .map_err(|_| TranscriptError::InvalidCommonProofMessage)?,
            ),
            CanonicalItem::variable_bytes(canonical_round_message_bytes)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        ],
    )
}

fn response_absorption_state(
    predecessor_state: [u8; Hash512::BYTE_LENGTH],
    round_tag: &str,
    response_root: [u8; Hash512::BYTE_LENGTH],
) -> Result<[u8; Hash512::BYTE_LENGTH], TranscriptError> {
    transcript_hash(
        TRANSCRIPT_ABSORB_DOMAIN,
        vec![
            CanonicalItem::hash512(predecessor_state),
            CanonicalItem::nonempty_ascii(round_tag)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
            CanonicalItem::hash512(response_root),
        ],
    )
}

fn transcript_streaming_hash_error(_error: StreamingFoundationHashError) -> TranscriptError {
    TranscriptError::InvalidCommonProofMessage
}

struct CommonProofRoundMessageAbsorber {
    starting_transcript_state: [u8; 64],
    round_tag: String,
    streaming_hash: StreamingFoundationTupleHash512,
}

/// Closed round tags for the common transparent proof.  Callers never supply
/// free-form labels on this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofRound {
    BaseRoot { tree_ordinal: u16 },
    AuxiliaryRoot { tree_ordinal: u16 },
    RowCodeWhirQuotientPhaseRoot,
    OutOfDomainEvaluations,
}

impl CommonProofRound {
    pub(crate) fn tag(self, application_statement_schema_identifier: u16) -> String {
        let prefix = format!("proof/{application_statement_schema_identifier:04x}");
        match self {
            Self::BaseRoot { tree_ordinal } => {
                format!("{prefix}/base-root/{tree_ordinal:04x}")
            }
            Self::AuxiliaryRoot { tree_ordinal } => {
                format!("{prefix}/auxiliary-root/{tree_ordinal:04x}")
            }
            Self::RowCodeWhirQuotientPhaseRoot => {
                format!("{prefix}/row-code-whir-quotient-phase-root")
            }
            Self::OutOfDomainEvaluations => {
                format!("{prefix}/out-of-domain-evaluations")
            }
        }
    }

    fn requires_hash512_message(self) -> bool {
        matches!(
            self,
            Self::BaseRoot { .. } | Self::AuxiliaryRoot { .. } | Self::RowCodeWhirQuotientPhaseRoot
        )
    }
}

/// Closed Fiat-Shamir challenge tags for the common transparent proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CommonProofChallenge {
    Theta { modulus_ordinal: u16 },
    Alpha { modulus_ordinal: u16 },
    Composition { constraint_ordinal: u32 },
    OutOfDomainPoint { point_ordinal: u16 },
}

impl CommonProofChallenge {
    pub(crate) fn tag(self, application_statement_schema_identifier: u16) -> String {
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
            Self::OutOfDomainPoint { point_ordinal } => {
                format!("{prefix}/out-of-domain-point/{point_ordinal:04x}")
            }
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
pub(crate) enum RowCodeWhirTracePhase {
    Base,
    Auxiliary,
}

impl RowCodeWhirTracePhase {
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
    TraceColumnGroupWeight {
        opening_point_ordinal: u16,
        phase: RowCodeWhirTracePhase,
        column_group_ordinal: u32,
    },
    QuotientGroupWeight {
        opening_point_ordinal: u16,
        source_group_ordinal: u32,
    },
    OpeningBatchMaskWeight {
        opening_point_ordinal: u16,
    },
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
    pub(crate) fn tag(self) -> String {
        let prefix = "row-code-whir";
        match self {
            Self::PointSelectorWeight {
                opening_point_ordinal,
                selector_ordinal,
            } => format!(
                "{prefix}/point/{opening_point_ordinal:04x}/selector/{selector_ordinal:04x}"
            ),
            Self::TraceColumnGroupWeight {
                opening_point_ordinal,
                phase,
                column_group_ordinal,
            } => format!(
                "{prefix}/point/{opening_point_ordinal:04x}/{}/column-group/{column_group_ordinal:08x}",
                phase.tag()
            ),
            Self::QuotientGroupWeight {
                opening_point_ordinal,
                source_group_ordinal,
            } => format!(
                "{prefix}/point/{opening_point_ordinal:04x}/quotient-group/{source_group_ordinal:08x}"
            ),
            Self::OpeningBatchMaskWeight {
                opening_point_ordinal,
            } => format!("{prefix}/point/{opening_point_ordinal:04x}/opening-batch-mask-weight"),
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
            | Self::TraceColumnGroupWeight { .. }
            | Self::QuotientGroupWeight { .. }
            | Self::OpeningBatchMaskWeight { .. }
            | Self::BoundOpeningWeight { .. } => RowCodeWhirChallengeStage::BeforeCommitment,
            Self::OuterQueryVector | Self::BoundQueryVector => {
                RowCodeWhirChallengeStage::AfterCommitment
            }
            Self::BoundDegreeCoordinate { .. } => RowCodeWhirChallengeStage::DegreeTest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirChallengeStage {
    BeforeCommitment,
    AfterCommitment,
    DegreeTest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirRound {
    OpeningBatchMaskEvaluations,
    ProtocolSchedule,
    AggregateCommitment,
    AggregateWidePadCommitment,
    BaseFreshSourceCommitment,
    BaseFreshPadCommitment,
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
            Self::AggregateWidePadCommitment => {
                format!("{prefix}/aggregate-wide-pad-commitment")
            }
            Self::BaseFreshSourceCommitment => {
                format!("{prefix}/base-fresh-source-commitment")
            }
            Self::BaseFreshPadCommitment => {
                format!("{prefix}/base-fresh-pad-commitment")
            }
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

    pub(crate) const fn modulus(self) -> u64 {
        self.modulus
    }

    pub(crate) fn coordinate_count(self) -> u16 {
        self.coordinate_count
    }

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

    #[cfg(test)]
    pub(crate) const fn accepted_vector_byte_length(self) -> u64 {
        self.accepted_vector_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn chain_handle_xof_query_count(self) -> u64 {
        self.chain_handle_xof_query_count
    }

    pub(crate) const fn candidate_xof_query_count_ceiling(self) -> u64 {
        self.candidate_xof_query_count_ceiling
    }

    pub(crate) const fn total_xof_query_count_ceiling(self) -> u64 {
        self.total_xof_query_count_ceiling
    }

    #[cfg(test)]
    pub(crate) const fn maximum_oracle_answer_byte_length(self) -> u64 {
        FIXED_CHALLENGE_BLOCK_BYTE_LENGTH as u64
    }
}

/// Exact plan-derived schedule shared by the relation prefix and its opening
/// argument. It contains no opening-argument tail geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofRelationPrefixSchedule {
    ordered_base_tree_ordinals: Vec<u16>,
    ordered_application_challenge_groups: Vec<CommonProofApplicationChallengeGroup>,
    ordered_auxiliary_tree_ordinals: Vec<u16>,
    composition_challenge_count: u32,
    quotient_component_count: u16,
    out_of_domain_point_count: u16,
    opening_claim_count: u32,
    maximum_candidate_draws_per_output: u32,
    privacy_mode: CommonProofPrivacyMode,
}

impl CommonProofRelationPrefixSchedule {
    pub(crate) fn resident_owned_payload_byte_length(&self) -> Result<u64, TranscriptError> {
        fn vector_allocation_byte_length<T>(capacity: usize) -> Result<u64, TranscriptError> {
            u64::try_from(capacity)
                .ok()
                .and_then(|count| {
                    count.checked_mul(
                        u64::try_from(core::mem::size_of::<T>()).expect("type size fits u64"),
                    )
                })
                .ok_or(TranscriptError::ChallengeCounterOverflow)
        }

        vector_allocation_byte_length::<u16>(self.ordered_base_tree_ordinals.capacity())?
            .checked_add(vector_allocation_byte_length::<
                CommonProofApplicationChallengeGroup,
            >(
                self.ordered_application_challenge_groups.capacity()
            )?)
            .and_then(|total| {
                vector_allocation_byte_length::<u16>(
                    self.ordered_auxiliary_tree_ordinals.capacity(),
                )
                .ok()
                .and_then(|byte_length| total.checked_add(byte_length))
            })
            .ok_or(TranscriptError::ChallengeCounterOverflow)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ordered_base_tree_ordinals: Vec<u16>,
        ordered_application_challenge_groups: Vec<CommonProofApplicationChallengeGroup>,
        ordered_auxiliary_tree_ordinals: Vec<u16>,
        composition_challenge_count: u32,
        quotient_component_count: u16,
        out_of_domain_point_count: u16,
        opening_claim_count: u32,
        maximum_candidate_draws_per_output: u32,
        privacy_mode: CommonProofPrivacyMode,
    ) -> Result<Self, TranscriptError> {
        let schedule = Self {
            ordered_base_tree_ordinals,
            ordered_application_challenge_groups,
            ordered_auxiliary_tree_ordinals,
            composition_challenge_count,
            quotient_component_count,
            out_of_domain_point_count,
            opening_claim_count,
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
            || self.out_of_domain_point_count == 0
            || self.opening_claim_count == 0
            || self.maximum_candidate_draws_per_output == 0
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn canonical_identity_bytes(
        &self,
    ) -> Result<Vec<u8>, TranscriptError> {
        self.validate()?;

        fn push_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), TranscriptError> {
            bytes.extend_from_slice(
                &u64::try_from(length)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?
                    .to_le_bytes(),
            );
            Ok(())
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &COMMON_PROOF_RELATION_PREFIX_SCHEDULE_IDENTITY_ENCODING_VERSION.to_le_bytes(),
        );

        push_length(&mut bytes, self.ordered_base_tree_ordinals.len())?;
        for tree_ordinal in &self.ordered_base_tree_ordinals {
            bytes.extend_from_slice(&tree_ordinal.to_le_bytes());
        }

        push_length(&mut bytes, self.ordered_application_challenge_groups.len())?;
        for group in &self.ordered_application_challenge_groups {
            match group.challenge {
                CommonProofChallenge::Theta { modulus_ordinal } => {
                    bytes.extend_from_slice(&1_u16.to_le_bytes());
                    bytes.extend_from_slice(&modulus_ordinal.to_le_bytes());
                }
                CommonProofChallenge::Alpha { modulus_ordinal } => {
                    bytes.extend_from_slice(&2_u16.to_le_bytes());
                    bytes.extend_from_slice(&modulus_ordinal.to_le_bytes());
                }
                _ => return Err(TranscriptError::InvalidCommonProofSchedule),
            }
            bytes.extend_from_slice(&group.modulus.to_le_bytes());
            bytes.extend_from_slice(&group.coordinate_count.to_le_bytes());
            bytes.extend_from_slice(&group.candidate_byte_length.to_le_bytes());
        }

        push_length(&mut bytes, self.ordered_auxiliary_tree_ordinals.len())?;
        for tree_ordinal in &self.ordered_auxiliary_tree_ordinals {
            bytes.extend_from_slice(&tree_ordinal.to_le_bytes());
        }

        bytes.extend_from_slice(&self.composition_challenge_count.to_le_bytes());
        bytes.extend_from_slice(&self.quotient_component_count.to_le_bytes());
        // The sole physical quotient commitment is the interleaved row phase.
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&self.out_of_domain_point_count.to_le_bytes());
        bytes.extend_from_slice(&self.opening_claim_count.to_le_bytes());
        bytes.extend_from_slice(&self.maximum_candidate_draws_per_output.to_le_bytes());
        bytes.extend_from_slice(
            &(match self.privacy_mode {
                CommonProofPrivacyMode::PublicOnly => 1_u16,
                CommonProofPrivacyMode::SecretBearing => 2_u16,
            })
            .to_le_bytes(),
        );
        Ok(bytes)
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

    pub(crate) const fn maximum_candidate_draws_per_output(&self) -> u32 {
        self.maximum_candidate_draws_per_output
    }
}

impl CommonProofRelationPrefixSchedule {
    pub(crate) const fn composition_challenge_count(&self) -> u32 {
        self.composition_challenge_count
    }

    #[cfg(test)]
    pub(crate) const fn quotient_component_count(&self) -> u16 {
        self.quotient_component_count
    }

    #[cfg(test)]
    pub(crate) const fn opening_claim_count(&self) -> u32 {
        self.opening_claim_count
    }

    pub(crate) const fn out_of_domain_point_count(&self) -> u16 {
        self.out_of_domain_point_count
    }

    #[cfg(test)]
    pub(crate) const fn privacy_mode(&self) -> CommonProofPrivacyMode {
        self.privacy_mode
    }

    fn row_code_whir_catalog_counter_origin(
        &self,
    ) -> Result<TranscriptHashQueryCounter, TranscriptError> {
        let mut counter = TranscriptHashQueryCounter::new();

        for _ in &self.ordered_base_tree_ordinals {
            counter.absorb_response(false)?;
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
            counter.absorb_response(false)?;
        }
        for _ in 0..self.composition_challenge_count {
            counter.begin_challenge(maximum_extension_challenge_hash_count(
                self.maximum_candidate_draws_per_output,
            )?)?;
        }
        counter.absorb_response(false)?;
        for _ in 0..self.out_of_domain_point_count {
            counter.begin_challenge(maximum_extension_challenge_hash_count(
                self.maximum_candidate_draws_per_output,
            )?)?;
        }
        counter.absorb_response(true)?;
        if counter.pending_challenge {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        Ok(counter)
    }
}

pub(crate) fn sample_relation_application_challenges(
    transcript: &mut CommonProofTranscript,
    schedule: &CommonProofRelationPrefixSchedule,
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
            // The canonical header root and its first chain edge from the
            // fixed all-zero predecessor.
            hash_query_count: 2,
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

    fn absorb_response(
        &mut self,
        response_root_is_recomputed: bool,
    ) -> Result<(), TranscriptError> {
        // One edge either closes the preceding accepted challenge or derives
        // the cataloged virtual verifier message. The next edge absorbs the
        // response root. Variable responses additionally recompute their
        // fixed-width canonical root before that absorption edge.
        self.add_hash_queries(2 + u64::from(response_root_is_recomputed))?;
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
    let candidate_block_count = group
        .candidate_byte_length
        .checked_div(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH as u64)
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    if candidate_block_count == 0
        || !group
            .candidate_byte_length
            .is_multiple_of(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH as u64)
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    let candidate_xof_query_count_ceiling = u64::from(maximum_candidate_draws)
        .checked_mul(candidate_block_count)
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
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
    let minimum_candidate_byte_length = candidate_bit_length
        .checked_add(7)
        .and_then(|length| length.checked_div(8))
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    let fixed_block_byte_length = u64::try_from(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
    let candidate_block_count = minimum_candidate_byte_length
        .checked_add(fixed_block_byte_length - 1)
        .and_then(|length| length.checked_div(fixed_block_byte_length))
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    usize::try_from(
        candidate_block_count
            .checked_mul(fixed_block_byte_length)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?,
    )
    .map_err(|_| TranscriptError::ChallengeCounterOverflow)
}

fn product_residue_candidate_block_input(
    previous_chain_state: [u8; Hash512::BYTE_LENGTH],
    candidate_ordinal: u64,
    block_ordinal: u64,
) -> Result<Vec<CanonicalItem>, TranscriptError> {
    challenge_expansion_block_input(
        previous_chain_state,
        PRODUCT_RESIDUE_VECTOR_SAMPLER_TYPE,
        candidate_ordinal,
        block_ordinal,
    )
}

fn product_residue_candidate_block(
    previous_chain_state: [u8; Hash512::BYTE_LENGTH],
    candidate_ordinal: u64,
    block_ordinal: u64,
) -> Result<[u8; Hash512::BYTE_LENGTH], TranscriptError> {
    transcript_hash(
        TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN,
        product_residue_candidate_block_input(
            previous_chain_state,
            candidate_ordinal,
            block_ordinal,
        )?,
    )
}

fn distinct_query_block_input(
    previous_chain_state: [u8; Hash512::BYTE_LENGTH],
    output_ordinal: u64,
    block_ordinal: u64,
) -> Result<Vec<CanonicalItem>, TranscriptError> {
    challenge_expansion_block_input(
        previous_chain_state,
        DISTINCT_QUERY_VECTOR_SAMPLER_TYPE,
        output_ordinal,
        block_ordinal,
    )
}

fn distinct_query_challenge_hash_count(
    output_count: u32,
    maximum_candidate_draws_per_output: u32,
) -> Result<u64, TranscriptError> {
    if output_count == 0 || maximum_candidate_draws_per_output == 0 {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    let candidates_per_block =
        u64::try_from(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH / std::mem::size_of::<u64>())
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
    let block_count_per_output = u64::from(maximum_candidate_draws_per_output)
        .checked_add(candidates_per_block - 1)
        .and_then(|count| count.checked_div(candidates_per_block))
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    let maximum_block_count = u64::from(output_count)
        .checked_mul(block_count_per_output)
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    maximum_block_count
        .checked_add(1)
        .ok_or(TranscriptError::ChallengeCounterOverflow)
}

fn sample_distinct_query_positions_from_transcript_blocks(
    stream: &mut CommonChallengeStream,
) -> Result<Vec<u64>, TranscriptError> {
    let (query_domain_cardinality, output_count, maximum_candidate_draws_per_output) = stream
        .expansion_accumulator
        .as_ref()
        .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
        .distinct_sampling_geometry()?;
    if query_domain_cardinality == 0
        || !query_domain_cardinality.is_power_of_two()
        || output_count == 0
        || u64::from(output_count) > query_domain_cardinality
        || maximum_candidate_draws_per_output == 0
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }

    let candidate_mask = query_domain_cardinality - 1;
    let mut accepted_set = BTreeSet::new();
    let mut accepted_indices = Vec::new();
    accepted_indices
        .try_reserve_exact(
            usize::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        )
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
    for output_ordinal in 0..output_count {
        let mut block = [0_u8; FIXED_CHALLENGE_BLOCK_BYTE_LENGTH];
        let mut block_offset = block.len();
        let mut block_ordinal = 0_u64;
        let mut accepted_index = None;
        for _ in 0..maximum_candidate_draws_per_output {
            if block_offset == block.len() {
                block = stream.derive_distinct_query_block(output_ordinal, block_ordinal)?;
                block_ordinal = block_ordinal
                    .checked_add(1)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                block_offset = 0;
            }
            let candidate_end = block_offset
                .checked_add(std::mem::size_of::<u64>())
                .ok_or(TranscriptError::ChallengeCounterOverflow)?;
            let candidate = u64::from_le_bytes(
                block[block_offset..candidate_end]
                    .try_into()
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            ) & candidate_mask;
            block_offset = candidate_end;
            if accepted_set.insert(candidate) {
                accepted_index = Some(candidate);
                break;
            }
        }
        accepted_indices
            .push(accepted_index.ok_or(TranscriptError::CommonChallengeDrawsExhausted)?);
        stream.finish_distinct_output(output_ordinal)?;
    }
    Ok(accepted_indices)
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
    QuotientPhaseRoot,
    OutOfDomainPoints(u16),
    OutOfDomainEvaluations,
    ReadyForRowCodeWhir,
}

/// Semantic roles independently derived from the checked construction
/// geometry. The live P3 adapter consumes these roles while the transcript
/// cursor independently consumes the canonical operation catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RowCodeWhirLiveRoleSchedule {
    observation_roles: Vec<RowCodeWhirObservationRole>,
    extension_roles: Vec<RowCodeWhirExtensionRole>,
}

impl RowCodeWhirLiveRoleSchedule {
    fn for_construction_plan(
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> Result<Self, TranscriptError> {
        let whir = construction_plan.whir_plan();
        let mut observation_roles = Vec::new();
        let mut extension_roles = Vec::new();

        if whir.initial_out_of_domain_sample_count != 0 {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        for batch in construction_plan.opening_batches() {
            observation_roles.push(RowCodeWhirObservationRole::OpeningPoint {
                batch_ordinal: batch.point_ordinal,
            });
            observation_roles.push(RowCodeWhirObservationRole::OpeningEvaluations {
                batch_ordinal: batch.point_ordinal,
            });
        }
        extension_roles.push(RowCodeWhirExtensionRole::OpeningBatching);
        observation_roles
            .push(RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal: 0 });
        extension_roles.push(RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal: 0 });
        for round_index in 0..whir.initial_sumcheck_round_count {
            let round_ordinal = u32::try_from(round_index)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
            observation_roles.push(RowCodeWhirObservationRole::MaskedSumcheckPolynomial {
                batch_ordinal: 0,
                round_ordinal,
            });
            extension_roles.push(RowCodeWhirExtensionRole::MaskedSumcheckRound {
                batch_ordinal: 0,
                round_ordinal,
            });
        }
        for (round_index, round) in whir.rounds.iter().enumerate() {
            if round.out_of_domain_sample_count != 0 {
                return Err(TranscriptError::InvalidCommonProofSchedule);
            }
            extension_roles.push(RowCodeWhirExtensionRole::RoundCheckpoint {
                round_ordinal: round.round_ordinal,
            });
            extension_roles.push(RowCodeWhirExtensionRole::RoundCombination {
                round_ordinal: round.round_ordinal,
            });
            observation_roles.push(RowCodeWhirObservationRole::SwitchMaskDelta {
                round_ordinal: round.round_ordinal,
            });
            let batch_ordinal = u32::try_from(round_index + 1)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
            observation_roles
                .push(RowCodeWhirObservationRole::MaskedSumcheckClaim { batch_ordinal });
            observation_roles
                .push(RowCodeWhirObservationRole::MaskedSumcheckMaskClaim { batch_ordinal });
            extension_roles.push(RowCodeWhirExtensionRole::MaskedSumcheckEpsilon { batch_ordinal });
            for sumcheck_round_index in 0..round.following_sumcheck_round_count {
                let round_ordinal = u32::try_from(sumcheck_round_index)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
                observation_roles.push(RowCodeWhirObservationRole::MaskedSumcheckPolynomial {
                    batch_ordinal,
                    round_ordinal,
                });
                extension_roles.push(RowCodeWhirExtensionRole::MaskedSumcheckRound {
                    batch_ordinal,
                    round_ordinal,
                });
            }
        }
        observation_roles.push(RowCodeWhirObservationRole::BaseMaskedClaim);
        extension_roles.push(RowCodeWhirExtensionRole::BaseCaseBlinding);
        observation_roles.extend([
            RowCodeWhirObservationRole::BaseBlindedSourceMessage,
            RowCodeWhirObservationRole::BaseBlindedSourceRandomness,
            RowCodeWhirObservationRole::BaseBlindedPadMessage,
            RowCodeWhirObservationRole::BaseBlindedPadRandomness,
        ]);

        Ok(Self {
            observation_roles,
            extension_roles,
        })
    }

    fn observation_role(
        &self,
        observation_ordinal: u32,
    ) -> Result<RowCodeWhirObservationRole, TranscriptError> {
        self.observation_roles
            .get(
                usize::try_from(observation_ordinal)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .copied()
            .ok_or(TranscriptError::IncompleteRowCodeWhirTranscript)
    }

    fn extension_role(
        &self,
        challenge_ordinal: u32,
    ) -> Result<RowCodeWhirExtensionRole, TranscriptError> {
        self.extension_roles
            .get(
                usize::try_from(challenge_ordinal)
                    .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .copied()
            .ok_or(TranscriptError::IncompleteRowCodeWhirTranscript)
    }

    fn is_consumed(&self, observation_ordinal: u32, challenge_ordinal: u32) -> bool {
        usize::try_from(observation_ordinal).ok() == Some(self.observation_roles.len())
            && usize::try_from(challenge_ordinal).ok() == Some(self.extension_roles.len())
    }
}

/// Stateful exact common-proof transcript.  The schedule is fixed by the
/// checked relation plan and proof profile; bytes cannot choose a round, tag,
/// modulus, count, or privacy-mode branch.
#[derive(Clone)]
pub(crate) struct CommonProofTranscript {
    transcript: CanonicalProofTranscript,
    hash_query_counter: TranscriptHashQueryCounter,
    relation_prefix_schedule: CommonProofRelationPrefixSchedule,
    progress: CommonProofProgress,
    accepted_out_of_domain_points: Vec<ProofChallengeExtensionElement>,
    row_code_whir_transcript_operations: Option<Vec<RowCodeWhirTranscriptOperation>>,
    row_code_whir_live_role_schedule: Option<RowCodeWhirLiveRoleSchedule>,
    #[cfg(test)]
    observed_public_sampler_trace: Option<ObservedPublicSamplerTrace>,
}

struct CommonProofTranscriptInitialization<'a> {
    protocol_version: u16,
    suite_id: [u8; 64],
    row_code_whir_construction_plan_identity_hash: [u8; 64],
    application_statement_schema_identifier: u16,
    canonical_proof_object_header_bytes: &'a [u8],
    relation_prefix_schedule: CommonProofRelationPrefixSchedule,
    row_code_whir_transcript_operations: Option<Vec<RowCodeWhirTranscriptOperation>>,
    row_code_whir_live_role_schedule: Option<RowCodeWhirLiveRoleSchedule>,
}

impl CommonProofTranscript {
    #[cfg(test)]
    pub(crate) fn new_relation_prefix(
        protocol_version: u16,
        suite_id: [u8; 64],
        row_code_whir_construction_plan_identity_hash: [u8; 64],
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
        schedule: CommonProofRelationPrefixSchedule,
    ) -> Result<Self, TranscriptError> {
        Self::new_with_schedule(CommonProofTranscriptInitialization {
            protocol_version,
            suite_id,
            row_code_whir_construction_plan_identity_hash,
            application_statement_schema_identifier,
            canonical_proof_object_header_bytes,
            relation_prefix_schedule: schedule,
            row_code_whir_transcript_operations: None,
            row_code_whir_live_role_schedule: None,
        })
    }

    pub(in crate::bgv::proof_suite) fn new_relation_prefix_for_construction_plan(
        protocol_version: u16,
        suite_id: [u8; 64],
        construction_plan: &RowCodeWhirConstructionPlan,
        application_statement_schema_identifier: u16,
        canonical_proof_object_header_bytes: &[u8],
        schedule: CommonProofRelationPrefixSchedule,
    ) -> Result<Self, TranscriptError> {
        if application_statement_schema_identifier
            != construction_plan.application_statement_schema_identifier()
            || &schedule != construction_plan.relation_prefix_schedule()
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let construction_plan_identity_hash = construction_plan
            .canonical_identity_hash()
            .map_err(|_| TranscriptError::InvalidCommonProofSchedule)?;
        let live_role_schedule =
            RowCodeWhirLiveRoleSchedule::for_construction_plan(construction_plan)?;
        Self::new_with_schedule(CommonProofTranscriptInitialization {
            protocol_version,
            suite_id,
            row_code_whir_construction_plan_identity_hash: construction_plan_identity_hash,
            application_statement_schema_identifier,
            canonical_proof_object_header_bytes,
            relation_prefix_schedule: schedule,
            row_code_whir_transcript_operations: Some(
                construction_plan.transcript_operations().to_vec(),
            ),
            row_code_whir_live_role_schedule: Some(live_role_schedule),
        })
    }

    fn new_with_schedule(
        initialization: CommonProofTranscriptInitialization<'_>,
    ) -> Result<Self, TranscriptError> {
        let CommonProofTranscriptInitialization {
            protocol_version,
            suite_id,
            row_code_whir_construction_plan_identity_hash,
            application_statement_schema_identifier,
            canonical_proof_object_header_bytes,
            relation_prefix_schedule,
            row_code_whir_transcript_operations,
            row_code_whir_live_role_schedule,
        } = initialization;
        let mut accepted_out_of_domain_points = Vec::new();
        accepted_out_of_domain_points
            .try_reserve_exact(usize::from(
                relation_prefix_schedule.out_of_domain_point_count,
            ))
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let mut result = Self {
            transcript: CanonicalProofTranscript::try_new_row_code_whir(
                protocol_version,
                suite_id,
                row_code_whir_construction_plan_identity_hash,
                application_statement_schema_identifier,
                canonical_proof_object_header_bytes,
            )?,
            hash_query_counter: TranscriptHashQueryCounter::new(),
            relation_prefix_schedule,
            progress: CommonProofProgress::BaseRoots(0),
            accepted_out_of_domain_points,
            row_code_whir_transcript_operations,
            row_code_whir_live_role_schedule,
            #[cfg(test)]
            observed_public_sampler_trace: None,
        };
        result.skip_empty_prefix_phases();
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn enable_public_sampler_trace(
        &mut self,
        out_of_domain_point_cardinality_bounds: &[OutOfDomainPointSamplerCardinalityBound],
    ) -> Result<(), TranscriptError> {
        if self.observed_public_sampler_trace.is_some()
            || self.progress != CommonProofProgress::BaseRoots(0)
            || out_of_domain_point_cardinality_bounds.len()
                != usize::from(self.relation_prefix_schedule.out_of_domain_point_count)
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let field_cardinality = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
            u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
        );
        let mut out_of_domain_forbidden_cardinality_ceilings = Vec::new();
        out_of_domain_forbidden_cardinality_ceilings
            .try_reserve_exact(out_of_domain_point_cardinality_bounds.len())
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        for bound in out_of_domain_point_cardinality_bounds {
            if bound.field_cardinality() != &field_cardinality
                || bound.accepted_candidate_count_floor()
                    + bound.forbidden_candidate_count_ceiling()
                    != field_cardinality
                || bound.accepted_candidate_count_floor() == &BigUint::default()
            {
                return Err(TranscriptError::InvalidCommonProofSchedule);
            }
            out_of_domain_forbidden_cardinality_ceilings
                .push(bound.forbidden_candidate_count_ceiling().clone());
        }
        self.observed_public_sampler_trace = Some(ObservedPublicSamplerTrace {
            rows: Vec::new(),
            out_of_domain_forbidden_cardinality_ceilings,
        });
        Ok(())
    }

    #[cfg(test)]
    fn traced_extension_sampler_row(
        &self,
        challenge: CommonProofChallenge,
    ) -> Result<Option<ObservedPublicSamplerRow>, TranscriptError> {
        let Some(trace) = &self.observed_public_sampler_trace else {
            return Ok(None);
        };
        let (sampler_kind, forbidden_cardinality_ceiling) = match challenge {
            CommonProofChallenge::OutOfDomainPoint { point_ordinal } => (
                PublicSamplerKind::OutOfDomain,
                Some(
                    trace
                        .out_of_domain_forbidden_cardinality_ceilings
                        .get(usize::from(point_ordinal))
                        .ok_or(TranscriptError::InvalidCommonProofSchedule)?
                        .clone(),
                ),
            ),
            _ => (PublicSamplerKind::Extension, None),
        };
        ObservedPublicSamplerRow::extension(
            challenge.tag(self.transcript.application_statement_schema_identifier),
            sampler_kind,
            self.relation_prefix_schedule
                .maximum_candidate_draws_per_output,
            forbidden_cardinality_ceiling,
        )
        .map(Some)
    }

    #[cfg(test)]
    fn record_public_sampler_row(
        &mut self,
        row: Option<ObservedPublicSamplerRow>,
    ) -> Result<(), TranscriptError> {
        let (Some(trace), Some(row)) = (&mut self.observed_public_sampler_trace, row) else {
            return Ok(());
        };
        trace
            .rows
            .try_reserve(1)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        trace.rows.push(row);
        Ok(())
    }

    pub(crate) fn absorb_base_root(
        &mut self,
        tree_ordinal: u16,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        let CommonProofProgress::BaseRoots(next_index) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        };
        if self
            .relation_prefix_schedule
            .ordered_base_tree_ordinals
            .get(next_index)
            != Some(&tree_ordinal)
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::BaseRoot { tree_ordinal }, &root)?;
        self.hash_query_counter.absorb_response(false)?;
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
            .relation_prefix_schedule
            .ordered_application_challenge_groups
            .get(next_index)
            .copied()
        else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if expected.challenge != challenge {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        #[cfg(test)]
        let observed_sampler_row = if self.observed_public_sampler_trace.is_some() {
            Some(ObservedPublicSamplerRow::product(
                expected
                    .challenge
                    .tag(self.transcript.application_statement_schema_identifier),
                expected.modulus,
                expected.coordinate_count,
                expected.candidate_byte_length,
                self.relation_prefix_schedule
                    .maximum_candidate_draws_per_output,
            )?)
        } else {
            None
        };
        let mut stream = self.transcript.begin_common_product_residue_challenge(
            expected,
            self.relation_prefix_schedule
                .maximum_candidate_draws_per_output,
        )?;
        let sampled = stream.sample_residue_vector()?;
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
                self.relation_prefix_schedule
                    .maximum_candidate_draws_per_output,
            )?
            .total_xof_query_count_ceiling(),
        )?;
        #[cfg(test)]
        self.record_public_sampler_row(observed_sampler_row)?;
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
            .relation_prefix_schedule
            .ordered_auxiliary_tree_ordinals
            .get(next_index)
            != Some(&tree_ordinal)
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::AuxiliaryRoot { tree_ordinal }, &root)?;
        self.hash_query_counter.absorb_response(false)?;
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

    pub(crate) fn absorb_row_code_whir_quotient_phase_root(
        &mut self,
        root: [u8; 64],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::QuotientPhaseRoot {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript
            .absorb_common_round(CommonProofRound::RowCodeWhirQuotientPhaseRoot, &root)?;
        self.hash_query_counter.absorb_response(false)?;
        self.progress = CommonProofProgress::OutOfDomainPoints(0);
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn sample_out_of_domain_point<F>(
        &mut self,
        point_ordinal: u16,
        mut is_forbidden: F,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError>
    where
        F: FnMut(ProofChallengeExtensionElement) -> bool,
    {
        let CommonProofProgress::OutOfDomainPoints(next_ordinal) = self.progress else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if next_ordinal != point_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let already_accepted = self.accepted_out_of_domain_points.clone();
        let sampled = self.sample_extension(
            CommonProofChallenge::OutOfDomainPoint { point_ordinal },
            |candidate| {
                candidate.is_zero()
                    || already_accepted.contains(&candidate)
                    || is_forbidden(candidate)
            },
        )?;
        self.accepted_out_of_domain_points.push(sampled);
        self.progress = CommonProofProgress::OutOfDomainPoints(next_ordinal + 1);
        self.skip_empty_prefix_phases();
        Ok(sampled)
    }

    pub(crate) fn absorb_out_of_domain_evaluations(
        &mut self,
        out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if self.progress != CommonProofProgress::OutOfDomainEvaluations
            || u32::try_from(out_of_domain_evaluations.len()).ok()
                != Some(self.relation_prefix_schedule.opening_claim_count)
        {
            return Err(TranscriptError::UnexpectedCommonProofRound);
        }
        self.transcript.absorb_common_extension_value_list(
            CommonProofRound::OutOfDomainEvaluations,
            out_of_domain_evaluations,
        )?;
        self.hash_query_counter.absorb_response(true)?;
        self.progress = CommonProofProgress::ReadyForRowCodeWhir;
        self.skip_empty_prefix_phases();
        Ok(())
    }

    pub(crate) fn into_public_row_code_whir_transcript(
        self,
    ) -> Result<RowCodeWhirTranscript, TranscriptError> {
        if self.relation_prefix_schedule.privacy_mode != CommonProofPrivacyMode::PublicOnly
            || self.progress != CommonProofProgress::ReadyForRowCodeWhir
            || self.transcript.pending_common_challenge.is_some()
            || self.hash_query_counter.pending_challenge
        {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        let maximum_candidate_draws_per_output = self
            .relation_prefix_schedule
            .maximum_candidate_draws_per_output;
        let row_code_whir_transcript = RowCodeWhirTranscript::from_public_common_prefix(
            self.transcript,
            self.hash_query_counter,
            maximum_candidate_draws_per_output,
            self.row_code_whir_transcript_operations,
            self.row_code_whir_live_role_schedule,
        );
        #[cfg(test)]
        let row_code_whir_transcript = {
            let mut row_code_whir_transcript = row_code_whir_transcript;
            row_code_whir_transcript.observed_public_sampler_rows =
                self.observed_public_sampler_trace.map(|trace| trace.rows);
            row_code_whir_transcript
        };
        Ok(row_code_whir_transcript)
    }

    pub(crate) fn into_secret_bearing_row_code_whir_transcript(
        self,
        opening_batch_mask_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<RowCodeWhirTranscript, TranscriptError> {
        if self.relation_prefix_schedule.privacy_mode != CommonProofPrivacyMode::SecretBearing
            || self.progress != CommonProofProgress::ReadyForRowCodeWhir
            || self.transcript.pending_common_challenge.is_some()
            || self.hash_query_counter.pending_challenge
        {
            return Err(TranscriptError::IncompleteCommonProofTranscript);
        }
        let maximum_candidate_draws_per_output = self
            .relation_prefix_schedule
            .maximum_candidate_draws_per_output;
        let row_code_whir_transcript = RowCodeWhirTranscript::from_secret_bearing_common_prefix(
            self.transcript,
            self.hash_query_counter,
            maximum_candidate_draws_per_output,
            self.row_code_whir_transcript_operations,
            self.row_code_whir_live_role_schedule,
            opening_batch_mask_evaluations,
        )?;
        #[cfg(test)]
        let row_code_whir_transcript = {
            let mut row_code_whir_transcript = row_code_whir_transcript;
            row_code_whir_transcript.observed_public_sampler_rows =
                self.observed_public_sampler_trace.map(|trace| trace.rows);
            row_code_whir_transcript
        };
        Ok(row_code_whir_transcript)
    }

    fn sample_extension<F>(
        &mut self,
        challenge: CommonProofChallenge,
        mut is_forbidden: F,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError>
    where
        F: FnMut(ProofChallengeExtensionElement) -> bool,
    {
        #[cfg(test)]
        let observed_sampler_row = self.traced_extension_sampler_row(challenge)?;
        let mut stream = self.transcript.begin_common_challenge(challenge)?;
        for draw_ordinal in 0..self
            .relation_prefix_schedule
            .maximum_candidate_draws_per_output
        {
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
                        self.relation_prefix_schedule
                            .maximum_candidate_draws_per_output,
                    )?)?;
                #[cfg(test)]
                self.record_public_sampler_row(observed_sampler_row)?;
                return Ok(candidate);
            }
            if draw_ordinal + 1
                < self
                    .relation_prefix_schedule
                    .maximum_candidate_draws_per_output
            {
                stream.reject_current_candidate()?;
            }
        }
        Err(TranscriptError::CommonChallengeDrawsExhausted)
    }

    #[cfg(test)]
    pub(super) const fn transcript_state_for_test(&self) -> [u8; 64] {
        self.transcript.state
    }

    fn skip_empty_prefix_phases(&mut self) {
        loop {
            self.progress = match self.progress {
                CommonProofProgress::BaseRoots(next)
                    if next
                        == self
                            .relation_prefix_schedule
                            .ordered_base_tree_ordinals
                            .len() =>
                {
                    CommonProofProgress::ApplicationChallenges(0)
                }
                CommonProofProgress::ApplicationChallenges(next)
                    if next
                        == self
                            .relation_prefix_schedule
                            .ordered_application_challenge_groups
                            .len() =>
                {
                    CommonProofProgress::AuxiliaryRoots(0)
                }
                CommonProofProgress::AuxiliaryRoots(next)
                    if next
                        == self
                            .relation_prefix_schedule
                            .ordered_auxiliary_tree_ordinals
                            .len() =>
                {
                    CommonProofProgress::CompositionChallenges(0)
                }
                CommonProofProgress::CompositionChallenges(next)
                    if next == self.relation_prefix_schedule.composition_challenge_count =>
                {
                    CommonProofProgress::QuotientPhaseRoot
                }
                CommonProofProgress::OutOfDomainPoints(next)
                    if next == self.relation_prefix_schedule.out_of_domain_point_count =>
                {
                    CommonProofProgress::OutOfDomainEvaluations
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
    BeforeAggregateSourceCommitment,
    AfterAggregateSourceCommitment,
    AfterAggregatePadCommitment,
    Whir,
    Complete,
}

const ROW_CODE_WHIR_TRANSCRIPT_CURSOR_MAGIC: &[u8; 8] = b"SLXTCU02";
const ROW_CODE_WHIR_TRANSCRIPT_CURSOR_VERSION: u16 = 2;
const MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CURSOR_BYTE_LENGTH: usize = 16 * 1024;
const ROW_CODE_WHIR_TRANSCRIPT_CURSOR_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/transcript/checkpoint-cursor/v2";

#[derive(Clone, Debug, PartialEq, Eq)]
struct RowCodeWhirTranscriptCheckpointSnapshot {
    construction_plan_identity_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    transcript_state: [u8; Hash512::BYTE_LENGTH],
    hash_query_count: u64,
    logical_verifier_message_count: u64,
    hash_query_counter_pending_challenge: bool,
    maximum_candidate_draws_per_output: u32,
    next_transcript_operation_index: usize,
    progress: RowCodeWhirProgress,
    next_whir_commitment_ordinal: u32,
    next_whir_observation_ordinal: u32,
    next_whir_challenge_ordinal: u32,
    next_whir_bit_challenge_ordinal: u32,
    pending_common_challenge: Option<PendingCommonChallenge>,
}

/// Canonical authenticated state needed to resume the exact successor
/// transcript. The browser checkpoint envelope authenticates these bytes; the
/// embedded digest detects accidental corruption before plan-bound restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite) struct RowCodeWhirTranscriptCheckpointCursor {
    canonical_bytes: Vec<u8>,
    digest: [u8; Hash512::BYTE_LENGTH],
    snapshot: RowCodeWhirTranscriptCheckpointSnapshot,
}

impl RowCodeWhirTranscriptCheckpointCursor {
    pub(in crate::bgv::proof_suite) fn from_canonical_bytes(
        canonical_bytes: &[u8],
    ) -> Result<Self, TranscriptError> {
        let snapshot = decode_row_code_whir_transcript_checkpoint_snapshot(canonical_bytes)?;
        let reencoded = encode_row_code_whir_transcript_checkpoint_snapshot(&snapshot)?;
        if reencoded != canonical_bytes {
            return Err(TranscriptError::CanonicalEncoding);
        }
        let digest = canonical_bytes
            .get(canonical_bytes.len() - Hash512::BYTE_LENGTH..)
            .ok_or(TranscriptError::CanonicalEncoding)?
            .try_into()
            .map_err(|_| TranscriptError::CanonicalEncoding)?;
        Ok(Self {
            canonical_bytes: reencoded,
            digest,
            snapshot,
        })
    }

    fn from_snapshot(
        snapshot: RowCodeWhirTranscriptCheckpointSnapshot,
    ) -> Result<Self, TranscriptError> {
        let canonical_bytes = encode_row_code_whir_transcript_checkpoint_snapshot(&snapshot)?;
        Self::from_canonical_bytes(&canonical_bytes)
    }

    pub(in crate::bgv::proof_suite) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(in crate::bgv::proof_suite) const fn digest(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.digest
    }

    pub(in crate::bgv::proof_suite) const fn next_transcript_operation_index(&self) -> usize {
        self.snapshot.next_transcript_operation_index
    }

    pub(in crate::bgv::proof_suite) fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

impl RowCodeWhirProgress {
    const fn canonical_code(self) -> u8 {
        match self {
            Self::AwaitingMaskEvaluations => 0,
            Self::AwaitingProtocolSchedule => 1,
            Self::BeforeAggregateSourceCommitment => 2,
            Self::AfterAggregateSourceCommitment => 3,
            Self::AfterAggregatePadCommitment => 4,
            Self::Whir => 5,
            Self::Complete => 6,
        }
    }

    fn from_canonical_code(code: u8) -> Result<Self, TranscriptError> {
        match code {
            0 => Ok(Self::AwaitingMaskEvaluations),
            1 => Ok(Self::AwaitingProtocolSchedule),
            2 => Ok(Self::BeforeAggregateSourceCommitment),
            3 => Ok(Self::AfterAggregateSourceCommitment),
            4 => Ok(Self::AfterAggregatePadCommitment),
            5 => Ok(Self::Whir),
            6 => Ok(Self::Complete),
            _ => Err(TranscriptError::CanonicalEncoding),
        }
    }
}

fn row_code_whir_transcript_cursor_digest(
    canonical_prefix: &[u8],
) -> Result<[u8; Hash512::BYTE_LENGTH], TranscriptError> {
    transcript_hash(
        ROW_CODE_WHIR_TRANSCRIPT_CURSOR_DIGEST_DOMAIN,
        vec![
            CanonicalItem::variable_bytes(canonical_prefix)
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        ],
    )
}

fn encode_row_code_whir_transcript_checkpoint_snapshot(
    snapshot: &RowCodeWhirTranscriptCheckpointSnapshot,
) -> Result<Vec<u8>, TranscriptError> {
    let pending_tag_byte_length =
        snapshot
            .pending_common_challenge
            .as_ref()
            .map_or(Ok(0_u16), |pending| {
                if pending.challenge_tag.is_empty() || !pending.challenge_tag.is_ascii() {
                    return Err(TranscriptError::CanonicalEncoding);
                }
                u16::try_from(pending.challenge_tag.len())
                    .map_err(|_| TranscriptError::CanonicalEncoding)
            })?;
    let pending_output_byte_length =
        snapshot
            .pending_common_challenge
            .as_ref()
            .map_or(Ok(0_u32), |pending| {
                if pending.canonical_output_bytes.is_empty() {
                    return Err(TranscriptError::CanonicalEncoding);
                }
                u32::try_from(pending.canonical_output_bytes.len())
                    .map_err(|_| TranscriptError::CanonicalEncoding)
            })?;
    let next_transcript_operation_index = u32::try_from(snapshot.next_transcript_operation_index)
        .map_err(|_| TranscriptError::CanonicalEncoding)?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(ROW_CODE_WHIR_TRANSCRIPT_CURSOR_MAGIC);
    bytes.extend_from_slice(&ROW_CODE_WHIR_TRANSCRIPT_CURSOR_VERSION.to_le_bytes());
    let total_byte_length_offset = bytes.len();
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&snapshot.construction_plan_identity_hash);
    bytes.extend_from_slice(
        &snapshot
            .application_statement_schema_identifier
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&snapshot.transcript_state);
    bytes.extend_from_slice(&snapshot.hash_query_count.to_le_bytes());
    bytes.extend_from_slice(&snapshot.logical_verifier_message_count.to_le_bytes());
    bytes.push(u8::from(snapshot.hash_query_counter_pending_challenge));
    bytes.extend_from_slice(&snapshot.maximum_candidate_draws_per_output.to_le_bytes());
    bytes.extend_from_slice(&next_transcript_operation_index.to_le_bytes());
    bytes.push(snapshot.progress.canonical_code());
    bytes.extend_from_slice(&snapshot.next_whir_commitment_ordinal.to_le_bytes());
    bytes.extend_from_slice(&snapshot.next_whir_observation_ordinal.to_le_bytes());
    bytes.extend_from_slice(&snapshot.next_whir_challenge_ordinal.to_le_bytes());
    bytes.extend_from_slice(&snapshot.next_whir_bit_challenge_ordinal.to_le_bytes());
    bytes.push(u8::from(snapshot.pending_common_challenge.is_some()));
    if let Some(pending) = &snapshot.pending_common_challenge {
        bytes.extend_from_slice(&pending.candidate_seed);
        bytes.extend_from_slice(&pending_tag_byte_length.to_le_bytes());
        bytes.extend_from_slice(pending.challenge_tag.as_bytes());
        bytes.extend_from_slice(&pending_output_byte_length.to_le_bytes());
        bytes.extend_from_slice(&pending.canonical_output_bytes);
    }
    let total_byte_length = bytes
        .len()
        .checked_add(Hash512::BYTE_LENGTH)
        .filter(|length| *length <= MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CURSOR_BYTE_LENGTH)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(TranscriptError::CanonicalEncoding)?;
    bytes[total_byte_length_offset..total_byte_length_offset + std::mem::size_of::<u32>()]
        .copy_from_slice(&total_byte_length.to_le_bytes());
    let digest = row_code_whir_transcript_cursor_digest(&bytes)?;
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_row_code_whir_transcript_checkpoint_snapshot(
    canonical_bytes: &[u8],
) -> Result<RowCodeWhirTranscriptCheckpointSnapshot, TranscriptError> {
    if canonical_bytes.len() > MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CURSOR_BYTE_LENGTH
        || canonical_bytes.len()
            < ROW_CODE_WHIR_TRANSCRIPT_CURSOR_MAGIC.len()
                + std::mem::size_of::<u16>()
                + std::mem::size_of::<u32>()
                + 2 * Hash512::BYTE_LENGTH
    {
        return Err(TranscriptError::CanonicalEncoding);
    }
    let digest_offset = canonical_bytes
        .len()
        .checked_sub(Hash512::BYTE_LENGTH)
        .ok_or(TranscriptError::CanonicalEncoding)?;
    let expected_digest =
        row_code_whir_transcript_cursor_digest(&canonical_bytes[..digest_offset])?;
    if canonical_bytes[digest_offset..] != expected_digest {
        return Err(TranscriptError::CanonicalEncoding);
    }
    let mut decoder = RowCodeWhirTranscriptCursorDecoder {
        bytes: &canonical_bytes[..digest_offset],
        offset: 0,
    };
    if decoder.read_array::<8>()? != *ROW_CODE_WHIR_TRANSCRIPT_CURSOR_MAGIC
        || decoder.read_u16()? != ROW_CODE_WHIR_TRANSCRIPT_CURSOR_VERSION
        || usize::try_from(decoder.read_u32()?).map_err(|_| TranscriptError::CanonicalEncoding)?
            != canonical_bytes.len()
    {
        return Err(TranscriptError::CanonicalEncoding);
    }
    let construction_plan_identity_hash = decoder.read_array()?;
    let application_statement_schema_identifier = decoder.read_u16()?;
    let transcript_state = decoder.read_array()?;
    let hash_query_count = decoder.read_u64()?;
    let logical_verifier_message_count = decoder.read_u64()?;
    let hash_query_counter_pending_challenge = decoder.read_bool()?;
    let maximum_candidate_draws_per_output = decoder.read_u32()?;
    let next_transcript_operation_index =
        usize::try_from(decoder.read_u32()?).map_err(|_| TranscriptError::CanonicalEncoding)?;
    let progress = RowCodeWhirProgress::from_canonical_code(decoder.read_u8()?)?;
    let next_whir_commitment_ordinal = decoder.read_u32()?;
    let next_whir_observation_ordinal = decoder.read_u32()?;
    let next_whir_challenge_ordinal = decoder.read_u32()?;
    let next_whir_bit_challenge_ordinal = decoder.read_u32()?;
    let pending_common_challenge = if decoder.read_bool()? {
        let candidate_seed = decoder.read_array()?;
        let challenge_tag_byte_length = usize::from(decoder.read_u16()?);
        let challenge_tag_bytes = decoder.read_bytes(challenge_tag_byte_length)?;
        let challenge_tag = String::from_utf8(challenge_tag_bytes.to_vec())
            .map_err(|_| TranscriptError::CanonicalEncoding)?;
        if challenge_tag.is_empty() || !challenge_tag.is_ascii() {
            return Err(TranscriptError::CanonicalEncoding);
        }
        let canonical_output_byte_length =
            usize::try_from(decoder.read_u32()?).map_err(|_| TranscriptError::CanonicalEncoding)?;
        if canonical_output_byte_length == 0 {
            return Err(TranscriptError::CanonicalEncoding);
        }
        let canonical_output_bytes = decoder.read_bytes(canonical_output_byte_length)?.to_vec();
        Some(PendingCommonChallenge {
            candidate_seed,
            challenge_tag,
            canonical_output_bytes,
        })
    } else {
        None
    };
    if !decoder.is_complete()
        || hash_query_counter_pending_challenge != pending_common_challenge.is_some()
        || hash_query_count < 2
    {
        return Err(TranscriptError::CanonicalEncoding);
    }
    Ok(RowCodeWhirTranscriptCheckpointSnapshot {
        construction_plan_identity_hash,
        application_statement_schema_identifier,
        transcript_state,
        hash_query_count,
        logical_verifier_message_count,
        hash_query_counter_pending_challenge,
        maximum_candidate_draws_per_output,
        next_transcript_operation_index,
        progress,
        next_whir_commitment_ordinal,
        next_whir_observation_ordinal,
        next_whir_challenge_ordinal,
        next_whir_bit_challenge_ordinal,
        pending_common_challenge,
    })
}

struct RowCodeWhirTranscriptCursorDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RowCodeWhirTranscriptCursorDecoder<'a> {
    fn read_bytes(&mut self, byte_length: usize) -> Result<&'a [u8], TranscriptError> {
        let end = self
            .offset
            .checked_add(byte_length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(TranscriptError::CanonicalEncoding)?;
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn read_array<const BYTE_LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; BYTE_LENGTH], TranscriptError> {
        self.read_bytes(BYTE_LENGTH)?
            .try_into()
            .map_err(|_| TranscriptError::CanonicalEncoding)
    }

    fn read_u8(&mut self) -> Result<u8, TranscriptError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_bool(&mut self) -> Result<bool, TranscriptError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(TranscriptError::CanonicalEncoding),
        }
    }

    fn read_u16(&mut self) -> Result<u16, TranscriptError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, TranscriptError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, TranscriptError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn is_complete(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Copy)]
struct ExpectedRowCodeWhirCursorPosition {
    progress: RowCodeWhirProgress,
    next_whir_commitment_ordinal: u32,
    next_whir_observation_ordinal: u32,
    next_whir_challenge_ordinal: u32,
    pending_challenge_operation_index: Option<usize>,
    hash_query_count: u64,
    logical_verifier_message_count: u64,
    hash_query_counter_pending_challenge: bool,
}

const fn row_code_whir_direct_challenge_is_allowed(
    challenge: RowCodeWhirChallenge,
    progress: RowCodeWhirProgress,
) -> bool {
    match challenge.stage() {
        RowCodeWhirChallengeStage::BeforeCommitment => {
            matches!(
                progress,
                RowCodeWhirProgress::BeforeAggregateSourceCommitment
            )
        }
        RowCodeWhirChallengeStage::AfterCommitment => {
            matches!(progress, RowCodeWhirProgress::AfterAggregatePadCommitment)
        }
        RowCodeWhirChallengeStage::DegreeTest => {
            matches!(progress, RowCodeWhirProgress::AfterAggregatePadCommitment)
        }
    }
}

fn validate_row_code_whir_transcript_checkpoint_snapshot(
    construction_plan: &RowCodeWhirConstructionPlan,
    snapshot: &RowCodeWhirTranscriptCheckpointSnapshot,
) -> Result<(), TranscriptError> {
    let construction_plan_identity_hash = construction_plan
        .canonical_identity_hash()
        .map_err(|_| TranscriptError::InvalidCommonProofSchedule)?;
    let operations = construction_plan.transcript_operations();
    if snapshot.construction_plan_identity_hash != construction_plan_identity_hash
        || snapshot.application_statement_schema_identifier
            != construction_plan.application_statement_schema_identifier()
        || snapshot.maximum_candidate_draws_per_output
            != construction_plan
                .relation_prefix_schedule()
                .maximum_candidate_draws_per_output()
        || snapshot.maximum_candidate_draws_per_output == 0
        || snapshot.next_transcript_operation_index > operations.len()
        || snapshot.next_whir_bit_challenge_ordinal != 0
        || snapshot.hash_query_counter_pending_challenge
            != snapshot.pending_common_challenge.is_some()
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    let expected_counter_origin = construction_plan
        .relation_prefix_schedule()
        .row_code_whir_catalog_counter_origin()?;
    let expected = expected_row_code_whir_cursor_position(
        operations,
        snapshot.next_transcript_operation_index,
        construction_plan
            .relation_prefix_schedule()
            .maximum_candidate_draws_per_output(),
        expected_counter_origin,
    )?;
    if snapshot.progress != expected.progress
        || snapshot.next_whir_commitment_ordinal != expected.next_whir_commitment_ordinal
        || snapshot.next_whir_observation_ordinal != expected.next_whir_observation_ordinal
        || snapshot.next_whir_challenge_ordinal != expected.next_whir_challenge_ordinal
        || snapshot.hash_query_count != expected.hash_query_count
        || snapshot.logical_verifier_message_count != expected.logical_verifier_message_count
        || snapshot.hash_query_counter_pending_challenge
            != expected.hash_query_counter_pending_challenge
        || snapshot.pending_common_challenge.is_some()
            != expected.pending_challenge_operation_index.is_some()
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    match (
        expected.pending_challenge_operation_index,
        &snapshot.pending_common_challenge,
    ) {
        (Some(operation_index), Some(pending)) => {
            validate_pending_row_code_whir_challenge(
                operations
                    .get(operation_index)
                    .ok_or(TranscriptError::InvalidCommonProofSchedule)?,
                pending,
            )?;
        }
        (None, None) => {}
        _ => return Err(TranscriptError::InvalidCommonProofSchedule),
    }
    Ok(())
}

fn expected_row_code_whir_cursor_position(
    operations: &[RowCodeWhirTranscriptOperation],
    consumed_operation_count: usize,
    maximum_candidate_draws_per_output: u32,
    mut hash_query_counter: TranscriptHashQueryCounter,
) -> Result<ExpectedRowCodeWhirCursorPosition, TranscriptError> {
    let consumed_operations = operations
        .get(..consumed_operation_count)
        .ok_or(TranscriptError::InvalidCommonProofSchedule)?;
    if maximum_candidate_draws_per_output == 0 || hash_query_counter.pending_challenge {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    let mut progress = if matches!(
        operations.first(),
        Some(RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. })
    ) {
        RowCodeWhirProgress::AwaitingMaskEvaluations
    } else {
        RowCodeWhirProgress::AwaitingProtocolSchedule
    };
    let mut next_whir_commitment_ordinal = 0_u32;
    let mut next_whir_observation_ordinal = 0_u32;
    let mut next_whir_challenge_ordinal = 0_u32;
    let mut pending_challenge_operation_index = None;

    for (operation_index, operation) in consumed_operations.iter().enumerate() {
        pending_challenge_operation_index = None;
        match operation {
            RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { value_count }
                if progress == RowCodeWhirProgress::AwaitingMaskEvaluations && *value_count > 0 =>
            {
                hash_query_counter.absorb_response(true)?;
                progress = RowCodeWhirProgress::AwaitingProtocolSchedule;
            }
            RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { canonical_values }
                if progress == RowCodeWhirProgress::AwaitingProtocolSchedule
                    && !canonical_values.is_empty() =>
            {
                hash_query_counter.absorb_response(true)?;
                progress = RowCodeWhirProgress::BeforeAggregateSourceCommitment;
            }
            RowCodeWhirTranscriptOperation::SampleExtension {
                role: RowCodeWhirExtensionRole::Direct(challenge),
                whir_challenge_ordinal: None,
            } if row_code_whir_direct_challenge_is_allowed(*challenge, progress) => {
                hash_query_counter.begin_challenge(maximum_extension_challenge_hash_count(
                    maximum_candidate_draws_per_output,
                )?)?;
                pending_challenge_operation_index = Some(operation_index);
            }
            RowCodeWhirTranscriptOperation::SampleExtension {
                role,
                whir_challenge_ordinal: Some(challenge_ordinal),
            } if !matches!(role, RowCodeWhirExtensionRole::Direct(_))
                && matches!(
                    progress,
                    RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
                )
                && *challenge_ordinal == next_whir_challenge_ordinal =>
            {
                hash_query_counter.begin_challenge(maximum_extension_challenge_hash_count(
                    maximum_candidate_draws_per_output,
                )?)?;
                next_whir_challenge_ordinal = next_whir_challenge_ordinal
                    .checked_add(1)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                progress = RowCodeWhirProgress::Whir;
                pending_challenge_operation_index = Some(operation_index);
            }
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::Aggregate,
            } if progress == RowCodeWhirProgress::BeforeAggregateSourceCommitment => {
                hash_query_counter.absorb_response(false)?;
                progress = RowCodeWhirProgress::AfterAggregateSourceCommitment;
            }
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::AggregateWidePad,
            } if progress == RowCodeWhirProgress::AfterAggregateSourceCommitment => {
                hash_query_counter.absorb_response(false)?;
                progress = RowCodeWhirProgress::AfterAggregatePadCommitment;
            }
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::WhirRound { round_ordinal },
            } if matches!(
                progress,
                RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
            ) && *round_ordinal == next_whir_commitment_ordinal =>
            {
                hash_query_counter.absorb_response(false)?;
                next_whir_commitment_ordinal = next_whir_commitment_ordinal
                    .checked_add(1)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                progress = RowCodeWhirProgress::Whir;
            }
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role:
                    RowCodeWhirCommitmentRole::BaseFreshSource | RowCodeWhirCommitmentRole::BaseFreshPad,
            } if progress == RowCodeWhirProgress::Whir => {
                hash_query_counter.absorb_response(false)?;
            }
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role: RowCodeWhirQueryRole::Outer | RowCodeWhirQueryRole::Bound,
                upper_bound,
                output_count,
            } if progress == RowCodeWhirProgress::AfterAggregatePadCommitment
                && *upper_bound > 0
                && upper_bound.is_power_of_two()
                && *output_count > 0
                && *output_count <= *upper_bound =>
            {
                hash_query_counter.begin_challenge(distinct_query_challenge_hash_count(
                    u32::try_from(*output_count)
                        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
                    maximum_candidate_draws_per_output,
                )?)?;
                pending_challenge_operation_index = Some(operation_index);
            }
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role: RowCodeWhirQueryRole::WhirEpoch { .. },
                upper_bound,
                output_count,
            } if matches!(
                progress,
                RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
            ) && *upper_bound > 0
                && upper_bound.is_power_of_two()
                && *output_count > 0
                && *output_count <= *upper_bound =>
            {
                hash_query_counter.begin_challenge(distinct_query_challenge_hash_count(
                    u32::try_from(*output_count)
                        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
                    maximum_candidate_draws_per_output,
                )?)?;
                progress = RowCodeWhirProgress::Whir;
                pending_challenge_operation_index = Some(operation_index);
            }
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                observation_ordinal,
                value_count,
                ..
            } if matches!(
                progress,
                RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
            ) && *observation_ordinal == next_whir_observation_ordinal
                && *value_count > 0 =>
            {
                hash_query_counter.absorb_response(true)?;
                next_whir_observation_ordinal = next_whir_observation_ordinal
                    .checked_add(1)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                progress = RowCodeWhirProgress::Whir;
            }
            RowCodeWhirTranscriptOperation::FinishProofStream
                if progress == RowCodeWhirProgress::Whir
                    && operation_index + 1 == operations.len() =>
            {
                hash_query_counter.absorb_response(true)?;
                progress = RowCodeWhirProgress::Complete;
            }
            _ => return Err(TranscriptError::InvalidCommonProofSchedule),
        }
    }
    if hash_query_counter.pending_challenge != pending_challenge_operation_index.is_some() {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    Ok(ExpectedRowCodeWhirCursorPosition {
        progress,
        next_whir_commitment_ordinal,
        next_whir_observation_ordinal,
        next_whir_challenge_ordinal,
        pending_challenge_operation_index,
        hash_query_count: hash_query_counter.hash_query_count,
        logical_verifier_message_count: hash_query_counter.logical_verifier_message_count,
        hash_query_counter_pending_challenge: hash_query_counter.pending_challenge,
    })
}

fn validate_pending_row_code_whir_challenge(
    operation: &RowCodeWhirTranscriptOperation,
    pending: &PendingCommonChallenge,
) -> Result<(), TranscriptError> {
    let (expected_tag, expected_output_count, upper_bound) = match operation {
        RowCodeWhirTranscriptOperation::SampleExtension {
            role: RowCodeWhirExtensionRole::Direct(challenge),
            whir_challenge_ordinal: None,
        } => (challenge.tag(), PROOF_CHALLENGE_EXTENSION_DEGREE, None),
        RowCodeWhirTranscriptOperation::SampleExtension {
            role,
            whir_challenge_ordinal: Some(challenge_ordinal),
        } if !matches!(role, RowCodeWhirExtensionRole::Direct(_)) => (
            format!("row-code-whir/whir-challenge/{challenge_ordinal:08x}"),
            PROOF_CHALLENGE_EXTENSION_DEGREE,
            None,
        ),
        RowCodeWhirTranscriptOperation::SampleDistinctIndices {
            role,
            upper_bound,
            output_count,
        } => {
            let upper_bound_u64 =
                u64::try_from(*upper_bound).map_err(|_| TranscriptError::CanonicalEncoding)?;
            let output_count_u64 =
                u64::try_from(*output_count).map_err(|_| TranscriptError::CanonicalEncoding)?;
            let tag = match role {
                RowCodeWhirQueryRole::Outer => format!(
                    "{}/{upper_bound_u64:016x}/{output_count_u64:016x}",
                    RowCodeWhirChallenge::OuterQueryVector.tag(),
                ),
                RowCodeWhirQueryRole::Bound => format!(
                    "{}/{upper_bound_u64:016x}/{output_count_u64:016x}",
                    RowCodeWhirChallenge::BoundQueryVector.tag(),
                ),
                RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal } => format!(
                    "row-code-whir/whir-query-vector/{epoch_ordinal:08x}/{:04x}/{output_count_u64:016x}",
                    upper_bound.ilog2(),
                ),
            };
            (tag, *output_count, Some(*upper_bound))
        }
        _ => return Err(TranscriptError::InvalidCommonProofSchedule),
    };
    if pending.challenge_tag != expected_tag
        || pending.canonical_output_bytes.len()
            != expected_output_count
                .checked_mul(std::mem::size_of::<u64>())
                .ok_or(TranscriptError::CanonicalEncoding)?
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    let mut accepted_values = BTreeSet::new();
    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
    for (value_ordinal, bytes) in pending
        .canonical_output_bytes
        .chunks_exact(std::mem::size_of::<u64>())
        .enumerate()
    {
        let value = u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| TranscriptError::CanonicalEncoding)?,
        );
        if let Some(upper_bound) = upper_bound {
            if value
                >= u64::try_from(upper_bound).map_err(|_| TranscriptError::CanonicalEncoding)?
                || !accepted_values.insert(value)
            {
                return Err(TranscriptError::InvalidCommonProofSchedule);
            }
        } else {
            coordinates[value_ordinal] = value;
        }
    }
    if upper_bound.is_none()
        && ProofChallengeExtensionElement::from_canonical_coordinates(coordinates).is_err()
    {
        return Err(TranscriptError::InvalidCommonProofSchedule);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RowCodeWhirTranscriptSummary {
    maximum_hash_query_count: u64,
    logical_verifier_message_count: u64,
    #[cfg(test)]
    observed_public_sampler_rows: Option<Vec<ObservedPublicSamplerRow>>,
}

/// Incrementally binds the final proof byte stream without retaining a second
/// complete copy in transcript memory.
pub(crate) struct RowCodeWhirProofStreamAbsorber {
    transcript: RowCodeWhirTranscript,
    round_message_absorber: CommonProofRoundMessageAbsorber,
}

impl RowCodeWhirProofStreamAbsorber {
    pub(crate) fn absorb(
        &mut self,
        canonical_proof_byte_chunk: &[u8],
    ) -> Result<(), TranscriptError> {
        self.round_message_absorber
            .streaming_hash
            .absorb(canonical_proof_byte_chunk)
            .map_err(transcript_streaming_hash_error)
    }

    pub(crate) fn finish(mut self) -> Result<RowCodeWhirTranscriptSummary, TranscriptError> {
        self.transcript
            .transcript
            .finish_streamed_common_round(self.round_message_absorber)?;
        self.transcript.hash_query_counter.absorb_response(true)?;
        self.transcript.consume_catalog_operation()?;
        self.transcript.progress = RowCodeWhirProgress::Complete;
        self.transcript.validate_catalog_cursor_position()?;
        if self
            .transcript
            .transcript
            .pending_common_challenge
            .is_some()
            || self
                .transcript
                .transcript_operations
                .as_ref()
                .is_some_and(|operations| {
                    self.transcript.next_transcript_operation_index != operations.len()
                })
        {
            return Err(TranscriptError::IncompleteRowCodeWhirTranscript);
        }
        let logical_verifier_message_count = self
            .transcript
            .hash_query_counter
            .logical_verifier_message_count();
        Ok(RowCodeWhirTranscriptSummary {
            maximum_hash_query_count: self.transcript.hash_query_counter.finish()?,
            logical_verifier_message_count,
            #[cfg(test)]
            observed_public_sampler_rows: self.transcript.observed_public_sampler_rows,
        })
    }
}

impl RowCodeWhirTranscriptSummary {
    pub(crate) const fn maximum_hash_query_count(&self) -> u64 {
        self.maximum_hash_query_count
    }

    pub(crate) const fn logical_verifier_message_count(&self) -> u64 {
        self.logical_verifier_message_count
    }

    #[cfg(test)]
    pub(crate) fn observed_public_sampler_rows(&self) -> Option<&[ObservedPublicSamplerRow]> {
        self.observed_public_sampler_rows.as_deref()
    }
}

/// The sole typed Fiat-Shamir state for the row-code construction. It consumes
/// the live common-proof prefix instead of hashing a digest into a second
/// challenger. Public-only handoffs begin directly at the protocol schedule;
/// secret-bearing handoffs first absorb the checked mask evaluations as an
/// ordinary typed prover round with no preceding opening-batch challenge.
#[derive(Clone, Debug)]
pub(crate) struct RowCodeWhirTranscript {
    transcript: CanonicalProofTranscript,
    hash_query_counter: TranscriptHashQueryCounter,
    catalog_counter_origin: Option<TranscriptHashQueryCounter>,
    maximum_candidate_draws_per_output: u32,
    transcript_operations: Option<Vec<RowCodeWhirTranscriptOperation>>,
    live_role_schedule: Option<RowCodeWhirLiveRoleSchedule>,
    next_transcript_operation_index: usize,
    progress: RowCodeWhirProgress,
    next_whir_commitment_ordinal: u32,
    next_whir_observation_ordinal: u32,
    next_whir_challenge_ordinal: u32,
    next_whir_bit_challenge_ordinal: u32,
    #[cfg(test)]
    observed_public_sampler_rows: Option<Vec<ObservedPublicSamplerRow>>,
}

impl RowCodeWhirTranscript {
    fn validate_catalog_cursor_position(&self) -> Result<(), TranscriptError> {
        let (operations, counter_origin) = match (
            self.transcript_operations.as_deref(),
            self.catalog_counter_origin.clone(),
        ) {
            (Some(operations), Some(counter_origin)) => (operations, counter_origin),
            (None, None) => return Ok(()),
            _ => return Err(TranscriptError::InvalidCommonProofSchedule),
        };
        let expected = expected_row_code_whir_cursor_position(
            operations,
            self.next_transcript_operation_index,
            self.maximum_candidate_draws_per_output,
            counter_origin,
        )?;
        if self.progress != expected.progress
            || self.next_whir_commitment_ordinal != expected.next_whir_commitment_ordinal
            || self.next_whir_observation_ordinal != expected.next_whir_observation_ordinal
            || self.next_whir_challenge_ordinal != expected.next_whir_challenge_ordinal
            || self.hash_query_counter.hash_query_count != expected.hash_query_count
            || self.hash_query_counter.logical_verifier_message_count
                != expected.logical_verifier_message_count
            || self.hash_query_counter.pending_challenge
                != expected.hash_query_counter_pending_challenge
            || self.transcript.pending_common_challenge.is_some()
                != expected.pending_challenge_operation_index.is_some()
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        match (
            expected.pending_challenge_operation_index,
            &self.transcript.pending_common_challenge,
        ) {
            (Some(operation_index), Some(pending)) => {
                validate_pending_row_code_whir_challenge(
                    operations
                        .get(operation_index)
                        .ok_or(TranscriptError::InvalidCommonProofSchedule)?,
                    pending,
                )?;
            }
            (None, None) => {}
            _ => return Err(TranscriptError::InvalidCommonProofSchedule),
        }
        Ok(())
    }

    fn next_catalog_operation(
        &self,
    ) -> Result<Option<RowCodeWhirTranscriptOperation>, TranscriptError> {
        let Some(operations) = &self.transcript_operations else {
            return Ok(None);
        };
        operations
            .get(self.next_transcript_operation_index)
            .cloned()
            .map(Some)
            .ok_or(TranscriptError::IncompleteRowCodeWhirTranscript)
    }

    fn consume_catalog_operation(&mut self) -> Result<(), TranscriptError> {
        if self.transcript_operations.is_none() {
            return Ok(());
        }
        self.next_transcript_operation_index = self
            .next_transcript_operation_index
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn next_live_whir_observation_role(
        &self,
    ) -> Result<Option<RowCodeWhirObservationRole>, TranscriptError> {
        self.live_role_schedule
            .as_ref()
            .map(|schedule| schedule.observation_role(self.next_whir_observation_ordinal))
            .transpose()
    }

    pub(in crate::bgv::proof_suite) fn next_live_whir_extension_role(
        &self,
    ) -> Result<Option<RowCodeWhirExtensionRole>, TranscriptError> {
        self.live_role_schedule
            .as_ref()
            .map(|schedule| schedule.extension_role(self.next_whir_challenge_ordinal))
            .transpose()
    }

    pub(in crate::bgv::proof_suite) fn checkpoint_cursor(
        &self,
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> Result<RowCodeWhirTranscriptCheckpointCursor, TranscriptError> {
        self.validate_catalog_cursor_position()?;
        let construction_plan_identity_hash = construction_plan
            .canonical_identity_hash()
            .map_err(|_| TranscriptError::InvalidCommonProofSchedule)?;
        let expected_live_role_schedule =
            RowCodeWhirLiveRoleSchedule::for_construction_plan(construction_plan)?;
        if self
            .transcript
            .row_code_whir_construction_plan_identity_hash
            != construction_plan_identity_hash
            || self.transcript.application_statement_schema_identifier
                != construction_plan.application_statement_schema_identifier()
            || self.maximum_candidate_draws_per_output
                != construction_plan
                    .relation_prefix_schedule()
                    .maximum_candidate_draws_per_output()
            || self.transcript_operations.as_deref()
                != Some(construction_plan.transcript_operations())
            || self.live_role_schedule.as_ref() != Some(&expected_live_role_schedule)
        {
            return Err(TranscriptError::InvalidCommonProofSchedule);
        }
        let snapshot = RowCodeWhirTranscriptCheckpointSnapshot {
            construction_plan_identity_hash,
            application_statement_schema_identifier: self
                .transcript
                .application_statement_schema_identifier,
            transcript_state: self.transcript.state,
            hash_query_count: self.hash_query_counter.hash_query_count,
            logical_verifier_message_count: self.hash_query_counter.logical_verifier_message_count,
            hash_query_counter_pending_challenge: self.hash_query_counter.pending_challenge,
            maximum_candidate_draws_per_output: self.maximum_candidate_draws_per_output,
            next_transcript_operation_index: self.next_transcript_operation_index,
            progress: self.progress,
            next_whir_commitment_ordinal: self.next_whir_commitment_ordinal,
            next_whir_observation_ordinal: self.next_whir_observation_ordinal,
            next_whir_challenge_ordinal: self.next_whir_challenge_ordinal,
            next_whir_bit_challenge_ordinal: self.next_whir_bit_challenge_ordinal,
            pending_common_challenge: self.transcript.pending_common_challenge.clone(),
        };
        validate_row_code_whir_transcript_checkpoint_snapshot(construction_plan, &snapshot)?;
        RowCodeWhirTranscriptCheckpointCursor::from_snapshot(snapshot)
    }

    pub(in crate::bgv::proof_suite) fn restore_checkpoint_cursor(
        construction_plan: &RowCodeWhirConstructionPlan,
        cursor: &RowCodeWhirTranscriptCheckpointCursor,
    ) -> Result<Self, TranscriptError> {
        validate_row_code_whir_transcript_checkpoint_snapshot(construction_plan, &cursor.snapshot)?;
        let snapshot = &cursor.snapshot;
        let catalog_counter_origin = construction_plan
            .relation_prefix_schedule()
            .row_code_whir_catalog_counter_origin()?;
        Ok(Self {
            transcript: CanonicalProofTranscript {
                application_statement_schema_identifier: snapshot
                    .application_statement_schema_identifier,
                row_code_whir_construction_plan_identity_hash: snapshot
                    .construction_plan_identity_hash,
                state: snapshot.transcript_state,
                pending_common_challenge: snapshot.pending_common_challenge.clone(),
            },
            hash_query_counter: TranscriptHashQueryCounter {
                hash_query_count: snapshot.hash_query_count,
                logical_verifier_message_count: snapshot.logical_verifier_message_count,
                pending_challenge: snapshot.hash_query_counter_pending_challenge,
            },
            catalog_counter_origin: Some(catalog_counter_origin),
            maximum_candidate_draws_per_output: snapshot.maximum_candidate_draws_per_output,
            transcript_operations: Some(construction_plan.transcript_operations().to_vec()),
            live_role_schedule: Some(RowCodeWhirLiveRoleSchedule::for_construction_plan(
                construction_plan,
            )?),
            next_transcript_operation_index: snapshot.next_transcript_operation_index,
            progress: snapshot.progress,
            next_whir_commitment_ordinal: snapshot.next_whir_commitment_ordinal,
            next_whir_observation_ordinal: snapshot.next_whir_observation_ordinal,
            next_whir_challenge_ordinal: snapshot.next_whir_challenge_ordinal,
            next_whir_bit_challenge_ordinal: snapshot.next_whir_bit_challenge_ordinal,
            #[cfg(test)]
            observed_public_sampler_rows: None,
        })
    }

    fn from_public_common_prefix(
        transcript: CanonicalProofTranscript,
        hash_query_counter: TranscriptHashQueryCounter,
        maximum_candidate_draws_per_output: u32,
        transcript_operations: Option<Vec<RowCodeWhirTranscriptOperation>>,
        live_role_schedule: Option<RowCodeWhirLiveRoleSchedule>,
    ) -> Self {
        let catalog_counter_origin = transcript_operations
            .as_ref()
            .map(|_| hash_query_counter.clone());
        Self {
            transcript,
            hash_query_counter,
            catalog_counter_origin,
            maximum_candidate_draws_per_output,
            transcript_operations,
            live_role_schedule,
            next_transcript_operation_index: 0,
            progress: RowCodeWhirProgress::AwaitingProtocolSchedule,
            next_whir_commitment_ordinal: 0,
            next_whir_observation_ordinal: 0,
            next_whir_challenge_ordinal: 0,
            next_whir_bit_challenge_ordinal: 0,
            #[cfg(test)]
            observed_public_sampler_rows: None,
        }
    }

    fn from_secret_bearing_common_prefix(
        transcript: CanonicalProofTranscript,
        hash_query_counter: TranscriptHashQueryCounter,
        maximum_candidate_draws_per_output: u32,
        transcript_operations: Option<Vec<RowCodeWhirTranscriptOperation>>,
        live_role_schedule: Option<RowCodeWhirLiveRoleSchedule>,
        opening_batch_mask_evaluations: &[ProofChallengeExtensionElement],
    ) -> Result<Self, TranscriptError> {
        let catalog_counter_origin = transcript_operations
            .as_ref()
            .map(|_| hash_query_counter.clone());
        let mut result = Self {
            transcript,
            hash_query_counter,
            catalog_counter_origin,
            maximum_candidate_draws_per_output,
            transcript_operations,
            live_role_schedule,
            next_transcript_operation_index: 0,
            progress: RowCodeWhirProgress::AwaitingMaskEvaluations,
            next_whir_commitment_ordinal: 0,
            next_whir_observation_ordinal: 0,
            next_whir_challenge_ordinal: 0,
            next_whir_bit_challenge_ordinal: 0,
            #[cfg(test)]
            observed_public_sampler_rows: None,
        };
        result.absorb_opening_batch_mask_evaluations(opening_batch_mask_evaluations)?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(statement: &[u8]) -> Result<Self, TranscriptError> {
        Ok(Self {
            transcript: CanonicalProofTranscript::try_new_row_code_whir(
                1,
                [0_u8; Hash512::BYTE_LENGTH],
                [0x63_u8; Hash512::BYTE_LENGTH],
                u16::MAX,
                statement,
            )?,
            hash_query_counter: TranscriptHashQueryCounter::new(),
            catalog_counter_origin: None,
            maximum_candidate_draws_per_output:
                super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            transcript_operations: None,
            live_role_schedule: None,
            next_transcript_operation_index: 0,
            progress: RowCodeWhirProgress::AwaitingProtocolSchedule,
            next_whir_commitment_ordinal: 0,
            next_whir_observation_ordinal: 0,
            next_whir_challenge_ordinal: 0,
            next_whir_bit_challenge_ordinal: 0,
            #[cfg(test)]
            observed_public_sampler_rows: None,
        })
    }

    #[cfg(test)]
    fn record_public_sampler_row(
        &mut self,
        row: Option<ObservedPublicSamplerRow>,
    ) -> Result<(), TranscriptError> {
        let (Some(rows), Some(row)) = (&mut self.observed_public_sampler_rows, row) else {
            return Ok(());
        };
        rows.try_reserve(1)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        rows.push(row);
        Ok(())
    }

    fn absorb_opening_batch_mask_evaluations(
        &mut self,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if self.progress != RowCodeWhirProgress::AwaitingMaskEvaluations || values.is_empty() {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        if let Some(operation) = self.next_catalog_operation()?
            && operation
                != (RowCodeWhirTranscriptOperation::ObserveMaskEvaluations {
                    value_count: values.len(),
                })
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        self.transcript.absorb_typed_extension_value_list(
            RowCodeWhirRound::OpeningBatchMaskEvaluations.tag(),
            values,
        )?;
        self.hash_query_counter.absorb_response(true)?;
        self.consume_catalog_operation()?;
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
        if let Some(operation) = self.next_catalog_operation()?
            && operation
                != (RowCodeWhirTranscriptOperation::ObserveProtocolSchedule {
                    canonical_values: values.to_vec(),
                })
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        self.transcript
            .absorb_typed_extension_value_list(RowCodeWhirRound::ProtocolSchedule.tag(), values)?;
        self.hash_query_counter.absorb_response(true)?;
        self.consume_catalog_operation()?;
        self.progress = RowCodeWhirProgress::BeforeAggregateSourceCommitment;
        Ok(())
    }

    pub(crate) fn sample_direct_extension(
        &mut self,
        challenge: RowCodeWhirChallenge,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        if !row_code_whir_direct_challenge_is_allowed(challenge, self.progress)
            || matches!(
                challenge,
                RowCodeWhirChallenge::OuterQueryVector | RowCodeWhirChallenge::BoundQueryVector
            )
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        if let Some(operation) = self.next_catalog_operation()?
            && operation
                != (RowCodeWhirTranscriptOperation::SampleExtension {
                    role: RowCodeWhirExtensionRole::Direct(challenge),
                    whir_challenge_ordinal: None,
                })
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let sampled = self.sample_extension_with_tag(challenge.tag())?;
        self.consume_catalog_operation()?;
        Ok(sampled)
    }

    pub(crate) fn sample_direct_distinct_indices(
        &mut self,
        challenge: RowCodeWhirChallenge,
        upper_bound: usize,
        output_count: usize,
    ) -> Result<Vec<usize>, TranscriptError> {
        if self.progress != RowCodeWhirProgress::AfterAggregatePadCommitment
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
        let expected_role = match challenge {
            RowCodeWhirChallenge::OuterQueryVector => RowCodeWhirQueryRole::Outer,
            RowCodeWhirChallenge::BoundQueryVector => RowCodeWhirQueryRole::Bound,
            _ => return Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        };
        if let Some(operation) = self.next_catalog_operation()?
            && operation
                != (RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    role: expected_role,
                    upper_bound,
                    output_count,
                })
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let candidate_byte_length = std::mem::size_of::<u64>();
        let upper_bound_u64 =
            u64::try_from(upper_bound).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let output_count_u64 =
            u64::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let challenge_tag = format!(
            "{}/{upper_bound_u64:016x}/{output_count_u64:016x}",
            challenge.tag()
        );
        #[cfg(test)]
        let observed_sampler_row = if self.observed_public_sampler_rows.is_some() {
            Some(ObservedPublicSamplerRow::distinct(
                challenge_tag.clone(),
                upper_bound,
                output_count,
                self.maximum_candidate_draws_per_output,
            )?)
        } else {
            None
        };
        let output_count_u32 =
            u32::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let mut stream = self.transcript.begin_distinct_query_challenge(
            challenge_tag,
            upper_bound_u64,
            output_count_u32,
            self.maximum_candidate_draws_per_output,
        )?;
        let accepted_indices = sample_distinct_query_positions_from_transcript_blocks(&mut stream)?
            .into_iter()
            .map(|index| {
                usize::try_from(index).map_err(|_| TranscriptError::ChallengeCounterOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        self.hash_query_counter
            .begin_challenge(distinct_query_challenge_hash_count(
                output_count_u32,
                self.maximum_candidate_draws_per_output,
            )?)?;
        #[cfg(test)]
        self.record_public_sampler_row(observed_sampler_row)?;
        self.consume_catalog_operation()?;
        Ok(accepted_indices)
    }

    pub(crate) fn observe_commitment(
        &mut self,
        canonical_commitment_bytes: &[u8],
    ) -> Result<(), TranscriptError> {
        if canonical_commitment_bytes.len() != Hash512::BYTE_LENGTH {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        let round = match self.next_catalog_operation()? {
            Some(RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::Aggregate,
            }) if self.progress == RowCodeWhirProgress::BeforeAggregateSourceCommitment => {
                RowCodeWhirRound::AggregateCommitment
            }
            Some(RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::AggregateWidePad,
            }) if self.progress == RowCodeWhirProgress::AfterAggregateSourceCommitment => {
                RowCodeWhirRound::AggregateWidePadCommitment
            }
            Some(RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::WhirRound { round_ordinal },
            }) if matches!(
                self.progress,
                RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
            ) && round_ordinal == self.next_whir_commitment_ordinal =>
            {
                RowCodeWhirRound::WhirCommitment {
                    commitment_ordinal: round_ordinal,
                }
            }
            Some(RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::BaseFreshSource,
            }) if self.progress == RowCodeWhirProgress::Whir => {
                RowCodeWhirRound::BaseFreshSourceCommitment
            }
            Some(RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::BaseFreshPad,
            }) if self.progress == RowCodeWhirProgress::Whir => {
                RowCodeWhirRound::BaseFreshPadCommitment
            }
            Some(_) => return Err(TranscriptError::UnexpectedRowCodeWhirRound),
            None => match self.progress {
                RowCodeWhirProgress::BeforeAggregateSourceCommitment => {
                    RowCodeWhirRound::AggregateCommitment
                }
                RowCodeWhirProgress::AfterAggregateSourceCommitment => {
                    RowCodeWhirRound::AggregateWidePadCommitment
                }
                RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir => {
                    RowCodeWhirRound::WhirCommitment {
                        commitment_ordinal: self.next_whir_commitment_ordinal,
                    }
                }
                _ => return Err(TranscriptError::UnexpectedRowCodeWhirRound),
            },
        };
        self.transcript
            .absorb_typed_round(round.tag(), true, canonical_commitment_bytes)?;
        self.hash_query_counter.absorb_response(false)?;
        self.consume_catalog_operation()?;
        match round {
            RowCodeWhirRound::AggregateCommitment => {
                self.progress = RowCodeWhirProgress::AfterAggregateSourceCommitment;
            }
            RowCodeWhirRound::AggregateWidePadCommitment => {
                self.progress = RowCodeWhirProgress::AfterAggregatePadCommitment;
            }
            RowCodeWhirRound::WhirCommitment { commitment_ordinal } => {
                self.next_whir_commitment_ordinal = commitment_ordinal
                    .checked_add(1)
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?;
                self.progress = RowCodeWhirProgress::Whir;
            }
            RowCodeWhirRound::BaseFreshSourceCommitment
            | RowCodeWhirRound::BaseFreshPadCommitment => {
                self.progress = RowCodeWhirProgress::Whir;
            }
            _ => return Err(TranscriptError::UnexpectedRowCodeWhirRound),
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn observe_whir_values(
        &mut self,
        role: RowCodeWhirObservationRole,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        self.observe_whir_values_with_role(Some(role), values)
    }

    #[cfg(test)]
    pub(crate) fn observe_whir_values_without_role_for_test(
        &mut self,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        self.observe_whir_values_with_role(None, values)
    }

    fn observe_whir_values_with_role(
        &mut self,
        role: Option<RowCodeWhirObservationRole>,
        values: &[ProofChallengeExtensionElement],
    ) -> Result<(), TranscriptError> {
        if values.is_empty() {
            return Ok(());
        }
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
        ) {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        if self.next_live_whir_observation_role()? != role && self.live_role_schedule.is_some() {
            return Err(TranscriptError::UnexpectedRowCodeWhirRound);
        }
        let observation_ordinal = match self.next_catalog_operation()? {
            Some(RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                observation_ordinal,
                role: catalog_role,
                value_count,
            }) if value_count == values.len()
                && Some(catalog_role) == role
                && observation_ordinal == self.next_whir_observation_ordinal =>
            {
                observation_ordinal
            }
            Some(_) => return Err(TranscriptError::UnexpectedRowCodeWhirRound),
            None => self.next_whir_observation_ordinal,
        };
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
        self.hash_query_counter.absorb_response(true)?;
        self.consume_catalog_operation()?;
        self.progress = RowCodeWhirProgress::Whir;
        Ok(())
    }

    pub(in crate::bgv::proof_suite) fn sample_whir_extension(
        &mut self,
        role: RowCodeWhirExtensionRole,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        self.sample_whir_extension_with_role(Some(role))
    }

    #[cfg(test)]
    pub(crate) fn sample_whir_extension_without_role_for_test(
        &mut self,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        self.sample_whir_extension_with_role(None)
    }

    fn sample_whir_extension_with_role(
        &mut self,
        role: Option<RowCodeWhirExtensionRole>,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
        ) {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        if self.next_live_whir_extension_role()? != role && self.live_role_schedule.is_some() {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let challenge_ordinal = match self.next_catalog_operation()? {
            Some(RowCodeWhirTranscriptOperation::SampleExtension {
                role: catalog_role,
                whir_challenge_ordinal: Some(challenge_ordinal),
            }) if Some(catalog_role) == role
                && !matches!(catalog_role, RowCodeWhirExtensionRole::Direct(_))
                && challenge_ordinal == self.next_whir_challenge_ordinal =>
            {
                challenge_ordinal
            }
            Some(_) => return Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
            None => self.next_whir_challenge_ordinal,
        };
        self.next_whir_challenge_ordinal = challenge_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        self.progress = RowCodeWhirProgress::Whir;
        let sampled = self.sample_extension_with_tag(format!(
            "row-code-whir/whir-challenge/{challenge_ordinal:08x}"
        ))?;
        self.consume_catalog_operation()?;
        Ok(sampled)
    }

    pub(crate) fn sample_whir_bits(&mut self, bits: usize) -> Result<usize, TranscriptError> {
        if self.transcript_operations.is_some() {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        if !matches!(
            self.progress,
            RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
        ) || bits >= usize::BITS as usize
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let challenge_ordinal = self.next_whir_bit_challenge_ordinal;
        self.next_whir_bit_challenge_ordinal = challenge_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        let tag = format!("row-code-whir/whir-bits/{challenge_ordinal:08x}/{bits:04x}");
        let stream = self.transcript.begin_typed_challenge(tag)?;
        let bytes: [u8; std::mem::size_of::<u64>()] = stream.current_candidate_seed
            [..std::mem::size_of::<u64>()]
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
            RowCodeWhirProgress::AfterAggregatePadCommitment | RowCodeWhirProgress::Whir
        ) || bits >= usize::BITS as usize
            || output_count == 0
            || output_count > (1_usize << bits)
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let query_domain_cardinality = 1_usize
            .checked_shl(
                u32::try_from(bits).map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
            )
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        if let Some(operation) = self.next_catalog_operation()?
            && operation
                != (RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    role: RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal },
                    upper_bound: query_domain_cardinality,
                    output_count,
                })
        {
            return Err(TranscriptError::UnexpectedRowCodeWhirChallenge);
        }
        let output_count_u64 =
            u64::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let tag = format!(
            "row-code-whir/whir-query-vector/{epoch_ordinal:08x}/{bits:04x}/{output_count_u64:016x}"
        );
        #[cfg(test)]
        let observed_sampler_row = if self.observed_public_sampler_rows.is_some() {
            Some(ObservedPublicSamplerRow::distinct(
                tag.clone(),
                1_usize
                    .checked_shl(
                        u32::try_from(bits)
                            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?,
                    )
                    .ok_or(TranscriptError::ChallengeCounterOverflow)?,
                output_count,
                self.maximum_candidate_draws_per_output,
            )?)
        } else {
            None
        };
        let query_domain_cardinality = u64::try_from(query_domain_cardinality)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let output_count_u32 =
            u32::try_from(output_count).map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        let mut stream = self.transcript.begin_distinct_query_challenge(
            tag,
            query_domain_cardinality,
            output_count_u32,
            self.maximum_candidate_draws_per_output,
        )?;
        let accepted_indices = sample_distinct_query_positions_from_transcript_blocks(&mut stream)?
            .into_iter()
            .map(|index| {
                usize::try_from(index).map_err(|_| TranscriptError::ChallengeCounterOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        self.hash_query_counter
            .begin_challenge(distinct_query_challenge_hash_count(
                output_count_u32,
                self.maximum_candidate_draws_per_output,
            )?)?;
        #[cfg(test)]
        self.record_public_sampler_row(observed_sampler_row)?;
        self.consume_catalog_operation()?;
        self.progress = RowCodeWhirProgress::Whir;
        Ok(accepted_indices)
    }

    pub(crate) fn begin_final_proof_stream(
        mut self,
        canonical_proof_byte_length: usize,
    ) -> Result<RowCodeWhirProofStreamAbsorber, TranscriptError> {
        self.validate_catalog_cursor_position()?;
        if self.progress != RowCodeWhirProgress::Whir
            || canonical_proof_byte_length == 0
            || self.live_role_schedule.as_ref().is_some_and(|schedule| {
                !schedule.is_consumed(
                    self.next_whir_observation_ordinal,
                    self.next_whir_challenge_ordinal,
                )
            })
            || matches!(
                self.next_catalog_operation()?,
                Some(operation) if operation != RowCodeWhirTranscriptOperation::FinishProofStream
            )
        {
            return Err(TranscriptError::IncompleteRowCodeWhirTranscript);
        }
        let round_message_absorber = self.transcript.begin_streamed_typed_round(
            RowCodeWhirRound::FinalProofOpenings.tag(),
            false,
            canonical_proof_byte_length,
        )?;
        Ok(RowCodeWhirProofStreamAbsorber {
            transcript: self,
            round_message_absorber,
        })
    }

    #[cfg(test)]
    pub(crate) fn finish(
        self,
        canonical_proof_bytes: &[u8],
    ) -> Result<RowCodeWhirTranscriptSummary, TranscriptError> {
        let mut absorber = self.begin_final_proof_stream(canonical_proof_bytes.len())?;
        absorber.absorb(canonical_proof_bytes)?;
        absorber.finish()
    }

    fn sample_extension_with_tag(
        &mut self,
        challenge_tag: String,
    ) -> Result<ProofChallengeExtensionElement, TranscriptError> {
        #[cfg(test)]
        let observed_sampler_row = if self.observed_public_sampler_rows.is_some() {
            Some(ObservedPublicSamplerRow::extension(
                challenge_tag.clone(),
                PublicSamplerKind::Extension,
                self.maximum_candidate_draws_per_output,
                None,
            )?)
        } else {
            None
        };
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
                #[cfg(test)]
                self.record_public_sampler_row(observed_sampler_row)?;
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
    expansion_accumulator: Option<ChallengeExpansionAccumulator>,
}

impl CommonChallengeStream {
    fn new(challenge_seed: [u8; 64], challenge_tag: String) -> Self {
        Self {
            current_candidate_seed: challenge_seed,
            challenge_tag,
            next_draw_ordinal: Some(1),
            expansion_accumulator: None,
        }
    }

    fn new_product(
        chain_handle: [u8; 64],
        challenge_tag: String,
        group: CommonProofApplicationChallengeGroup,
        maximum_candidate_draws: u32,
        block_count_per_candidate: u64,
    ) -> Self {
        Self {
            current_candidate_seed: chain_handle,
            challenge_tag,
            next_draw_ordinal: None,
            expansion_accumulator: Some(ChallengeExpansionAccumulator::new_product(
                group,
                maximum_candidate_draws,
                block_count_per_candidate,
            )),
        }
    }

    fn new_distinct(
        chain_handle: [u8; 64],
        challenge_tag: String,
        query_domain_cardinality: u64,
        output_count: u32,
        maximum_candidate_draws_per_output: u32,
        maximum_block_count_per_output: u64,
    ) -> Self {
        Self {
            current_candidate_seed: chain_handle,
            challenge_tag,
            next_draw_ordinal: None,
            expansion_accumulator: Some(ChallengeExpansionAccumulator::new_distinct(
                query_domain_cardinality,
                output_count,
                maximum_candidate_draws_per_output,
                maximum_block_count_per_output,
            )),
        }
    }

    fn into_accepted_terminal_seed(self) -> Result<([u8; 64], String), TranscriptError> {
        let terminal_seed = match self.expansion_accumulator {
            Some(accumulator) => {
                accumulator.ensure_complete()?;
                self.current_candidate_seed
            }
            None => self.current_candidate_seed,
        };
        Ok((terminal_seed, self.challenge_tag))
    }

    fn derive_product_residue_candidate(
        &mut self,
        candidate_ordinal: u64,
        candidate_byte_length: usize,
    ) -> Result<Vec<u8>, TranscriptError> {
        let (group, _) = self
            .expansion_accumulator
            .as_ref()
            .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
            .product_sampling_geometry()?;
        let bound_candidate_byte_length = usize::try_from(group.candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        if candidate_byte_length == 0
            || candidate_byte_length != bound_candidate_byte_length
            || !candidate_byte_length.is_multiple_of(FIXED_CHALLENGE_BLOCK_BYTE_LENGTH)
        {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        let block_count = candidate_byte_length / FIXED_CHALLENGE_BLOCK_BYTE_LENGTH;
        let mut candidate_bytes = Vec::new();
        candidate_bytes
            .try_reserve_exact(candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        for block_index in 0..block_count {
            let block_ordinal = u64::try_from(block_index)
                .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
            let block = self
                .expansion_accumulator
                .as_mut()
                .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
                .derive_product_block(
                    self.current_candidate_seed,
                    candidate_ordinal,
                    block_ordinal,
                )?;
            self.current_candidate_seed = block;
            candidate_bytes.extend_from_slice(&block);
        }
        Ok(candidate_bytes)
    }

    fn derive_distinct_query_block(
        &mut self,
        output_ordinal: u32,
        block_ordinal: u64,
    ) -> Result<[u8; 64], TranscriptError> {
        let block = self
            .expansion_accumulator
            .as_mut()
            .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
            .derive_distinct_block(self.current_candidate_seed, output_ordinal, block_ordinal)?;
        self.current_candidate_seed = block;
        Ok(block)
    }

    fn finish_distinct_output(&mut self, output_ordinal: u32) -> Result<(), TranscriptError> {
        self.expansion_accumulator
            .as_mut()
            .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
            .finish_distinct_output(output_ordinal)
    }

    /// Samples one uniform vector from `Z_modulus^coordinate_count` as one
    /// verifier message. Every bounded candidate is assembled from directly
    /// addressed 512-bit blocks under the fixed transcript chain handle.
    /// Rejection occurs against the complete product cardinality before the
    /// accepted residue is decoded into base-`modulus` coordinates.
    fn sample_residue_vector(&mut self) -> Result<Vec<u64>, TranscriptError> {
        let (group, maximum_candidate_draws) = self
            .expansion_accumulator
            .as_ref()
            .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
            .product_sampling_geometry()?;
        if group.modulus <= 1 || group.coordinate_count == 0 || maximum_candidate_draws == 0 {
            return Err(TranscriptError::InvalidChallengeModulus);
        }
        let candidate_byte_length = usize::try_from(group.candidate_byte_length)
            .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
        for candidate_ordinal in 0..maximum_candidate_draws {
            let candidate_bytes = self.derive_product_residue_candidate(
                u64::from(candidate_ordinal),
                candidate_byte_length,
            )?;
            if let Some(coordinates) = decode_product_residue_candidate(&candidate_bytes, group)? {
                self.expansion_accumulator
                    .as_mut()
                    .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
                    .finish_product_candidate(u64::from(candidate_ordinal), true)?;
                return Ok(coordinates);
            }
            self.expansion_accumulator
                .as_mut()
                .ok_or(TranscriptError::UnexpectedCommonProofChallenge)?
                .finish_product_candidate(u64::from(candidate_ordinal), false)?;
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
            TRANSCRIPT_CHALLENGE_HANDLE_DOMAIN,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChallengeExpansionAccumulator {
    progress: ChallengeExpansionProgress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChallengeExpansionProgress {
    Product {
        group: CommonProofApplicationChallengeGroup,
        maximum_candidate_draws: u32,
        block_count_per_candidate: u64,
        current_candidate_ordinal: u64,
        next_block_ordinal: u64,
        awaiting_candidate_outcome: bool,
        accepted: bool,
    },
    Distinct {
        query_domain_cardinality: u64,
        output_count: u32,
        maximum_candidate_draws_per_output: u32,
        maximum_block_count_per_output: u64,
        current_output_ordinal: u32,
        next_block_ordinal: u64,
        current_output_has_block: bool,
        complete: bool,
    },
}

impl ChallengeExpansionAccumulator {
    fn new_product(
        group: CommonProofApplicationChallengeGroup,
        maximum_candidate_draws: u32,
        block_count_per_candidate: u64,
    ) -> Self {
        Self {
            progress: ChallengeExpansionProgress::Product {
                group,
                maximum_candidate_draws,
                block_count_per_candidate,
                current_candidate_ordinal: 0,
                next_block_ordinal: 0,
                awaiting_candidate_outcome: false,
                accepted: false,
            },
        }
    }

    fn new_distinct(
        query_domain_cardinality: u64,
        output_count: u32,
        maximum_candidate_draws_per_output: u32,
        maximum_block_count_per_output: u64,
    ) -> Self {
        Self {
            progress: ChallengeExpansionProgress::Distinct {
                query_domain_cardinality,
                output_count,
                maximum_candidate_draws_per_output,
                maximum_block_count_per_output,
                current_output_ordinal: 0,
                next_block_ordinal: 0,
                current_output_has_block: false,
                complete: false,
            },
        }
    }

    fn product_sampling_geometry(
        &self,
    ) -> Result<(CommonProofApplicationChallengeGroup, u32), TranscriptError> {
        match &self.progress {
            ChallengeExpansionProgress::Product {
                group,
                maximum_candidate_draws,
                ..
            } => Ok((*group, *maximum_candidate_draws)),
            ChallengeExpansionProgress::Distinct { .. } => {
                Err(TranscriptError::UnexpectedCommonProofChallenge)
            }
        }
    }

    fn distinct_sampling_geometry(&self) -> Result<(u64, u32, u32), TranscriptError> {
        match &self.progress {
            ChallengeExpansionProgress::Distinct {
                query_domain_cardinality,
                output_count,
                maximum_candidate_draws_per_output,
                ..
            } => Ok((
                *query_domain_cardinality,
                *output_count,
                *maximum_candidate_draws_per_output,
            )),
            ChallengeExpansionProgress::Product { .. } => {
                Err(TranscriptError::UnexpectedCommonProofChallenge)
            }
        }
    }

    fn derive_product_block(
        &mut self,
        previous_chain_state: [u8; 64],
        candidate_ordinal: u64,
        block_ordinal: u64,
    ) -> Result<[u8; 64], TranscriptError> {
        let ChallengeExpansionProgress::Product {
            maximum_candidate_draws,
            block_count_per_candidate,
            current_candidate_ordinal,
            next_block_ordinal,
            awaiting_candidate_outcome,
            accepted,
            ..
        } = &mut self.progress
        else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if *accepted
            || *awaiting_candidate_outcome
            || candidate_ordinal >= u64::from(*maximum_candidate_draws)
            || *block_count_per_candidate == 0
            || candidate_ordinal != *current_candidate_ordinal
            || block_ordinal != *next_block_ordinal
            || block_ordinal >= *block_count_per_candidate
        {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let block = product_residue_candidate_block(
            previous_chain_state,
            candidate_ordinal,
            block_ordinal,
        )?;
        *next_block_ordinal = next_block_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        if *next_block_ordinal == *block_count_per_candidate {
            *awaiting_candidate_outcome = true;
        }
        Ok(block)
    }

    fn finish_product_candidate(
        &mut self,
        candidate_ordinal: u64,
        accepted_candidate: bool,
    ) -> Result<(), TranscriptError> {
        let ChallengeExpansionProgress::Product {
            current_candidate_ordinal,
            next_block_ordinal,
            awaiting_candidate_outcome,
            accepted,
            ..
        } = &mut self.progress
        else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if *accepted
            || !*awaiting_candidate_outcome
            || candidate_ordinal != *current_candidate_ordinal
        {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        if accepted_candidate {
            *accepted = true;
        } else {
            *current_candidate_ordinal = current_candidate_ordinal
                .checked_add(1)
                .ok_or(TranscriptError::ChallengeCounterOverflow)?;
            *next_block_ordinal = 0;
            *awaiting_candidate_outcome = false;
        }
        Ok(())
    }

    fn derive_distinct_block(
        &mut self,
        previous_chain_state: [u8; 64],
        output_ordinal: u32,
        block_ordinal: u64,
    ) -> Result<[u8; 64], TranscriptError> {
        let ChallengeExpansionProgress::Distinct {
            maximum_block_count_per_output,
            current_output_ordinal,
            next_block_ordinal,
            current_output_has_block,
            complete,
            ..
        } = &mut self.progress
        else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if *complete
            || *maximum_block_count_per_output == 0
            || output_ordinal != *current_output_ordinal
            || block_ordinal != *next_block_ordinal
            || block_ordinal >= *maximum_block_count_per_output
        {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        let block = transcript_hash(
            TRANSCRIPT_CHALLENGE_EXPANSION_ACCUMULATOR_DOMAIN,
            distinct_query_block_input(
                previous_chain_state,
                u64::from(output_ordinal),
                block_ordinal,
            )?,
        )?;
        *next_block_ordinal = next_block_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        *current_output_has_block = true;
        Ok(block)
    }

    fn finish_distinct_output(&mut self, output_ordinal: u32) -> Result<(), TranscriptError> {
        let ChallengeExpansionProgress::Distinct {
            output_count,
            current_output_ordinal,
            next_block_ordinal,
            current_output_has_block,
            complete,
            ..
        } = &mut self.progress
        else {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        };
        if *complete || !*current_output_has_block || output_ordinal != *current_output_ordinal {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        *current_output_ordinal = current_output_ordinal
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        *next_block_ordinal = 0;
        *current_output_has_block = false;
        *complete = *current_output_ordinal == *output_count;
        Ok(())
    }

    fn ensure_complete(self) -> Result<(), TranscriptError> {
        let complete = match self.progress {
            ChallengeExpansionProgress::Product { accepted, .. } => accepted,
            ChallengeExpansionProgress::Distinct { complete, .. } => complete,
        };
        if !complete {
            return Err(TranscriptError::UnexpectedCommonProofChallenge);
        }
        Ok(())
    }
}

fn challenge_expansion_block_input(
    previous_chain_state: [u8; 64],
    sampler_type: &str,
    candidate_or_output_ordinal: u64,
    block_ordinal: u64,
) -> Result<Vec<CanonicalItem>, TranscriptError> {
    Ok(vec![
        CanonicalItem::hash512(previous_chain_state),
        CanonicalItem::nonempty_ascii(sampler_type)
            .map_err(|_| TranscriptError::CanonicalEncoding)?,
        CanonicalItem::unsigned64(candidate_or_output_ordinal),
        CanonicalItem::unsigned64(block_ordinal),
    ])
}

fn decode_product_residue_candidate(
    candidate_bytes: &[u8],
    group: CommonProofApplicationChallengeGroup,
) -> Result<Option<Vec<u64>>, TranscriptError> {
    let candidate_byte_length = usize::try_from(group.candidate_byte_length)
        .map_err(|_| TranscriptError::ChallengeCounterOverflow)?;
    if candidate_bytes.len() != candidate_byte_length {
        return Err(TranscriptError::InvalidChallengeModulus);
    }
    let modulus_big = BigUint::from(group.modulus);
    let product_cardinality = modulus_big.pow(u32::from(group.coordinate_count));
    let candidate_bit_length = candidate_byte_length
        .checked_mul(8)
        .ok_or(TranscriptError::ChallengeCounterOverflow)?;
    let sample_space = BigUint::one() << candidate_bit_length;
    let acceptance_limit = (&sample_space / &product_cardinality) * &product_cardinality;
    let candidate = BigUint::from_bytes_le(candidate_bytes);
    if candidate >= acceptance_limit {
        return Ok(None);
    }
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
    Ok(Some(coordinates))
}

#[cfg(test)]
mod row_code_whir_transcript_tests {
    use std::collections::BTreeSet;

    use crate::bgv::proof_suite::field::ProofChallengeExtensionElement;
    use crate::bgv::proof_suite::row_code_whir::construction_plan::{
        RowCodeWhirCommitmentRole, RowCodeWhirConstructionPlan, RowCodeWhirExtensionRole,
        RowCodeWhirObservationRole, RowCodeWhirQueryRole, RowCodeWhirTranscriptOperation,
    };
    use crate::bgv::proof_suite::{
        ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
        selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
    };
    use crate::foundation::{Hash512, ProofApplicationSlotCeilings};

    use super::{
        CanonicalProofTranscript, CommonProofTranscript, RowCodeWhirChallenge,
        RowCodeWhirLiveRoleSchedule, RowCodeWhirProgress, RowCodeWhirTranscript,
        RowCodeWhirTranscriptCheckpointCursor, TranscriptError,
        expected_row_code_whir_cursor_position,
    };

    fn transcript_before_aggregate_commitment(statement: &[u8]) -> RowCodeWhirTranscript {
        let mut transcript = RowCodeWhirTranscript::new_for_test(statement)
            .expect("the fixed test statement is canonical");
        transcript
            .absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE])
            .expect("the nonempty protocol schedule is accepted in its typed phase");
        transcript
    }

    fn transcript_after_aggregate_pad_commitment(statement: &[u8]) -> RowCodeWhirTranscript {
        let mut transcript = transcript_before_aggregate_commitment(statement);
        transcript
            .observe_commitment(&[0x5a; Hash512::BYTE_LENGTH])
            .expect("the fixed-width aggregate-source commitment advances the transcript");
        transcript
            .observe_commitment(&[0x6a; Hash512::BYTE_LENGTH])
            .expect("the fixed-width aggregate-pad commitment advances the transcript");
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

    fn selected_same_secret_construction_plan() -> RowCodeWhirConstructionPlan {
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected same-secret relation context derives");
        let compiled_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &context,
        )
        .expect("the selected same-secret relation plan compiles");
        let artifact =
            ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled_plan, &context)
                .expect("the selected same-secret relation plan validates");
        RowCodeWhirConstructionPlan::for_selected_variant(&artifact, None, None)
            .expect("the selected same-secret construction plan derives")
    }

    fn plan_bound_test_transcript(
        construction_plan: &RowCodeWhirConstructionPlan,
    ) -> RowCodeWhirTranscript {
        let construction_plan_identity_hash = construction_plan
            .canonical_identity_hash()
            .expect("the test construction identity derives");
        let operations = construction_plan.transcript_operations().to_vec();
        let catalog_counter_origin = construction_plan
            .relation_prefix_schedule()
            .row_code_whir_catalog_counter_origin()
            .expect("the test transcript counter origin derives");
        RowCodeWhirTranscript {
            transcript: CanonicalProofTranscript::try_new_row_code_whir(
                1,
                [0x41; Hash512::BYTE_LENGTH],
                construction_plan_identity_hash,
                construction_plan.application_statement_schema_identifier(),
                b"plan-bound transcript cursor",
            )
            .expect("the plan-bound test header is canonical"),
            hash_query_counter: catalog_counter_origin.clone(),
            catalog_counter_origin: Some(catalog_counter_origin),
            maximum_candidate_draws_per_output: construction_plan
                .relation_prefix_schedule()
                .maximum_candidate_draws_per_output(),
            transcript_operations: Some(operations.clone()),
            live_role_schedule: Some(
                RowCodeWhirLiveRoleSchedule::for_construction_plan(construction_plan)
                    .expect("the plan-bound live role schedule derives"),
            ),
            next_transcript_operation_index: 0,
            progress: if matches!(
                operations.first(),
                Some(RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { .. })
            ) {
                RowCodeWhirProgress::AwaitingMaskEvaluations
            } else {
                RowCodeWhirProgress::AwaitingProtocolSchedule
            },
            next_whir_commitment_ordinal: 0,
            next_whir_observation_ordinal: 0,
            next_whir_challenge_ordinal: 0,
            next_whir_bit_challenge_ordinal: 0,
            observed_public_sampler_rows: None,
        }
    }

    fn consume_nonterminal_catalog_operation(
        transcript: &mut RowCodeWhirTranscript,
        operation: &RowCodeWhirTranscriptOperation,
    ) -> Result<(), TranscriptError> {
        match operation {
            RowCodeWhirTranscriptOperation::ObserveMaskEvaluations { value_count } => transcript
                .absorb_opening_batch_mask_evaluations(&vec![
                    ProofChallengeExtensionElement::ONE;
                    *value_count
                ]),
            RowCodeWhirTranscriptOperation::ObserveProtocolSchedule { canonical_values } => {
                transcript.absorb_protocol_schedule(canonical_values)
            }
            RowCodeWhirTranscriptOperation::SampleExtension {
                role: RowCodeWhirExtensionRole::Direct(challenge),
                ..
            } => transcript.sample_direct_extension(*challenge).map(drop),
            RowCodeWhirTranscriptOperation::SampleExtension { role, .. } => {
                transcript.sample_whir_extension(*role).map(drop)
            }
            RowCodeWhirTranscriptOperation::ObserveCommitment { .. } => {
                transcript.observe_commitment(&[0x71; Hash512::BYTE_LENGTH])
            }
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role: RowCodeWhirQueryRole::Outer,
                upper_bound,
                output_count,
            } => transcript
                .sample_direct_distinct_indices(
                    RowCodeWhirChallenge::OuterQueryVector,
                    *upper_bound,
                    *output_count,
                )
                .map(drop),
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role: RowCodeWhirQueryRole::Bound,
                upper_bound,
                output_count,
            } => transcript
                .sample_direct_distinct_indices(
                    RowCodeWhirChallenge::BoundQueryVector,
                    *upper_bound,
                    *output_count,
                )
                .map(drop),
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role: RowCodeWhirQueryRole::WhirEpoch { epoch_ordinal },
                upper_bound,
                output_count,
            } => transcript
                .sample_whir_query_vector(
                    (*upper_bound).ilog2() as usize,
                    *epoch_ordinal,
                    *output_count,
                )
                .map(drop),
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                role, value_count, ..
            } => transcript.observe_whir_values(
                *role,
                &vec![ProofChallengeExtensionElement::ONE; *value_count],
            ),
            RowCodeWhirTranscriptOperation::FinishProofStream => {
                Err(TranscriptError::IncompleteRowCodeWhirTranscript)
            }
        }
    }

    fn assert_catalog_operation_rejected(
        mut transcript: RowCodeWhirTranscript,
        operation: &RowCodeWhirTranscriptOperation,
    ) {
        let next_operation_index = transcript.next_transcript_operation_index;
        let result = match operation {
            RowCodeWhirTranscriptOperation::FinishProofStream => {
                transcript.clone().begin_final_proof_stream(1).map(|_| ())
            }
            _ => consume_nonterminal_catalog_operation(&mut transcript, operation),
        };
        assert!(
            result.is_err(),
            "an out-of-order catalog operation was accepted"
        );
        assert_eq!(
            transcript.next_transcript_operation_index, next_operation_index,
            "a refused catalog operation advanced the single-use cursor",
        );
    }

    fn catalog_operations_have_distinguishable_call_shapes(
        expected: &RowCodeWhirTranscriptOperation,
        probe: &RowCodeWhirTranscriptOperation,
    ) -> bool {
        !matches!(
            (expected, probe),
            (
                RowCodeWhirTranscriptOperation::ObserveCommitment { .. },
                RowCodeWhirTranscriptOperation::ObserveCommitment { .. }
            )
        )
    }

    #[test]
    fn selected_construction_catalog_is_consumed_once_in_exact_order() {
        let construction_plan = selected_same_secret_construction_plan();
        let operations = construction_plan.transcript_operations().to_vec();
        let expected_terminal = expected_row_code_whir_cursor_position(
            &operations,
            operations.len(),
            construction_plan
                .relation_prefix_schedule()
                .maximum_candidate_draws_per_output(),
            construction_plan
                .relation_prefix_schedule()
                .row_code_whir_catalog_counter_origin()
                .expect("the terminal counter origin derives"),
        )
        .expect("the terminal catalog counters derive exactly");
        let mut transcript = plan_bound_test_transcript(&construction_plan);

        for (operation_index, operation) in operations.iter().enumerate() {
            if operation_index > 0
                && catalog_operations_have_distinguishable_call_shapes(
                    operation,
                    &operations[operation_index - 1],
                )
            {
                assert_catalog_operation_rejected(
                    transcript.clone(),
                    &operations[operation_index - 1],
                );
            }
            if operation_index + 1 < operations.len()
                && catalog_operations_have_distinguishable_call_shapes(
                    operation,
                    &operations[operation_index + 1],
                )
            {
                assert_catalog_operation_rejected(
                    transcript.clone(),
                    &operations[operation_index + 1],
                );
            }
            if matches!(operation, RowCodeWhirTranscriptOperation::FinishProofStream) {
                let mut absorber = transcript
                    .begin_final_proof_stream(5)
                    .expect("the proof stream starts only at the terminal catalog entry");
                absorber
                    .absorb(b"proof")
                    .expect("the terminal proof bytes bind");
                let summary = absorber
                    .finish()
                    .expect("the exact selected catalog is exhausted once");
                assert_eq!(
                    summary.maximum_hash_query_count(),
                    expected_terminal.hash_query_count,
                );
                assert_eq!(
                    summary.logical_verifier_message_count(),
                    expected_terminal.logical_verifier_message_count,
                );
                return;
            }
            consume_nonterminal_catalog_operation(&mut transcript, operation)
                .expect("the next exact selected catalog entry is accepted");
            assert_eq!(
                transcript.next_transcript_operation_index,
                operation_index + 1,
                "one accepted catalog entry advances exactly one cursor position",
            );
            if !matches!(
                operations.get(operation_index + 1),
                Some(RowCodeWhirTranscriptOperation::FinishProofStream)
            ) {
                assert!(
                    matches!(
                        transcript.clone().begin_final_proof_stream(1),
                        Err(TranscriptError::IncompleteRowCodeWhirTranscript)
                    ),
                    "the transcript cannot finish before the terminal catalog boundary"
                );
            }
        }
        panic!("the selected construction catalog has no terminal proof entry");
    }

    #[test]
    fn plan_bound_checkpoint_cursor_roundtrips_and_rejects_mismatched_state() {
        let construction_plan = selected_same_secret_construction_plan();
        let operations = construction_plan.transcript_operations();
        let first_challenge_operation_index = operations
            .iter()
            .position(|operation| {
                matches!(
                    operation,
                    RowCodeWhirTranscriptOperation::SampleExtension { .. }
                        | RowCodeWhirTranscriptOperation::SampleDistinctIndices { .. }
                )
            })
            .expect("the selected catalog contains a verifier challenge");
        let mut original = plan_bound_test_transcript(&construction_plan);
        for operation in &operations[..=first_challenge_operation_index] {
            consume_nonterminal_catalog_operation(&mut original, operation)
                .expect("the catalog prefix is consumed exactly once");
        }
        let cursor = original
            .checkpoint_cursor(&construction_plan)
            .expect("the plan-bound transcript cursor encodes");
        let parsed =
            RowCodeWhirTranscriptCheckpointCursor::from_canonical_bytes(cursor.canonical_bytes())
                .expect("the canonical transcript cursor decodes");
        assert_eq!(parsed.canonical_bytes(), cursor.canonical_bytes());
        assert_eq!(parsed.digest(), cursor.digest());

        let mut restored =
            RowCodeWhirTranscript::restore_checkpoint_cursor(&construction_plan, &parsed)
                .expect("the exact plan restores its transcript cursor");
        assert_eq!(
            restored
                .checkpoint_cursor(&construction_plan)
                .expect("the restored cursor re-encodes")
                .canonical_bytes(),
            cursor.canonical_bytes(),
            "restore must preserve the exact authenticated cursor bytes",
        );
        let next_operation = operations
            .get(first_challenge_operation_index + 1)
            .expect("the selected challenge has a successor operation");
        consume_nonterminal_catalog_operation(&mut original, next_operation)
            .expect("the original transcript consumes the successor operation");
        consume_nonterminal_catalog_operation(&mut restored, next_operation)
            .expect("the restored transcript consumes the same successor operation");
        assert_eq!(
            restored
                .checkpoint_cursor(&construction_plan)
                .expect("the advanced restored cursor encodes")
                .canonical_bytes(),
            original
                .checkpoint_cursor(&construction_plan)
                .expect("the advanced original cursor encodes")
                .canonical_bytes(),
            "the restored transcript must derive byte-identical downstream state",
        );

        let mut corrupted = cursor.canonical_bytes().to_vec();
        corrupted[32] ^= 1;
        assert_eq!(
            RowCodeWhirTranscriptCheckpointCursor::from_canonical_bytes(&corrupted),
            Err(TranscriptError::CanonicalEncoding),
        );
        let mut trailing = cursor.canonical_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            RowCodeWhirTranscriptCheckpointCursor::from_canonical_bytes(&trailing),
            Err(TranscriptError::CanonicalEncoding),
        );

        let rejects_snapshot = |snapshot| {
            let changed_cursor = RowCodeWhirTranscriptCheckpointCursor::from_snapshot(snapshot)
                .expect("the hostile cursor state has a canonical encoding");
            assert!(matches!(
                RowCodeWhirTranscript::restore_checkpoint_cursor(
                    &construction_plan,
                    &changed_cursor,
                ),
                Err(TranscriptError::InvalidCommonProofSchedule)
            ));
        };

        let mut wrong_identity = cursor.snapshot.clone();
        wrong_identity.construction_plan_identity_hash[0] ^= 1;
        rejects_snapshot(wrong_identity);
        let mut wrong_operation_index = cursor.snapshot.clone();
        wrong_operation_index.next_transcript_operation_index += 1;
        rejects_snapshot(wrong_operation_index);
        let mut excessive_hash_query_count = cursor.snapshot.clone();
        excessive_hash_query_count.hash_query_count += 1;
        rejects_snapshot(excessive_hash_query_count);
        let mut deficient_hash_query_count = cursor.snapshot.clone();
        deficient_hash_query_count.hash_query_count -= 1;
        rejects_snapshot(deficient_hash_query_count);
        let mut excessive_logical_message_count = cursor.snapshot.clone();
        excessive_logical_message_count.logical_verifier_message_count += 1;
        rejects_snapshot(excessive_logical_message_count);
        let mut deficient_logical_message_count = cursor.snapshot.clone();
        deficient_logical_message_count.logical_verifier_message_count -= 1;
        rejects_snapshot(deficient_logical_message_count);
        let mut wrong_progress = cursor.snapshot.clone();
        wrong_progress.progress = RowCodeWhirProgress::Complete;
        rejects_snapshot(wrong_progress);
        let mut wrong_observation_ordinal = cursor.snapshot.clone();
        wrong_observation_ordinal.next_whir_observation_ordinal += 1;
        rejects_snapshot(wrong_observation_ordinal);
        let mut wrong_challenge_ordinal = cursor.snapshot.clone();
        wrong_challenge_ordinal.next_whir_challenge_ordinal += 1;
        rejects_snapshot(wrong_challenge_ordinal);
        let mut wrong_commitment_ordinal = cursor.snapshot.clone();
        wrong_commitment_ordinal.next_whir_commitment_ordinal += 1;
        rejects_snapshot(wrong_commitment_ordinal);
        let mut wrong_pending_tag = cursor.snapshot.clone();
        wrong_pending_tag
            .pending_common_challenge
            .as_mut()
            .expect("the checkpoint follows a challenge")
            .challenge_tag
            .push_str("/replayed");
        rejects_snapshot(wrong_pending_tag);
    }

    #[test]
    fn construction_plan_transcript_rejects_independent_schema_and_schedule_mismatches() {
        let construction_plan = selected_same_secret_construction_plan();
        let schema_identifier = construction_plan.application_statement_schema_identifier();
        let expected_schedule = construction_plan.relation_prefix_schedule().clone();
        let header = b"checked construction transcript";

        assert!(matches!(
            CommonProofTranscript::new_relation_prefix_for_construction_plan(
                1,
                [0x41; Hash512::BYTE_LENGTH],
                &construction_plan,
                schema_identifier ^ 1,
                header,
                expected_schedule.clone(),
            ),
            Err(TranscriptError::InvalidCommonProofSchedule),
        ));

        let mut mismatched_schedule = expected_schedule.clone();
        mismatched_schedule.opening_claim_count = mismatched_schedule
            .opening_claim_count
            .checked_add(1)
            .expect("the test opening-claim count can increase");
        assert!(matches!(
            CommonProofTranscript::new_relation_prefix_for_construction_plan(
                1,
                [0x41; Hash512::BYTE_LENGTH],
                &construction_plan,
                schema_identifier,
                header,
                mismatched_schedule,
            ),
            Err(TranscriptError::InvalidCommonProofSchedule),
        ));

        assert!(
            CommonProofTranscript::new_relation_prefix_for_construction_plan(
                1,
                [0x41; Hash512::BYTE_LENGTH],
                &construction_plan,
                schema_identifier,
                header,
                expected_schedule,
            )
            .is_ok(),
            "the exact plan-derived schema and prefix schedule are accepted",
        );
    }

    #[test]
    fn construction_catalog_rejects_mismatch_and_early_finish_without_advancing() {
        let mut transcript = RowCodeWhirTranscript::new_for_test(b"catalog-cursor")
            .expect("the test transcript is valid");
        transcript.transcript_operations = Some(vec![
            RowCodeWhirTranscriptOperation::ObserveProtocolSchedule {
                canonical_values: vec![ProofChallengeExtensionElement::ONE],
            },
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::Aggregate,
            },
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::AggregateWidePad,
            },
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                observation_ordinal: 0,
                role: RowCodeWhirObservationRole::BaseMaskedClaim,
                value_count: 1,
            },
            RowCodeWhirTranscriptOperation::FinishProofStream,
        ]);
        transcript.catalog_counter_origin = Some(transcript.hash_query_counter.clone());

        assert_eq!(
            transcript.absorb_protocol_schedule(&[ProofChallengeExtensionElement::ZERO]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(transcript.next_transcript_operation_index, 0);
        transcript
            .absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE])
            .expect("the cataloged schedule is accepted");
        transcript
            .observe_commitment(&[0x31; Hash512::BYTE_LENGTH])
            .expect("the cataloged aggregate-source commitment is accepted");
        transcript
            .observe_commitment(&[0x41; Hash512::BYTE_LENGTH])
            .expect("the cataloged aggregate-pad commitment is accepted");
        assert_eq!(
            transcript.clone().finish(b"proof"),
            Err(TranscriptError::IncompleteRowCodeWhirTranscript),
        );
        transcript
            .observe_whir_values(
                RowCodeWhirObservationRole::BaseMaskedClaim,
                &[ProofChallengeExtensionElement::ONE],
            )
            .expect("the cataloged WHIR observation is accepted");
        let mut absorber = transcript
            .begin_final_proof_stream(5)
            .expect("the final proof stream starts at the cataloged boundary");
        absorber.absorb(b"pr").expect("the first chunk is accepted");
        absorber
            .absorb(b"oof")
            .expect("the final chunk is accepted");
        absorber.finish().expect("the exact catalog is exhausted");
    }

    #[test]
    fn construction_catalog_owns_direct_query_role_and_geometry() {
        let mut transcript = transcript_after_aggregate_pad_commitment(b"catalog-query-geometry");
        transcript.transcript_operations = Some(vec![
            RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                role: RowCodeWhirQueryRole::Bound,
                upper_bound: 8,
                output_count: 2,
            },
        ]);
        assert_eq!(
            transcript
                .sample_direct_distinct_indices(RowCodeWhirChallenge::OuterQueryVector, 8, 2,),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        assert_eq!(
            transcript
                .sample_direct_distinct_indices(RowCodeWhirChallenge::BoundQueryVector, 8, 3,),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        let accepted = transcript
            .sample_direct_distinct_indices(RowCodeWhirChallenge::BoundQueryVector, 8, 2)
            .expect("the exact cataloged role and geometry are accepted");
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted.iter().copied().collect::<BTreeSet<_>>().len(), 2);
    }

    #[test]
    fn construction_catalog_rejects_swapped_aggregate_commitment_roles() {
        let mut pad_at_source = transcript_before_aggregate_commitment(b"catalog-pad-at-source");
        pad_at_source.transcript_operations =
            Some(vec![RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::AggregateWidePad,
            }]);
        assert_eq!(
            pad_at_source.observe_commitment(&[0x51; Hash512::BYTE_LENGTH]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(pad_at_source.next_transcript_operation_index, 0);

        let mut source_at_pad = transcript_before_aggregate_commitment(b"catalog-source-at-pad");
        source_at_pad.transcript_operations = Some(vec![
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::Aggregate,
            },
            RowCodeWhirTranscriptOperation::ObserveCommitment {
                role: RowCodeWhirCommitmentRole::Aggregate,
            },
        ]);
        source_at_pad
            .observe_commitment(&[0x61; Hash512::BYTE_LENGTH])
            .expect("the source commitment is accepted at its cataloged position");
        assert_eq!(
            source_at_pad.observe_commitment(&[0x71; Hash512::BYTE_LENGTH]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(source_at_pad.next_transcript_operation_index, 1);
    }

    #[test]
    fn construction_catalog_rejects_same_shaped_whir_role_swaps() {
        let opening_point_role = RowCodeWhirObservationRole::OpeningPoint { batch_ordinal: 0 };
        let opening_evaluations_role =
            RowCodeWhirObservationRole::OpeningEvaluations { batch_ordinal: 0 };
        let mut observation_transcript =
            transcript_after_aggregate_pad_commitment(b"catalog-observation-role-swap");
        observation_transcript.live_role_schedule = Some(RowCodeWhirLiveRoleSchedule {
            observation_roles: vec![opening_point_role],
            extension_roles: Vec::new(),
        });
        observation_transcript.transcript_operations = Some(vec![
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                observation_ordinal: 0,
                role: opening_evaluations_role,
                value_count: 1,
            },
        ]);
        assert_eq!(
            observation_transcript
                .observe_whir_values(opening_point_role, &[ProofChallengeExtensionElement::ONE],),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
        assert_eq!(observation_transcript.next_transcript_operation_index, 0);
        assert_eq!(observation_transcript.next_whir_observation_ordinal, 0);
        observation_transcript.transcript_operations = Some(vec![
            RowCodeWhirTranscriptOperation::ObserveExtensionValues {
                observation_ordinal: 0,
                role: opening_point_role,
                value_count: 1,
            },
        ]);
        observation_transcript
            .observe_whir_values(opening_point_role, &[ProofChallengeExtensionElement::ONE])
            .expect("the independently derived observation role is accepted");

        let checkpoint_role = RowCodeWhirExtensionRole::RoundCheckpoint { round_ordinal: 0 };
        let combination_role = RowCodeWhirExtensionRole::RoundCombination { round_ordinal: 0 };
        let mut challenge_transcript =
            transcript_after_aggregate_pad_commitment(b"catalog-challenge-role-swap");
        challenge_transcript.live_role_schedule = Some(RowCodeWhirLiveRoleSchedule {
            observation_roles: Vec::new(),
            extension_roles: vec![checkpoint_role],
        });
        challenge_transcript.transcript_operations =
            Some(vec![RowCodeWhirTranscriptOperation::SampleExtension {
                role: combination_role,
                whir_challenge_ordinal: Some(0),
            }]);
        assert_eq!(
            challenge_transcript.sample_whir_extension(checkpoint_role),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        assert_eq!(challenge_transcript.next_transcript_operation_index, 0);
        assert_eq!(challenge_transcript.next_whir_challenge_ordinal, 0);
        challenge_transcript.transcript_operations =
            Some(vec![RowCodeWhirTranscriptOperation::SampleExtension {
                role: checkpoint_role,
                whir_challenge_ordinal: Some(0),
            }]);
        challenge_transcript
            .sample_whir_extension(checkpoint_role)
            .expect("the independently derived extension role is accepted");
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
            transcript.observe_whir_values(
                RowCodeWhirObservationRole::BaseMaskedClaim,
                &[ProofChallengeExtensionElement::ONE],
            ),
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
            transcript.sample_direct_extension(RowCodeWhirChallenge::OpeningBatchMaskWeight {
                opening_point_ordinal: 0,
            }),
            Err(TranscriptError::UnexpectedRowCodeWhirChallenge),
        );
        assert_eq!(
            transcript.absorb_protocol_schedule(&[ProofChallengeExtensionElement::ONE]),
            Err(TranscriptError::UnexpectedRowCodeWhirRound),
        );
    }

    #[test]
    fn row_code_whir_distinct_samplers_validate_geometry_and_preserve_acceptance_order() {
        let mut challenged =
            transcript_after_aggregate_pad_commitment(b"distinct-acceptance-order");
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

        let mut replay = transcript_after_aggregate_pad_commitment(b"distinct-acceptance-order");
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
        let before_whir = transcript_after_aggregate_pad_commitment(b"finish-before-whir");
        assert_eq!(
            before_whir.finish(b"final proof openings"),
            Err(TranscriptError::IncompleteRowCodeWhirTranscript),
        );

        let mut missing_response =
            transcript_after_aggregate_pad_commitment(b"finish-without-response");
        missing_response
            .observe_whir_values(
                RowCodeWhirObservationRole::BaseMaskedClaim,
                &[ProofChallengeExtensionElement::ONE],
            )
            .expect("one WHIR observation starts the WHIR phase");
        assert_eq!(
            missing_response.finish(&[]),
            Err(TranscriptError::IncompleteRowCodeWhirTranscript),
        );

        let mut pending_challenge =
            transcript_after_aggregate_pad_commitment(b"finish-pending-challenge");
        pending_challenge
            .sample_whir_extension(RowCodeWhirExtensionRole::OpeningBatching)
            .expect("the fixed WHIR challenge samples within the bounded draw ceiling");
        let summary = pending_challenge
            .finish(b"final proof openings")
            .expect("the final proof response answers the pending verifier challenge");
        assert!(summary.maximum_hash_query_count() > 0);
    }
}
