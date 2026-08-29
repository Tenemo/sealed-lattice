use core::{fmt, mem::size_of};

use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512,
};

use super::{
    TallyPreparationError,
    direct_mpc_field_stream::{
        DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH, DirectMpcFieldStreamCoordinate,
        DirectMpcFieldStreamError, DirectMpcFieldStreamKind, direct_mpc_field_stream_chunk_count,
        generate_direct_mpc_field_stream_chunk,
    },
    direct_mpc_prime_field::{
        DIRECT_MPC_PRIME_FIELD_MODULUS, DirectMpcPrimeFieldElement, DirectMpcPrimeFieldError,
    },
    pseudorandom_zero_sharing_seed_master_join_320::LocallyJoinedPseudorandomZeroSharingSubsetMaster320,
    replicated_random_sharing::{ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset},
};

pub(crate) const DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH: usize = 40;
pub(crate) const DIRECT_MPC_CURSOR_CHECKPOINT_TAG_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;

const CHECKPOINT_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/prss-cursor-checkpoint";
const OUTPUT_DOMAIN: &str = "sealed-lattice/v1/direct-mpc/prss-cursor-output";
const CHECKPOINT_TAG_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/direct-mpc/prss-cursor-checkpoint-tag";
const CHECKPOINT_VERSION: u16 = 1;
const CSHAKE256_RATE_BYTE_LENGTH: usize = 136;
const ENCODED_CSHAKE256_RATE: [u8; 2] = [1, 136];
const ENCODED_CHECKPOINT_KEY_BIT_LENGTH: [u8; 3] = [2, 1, 64];
const KMAC512_OUTPUT_BIT_LENGTH: [u8; 3] = [2, 0, 2];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum DirectMpcCursorRefusalCode {
    CheckpointEncoding = 3,
    CheckpointAuthentication = 4,
    CheckpointContext = 5,
    SourceGeometry = 6,
    InvalidState = 7,
    Unexpected = u32::MAX,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcCursorError {
    Canonical(CanonicalCodecError),
    FieldStream(DirectMpcFieldStreamError),
    Preparation(TallyPreparationError),
    PrimeField(DirectMpcPrimeFieldError),
    ParticipantPositionOutOfRange {
        participant_position: u16,
        participant_count: u16,
    },
    SubsetMasterCountMismatch {
        expected: usize,
        actual: usize,
    },
    SubsetMasterScopeMismatch {
        master_position: usize,
    },
    SubsetMasterExcludesParticipant {
        master_position: usize,
    },
    StreamRequiresMultipleChunks {
        stream: &'static str,
        chunk_count: u64,
    },
    CursorFinished,
    ResultUnavailable,
    CheckpointUnavailable,
    CheckpointEncoding,
    CheckpointAuthenticationFailed,
    CheckpointMismatch {
        field: &'static str,
    },
    CheckpointStateOutOfRange {
        next_stream_index: u64,
    },
    ArithmeticOverflow,
    IntegerConversion,
}

impl DirectMpcCursorError {
    pub(crate) const fn refusal_code(&self) -> DirectMpcCursorRefusalCode {
        match self {
            Self::CheckpointEncoding | Self::Canonical(_) => {
                DirectMpcCursorRefusalCode::CheckpointEncoding
            }
            Self::CheckpointAuthenticationFailed => {
                DirectMpcCursorRefusalCode::CheckpointAuthentication
            }
            Self::CheckpointMismatch { .. } => DirectMpcCursorRefusalCode::CheckpointContext,
            Self::ParticipantPositionOutOfRange { .. }
            | Self::SubsetMasterCountMismatch { .. }
            | Self::SubsetMasterScopeMismatch { .. }
            | Self::SubsetMasterExcludesParticipant { .. }
            | Self::StreamRequiresMultipleChunks { .. }
            | Self::Preparation(_)
            | Self::FieldStream(_) => DirectMpcCursorRefusalCode::SourceGeometry,
            Self::CursorFinished
            | Self::ResultUnavailable
            | Self::CheckpointUnavailable
            | Self::CheckpointStateOutOfRange { .. } => DirectMpcCursorRefusalCode::InvalidState,
            Self::PrimeField(_) | Self::ArithmeticOverflow | Self::IntegerConversion => {
                DirectMpcCursorRefusalCode::Unexpected
            }
        }
    }
}

impl fmt::Display for DirectMpcCursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "canonical cursor error: {error}"),
            Self::FieldStream(error) => write!(formatter, "field-stream error: {error}"),
            Self::Preparation(error) => write!(formatter, "preparation error: {error}"),
            Self::PrimeField(error) => write!(formatter, "prime-field error: {error}"),
            Self::ParticipantPositionOutOfRange {
                participant_position,
                participant_count,
            } => write!(
                formatter,
                "direct-MPC participant position {participant_position} is outside roster size {participant_count}"
            ),
            Self::SubsetMasterCountMismatch { expected, actual } => write!(
                formatter,
                "direct-MPC subset-master count mismatch: expected {expected}, received {actual}"
            ),
            Self::SubsetMasterScopeMismatch { master_position } => write!(
                formatter,
                "direct-MPC subset-master scope mismatch at position {master_position}"
            ),
            Self::SubsetMasterExcludesParticipant { master_position } => write!(
                formatter,
                "direct-MPC subset master {master_position} excludes the local participant"
            ),
            Self::StreamRequiresMultipleChunks {
                stream,
                chunk_count,
            } => write!(
                formatter,
                "direct-MPC {stream} stream requires {chunk_count} chunks; this exact candidate cursor admits one"
            ),
            Self::CursorFinished => formatter.write_str("direct-MPC cursor is already finished"),
            Self::ResultUnavailable => {
                formatter.write_str("direct-MPC cursor result is unavailable before completion")
            }
            Self::CheckpointUnavailable => formatter.write_str(
                "direct-MPC cursor checkpoint is unavailable before the first safe boundary",
            ),
            Self::CheckpointEncoding => {
                formatter.write_str("direct-MPC cursor checkpoint encoding is invalid")
            }
            Self::CheckpointAuthenticationFailed => {
                formatter.write_str("direct-MPC cursor checkpoint authentication failed")
            }
            Self::CheckpointMismatch { field } => {
                write!(formatter, "direct-MPC cursor checkpoint {field} mismatch")
            }
            Self::CheckpointStateOutOfRange { next_stream_index } => write!(
                formatter,
                "direct-MPC cursor checkpoint stream index {next_stream_index} is outside the admitted range"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("direct-MPC cursor arithmetic overflow")
            }
            Self::IntegerConversion => {
                formatter.write_str("direct-MPC cursor integer conversion failed")
            }
        }
    }
}

impl std::error::Error for DirectMpcCursorError {}

impl From<CanonicalCodecError> for DirectMpcCursorError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<DirectMpcFieldStreamError> for DirectMpcCursorError {
    fn from(error: DirectMpcFieldStreamError) -> Self {
        Self::FieldStream(error)
    }
}

impl From<TallyPreparationError> for DirectMpcCursorError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<DirectMpcPrimeFieldError> for DirectMpcCursorError {
    fn from(error: DirectMpcPrimeFieldError) -> Self {
        Self::PrimeField(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcPrssContext {
    candidate_identity: Hash512,
    preparation_context_identity: Hash512,
    seed_terminal_identity: Hash512,
    participant_count: u16,
    ordinary_field_count: u64,
    zero_field_count: u64,
}

impl DirectMpcPrssContext {
    pub(crate) const fn new(
        candidate_identity: Hash512,
        preparation_context_identity: Hash512,
        seed_terminal_identity: Hash512,
        participant_count: u16,
        ordinary_field_count: u64,
        zero_field_count: u64,
    ) -> Self {
        Self {
            candidate_identity,
            preparation_context_identity,
            seed_terminal_identity,
            participant_count,
            ordinary_field_count,
            zero_field_count,
        }
    }

    pub(crate) const fn candidate_identity(self) -> Hash512 {
        self.candidate_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn seed_terminal_identity(self) -> Hash512 {
        self.seed_terminal_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn ordinary_field_count(self) -> u64 {
        self.ordinary_field_count
    }

    pub(crate) const fn zero_field_count(self) -> u64 {
        self.zero_field_count
    }
}

/// One source-verified joined subset master.
pub(crate) struct DirectMpcJoinedSubsetMaster {
    subset: ReplicatedRandomSharingSubset,
    bytes: Zeroizing<[u8; DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH]>,
}

impl DirectMpcJoinedSubsetMaster {
    pub(crate) fn from_verified_joined_seed_master(
        master: &LocallyJoinedPseudorandomZeroSharingSubsetMaster320,
    ) -> Self {
        Self {
            subset: master.scope().subset(),
            bytes: Zeroizing::new(*master.as_bytes()),
        }
    }

    /// Constructs diagnostic source material only in tests and in the bounded
    /// scalar measurement build. Production continuation must use the adapter
    /// from positively verified joined seed custody.
    #[cfg(any(test, feature = "preparation-zero-sharing-measurement"))]
    pub(crate) fn new(
        subset: ReplicatedRandomSharingSubset,
        bytes: [u8; DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH],
    ) -> Self {
        Self {
            subset,
            bytes: Zeroizing::new(bytes),
        }
    }

    pub(crate) const fn subset(&self) -> ReplicatedRandomSharingSubset {
        self.subset
    }

    pub(crate) fn as_bytes(&self) -> &[u8; DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH] {
        &self.bytes
    }
}

/// Typed PRSS output available only after the bounded cursor has consumed its
/// complete source geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcPrssParticipantOutput {
    ordinary_values: Box<[DirectMpcPrimeFieldElement]>,
    zero_values: Box<[DirectMpcPrimeFieldElement]>,
}

impl DirectMpcPrssParticipantOutput {
    pub(crate) fn ordinary_values(&self) -> &[DirectMpcPrimeFieldElement] {
        &self.ordinary_values
    }

    pub(crate) fn zero_values(&self) -> &[DirectMpcPrimeFieldElement] {
        &self.zero_values
    }
}

impl Drop for DirectMpcPrssParticipantOutput {
    fn drop(&mut self) {
        self.ordinary_values.zeroize();
        self.zero_values.zeroize();
    }
}

impl fmt::Debug for DirectMpcJoinedSubsetMaster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectMpcJoinedSubsetMaster")
            .field("subset", &self.subset)
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcCursorResourceModel {
    pub(crate) authorized_subset_count_per_participant: u64,
    pub(crate) ordinary_stream_count: u64,
    pub(crate) zero_basis_stream_count: u64,
    pub(crate) total_stream_count: u64,
    pub(crate) ordinary_field_count: u64,
    pub(crate) zero_field_count: u64,
    pub(crate) field_output_count: u64,
    pub(crate) source_byte_length: u64,
    pub(crate) basis_precomputation_field_multiplication_count: u64,
    pub(crate) ordinary_basis_modular_inverse_count: u64,
    pub(crate) weight_field_multiplication_count: u64,
    pub(crate) accumulation_field_addition_count: u64,
    pub(crate) maximum_xof_output_allocation_byte_length: u64,
    pub(crate) canonical_accumulator_byte_length: u64,
    pub(crate) internal_accumulator_byte_length: u64,
    pub(crate) checkpoint_byte_length: u64,
    pub(crate) cumulative_checkpoint_byte_length: u64,
    pub(crate) result_byte_length: u64,
}

impl DirectMpcCursorResourceModel {
    pub(crate) fn derive(
        context: DirectMpcPrssContext,
        participant_position: u16,
    ) -> Result<Self, DirectMpcCursorError> {
        validate_context(context, participant_position)?;
        require_one_chunk("ordinary", context.ordinary_field_count)?;
        require_one_chunk("zero-basis", context.zero_field_count)?;
        let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count)?;
        let ordinary_stream_count = geometry.authorized_subset_count_per_participant;
        let zero_basis_stream_count = checked_multiply(
            geometry.authorized_subset_count_per_participant,
            geometry.active_fault_bound,
        )?;
        let total_stream_count = checked_add(ordinary_stream_count, zero_basis_stream_count)?;
        let ordinary_field_output_count =
            checked_multiply(ordinary_stream_count, context.ordinary_field_count)?;
        let zero_field_output_count =
            checked_multiply(zero_basis_stream_count, context.zero_field_count)?;
        let field_output_count = checked_add(ordinary_field_output_count, zero_field_output_count)?;
        let source_byte_length = checked_multiply(
            field_output_count,
            super::direct_mpc_candidate_compiler::DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
        )?;
        let canonical_accumulator_field_count =
            checked_add(context.ordinary_field_count, context.zero_field_count)?;
        let canonical_accumulator_byte_length = checked_multiply(
            canonical_accumulator_field_count,
            DirectMpcPrimeFieldElement::CANONICAL_BYTE_LENGTH as u64,
        )?;
        let internal_accumulator_byte_length = checked_multiply(
            canonical_accumulator_field_count,
            size_of::<DirectMpcPrimeFieldElement>() as u64,
        )?;
        let maximum_field_count = context.ordinary_field_count.max(context.zero_field_count);
        let maximum_xof_output_allocation_byte_length = checked_multiply(
            maximum_field_count,
            super::direct_mpc_candidate_compiler::DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
        )?;
        let basis_precomputation_field_multiplication_count = checked_add(
            checked_multiply(ordinary_stream_count, geometry.active_fault_bound + 1)?,
            checked_multiply(
                geometry.authorized_subset_count_per_participant,
                checked_sub(checked_multiply(geometry.active_fault_bound, 2)?, 1)?,
            )?,
        )?;
        let accumulation_field_addition_count = checked_add(
            checked_multiply(
                checked_sub(ordinary_stream_count, 1)?,
                context.ordinary_field_count,
            )?,
            checked_multiply(
                checked_sub(zero_basis_stream_count, 1)?,
                context.zero_field_count,
            )?,
        )?;
        let checkpoint_byte_length = checkpoint_byte_length(context)?;
        let cumulative_checkpoint_byte_length =
            checked_multiply(checkpoint_byte_length, total_stream_count)?;
        let result_byte_length = output_byte_length(context)?;
        Ok(Self {
            authorized_subset_count_per_participant: geometry
                .authorized_subset_count_per_participant,
            ordinary_stream_count,
            zero_basis_stream_count,
            total_stream_count,
            ordinary_field_count: context.ordinary_field_count,
            zero_field_count: context.zero_field_count,
            field_output_count,
            source_byte_length,
            basis_precomputation_field_multiplication_count,
            ordinary_basis_modular_inverse_count: ordinary_stream_count,
            weight_field_multiplication_count: field_output_count,
            accumulation_field_addition_count,
            maximum_xof_output_allocation_byte_length,
            canonical_accumulator_byte_length,
            internal_accumulator_byte_length,
            checkpoint_byte_length,
            cumulative_checkpoint_byte_length,
            result_byte_length,
        })
    }
}

/// Bounded scalar cursor for one participant's direct-MPC PRSS source.
///
/// One `step` consumes exactly one independently framed subset stream. A
/// checkpoint is available only after that stream has completed. This cursor
/// verifies source geometry and checkpoint integrity, but the future seed
/// terminal verifier and external encrypted rollback owner remain separate.
pub(crate) struct DirectMpcParticipantCursor {
    context: DirectMpcPrssContext,
    participant_position: u16,
    basis_position_count: u16,
    ordinary_basis_weights: Vec<DirectMpcPrimeFieldElement>,
    zero_basis_weights: Vec<DirectMpcPrimeFieldElement>,
    checkpoint_authentication_key: Zeroizing<[u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH]>,
    next_stream_index: u64,
    ordinary_accumulator: Zeroizing<Vec<DirectMpcPrimeFieldElement>>,
    zero_accumulator: Zeroizing<Vec<DirectMpcPrimeFieldElement>>,
}

impl DirectMpcParticipantCursor {
    pub(crate) fn new(
        context: DirectMpcPrssContext,
        participant_position: u16,
        subset_masters: &[DirectMpcJoinedSubsetMaster],
        checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
    ) -> Result<Self, DirectMpcCursorError> {
        validate_context(context, participant_position)?;
        require_one_chunk("ordinary", context.ordinary_field_count)?;
        require_one_chunk("zero-basis", context.zero_field_count)?;
        let (basis_position_count, ordinary_basis_weights, zero_basis_weights) =
            validate_masters_and_derive_basis_weights(
                context.participant_count,
                participant_position,
                subset_masters,
            )?;
        Ok(Self {
            context,
            participant_position,
            basis_position_count,
            ordinary_basis_weights,
            zero_basis_weights,
            checkpoint_authentication_key: Zeroizing::new(checkpoint_authentication_key),
            next_stream_index: 0,
            ordinary_accumulator: zero_field_vector(context.ordinary_field_count)?,
            zero_accumulator: zero_field_vector(context.zero_field_count)?,
        })
    }

    pub(crate) fn restore_from_checkpoint(
        context: DirectMpcPrssContext,
        participant_position: u16,
        subset_masters: &[DirectMpcJoinedSubsetMaster],
        checkpoint_authentication_key: [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
        checkpoint_bytes: &[u8],
    ) -> Result<Self, DirectMpcCursorError> {
        let mut cursor = Self::new(
            context,
            participant_position,
            subset_masters,
            checkpoint_authentication_key,
        )?;
        cursor.apply_checkpoint(checkpoint_bytes)?;
        Ok(cursor)
    }

    pub(crate) fn step(
        &mut self,
        subset_masters: &[DirectMpcJoinedSubsetMaster],
    ) -> Result<bool, DirectMpcCursorError> {
        validate_master_scopes(
            self.context.participant_count,
            self.participant_position,
            subset_masters,
        )?;
        let resource =
            DirectMpcCursorResourceModel::derive(self.context, self.participant_position)?;
        if self.next_stream_index >= resource.total_stream_count {
            return Err(DirectMpcCursorError::CursorFinished);
        }

        if self.next_stream_index < resource.ordinary_stream_count {
            let master_position = usize_from_u64(self.next_stream_index)?;
            let coordinate = DirectMpcFieldStreamCoordinate::new(
                self.context.candidate_identity,
                self.context.preparation_context_identity,
                self.context.seed_terminal_identity,
                DirectMpcFieldStreamKind::OrdinaryDegreeThree,
                subset_masters[master_position].subset(),
                0,
                self.context.ordinary_field_count,
            )?;
            let chunk = generate_direct_mpc_field_stream_chunk(
                subset_masters[master_position].as_bytes(),
                coordinate,
                0,
            )?;
            combine_stream(
                &mut self.ordinary_accumulator,
                &chunk,
                self.ordinary_basis_weights[master_position],
                self.next_stream_index == 0,
            )?;
        } else {
            let zero_stream_index =
                checked_sub(self.next_stream_index, resource.ordinary_stream_count)?;
            let basis_count = u64::from(self.basis_position_count);
            let master_position = usize_from_u64(zero_stream_index / basis_count)?;
            let basis_position = u16::try_from(zero_stream_index % basis_count)
                .map_err(|_| DirectMpcCursorError::IntegerConversion)?;
            let coordinate = DirectMpcFieldStreamCoordinate::new(
                self.context.candidate_identity,
                self.context.preparation_context_identity,
                self.context.seed_terminal_identity,
                DirectMpcFieldStreamKind::DegreeSixZeroBasis,
                subset_masters[master_position].subset(),
                basis_position,
                self.context.zero_field_count,
            )?;
            let chunk = generate_direct_mpc_field_stream_chunk(
                subset_masters[master_position].as_bytes(),
                coordinate,
                0,
            )?;
            let weight_position = master_position
                .checked_mul(usize::from(self.basis_position_count))
                .and_then(|value| value.checked_add(usize::from(basis_position)))
                .ok_or(DirectMpcCursorError::ArithmeticOverflow)?;
            combine_stream(
                &mut self.zero_accumulator,
                &chunk,
                self.zero_basis_weights[weight_position],
                zero_stream_index == 0,
            )?;
        }
        self.next_stream_index = checked_add(self.next_stream_index, 1)?;
        Ok(self.next_stream_index == resource.total_stream_count)
    }

    pub(crate) fn is_finished(&self) -> Result<bool, DirectMpcCursorError> {
        let resource =
            DirectMpcCursorResourceModel::derive(self.context, self.participant_position)?;
        Ok(self.next_stream_index == resource.total_stream_count)
    }

    pub(crate) const fn next_stream_index(&self) -> u64 {
        self.next_stream_index
    }

    pub(crate) fn checkpoint_bytes(&self) -> Result<Zeroizing<Vec<u8>>, DirectMpcCursorError> {
        if self.next_stream_index == 0 {
            return Err(DirectMpcCursorError::CheckpointUnavailable);
        }
        let body = encode_checkpoint_body(
            self.context,
            self.participant_position,
            self.next_stream_index,
            &self.ordinary_accumulator,
            &self.zero_accumulator,
        )?;
        let tag = authenticate_checkpoint_body(&self.checkpoint_authentication_key, &body);
        let checkpoint = CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::variable_bytes(body.as_slice())?,
                CanonicalItem::fixed_bytes(tag.as_slice())?,
            ],
        )
        .encode()?;
        Ok(Zeroizing::new(checkpoint))
    }

    pub(crate) fn result_bytes(&self) -> Result<Zeroizing<Vec<u8>>, DirectMpcCursorError> {
        if !self.is_finished()? {
            return Err(DirectMpcCursorError::ResultUnavailable);
        }
        encode_output(
            self.context,
            self.participant_position,
            &self.ordinary_accumulator,
            &self.zero_accumulator,
        )
    }

    pub(crate) fn verified_output(
        &self,
    ) -> Result<DirectMpcPrssParticipantOutput, DirectMpcCursorError> {
        if !self.is_finished()? {
            return Err(DirectMpcCursorError::ResultUnavailable);
        }
        Ok(DirectMpcPrssParticipantOutput {
            ordinary_values: self
                .ordinary_accumulator
                .as_slice()
                .to_vec()
                .into_boxed_slice(),
            zero_values: self.zero_accumulator.as_slice().to_vec().into_boxed_slice(),
        })
    }

    fn apply_checkpoint(&mut self, checkpoint_bytes: &[u8]) -> Result<(), DirectMpcCursorError> {
        let outer = Zeroizing::new(
            CanonicalTuple::decode(checkpoint_bytes, &checkpoint_decode_limits())
                .map_err(|_| DirectMpcCursorError::CheckpointEncoding)?,
        );
        if outer.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
            || outer.schema_version != CANONICAL_TUPLE_VERSION
            || outer.items.len() != 2
            || outer.items[0].item_type() != CanonicalItemType::RawBytes
            || outer.items[1].item_type() != CanonicalItemType::RawBytes
        {
            return Err(DirectMpcCursorError::CheckpointEncoding);
        }
        let body = outer.items[0]
            .variable_value_bytes()
            .map_err(|_| DirectMpcCursorError::CheckpointEncoding)?;
        let supplied_tag = outer.items[1].canonical_bytes();
        if supplied_tag.len() != DIRECT_MPC_CURSOR_CHECKPOINT_TAG_BYTE_LENGTH {
            return Err(DirectMpcCursorError::CheckpointEncoding);
        }
        let expected_tag = authenticate_checkpoint_body(&self.checkpoint_authentication_key, body);
        if supplied_tag.ct_eq(expected_tag.as_slice()).unwrap_u8() != 1 {
            return Err(DirectMpcCursorError::CheckpointAuthenticationFailed);
        }
        let checkpoint = Zeroizing::new(
            CanonicalTuple::decode(body, &checkpoint_decode_limits())
                .map_err(|_| DirectMpcCursorError::CheckpointEncoding)?,
        );
        if checkpoint.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
            || checkpoint.schema_version != CANONICAL_TUPLE_VERSION
            || checkpoint.items.len() != 12
        {
            return Err(DirectMpcCursorError::CheckpointEncoding);
        }
        require_ascii(&checkpoint.items[0], CHECKPOINT_DOMAIN)?;
        require_u16(&checkpoint.items[1], CHECKPOINT_VERSION, "version")?;
        require_hash(
            &checkpoint.items[2],
            self.context.candidate_identity,
            "candidate identity",
        )?;
        require_hash(
            &checkpoint.items[3],
            self.context.preparation_context_identity,
            "preparation context identity",
        )?;
        require_hash(
            &checkpoint.items[4],
            self.context.seed_terminal_identity,
            "seed terminal identity",
        )?;
        require_u16(
            &checkpoint.items[5],
            self.context.participant_count,
            "participant count",
        )?;
        require_u16(
            &checkpoint.items[6],
            self.participant_position,
            "participant position",
        )?;
        require_u64(
            &checkpoint.items[7],
            self.context.ordinary_field_count,
            "ordinary field count",
        )?;
        require_u64(
            &checkpoint.items[8],
            self.context.zero_field_count,
            "zero field count",
        )?;
        let next_stream_index = read_u64(&checkpoint.items[9])?;
        let total_stream_count =
            DirectMpcCursorResourceModel::derive(self.context, self.participant_position)?
                .total_stream_count;
        if next_stream_index == 0 || next_stream_index > total_stream_count {
            return Err(DirectMpcCursorError::CheckpointStateOutOfRange { next_stream_index });
        }
        self.ordinary_accumulator = decode_field_elements(
            read_variable_bytes(&checkpoint.items[10])?,
            self.context.ordinary_field_count,
        )?;
        self.zero_accumulator = decode_field_elements(
            read_variable_bytes(&checkpoint.items[11])?,
            self.context.zero_field_count,
        )?;
        self.next_stream_index = next_stream_index;
        Ok(())
    }
}

impl fmt::Debug for DirectMpcParticipantCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectMpcParticipantCursor")
            .field("context", &self.context)
            .field("participant_position", &self.participant_position)
            .field("basis_position_count", &self.basis_position_count)
            .field("next_stream_index", &self.next_stream_index)
            .field("checkpoint_authentication_key", &"[redacted]")
            .field("ordinary_accumulator", &"[redacted]")
            .field("zero_accumulator", &"[redacted]")
            .finish()
    }
}

fn validate_context(
    context: DirectMpcPrssContext,
    participant_position: u16,
) -> Result<(), DirectMpcCursorError> {
    if participant_position >= context.participant_count {
        return Err(DirectMpcCursorError::ParticipantPositionOutOfRange {
            participant_position,
            participant_count: context.participant_count,
        });
    }
    if context.ordinary_field_count == 0 || context.zero_field_count == 0 {
        return Err(DirectMpcFieldStreamError::FieldCountZero.into());
    }
    ReplicatedRandomSharingGeometry::derive(context.participant_count)?;
    Ok(())
}

fn require_one_chunk(stream: &'static str, field_count: u64) -> Result<(), DirectMpcCursorError> {
    let chunk_count = direct_mpc_field_stream_chunk_count(field_count)?;
    if chunk_count != 1 {
        return Err(DirectMpcCursorError::StreamRequiresMultipleChunks {
            stream,
            chunk_count,
        });
    }
    Ok(())
}

fn validate_masters_and_derive_basis_weights(
    participant_count: u16,
    participant_position: u16,
    subset_masters: &[DirectMpcJoinedSubsetMaster],
) -> Result<
    (
        u16,
        Vec<DirectMpcPrimeFieldElement>,
        Vec<DirectMpcPrimeFieldElement>,
    ),
    DirectMpcCursorError,
> {
    let expected_subsets =
        validate_master_scopes(participant_count, participant_position, subset_masters)?;
    let basis_position_count = expected_subsets
        .first()
        .ok_or(DirectMpcCursorError::SubsetMasterCountMismatch {
            expected: 1,
            actual: 0,
        })?
        .active_fault_bound();
    let participant_point = DirectMpcPrimeFieldElement::from_u16(
        participant_position
            .checked_add(1)
            .ok_or(DirectMpcCursorError::ArithmeticOverflow)?,
    );
    let mut ordinary_basis_weights = Vec::with_capacity(expected_subsets.len());
    let mut zero_basis_weights = Vec::with_capacity(
        expected_subsets
            .len()
            .checked_mul(usize::from(basis_position_count))
            .ok_or(DirectMpcCursorError::ArithmeticOverflow)?,
    );
    for subset in expected_subsets {
        ordinary_basis_weights.push(ordinary_basis_weight(subset, participant_point)?);
        zero_basis_weights.extend(zero_basis_weights_at_point(subset, participant_point)?);
    }
    Ok((
        basis_position_count,
        ordinary_basis_weights,
        zero_basis_weights,
    ))
}

fn validate_master_scopes(
    participant_count: u16,
    participant_position: u16,
    subset_masters: &[DirectMpcJoinedSubsetMaster],
) -> Result<Vec<ReplicatedRandomSharingSubset>, DirectMpcCursorError> {
    let expected_subsets = ReplicatedRandomSharingSubset::iter(participant_count)?
        .filter_map(|subset| match subset.contains(participant_position) {
            Ok(true) => Some(Ok(subset)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if subset_masters.len() != expected_subsets.len() {
        return Err(DirectMpcCursorError::SubsetMasterCountMismatch {
            expected: expected_subsets.len(),
            actual: subset_masters.len(),
        });
    }
    for (master_position, (master, expected_subset)) in
        subset_masters.iter().zip(&expected_subsets).enumerate()
    {
        if master.subset() != *expected_subset {
            return Err(DirectMpcCursorError::SubsetMasterScopeMismatch { master_position });
        }
        if !master.subset().contains(participant_position)? {
            return Err(DirectMpcCursorError::SubsetMasterExcludesParticipant { master_position });
        }
    }
    Ok(expected_subsets)
}

fn ordinary_basis_weight(
    subset: ReplicatedRandomSharingSubset,
    participant_point: DirectMpcPrimeFieldElement,
) -> Result<DirectMpcPrimeFieldElement, DirectMpcCursorError> {
    let mut numerator = DirectMpcPrimeFieldElement::ONE;
    let mut denominator_as_integer = 1_u64;
    for excluded_position in subset.excluded_positions() {
        let excluded_point = DirectMpcPrimeFieldElement::from_u16(
            excluded_position
                .checked_add(1)
                .ok_or(DirectMpcCursorError::ArithmeticOverflow)?,
        );
        numerator = numerator.multiply(participant_point.subtract(excluded_point));
        denominator_as_integer = denominator_as_integer
            .checked_mul(u64::from(
                DirectMpcPrimeFieldElement::ZERO
                    .subtract(excluded_point)
                    .canonical_u32(),
            ))
            .ok_or(DirectMpcCursorError::ArithmeticOverflow)?
            % u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS);
    }
    let denominator_inverse = modular_inverse_as_integer(
        u32::try_from(denominator_as_integer)
            .map_err(|_| DirectMpcCursorError::IntegerConversion)?,
    )?;
    Ok(
        numerator.multiply(DirectMpcPrimeFieldElement::from_canonical_u32(
            denominator_inverse,
        )?),
    )
}

fn zero_basis_weights_at_point(
    subset: ReplicatedRandomSharingSubset,
    participant_point: DirectMpcPrimeFieldElement,
) -> Result<Vec<DirectMpcPrimeFieldElement>, DirectMpcCursorError> {
    let mut base = participant_point;
    for excluded_position in subset.excluded_positions() {
        let excluded_point = DirectMpcPrimeFieldElement::from_u16(
            excluded_position
                .checked_add(1)
                .ok_or(DirectMpcCursorError::ArithmeticOverflow)?,
        );
        base = base.multiply(participant_point.subtract(excluded_point));
    }
    let mut values = Vec::with_capacity(usize::from(subset.active_fault_bound()));
    values.push(base);
    for _ in 1..subset.active_fault_bound() {
        let preceding = *values
            .last()
            .ok_or(DirectMpcCursorError::ArithmeticOverflow)?;
        values.push(preceding.multiply(participant_point));
    }
    Ok(values)
}

fn modular_inverse_as_integer(value: u32) -> Result<u32, DirectMpcCursorError> {
    if value == 0 {
        return Err(DirectMpcPrimeFieldError::ZeroHasNoMultiplicativeInverse.into());
    }
    let modulus = i64::from(DIRECT_MPC_PRIME_FIELD_MODULUS);
    let mut old_remainder = modulus;
    let mut remainder = i64::from(value);
    let mut old_coefficient = 0_i64;
    let mut coefficient = 1_i64;
    while remainder != 0 {
        let quotient = old_remainder / remainder;
        (old_remainder, remainder) = (remainder, old_remainder - quotient * remainder);
        (old_coefficient, coefficient) = (coefficient, old_coefficient - quotient * coefficient);
    }
    if old_remainder != 1 {
        return Err(DirectMpcPrimeFieldError::ZeroHasNoMultiplicativeInverse.into());
    }
    u32::try_from(old_coefficient.rem_euclid(modulus))
        .map_err(|_| DirectMpcCursorError::IntegerConversion)
}

fn combine_stream(
    accumulator: &mut [DirectMpcPrimeFieldElement],
    chunk: &super::direct_mpc_field_stream::DirectMpcFieldStreamChunk,
    weight: DirectMpcPrimeFieldElement,
    first_stream: bool,
) -> Result<(), DirectMpcCursorError> {
    if chunk.first_field_index() != 0 || usize_from_u64(chunk.field_count())? != accumulator.len() {
        return Err(DirectMpcCursorError::ArithmeticOverflow);
    }
    for (field_position, accumulated) in accumulator.iter_mut().enumerate() {
        let contribution = chunk
            .field_element(
                u64::try_from(field_position)
                    .map_err(|_| DirectMpcCursorError::IntegerConversion)?,
            )?
            .multiply(weight);
        *accumulated = if first_stream {
            contribution
        } else {
            accumulated.add(contribution)
        };
    }
    Ok(())
}

fn zero_field_vector(
    field_count: u64,
) -> Result<Zeroizing<Vec<DirectMpcPrimeFieldElement>>, DirectMpcCursorError> {
    Ok(Zeroizing::new(vec![
        DirectMpcPrimeFieldElement::ZERO;
        usize_from_u64(field_count)?
    ]))
}

fn encode_checkpoint_body(
    context: DirectMpcPrssContext,
    participant_position: u16,
    next_stream_index: u64,
    ordinary_accumulator: &[DirectMpcPrimeFieldElement],
    zero_accumulator: &[DirectMpcPrimeFieldElement],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcCursorError> {
    let ordinary_bytes = encode_field_elements(ordinary_accumulator)?;
    let zero_bytes = encode_field_elements(zero_accumulator)?;
    Ok(Zeroizing::new(
        CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(CHECKPOINT_DOMAIN)?,
                CanonicalItem::unsigned16(CHECKPOINT_VERSION),
                CanonicalItem::hash512(context.candidate_identity.into_bytes()),
                CanonicalItem::hash512(context.preparation_context_identity.into_bytes()),
                CanonicalItem::hash512(context.seed_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(context.participant_count),
                CanonicalItem::unsigned16(participant_position),
                CanonicalItem::unsigned64(context.ordinary_field_count),
                CanonicalItem::unsigned64(context.zero_field_count),
                CanonicalItem::unsigned64(next_stream_index),
                CanonicalItem::variable_bytes(ordinary_bytes.as_slice())?,
                CanonicalItem::variable_bytes(zero_bytes.as_slice())?,
            ],
        )
        .encode()?,
    ))
}

fn encode_output(
    context: DirectMpcPrssContext,
    participant_position: u16,
    ordinary_accumulator: &[DirectMpcPrimeFieldElement],
    zero_accumulator: &[DirectMpcPrimeFieldElement],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcCursorError> {
    let ordinary_bytes = encode_field_elements(ordinary_accumulator)?;
    let zero_bytes = encode_field_elements(zero_accumulator)?;
    Ok(Zeroizing::new(
        CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(OUTPUT_DOMAIN)?,
                CanonicalItem::hash512(context.candidate_identity.into_bytes()),
                CanonicalItem::hash512(context.preparation_context_identity.into_bytes()),
                CanonicalItem::hash512(context.seed_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(context.participant_count),
                CanonicalItem::unsigned16(participant_position),
                CanonicalItem::unsigned64(context.ordinary_field_count),
                CanonicalItem::unsigned64(context.zero_field_count),
                CanonicalItem::variable_bytes(ordinary_bytes.as_slice())?,
                CanonicalItem::variable_bytes(zero_bytes.as_slice())?,
            ],
        )
        .encode()?,
    ))
}

fn authenticate_checkpoint_body(
    authentication_key: &[u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
    checkpoint_body: &[u8],
) -> Zeroizing<[u8; DIRECT_MPC_CURSOR_CHECKPOINT_TAG_BYTE_LENGTH]> {
    let mut padded_key = Zeroizing::new([0_u8; CSHAKE256_RATE_BYTE_LENGTH]);
    let key_length_start = ENCODED_CSHAKE256_RATE.len();
    let key_start = key_length_start + ENCODED_CHECKPOINT_KEY_BIT_LENGTH.len();
    let key_end = key_start + authentication_key.len();
    padded_key[..key_length_start].copy_from_slice(&ENCODED_CSHAKE256_RATE);
    padded_key[key_length_start..key_start].copy_from_slice(&ENCODED_CHECKPOINT_KEY_BIT_LENGTH);
    padded_key[key_start..key_end].copy_from_slice(authentication_key);
    let mut authentication = CShake256::from_core(CShake256Core::new_with_function_name(
        b"KMAC",
        CHECKPOINT_TAG_CUSTOMIZATION,
    ));
    authentication.update(padded_key.as_ref());
    authentication.update(checkpoint_body);
    authentication.update(&KMAC512_OUTPUT_BIT_LENGTH);
    let mut tag = Zeroizing::new([0_u8; DIRECT_MPC_CURSOR_CHECKPOINT_TAG_BYTE_LENGTH]);
    authentication.finalize_xof().read(tag.as_mut());
    tag
}

fn encode_field_elements(
    field_elements: &[DirectMpcPrimeFieldElement],
) -> Result<Zeroizing<Vec<u8>>, DirectMpcCursorError> {
    let byte_length = field_elements
        .len()
        .checked_mul(DirectMpcPrimeFieldElement::CANONICAL_BYTE_LENGTH)
        .ok_or(DirectMpcCursorError::ArithmeticOverflow)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(byte_length));
    for field_element in field_elements {
        bytes.extend_from_slice(&field_element.canonical_bytes());
    }
    Ok(bytes)
}

fn decode_field_elements(
    bytes: &[u8],
    expected_field_count: u64,
) -> Result<Zeroizing<Vec<DirectMpcPrimeFieldElement>>, DirectMpcCursorError> {
    let expected_byte_length = usize_from_u64(checked_multiply(
        expected_field_count,
        DirectMpcPrimeFieldElement::CANONICAL_BYTE_LENGTH as u64,
    )?)?;
    if bytes.len() != expected_byte_length {
        return Err(DirectMpcCursorError::CheckpointMismatch {
            field: "accumulator byte length",
        });
    }
    let mut output = Zeroizing::new(Vec::with_capacity(usize_from_u64(expected_field_count)?));
    for field_bytes in bytes.chunks_exact(DirectMpcPrimeFieldElement::CANONICAL_BYTE_LENGTH) {
        output.push(DirectMpcPrimeFieldElement::from_canonical_bytes(
            field_bytes,
        )?);
    }
    Ok(output)
}

fn checkpoint_byte_length(context: DirectMpcPrssContext) -> Result<u64, DirectMpcCursorError> {
    let ordinary = zero_field_vector(context.ordinary_field_count)?;
    let zero = zero_field_vector(context.zero_field_count)?;
    let body = encode_checkpoint_body(context, 0, 1, &ordinary, &zero)?;
    let tag = [0_u8; DIRECT_MPC_CURSOR_CHECKPOINT_TAG_BYTE_LENGTH];
    let bytes = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::variable_bytes(body.as_slice())?,
            CanonicalItem::fixed_bytes(tag)?,
        ],
    )
    .encode()?;
    u64::try_from(bytes.len()).map_err(|_| DirectMpcCursorError::IntegerConversion)
}

fn output_byte_length(context: DirectMpcPrssContext) -> Result<u64, DirectMpcCursorError> {
    let ordinary = zero_field_vector(context.ordinary_field_count)?;
    let zero = zero_field_vector(context.zero_field_count)?;
    let output = encode_output(context, 0, &ordinary, &zero)?;
    u64::try_from(output.len()).map_err(|_| DirectMpcCursorError::IntegerConversion)
}

fn checkpoint_decode_limits() -> CanonicalDecodeLimits {
    let maximum = FOUNDATION_PROFILE.maximum_copied_buffer_byte_length;
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: maximum,
        maximum_item_count: 32,
        maximum_item_byte_length: maximum,
        maximum_nesting_depth: 4,
        maximum_cumulative_work_byte_length: maximum * 4,
        maximum_cumulative_allocation_byte_length: maximum * 4,
    }
}

fn require_ascii(item: &CanonicalItem, expected: &str) -> Result<(), DirectMpcCursorError> {
    if item.item_type() != CanonicalItemType::Ascii
        || item
            .variable_value_bytes()
            .map_err(|_| DirectMpcCursorError::CheckpointEncoding)?
            != expected.as_bytes()
    {
        return Err(DirectMpcCursorError::CheckpointEncoding);
    }
    Ok(())
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), DirectMpcCursorError> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes() != expected.as_bytes()
    {
        return Err(DirectMpcCursorError::CheckpointMismatch { field });
    }
    Ok(())
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), DirectMpcCursorError> {
    if item.item_type() != CanonicalItemType::Unsigned16
        || item.canonical_bytes() != expected.to_le_bytes()
    {
        return Err(DirectMpcCursorError::CheckpointMismatch { field });
    }
    Ok(())
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), DirectMpcCursorError> {
    if read_u64(item)? != expected {
        return Err(DirectMpcCursorError::CheckpointMismatch { field });
    }
    Ok(())
}

fn read_u64(item: &CanonicalItem) -> Result<u64, DirectMpcCursorError> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(DirectMpcCursorError::CheckpointEncoding);
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| DirectMpcCursorError::CheckpointEncoding)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_variable_bytes(item: &CanonicalItem) -> Result<&[u8], DirectMpcCursorError> {
    if item.item_type() != CanonicalItemType::RawBytes {
        return Err(DirectMpcCursorError::CheckpointEncoding);
    }
    item.variable_value_bytes()
        .map_err(|_| DirectMpcCursorError::CheckpointEncoding)
}

fn checked_add(left: u64, right: u64) -> Result<u64, DirectMpcCursorError> {
    left.checked_add(right)
        .ok_or(DirectMpcCursorError::ArithmeticOverflow)
}

fn checked_sub(left: u64, right: u64) -> Result<u64, DirectMpcCursorError> {
    left.checked_sub(right)
        .ok_or(DirectMpcCursorError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, DirectMpcCursorError> {
    left.checked_mul(right)
        .ok_or(DirectMpcCursorError::ArithmeticOverflow)
}

fn usize_from_u64(value: u64) -> Result<usize, DirectMpcCursorError> {
    usize::try_from(value).map_err(|_| DirectMpcCursorError::IntegerConversion)
}

#[cfg(test)]
pub(super) fn ordinary_basis_weight_for_test(
    subset: ReplicatedRandomSharingSubset,
    participant_point: DirectMpcPrimeFieldElement,
) -> Result<DirectMpcPrimeFieldElement, DirectMpcCursorError> {
    ordinary_basis_weight(subset, participant_point)
}

#[cfg(test)]
pub(super) fn zero_basis_weights_at_point_for_test(
    subset: ReplicatedRandomSharingSubset,
    participant_point: DirectMpcPrimeFieldElement,
) -> Result<Vec<DirectMpcPrimeFieldElement>, DirectMpcCursorError> {
    zero_basis_weights_at_point(subset, participant_point)
}
