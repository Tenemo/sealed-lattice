use core::fmt;

use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    encoding::CanonicalReader,
    foundation::{FOUNDATION_PROFILE, Hash512},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_320::{
        canonical_evaluation_point_320, pseudorandom_zero_sharing_basis_values_at_point,
    },
    pseudorandom_zero_sharing_field_stream_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH,
        PseudorandomZeroSharingFieldStreamCoordinate320,
        generate_pseudorandom_zero_sharing_field_chunk_320,
        pseudorandom_zero_sharing_field_chunk_count,
        pseudorandom_zero_sharing_field_elements_per_chunk,
    },
    pseudorandom_zero_sharing_seed_master_join_320::LocallyJoinedPseudorandomZeroSharingSubsetMaster320,
    replicated_random_sharing::{ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset},
};

pub(crate) const PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_DOMAIN: &[u8] =
    b"sealed-lattice/v1/preparation/pseudorandom-zero-sharing-cursor-checkpoint";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_KEY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/preparation/pseudorandom-zero-sharing-checkpoint-key";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_TAG_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/v1/preparation/pseudorandom-zero-sharing-checkpoint-tag";
const CHECKPOINT_VERSION: u64 = 1;
pub(crate) const CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH;
const CSHAKE256_RATE_BYTE_LENGTH: usize = 136;
const ENCODED_CSHAKE256_RATE: [u8; 2] = [1, 136];
const ENCODED_SUBSET_MASTER_BIT_LENGTH: [u8; 3] = [2, 1, 64];
const KMAC320_OUTPUT_BIT_LENGTH: [u8; 3] = [1, 64, 2];
const KMAC512_OUTPUT_BIT_LENGTH: [u8; 3] = [2, 0, 2];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub(crate) enum PseudorandomZeroSharingCursorState320 {
    Processing = 1,
    CompletedChunkReady = 2,
    Finished = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingCursorError320 {
    Preparation(TallyPreparationError),
    MasterCountMismatch {
        expected: usize,
        actual: usize,
    },
    MasterScopeMismatch {
        master_index: usize,
    },
    MasterSubsetExcludesParticipant {
        master_index: usize,
        participant_position: u16,
    },
    CursorNotProcessing {
        state: PseudorandomZeroSharingCursorState320,
    },
    CompletedChunkUnavailable {
        state: PseudorandomZeroSharingCursorState320,
    },
    CheckpointEncoding,
    CheckpointAuthenticationFailed,
    CheckpointMismatch {
        field: &'static str,
    },
    CheckpointByteLengthExceedsCopiedBufferLimit {
        byte_length: u64,
        maximum_byte_length: u64,
    },
    ArithmeticOverflow,
    IntegerConversion,
}

impl fmt::Display for PseudorandomZeroSharingCursorError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(error) => write!(formatter, "preparation error: {error}"),
            Self::MasterCountMismatch { expected, actual } => write!(
                formatter,
                "joined subset-master count mismatch: expected {expected}, received {actual}"
            ),
            Self::MasterScopeMismatch { master_index } => {
                write!(
                    formatter,
                    "joined subset-master scope mismatch at index {master_index}"
                )
            }
            Self::MasterSubsetExcludesParticipant {
                master_index,
                participant_position,
            } => write!(
                formatter,
                "joined subset master {master_index} excludes participant {participant_position}"
            ),
            Self::CursorNotProcessing { state } => {
                write!(
                    formatter,
                    "zero-sharing cursor is not processing: {state:?}"
                )
            }
            Self::CompletedChunkUnavailable { state } => write!(
                formatter,
                "zero-sharing cursor has no completed chunk in state {state:?}"
            ),
            Self::CheckpointEncoding => {
                formatter.write_str("zero-sharing cursor checkpoint encoding is invalid")
            }
            Self::CheckpointAuthenticationFailed => {
                formatter.write_str("zero-sharing cursor checkpoint authentication failed")
            }
            Self::CheckpointMismatch { field } => {
                write!(formatter, "zero-sharing cursor checkpoint {field} mismatch")
            }
            Self::CheckpointByteLengthExceedsCopiedBufferLimit {
                byte_length,
                maximum_byte_length,
            } => write!(
                formatter,
                "zero-sharing cursor checkpoint length {byte_length} exceeds copied-buffer limit {maximum_byte_length}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("zero-sharing cursor arithmetic overflow")
            }
            Self::IntegerConversion => {
                formatter.write_str("zero-sharing cursor integer conversion failed")
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingCursorError320 {}

impl From<TallyPreparationError> for PseudorandomZeroSharingCursorError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingCursorStep320 {
    pub(crate) chunk_index: u64,
    pub(crate) stream_index: u64,
    pub(crate) completed_chunk: bool,
}

/// Production-derived operation and checkpoint ledger for one participant's
/// bounded zero-sharing cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingCursorResourceModel320 {
    pub(crate) participant_count: u64,
    pub(crate) authorized_subset_count_per_participant: u64,
    pub(crate) basis_position_count_per_subset: u64,
    pub(crate) basis_stream_count: u64,
    pub(crate) zero_sharing_count: u64,
    pub(crate) field_output_count: u64,
    pub(crate) output_chunk_count: u64,
    pub(crate) work_checkpoint_count: u64,
    pub(crate) field_stream_kmacxof256_query_count: u64,
    pub(crate) checkpoint_key_derivation_kmac256_count: u64,
    pub(crate) checkpoint_tag_generation_kmac256_count: u64,
    pub(crate) cold_restore_checkpoint_tag_verification_kmac256_count: u64,
    pub(crate) basis_precomputation_field_multiplication_count: u64,
    pub(crate) combination_field_multiplication_count: u64,
    pub(crate) combination_field_addition_count: u64,
    pub(crate) full_chunk_field_count: u64,
    pub(crate) final_chunk_field_count: u64,
    pub(crate) full_chunk_payload_byte_length: u64,
    pub(crate) final_chunk_payload_byte_length: u64,
    pub(crate) minimum_completed_step_checkpoint_byte_length: u64,
    pub(crate) maximum_completed_step_checkpoint_byte_length: u64,
    pub(crate) cumulative_completed_step_checkpoint_byte_length: u64,
    pub(crate) cumulative_checkpoint_authenticated_body_byte_length: u64,
}

impl PseudorandomZeroSharingCursorResourceModel320 {
    pub(crate) fn derive(
        participant_count: u16,
        participant_position: u16,
        zero_sharing_count: u64,
    ) -> Result<Self, PseudorandomZeroSharingCursorError320> {
        if participant_position >= participant_count {
            return Err(TallyPreparationError::RosterPositionOutOfRange {
                roster_position: participant_position,
                participant_count,
            }
            .into());
        }
        if zero_sharing_count == 0 {
            return Err(TallyPreparationError::PseudorandomZeroSharingFieldCountZero.into());
        }
        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count)?;
        if geometry.active_fault_bound == 0 {
            return Err(TallyPreparationError::GeometryMismatch.into());
        }
        let basis_stream_count = checked_multiply_u64(
            geometry.authorized_subset_count_per_participant,
            geometry.active_fault_bound,
        )?;
        let output_chunk_count = pseudorandom_zero_sharing_field_chunk_count(zero_sharing_count)?;
        let work_checkpoint_count = checked_multiply_u64(basis_stream_count, output_chunk_count)?;
        let field_output_count = checked_multiply_u64(basis_stream_count, zero_sharing_count)?;
        let full_chunk_field_count = pseudorandom_zero_sharing_field_elements_per_chunk()?;
        let preceding_full_chunk_count = output_chunk_count
            .checked_sub(1)
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
        let final_chunk_field_count = zero_sharing_count
            .checked_sub(checked_multiply_u64(
                preceding_full_chunk_count,
                full_chunk_field_count,
            )?)
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
        let field_byte_length = u64::try_from(BinaryFieldElement320::CANONICAL_BYTE_LENGTH)
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
        let full_chunk_payload_byte_length =
            checked_multiply_u64(full_chunk_field_count, field_byte_length)?;
        let final_chunk_payload_byte_length =
            checked_multiply_u64(final_chunk_field_count, field_byte_length)?;
        let basis_multiplications_per_subset = geometry
            .active_fault_bound
            .checked_add(
                geometry
                    .active_fault_bound
                    .checked_sub(1)
                    .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?,
            )
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
        let basis_precomputation_field_multiplication_count = checked_multiply_u64(
            geometry.authorized_subset_count_per_participant,
            basis_multiplications_per_subset,
        )?;
        let combination_field_addition_count =
            field_output_count
                .checked_sub(zero_sharing_count)
                .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;

        let mut minimum_checkpoint_byte_length = u64::MAX;
        let mut maximum_checkpoint_byte_length = 0_u64;
        let mut cumulative_checkpoint_byte_length = 0_u64;
        let summed_next_stream_index_byte_lengths =
            sum_varuint_byte_lengths(1, basis_stream_count)?;
        for chunk_index in 0..output_chunk_count {
            let accumulator_byte_length = if chunk_index + 1 == output_chunk_count {
                final_chunk_payload_byte_length
            } else {
                full_chunk_payload_byte_length
            };
            let record_byte_length_with_zero_stream_index = checkpoint_record_byte_length(
                participant_count,
                participant_position,
                zero_sharing_count,
                chunk_index,
                0,
                accumulator_byte_length,
            )?;
            let fixed_record_byte_length = record_byte_length_with_zero_stream_index
                .checked_sub(varuint_byte_length(0))
                .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
            let chunk_checkpoint_byte_length = checked_add_u64(
                checked_multiply_u64(fixed_record_byte_length, basis_stream_count)?,
                summed_next_stream_index_byte_lengths,
            )?;
            cumulative_checkpoint_byte_length = checked_add_u64(
                cumulative_checkpoint_byte_length,
                chunk_checkpoint_byte_length,
            )?;

            let first_record_byte_length =
                checked_add_u64(fixed_record_byte_length, varuint_byte_length(1))?;
            let final_record_byte_length = checked_add_u64(
                fixed_record_byte_length,
                varuint_byte_length(basis_stream_count),
            )?;
            minimum_checkpoint_byte_length = minimum_checkpoint_byte_length
                .min(first_record_byte_length)
                .min(final_record_byte_length);
            maximum_checkpoint_byte_length = maximum_checkpoint_byte_length
                .max(first_record_byte_length)
                .max(final_record_byte_length);
        }
        let maximum_copied_buffer_byte_length =
            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
        if maximum_checkpoint_byte_length > maximum_copied_buffer_byte_length {
            return Err(
                PseudorandomZeroSharingCursorError320::CheckpointByteLengthExceedsCopiedBufferLimit {
                    byte_length: maximum_checkpoint_byte_length,
                    maximum_byte_length: maximum_copied_buffer_byte_length,
                },
            );
        }
        let cumulative_checkpoint_authenticated_body_byte_length =
            cumulative_checkpoint_byte_length
                .checked_sub(checked_multiply_u64(
                    work_checkpoint_count,
                    u64::try_from(CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH)
                        .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?,
                )?)
                .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;

        Ok(Self {
            participant_count: u64::from(participant_count),
            authorized_subset_count_per_participant: geometry
                .authorized_subset_count_per_participant,
            basis_position_count_per_subset: geometry.active_fault_bound,
            basis_stream_count,
            zero_sharing_count,
            field_output_count,
            output_chunk_count,
            work_checkpoint_count,
            field_stream_kmacxof256_query_count: work_checkpoint_count,
            checkpoint_key_derivation_kmac256_count: 1,
            checkpoint_tag_generation_kmac256_count: work_checkpoint_count,
            cold_restore_checkpoint_tag_verification_kmac256_count: 1,
            basis_precomputation_field_multiplication_count,
            combination_field_multiplication_count: field_output_count,
            combination_field_addition_count,
            full_chunk_field_count,
            final_chunk_field_count,
            full_chunk_payload_byte_length,
            final_chunk_payload_byte_length,
            minimum_completed_step_checkpoint_byte_length: minimum_checkpoint_byte_length,
            maximum_completed_step_checkpoint_byte_length: maximum_checkpoint_byte_length,
            cumulative_completed_step_checkpoint_byte_length: cumulative_checkpoint_byte_length,
            cumulative_checkpoint_authenticated_body_byte_length,
        })
    }
}

/// Bounded canonical producer for one participant's local zero-sharing values.
///
/// Construction accepts only source-authorized joined masters in canonical
/// subset order. One call to `step` performs exactly one independently framed
/// KMAC stream chunk and its public-weight combination. The checkpoint is
/// authenticated under a key derived from those exact masters, but remains
/// secret inner custody: an external state owner must encrypt it, bind an
/// authenticated head, reconcile rollback, and acknowledge durable output.
/// The retained derivation keys KMAC with the first ordered subset master. A
/// permitted corrupt holder can know that master, so this cursor is a measured
/// comparison baseline and its checkpoint authentication cannot authorize a
/// production continuation. The selected hidden-bit cursor requires a new
/// derivation whose key retains an independently hidden master after the full
/// permitted view is conditioned.
pub(crate) struct PseudorandomZeroSharingParticipantCursor320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    zero_sharing_catalog_identity: Hash512,
    participant_position: u16,
    total_field_count: u64,
    basis_position_count_per_subset: u16,
    basis_stream_count: u64,
    basis_weights: Vec<BinaryFieldElement320>,
    checkpoint_authentication_key:
        Zeroizing<[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH]>,
    current_chunk_index: u64,
    next_stream_index: u64,
    state: PseudorandomZeroSharingCursorState320,
    accumulator: Zeroizing<Vec<BinaryFieldElement320>>,
}

impl PseudorandomZeroSharingParticipantCursor320 {
    pub(crate) fn new(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        zero_sharing_catalog_identity: Hash512,
        participant_position: u16,
        total_field_count: u64,
        subset_masters: &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320],
    ) -> Result<Self, PseudorandomZeroSharingCursorError320> {
        let resource_model = PseudorandomZeroSharingCursorResourceModel320::derive(
            preparation_context.participant_count(),
            participant_position,
            total_field_count,
        )?;
        let (basis_position_count_per_subset, basis_weights) = validate_masters_and_basis_weights(
            parameter_identity,
            preparation_context,
            participant_position,
            subset_masters,
        )?;
        let basis_stream_count = u64::try_from(basis_weights.len())
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
        if basis_stream_count != resource_model.basis_stream_count {
            return Err(PseudorandomZeroSharingCursorError320::MasterCountMismatch {
                expected: usize::try_from(resource_model.basis_stream_count)
                    .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?,
                actual: basis_weights.len(),
            });
        }
        let checkpoint_authentication_key = derive_checkpoint_authentication_key(
            parameter_identity,
            preparation_context,
            zero_sharing_catalog_identity,
            participant_position,
            subset_masters,
        )?;
        let accumulator = zero_accumulator_for_chunk(total_field_count, 0)?;

        Ok(Self {
            parameter_identity,
            preparation_context,
            zero_sharing_catalog_identity,
            participant_position,
            total_field_count,
            basis_position_count_per_subset,
            basis_stream_count,
            basis_weights,
            checkpoint_authentication_key,
            current_chunk_index: 0,
            next_stream_index: 0,
            state: PseudorandomZeroSharingCursorState320::Processing,
            accumulator,
        })
    }

    pub(crate) fn restore_from_checkpoint(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        zero_sharing_catalog_identity: Hash512,
        participant_position: u16,
        total_field_count: u64,
        subset_masters: &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320],
        checkpoint_bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingCursorError320> {
        let mut cursor = Self::new(
            parameter_identity,
            preparation_context,
            zero_sharing_catalog_identity,
            participant_position,
            total_field_count,
            subset_masters,
        )?;
        cursor.restore_checkpoint_state(checkpoint_bytes)?;
        Ok(cursor)
    }

    pub(crate) const fn state(&self) -> PseudorandomZeroSharingCursorState320 {
        self.state
    }

    pub(crate) fn output_chunk_count(&self) -> Result<u64, PseudorandomZeroSharingCursorError320> {
        Ok(pseudorandom_zero_sharing_field_chunk_count(
            self.total_field_count,
        )?)
    }

    pub(crate) fn step(
        &mut self,
        subset_masters: &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320],
    ) -> Result<PseudorandomZeroSharingCursorStep320, PseudorandomZeroSharingCursorError320> {
        if self.state != PseudorandomZeroSharingCursorState320::Processing {
            return Err(PseudorandomZeroSharingCursorError320::CursorNotProcessing {
                state: self.state,
            });
        }
        validate_master_scopes(
            self.parameter_identity,
            self.preparation_context,
            self.participant_position,
            subset_masters,
        )?;
        let basis_position_count = u64::from(self.basis_position_count_per_subset);
        let master_index = usize::try_from(self.next_stream_index / basis_position_count)
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
        let basis_position = u16::try_from(self.next_stream_index % basis_position_count)
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
        let subset_master = subset_masters.get(master_index).ok_or(
            PseudorandomZeroSharingCursorError320::MasterCountMismatch {
                expected: master_index + 1,
                actual: subset_masters.len(),
            },
        )?;
        let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
            self.parameter_identity,
            self.preparation_context,
            self.zero_sharing_catalog_identity,
            subset_master.scope().subset(),
            basis_position,
            self.total_field_count,
        )?;
        let field_chunk = generate_pseudorandom_zero_sharing_field_chunk_320(
            subset_master,
            coordinate,
            self.current_chunk_index,
        )?;
        if field_chunk.field_count()
            != u64::try_from(self.accumulator.len())
                .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?
        {
            return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch {
                field: "accumulator field count",
            });
        }
        let basis_weight = self.basis_weights[usize::try_from(self.next_stream_index)
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?];
        for field_position in 0..field_chunk.field_count() {
            let mut generated_field = field_chunk.field_element(field_position)?;
            let mut weighted_field = generated_field.multiply(basis_weight);
            let accumulator_position = usize::try_from(field_position)
                .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
            self.accumulator[accumulator_position] = if self.next_stream_index == 0 {
                weighted_field
            } else {
                self.accumulator[accumulator_position].add(weighted_field)
            };
            generated_field.zeroize();
            weighted_field.zeroize();
        }

        let completed_stream_index = self.next_stream_index;
        self.next_stream_index = self
            .next_stream_index
            .checked_add(1)
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
        let completed_chunk = self.next_stream_index == self.basis_stream_count;
        if completed_chunk {
            self.state = PseudorandomZeroSharingCursorState320::CompletedChunkReady;
        }
        Ok(PseudorandomZeroSharingCursorStep320 {
            chunk_index: self.current_chunk_index,
            stream_index: completed_stream_index,
            completed_chunk,
        })
    }

    pub(crate) fn completed_chunk_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingCursorError320> {
        if self.state != PseudorandomZeroSharingCursorState320::CompletedChunkReady {
            return Err(
                PseudorandomZeroSharingCursorError320::CompletedChunkUnavailable {
                    state: self.state,
                },
            );
        }
        encode_field_elements(&self.accumulator)
    }

    /// Advances only after the caller has durably retained the completed local
    /// output chunk. This in-memory acknowledgement does not itself prove that
    /// persistence, recency reconciliation, or physical reclamation occurred.
    pub(crate) fn acknowledge_completed_chunk(
        &mut self,
    ) -> Result<PseudorandomZeroSharingCursorState320, PseudorandomZeroSharingCursorError320> {
        if self.state != PseudorandomZeroSharingCursorState320::CompletedChunkReady {
            return Err(
                PseudorandomZeroSharingCursorError320::CompletedChunkUnavailable {
                    state: self.state,
                },
            );
        }
        let output_chunk_count = self.output_chunk_count()?;
        self.current_chunk_index = self
            .current_chunk_index
            .checked_add(1)
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
        self.next_stream_index = 0;
        if self.current_chunk_index == output_chunk_count {
            self.accumulator.zeroize();
            self.accumulator = Zeroizing::new(Vec::new());
            self.state = PseudorandomZeroSharingCursorState320::Finished;
        } else {
            self.accumulator =
                zero_accumulator_for_chunk(self.total_field_count, self.current_chunk_index)?;
            self.state = PseudorandomZeroSharingCursorState320::Processing;
        }
        Ok(self.state)
    }

    pub(crate) fn checkpoint_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingCursorError320> {
        let accumulator_bytes = encode_field_elements(&self.accumulator)?;
        let mut checkpoint_body = Zeroizing::new(Vec::with_capacity(
            usize::try_from(checkpoint_record_byte_length(
                self.preparation_context.participant_count(),
                self.participant_position,
                self.total_field_count,
                self.current_chunk_index,
                self.next_stream_index,
                u64::try_from(accumulator_bytes.len())
                    .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?,
            )?)
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?,
        ));
        append_framed_bytes(
            &mut checkpoint_body,
            PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_DOMAIN,
        );
        append_varuint(&mut checkpoint_body, CHECKPOINT_VERSION);
        append_framed_bytes(&mut checkpoint_body, self.parameter_identity.as_bytes());
        append_framed_bytes(
            &mut checkpoint_body,
            self.preparation_context.identity().as_bytes(),
        );
        append_framed_bytes(
            &mut checkpoint_body,
            self.zero_sharing_catalog_identity.as_bytes(),
        );
        append_varuint(
            &mut checkpoint_body,
            u64::from(self.preparation_context.participant_count()),
        );
        append_varuint(&mut checkpoint_body, u64::from(self.participant_position));
        append_varuint(&mut checkpoint_body, self.total_field_count);
        append_varuint(&mut checkpoint_body, self.current_chunk_index);
        append_varuint(&mut checkpoint_body, self.next_stream_index);
        append_varuint(&mut checkpoint_body, self.state as u64);
        append_framed_bytes(&mut checkpoint_body, &accumulator_bytes);

        let checkpoint_tag =
            authenticate_checkpoint_body(&self.checkpoint_authentication_key, &checkpoint_body);
        checkpoint_body.extend_from_slice(checkpoint_tag.as_ref());
        let maximum_byte_length = FOUNDATION_PROFILE.maximum_copied_buffer_byte_length;
        if checkpoint_body.len() > maximum_byte_length {
            return Err(
                PseudorandomZeroSharingCursorError320::CheckpointByteLengthExceedsCopiedBufferLimit {
                    byte_length: u64::try_from(checkpoint_body.len()).map_err(|_| {
                        PseudorandomZeroSharingCursorError320::IntegerConversion
                    })?,
                    maximum_byte_length: u64::try_from(maximum_byte_length).map_err(|_| {
                        PseudorandomZeroSharingCursorError320::IntegerConversion
                    })?,
                },
            );
        }
        Ok(checkpoint_body)
    }

    fn restore_checkpoint_state(
        &mut self,
        checkpoint_bytes: &[u8],
    ) -> Result<(), PseudorandomZeroSharingCursorError320> {
        if checkpoint_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || checkpoint_bytes.len() < CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH
        {
            return Err(PseudorandomZeroSharingCursorError320::CheckpointEncoding);
        }
        let body_byte_length = checkpoint_bytes
            .len()
            .checked_sub(CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH)
            .ok_or(PseudorandomZeroSharingCursorError320::CheckpointEncoding)?;
        let (checkpoint_body, supplied_tag) = checkpoint_bytes.split_at(body_byte_length);
        let expected_tag =
            authenticate_checkpoint_body(&self.checkpoint_authentication_key, checkpoint_body);
        if !bool::from(expected_tag.as_ref().ct_eq(supplied_tag)) {
            return Err(PseudorandomZeroSharingCursorError320::CheckpointAuthenticationFailed);
        }

        let mut reader = CanonicalReader::new(checkpoint_body);
        require_framed_bytes(
            &mut reader,
            PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_DOMAIN,
            "domain",
        )?;
        require_varuint(&mut reader, CHECKPOINT_VERSION, "version")?;
        require_framed_bytes(
            &mut reader,
            self.parameter_identity.as_bytes(),
            "parameter identity",
        )?;
        require_framed_bytes(
            &mut reader,
            self.preparation_context.identity().as_bytes(),
            "preparation context identity",
        )?;
        require_framed_bytes(
            &mut reader,
            self.zero_sharing_catalog_identity.as_bytes(),
            "zero-sharing catalog identity",
        )?;
        require_varuint(
            &mut reader,
            u64::from(self.preparation_context.participant_count()),
            "participant count",
        )?;
        require_varuint(
            &mut reader,
            u64::from(self.participant_position),
            "participant position",
        )?;
        require_varuint(&mut reader, self.total_field_count, "total field count")?;
        let current_chunk_index = read_varuint(&mut reader)?;
        let next_stream_index = read_varuint(&mut reader)?;
        let state = match read_varuint(&mut reader)? {
            value if value == PseudorandomZeroSharingCursorState320::Processing as u64 => {
                PseudorandomZeroSharingCursorState320::Processing
            }
            value if value == PseudorandomZeroSharingCursorState320::CompletedChunkReady as u64 => {
                PseudorandomZeroSharingCursorState320::CompletedChunkReady
            }
            value if value == PseudorandomZeroSharingCursorState320::Finished as u64 => {
                PseudorandomZeroSharingCursorState320::Finished
            }
            _ => {
                return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch {
                    field: "state",
                });
            }
        };
        let accumulator_bytes = read_framed_slice(&mut reader)?;
        if !reader.is_finished() {
            return Err(PseudorandomZeroSharingCursorError320::CheckpointEncoding);
        }

        let output_chunk_count = self.output_chunk_count()?;
        let expected_accumulator_field_count = match state {
            PseudorandomZeroSharingCursorState320::Processing => {
                if current_chunk_index >= output_chunk_count
                    || next_stream_index >= self.basis_stream_count
                {
                    return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch {
                        field: "processing coordinate",
                    });
                }
                field_count_for_chunk(self.total_field_count, current_chunk_index)?
            }
            PseudorandomZeroSharingCursorState320::CompletedChunkReady => {
                if current_chunk_index >= output_chunk_count
                    || next_stream_index != self.basis_stream_count
                {
                    return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch {
                        field: "completed-chunk coordinate",
                    });
                }
                field_count_for_chunk(self.total_field_count, current_chunk_index)?
            }
            PseudorandomZeroSharingCursorState320::Finished => {
                if current_chunk_index != output_chunk_count || next_stream_index != 0 {
                    return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch {
                        field: "finished coordinate",
                    });
                }
                0
            }
        };
        let expected_accumulator_byte_length = checked_multiply_u64(
            expected_accumulator_field_count,
            u64::try_from(BinaryFieldElement320::CANONICAL_BYTE_LENGTH)
                .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?,
        )?;
        if u64::try_from(accumulator_bytes.len())
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?
            != expected_accumulator_byte_length
        {
            return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch {
                field: "accumulator byte length",
            });
        }
        let accumulator = decode_field_elements(accumulator_bytes)?;

        self.current_chunk_index = current_chunk_index;
        self.next_stream_index = next_stream_index;
        self.state = state;
        self.accumulator = accumulator;
        Ok(())
    }
}

impl fmt::Debug for PseudorandomZeroSharingParticipantCursor320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingParticipantCursor320")
            .field("parameter_identity", &self.parameter_identity)
            .field(
                "preparation_context_identity",
                &self.preparation_context.identity(),
            )
            .field(
                "zero_sharing_catalog_identity",
                &self.zero_sharing_catalog_identity,
            )
            .field("participant_position", &self.participant_position)
            .field("total_field_count", &self.total_field_count)
            .field("basis_stream_count", &self.basis_stream_count)
            .field("current_chunk_index", &self.current_chunk_index)
            .field("next_stream_index", &self.next_stream_index)
            .field("state", &self.state)
            .field("basis_weight_count", &self.basis_weights.len())
            .field("checkpoint_authentication_key", &"[redacted]")
            .field("accumulator", &"[redacted]")
            .finish()
    }
}

fn validate_masters_and_basis_weights(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    participant_position: u16,
    subset_masters: &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320],
) -> Result<(u16, Vec<BinaryFieldElement320>), PseudorandomZeroSharingCursorError320> {
    validate_master_scopes(
        parameter_identity,
        preparation_context,
        participant_position,
        subset_masters,
    )?;
    let basis_position_count = subset_masters
        .first()
        .ok_or(PseudorandomZeroSharingCursorError320::MasterCountMismatch {
            expected: 1,
            actual: 0,
        })?
        .scope()
        .subset()
        .active_fault_bound();
    if basis_position_count == 0 {
        return Err(TallyPreparationError::GeometryMismatch.into());
    }
    let evaluation_point = canonical_evaluation_point_320(
        preparation_context.participant_count(),
        participant_position,
    )?;
    let capacity = subset_masters
        .len()
        .checked_mul(usize::from(basis_position_count))
        .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
    let mut basis_weights = Vec::with_capacity(capacity);
    for master in subset_masters {
        basis_weights.extend(pseudorandom_zero_sharing_basis_values_at_point(
            master.scope().subset(),
            evaluation_point,
        )?);
    }
    Ok((basis_position_count, basis_weights))
}

fn validate_master_scopes(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    participant_position: u16,
    subset_masters: &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320],
) -> Result<(), PseudorandomZeroSharingCursorError320> {
    if participant_position >= preparation_context.participant_count() {
        return Err(TallyPreparationError::RosterPositionOutOfRange {
            roster_position: participant_position,
            participant_count: preparation_context.participant_count(),
        }
        .into());
    }
    let expected_subsets =
        ReplicatedRandomSharingSubset::iter(preparation_context.participant_count())?
            .filter_map(|subset| match subset.contains(participant_position) {
                Ok(true) => Some(Ok(subset)),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
    if subset_masters.len() != expected_subsets.len() {
        return Err(PseudorandomZeroSharingCursorError320::MasterCountMismatch {
            expected: expected_subsets.len(),
            actual: subset_masters.len(),
        });
    }
    for (master_index, (master, expected_subset)) in
        subset_masters.iter().zip(expected_subsets).enumerate()
    {
        let scope = master.scope();
        if scope.parameter_identity() != parameter_identity
            || scope.preparation_context_identity() != preparation_context.identity()
            || scope.subset() != expected_subset
        {
            return Err(PseudorandomZeroSharingCursorError320::MasterScopeMismatch {
                master_index,
            });
        }
        if !scope.subset().contains(participant_position)? {
            return Err(
                PseudorandomZeroSharingCursorError320::MasterSubsetExcludesParticipant {
                    master_index,
                    participant_position,
                },
            );
        }
    }
    Ok(())
}

fn derive_checkpoint_authentication_key(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    zero_sharing_catalog_identity: Hash512,
    participant_position: u16,
    subset_masters: &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320],
) -> Result<
    Zeroizing<[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH]>,
    PseudorandomZeroSharingCursorError320,
> {
    let first_master = subset_masters.first().ok_or(
        PseudorandomZeroSharingCursorError320::MasterCountMismatch {
            expected: 1,
            actual: 0,
        },
    )?;
    let mut derivation = initialize_kmac256(
        first_master.as_bytes(),
        PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_KEY_CUSTOMIZATION,
    );
    derivation.update(&CHECKPOINT_VERSION.to_le_bytes());
    derivation.update(parameter_identity.as_bytes());
    derivation.update(preparation_context.identity().as_bytes());
    derivation.update(zero_sharing_catalog_identity.as_bytes());
    derivation.update(&preparation_context.participant_count().to_le_bytes());
    derivation.update(&participant_position.to_le_bytes());
    derivation.update(
        &u64::try_from(subset_masters.len())
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?
            .to_le_bytes(),
    );
    for master in subset_masters {
        derivation.update(
            &master
                .scope()
                .subset()
                .excluded_position_mask()
                .to_le_bytes(),
        );
        derivation.update(master.as_bytes());
    }
    derivation.update(&KMAC320_OUTPUT_BIT_LENGTH);
    let mut authentication_key =
        Zeroizing::new([0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH]);
    derivation.finalize_xof().read(authentication_key.as_mut());
    Ok(authentication_key)
}

fn authenticate_checkpoint_body(
    authentication_key: &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH],
    checkpoint_body: &[u8],
) -> Zeroizing<[u8; CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH]> {
    let mut authentication = initialize_kmac256(
        authentication_key,
        PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_TAG_CUSTOMIZATION,
    );
    authentication.update(checkpoint_body);
    authentication.update(&KMAC512_OUTPUT_BIT_LENGTH);
    let mut tag = Zeroizing::new([0_u8; CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH]);
    authentication.finalize_xof().read(tag.as_mut());
    tag
}

fn initialize_kmac256(
    key: &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH],
    customization: &[u8],
) -> CShake256 {
    let mut padded_key = Zeroizing::new([0_u8; CSHAKE256_RATE_BYTE_LENGTH]);
    let encoded_key_start = ENCODED_CSHAKE256_RATE.len();
    let key_start = encoded_key_start + ENCODED_SUBSET_MASTER_BIT_LENGTH.len();
    let key_end = key_start + key.len();
    padded_key[..encoded_key_start].copy_from_slice(&ENCODED_CSHAKE256_RATE);
    padded_key[encoded_key_start..key_start].copy_from_slice(&ENCODED_SUBSET_MASTER_BIT_LENGTH);
    padded_key[key_start..key_end].copy_from_slice(key);

    let mut kmac = CShake256::from_core(CShake256Core::new_with_function_name(
        b"KMAC",
        customization,
    ));
    kmac.update(padded_key.as_ref());
    kmac
}

fn zero_accumulator_for_chunk(
    total_field_count: u64,
    chunk_index: u64,
) -> Result<Zeroizing<Vec<BinaryFieldElement320>>, PseudorandomZeroSharingCursorError320> {
    let field_count = field_count_for_chunk(total_field_count, chunk_index)?;
    let field_count = usize::try_from(field_count)
        .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
    Ok(Zeroizing::new(vec![
        BinaryFieldElement320::ZERO;
        field_count
    ]))
}

fn field_count_for_chunk(
    total_field_count: u64,
    chunk_index: u64,
) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    let chunk_count = pseudorandom_zero_sharing_field_chunk_count(total_field_count)?;
    if chunk_index >= chunk_count {
        return Err(
            TallyPreparationError::PseudorandomZeroSharingFieldStreamChunkOutOfRange {
                chunk_index,
                chunk_count,
            }
            .into(),
        );
    }
    let fields_per_chunk = pseudorandom_zero_sharing_field_elements_per_chunk()?;
    let first_field_index = checked_multiply_u64(chunk_index, fields_per_chunk)?;
    Ok(total_field_count
        .checked_sub(first_field_index)
        .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?
        .min(fields_per_chunk))
}

fn encode_field_elements(
    field_elements: &[BinaryFieldElement320],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingCursorError320> {
    let byte_length = field_elements
        .len()
        .checked_mul(BinaryFieldElement320::CANONICAL_BYTE_LENGTH)
        .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(byte_length));
    for field_element in field_elements {
        bytes.extend_from_slice(&field_element.canonical_bytes());
    }
    Ok(bytes)
}

fn decode_field_elements(
    bytes: &[u8],
) -> Result<Zeroizing<Vec<BinaryFieldElement320>>, PseudorandomZeroSharingCursorError320> {
    if !bytes
        .len()
        .is_multiple_of(BinaryFieldElement320::CANONICAL_BYTE_LENGTH)
    {
        return Err(PseudorandomZeroSharingCursorError320::CheckpointEncoding);
    }
    let mut field_elements = Zeroizing::new(Vec::with_capacity(
        bytes.len() / BinaryFieldElement320::CANONICAL_BYTE_LENGTH,
    ));
    for field_bytes in bytes.chunks_exact(BinaryFieldElement320::CANONICAL_BYTE_LENGTH) {
        field_elements.push(BinaryFieldElement320::from_canonical_bytes(field_bytes)?);
    }
    Ok(field_elements)
}

fn append_varuint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn append_framed_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    append_varuint(output, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

fn read_varuint(
    reader: &mut CanonicalReader<'_>,
) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    reader
        .read_varuint()
        .map_err(|_| PseudorandomZeroSharingCursorError320::CheckpointEncoding)
}

fn read_framed_slice<'a>(
    reader: &mut CanonicalReader<'a>,
) -> Result<&'a [u8], PseudorandomZeroSharingCursorError320> {
    let byte_length = usize::try_from(read_varuint(reader)?)
        .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
    reader
        .read_exact(byte_length)
        .map_err(|_| PseudorandomZeroSharingCursorError320::CheckpointEncoding)
}

fn require_framed_bytes(
    reader: &mut CanonicalReader<'_>,
    expected: &[u8],
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingCursorError320> {
    if read_framed_slice(reader)? != expected {
        return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch { field });
    }
    Ok(())
}

fn require_varuint(
    reader: &mut CanonicalReader<'_>,
    expected: u64,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingCursorError320> {
    if read_varuint(reader)? != expected {
        return Err(PseudorandomZeroSharingCursorError320::CheckpointMismatch { field });
    }
    Ok(())
}

fn checkpoint_record_byte_length(
    participant_count: u16,
    participant_position: u16,
    total_field_count: u64,
    current_chunk_index: u64,
    next_stream_index: u64,
    accumulator_byte_length: u64,
) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    let domain_byte_length =
        u64::try_from(PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_DOMAIN.len())
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
    let hash_byte_length = u64::try_from(Hash512::BYTE_LENGTH)
        .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
    let authentication_tag_byte_length =
        u64::try_from(CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH)
            .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?;
    checked_sum_u64(&[
        framed_byte_length(domain_byte_length)?,
        varuint_byte_length(CHECKPOINT_VERSION),
        framed_byte_length(hash_byte_length)?,
        framed_byte_length(hash_byte_length)?,
        framed_byte_length(hash_byte_length)?,
        varuint_byte_length(u64::from(participant_count)),
        varuint_byte_length(u64::from(participant_position)),
        varuint_byte_length(total_field_count),
        varuint_byte_length(current_chunk_index),
        varuint_byte_length(next_stream_index),
        varuint_byte_length(PseudorandomZeroSharingCursorState320::Processing as u64),
        framed_byte_length(accumulator_byte_length)?,
        authentication_tag_byte_length,
    ])
}

fn framed_byte_length(
    payload_byte_length: u64,
) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    checked_add_u64(
        varuint_byte_length(payload_byte_length),
        payload_byte_length,
    )
}

const fn varuint_byte_length(mut value: u64) -> u64 {
    let mut byte_length = 1_u64;
    while value >= 0x80 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

fn sum_varuint_byte_lengths(
    first_value: u64,
    final_value: u64,
) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    if first_value > final_value {
        return Ok(0);
    }
    let mut sum = 0_u64;
    let mut range_start = first_value;
    let mut byte_length = varuint_byte_length(first_value);
    loop {
        let next_boundary = if byte_length >= 10 {
            u64::MAX
        } else {
            1_u64
                .checked_shl(
                    u32::try_from(byte_length * 7)
                        .map_err(|_| PseudorandomZeroSharingCursorError320::IntegerConversion)?,
                )
                .unwrap_or(u64::MAX)
        };
        let range_end = final_value.min(next_boundary.saturating_sub(1));
        let range_count = range_end
            .checked_sub(range_start)
            .and_then(|value| value.checked_add(1))
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
        sum = checked_add_u64(sum, checked_multiply_u64(range_count, byte_length)?)?;
        if range_end == final_value {
            return Ok(sum);
        }
        range_start = next_boundary;
        byte_length = byte_length
            .checked_add(1)
            .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)?;
    }
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    left.checked_add(right)
        .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)
}

fn checked_multiply_u64(
    left: u64,
    right: u64,
) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    left.checked_mul(right)
        .ok_or(PseudorandomZeroSharingCursorError320::ArithmeticOverflow)
}

fn checked_sum_u64(values: &[u64]) -> Result<u64, PseudorandomZeroSharingCursorError320> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add_u64(sum, *value))
}
