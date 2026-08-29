use core::fmt;

use crate::foundation::Hash512;

use super::{
    TallyPreparationError,
    pseudorandom_zero_sharing_320::{
        PseudorandomZeroSharingResourceInput, PseudorandomZeroSharingResourceModel,
    },
    pseudorandom_zero_sharing_field_stream_320::{
        PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION,
        PSEUDORANDOM_ZERO_SHARING_FIELD_STREAM_QUERY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_participant_cursor_320::{
        CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_KEY_CUSTOMIZATION,
        PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_TAG_CUSTOMIZATION,
        PseudorandomZeroSharingCursorError320, PseudorandomZeroSharingCursorResourceModel320,
    },
    pseudorandom_zero_sharing_seed_mailbox_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
    },
    replicated_random_sharing::ReplicatedRandomSharingGeometry,
};

const CSHAKE256_RATE_BYTE_LENGTH: u64 = 136;
const KMAC_FUNCTION_NAME: &[u8] = b"KMAC";
const PRIVATE_MAILBOX_KEY_BYTE_LENGTH: u64 = 32;
const PRIVATE_MAILBOX_KEY_OUTPUT_BYTE_LENGTH: u64 = 32;
const PRIVATE_MAILBOX_NONCE_OUTPUT_BYTE_LENGTH: u64 = 12;
const CHECKPOINT_VERSION_BYTE_LENGTH: u64 = 8;
const CHECKPOINT_SCOPE_HASH_COUNT: u64 = 3;
const CHECKPOINT_PARTICIPANT_COUNT_BYTE_LENGTH: u64 = 2;
const CHECKPOINT_PARTICIPANT_POSITION_BYTE_LENGTH: u64 = 2;
const CHECKPOINT_MASTER_COUNT_BYTE_LENGTH: u64 = 8;
const CHECKPOINT_SUBSET_MASK_BYTE_LENGTH: u64 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreparationKmacCallCensusError320 {
    TallyPreparation(TallyPreparationError),
    Cursor(PseudorandomZeroSharingCursorError320),
    ArithmeticOverflow,
    IntegerConversion,
}

impl fmt::Display for PreparationKmacCallCensusError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TallyPreparation(error) => write!(formatter, "{error}"),
            Self::Cursor(error) => write!(formatter, "{error}"),
            Self::ArithmeticOverflow => formatter.write_str("KMAC call census arithmetic overflow"),
            Self::IntegerConversion => {
                formatter.write_str("KMAC call census integer conversion failed")
            }
        }
    }
}

impl std::error::Error for PreparationKmacCallCensusError320 {}

impl From<TallyPreparationError> for PreparationKmacCallCensusError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::TallyPreparation(error)
    }
}

impl From<PseudorandomZeroSharingCursorError320> for PreparationKmacCallCensusError320 {
    fn from(error: PseudorandomZeroSharingCursorError320) -> Self {
        Self::Cursor(error)
    }
}

/// Exact framing and scalar Keccak-f[1600] work for one emitted KMAC call.
///
/// The count includes the cSHAKE function-name/customization bytepad, the KMAC
/// key bytepad, the final padded message block, and every squeeze block. It is
/// an operation census only and does not assert pseudorandomness of fixed
/// Keccak-f[1600].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KmacCallShape320 {
    pub(crate) customization_byte_length: u64,
    pub(crate) key_byte_length: u64,
    pub(crate) message_byte_length: u64,
    pub(crate) right_encoded_output_length_byte_length: u64,
    pub(crate) output_byte_length: u64,
    pub(crate) absorb_block_count: u64,
    pub(crate) squeeze_block_count: u64,
    pub(crate) permutation_count: u64,
}

impl KmacCallShape320 {
    fn fixed_output(
        customization: &[u8],
        key_byte_length: u64,
        message_byte_length: u64,
        output_byte_length: u64,
    ) -> Result<Self, PreparationKmacCallCensusError320> {
        let output_bit_length = checked_multiply(output_byte_length, 8)?;
        Self::derive(
            customization,
            key_byte_length,
            message_byte_length,
            right_encode_byte_length(output_bit_length),
            output_byte_length,
        )
    }

    fn extendable_output(
        customization: &[u8],
        key_byte_length: u64,
        message_byte_length: u64,
        output_byte_length: u64,
    ) -> Result<Self, PreparationKmacCallCensusError320> {
        Self::derive(
            customization,
            key_byte_length,
            message_byte_length,
            right_encode_byte_length(0),
            output_byte_length,
        )
    }

    fn derive(
        customization: &[u8],
        key_byte_length: u64,
        message_byte_length: u64,
        right_encoded_output_length_byte_length: u64,
        output_byte_length: u64,
    ) -> Result<Self, PreparationKmacCallCensusError320> {
        let customization_byte_length = u64::try_from(customization.len())
            .map_err(|_| PreparationKmacCallCensusError320::IntegerConversion)?;
        let function_name_byte_length = u64::try_from(KMAC_FUNCTION_NAME.len())
            .map_err(|_| PreparationKmacCallCensusError320::IntegerConversion)?;
        let function_name_bit_length = checked_multiply(function_name_byte_length, 8)?;
        let customization_bit_length = checked_multiply(customization_byte_length, 8)?;
        let key_bit_length = checked_multiply(key_byte_length, 8)?;
        let cshake_prefix_unpadded_byte_length = checked_sum(&[
            left_encode_byte_length(CSHAKE256_RATE_BYTE_LENGTH),
            encode_string_byte_length(function_name_byte_length, function_name_bit_length)?,
            encode_string_byte_length(customization_byte_length, customization_bit_length)?,
        ])?;
        let key_prefix_unpadded_byte_length = checked_sum(&[
            left_encode_byte_length(CSHAKE256_RATE_BYTE_LENGTH),
            encode_string_byte_length(key_byte_length, key_bit_length)?,
        ])?;
        let cshake_prefix_absorb_block_count = checked_ceiling_divide(
            cshake_prefix_unpadded_byte_length,
            CSHAKE256_RATE_BYTE_LENGTH,
        )?;
        let key_prefix_absorb_block_count =
            checked_ceiling_divide(key_prefix_unpadded_byte_length, CSHAKE256_RATE_BYTE_LENGTH)?;
        let final_message_absorb_block_count = checked_add(
            checked_sum(&[message_byte_length, right_encoded_output_length_byte_length])?
                / CSHAKE256_RATE_BYTE_LENGTH,
            1,
        )?;
        let absorb_block_count = checked_sum(&[
            cshake_prefix_absorb_block_count,
            key_prefix_absorb_block_count,
            final_message_absorb_block_count,
        ])?;
        let squeeze_block_count =
            checked_ceiling_divide(output_byte_length, CSHAKE256_RATE_BYTE_LENGTH)?;
        let permutation_count = checked_sum(&[absorb_block_count, squeeze_block_count])?
            .checked_sub(1)
            .ok_or(PreparationKmacCallCensusError320::ArithmeticOverflow)?;
        Ok(Self {
            customization_byte_length,
            key_byte_length,
            message_byte_length,
            right_encoded_output_length_byte_length,
            output_byte_length,
            absorb_block_count,
            squeeze_block_count,
            permutation_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RepeatedKmacCallShape320 {
    pub(crate) call: KmacCallShape320,
    pub(crate) semantic_call_count: u64,
    pub(crate) successful_physical_call_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VariableMessageKmacCallFamily320 {
    pub(crate) minimum_message_call: KmacCallShape320,
    pub(crate) maximum_message_call: KmacCallShape320,
    pub(crate) semantic_call_count: u64,
    pub(crate) successful_physical_call_count: u64,
    pub(crate) cumulative_message_byte_length: u64,
}

/// Current emitted preparation KMAC calls for one exact workload.
///
/// Semantic counts collapse byte-identical sender/recipient and replicated
/// holder evaluations. Physical counts include both mailbox endpoints and
/// every holder that locally expands a shared subset stream. One cold cursor
/// restore repeats the participant's checkpoint-key derivation and the tag
/// computation for the retained checkpoint; it adds no new semantic query.
/// The census excludes any not-yet-emitted pair, collective-challenge, or
/// selected hidden-bit protocol calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparationKmacCallCensus320 {
    pub(crate) participant_count: u64,
    pub(crate) zero_sharing_count: u64,
    pub(crate) seed_mailbox_key_derivation: RepeatedKmacCallShape320,
    pub(crate) seed_mailbox_nonce_derivation: RepeatedKmacCallShape320,
    pub(crate) full_field_stream_output: RepeatedKmacCallShape320,
    pub(crate) final_field_stream_output: RepeatedKmacCallShape320,
    pub(crate) checkpoint_key_derivation: RepeatedKmacCallShape320,
    pub(crate) checkpoint_tag: VariableMessageKmacCallFamily320,
    pub(crate) semantic_call_count: u64,
    pub(crate) successful_physical_call_count: u64,
    pub(crate) additional_physical_call_count_per_cold_restore: u64,
}

impl PreparationKmacCallCensus320 {
    pub(crate) fn derive(
        participant_count: u16,
        zero_sharing_count: u64,
    ) -> Result<Self, PreparationKmacCallCensusError320> {
        let participant_count_u64 = u64::from(participant_count);
        let sharing_geometry = ReplicatedRandomSharingGeometry::derive(participant_count)?;
        let source_model =
            PseudorandomZeroSharingResourceModel::derive(PseudorandomZeroSharingResourceInput {
                participant_count,
                zero_sharing_count,
            })?;

        let seed_mailbox_key_semantic_call_count = source_model.mailbox_sender_key_derivation_count;
        let seed_mailbox_nonce_semantic_call_count =
            source_model.mailbox_sender_nonce_derivation_count;
        let seed_mailbox_key_derivation = RepeatedKmacCallShape320 {
            call: KmacCallShape320::fixed_output(
                PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_LABEL,
                PRIVATE_MAILBOX_KEY_BYTE_LENGTH,
                usize_to_u64(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_KEY_DERIVATION_CONTEXT_BYTE_LENGTH,
                )?,
                PRIVATE_MAILBOX_KEY_OUTPUT_BYTE_LENGTH,
            )?,
            semantic_call_count: seed_mailbox_key_semantic_call_count,
            successful_physical_call_count: checked_multiply(
                seed_mailbox_key_semantic_call_count,
                2,
            )?,
        };
        let seed_mailbox_nonce_derivation = RepeatedKmacCallShape320 {
            call: KmacCallShape320::fixed_output(
                PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_NONCE_DERIVATION_LABEL,
                PRIVATE_MAILBOX_KEY_BYTE_LENGTH,
                usize_to_u64(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_CHUNK_ASSOCIATED_DATA_BYTE_LENGTH,
                )?,
                PRIVATE_MAILBOX_NONCE_OUTPUT_BYTE_LENGTH,
            )?,
            semantic_call_count: seed_mailbox_nonce_semantic_call_count,
            successful_physical_call_count: checked_multiply(
                seed_mailbox_nonce_semantic_call_count,
                2,
            )?,
        };

        let representative_cursor = PseudorandomZeroSharingCursorResourceModel320::derive(
            participant_count,
            0,
            zero_sharing_count,
        )?;
        let subset_basis_stream_count = checked_multiply(
            sharing_geometry.authorized_subset_count,
            sharing_geometry.active_fault_bound,
        )?;
        let preceding_full_chunk_count = representative_cursor
            .output_chunk_count
            .checked_sub(1)
            .ok_or(PreparationKmacCallCensusError320::ArithmeticOverflow)?;
        let full_field_stream_semantic_call_count =
            checked_multiply(subset_basis_stream_count, preceding_full_chunk_count)?;
        let final_field_stream_semantic_call_count = subset_basis_stream_count;
        let full_field_stream_output = RepeatedKmacCallShape320 {
            call: KmacCallShape320::extendable_output(
                PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_FIELD_STREAM_QUERY_BYTE_LENGTH)?,
                representative_cursor.full_chunk_payload_byte_length,
            )?,
            semantic_call_count: full_field_stream_semantic_call_count,
            successful_physical_call_count: checked_multiply(
                full_field_stream_semantic_call_count,
                sharing_geometry.authorized_subset_size,
            )?,
        };
        let final_field_stream_output = RepeatedKmacCallShape320 {
            call: KmacCallShape320::extendable_output(
                PSEUDORANDOM_FIELD_STREAM_CUSTOMIZATION,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_FIELD_STREAM_QUERY_BYTE_LENGTH)?,
                representative_cursor.final_chunk_payload_byte_length,
            )?,
            semantic_call_count: final_field_stream_semantic_call_count,
            successful_physical_call_count: checked_multiply(
                final_field_stream_semantic_call_count,
                sharing_geometry.authorized_subset_size,
            )?,
        };
        let physical_field_stream_call_count = checked_sum(&[
            full_field_stream_output.successful_physical_call_count,
            final_field_stream_output.successful_physical_call_count,
        ])?;
        let participant_cursor_field_stream_call_count = checked_multiply(
            representative_cursor.field_stream_kmacxof256_query_count,
            participant_count_u64,
        )?;
        if physical_field_stream_call_count != participant_cursor_field_stream_call_count {
            return Err(PreparationKmacCallCensusError320::TallyPreparation(
                TallyPreparationError::GeometryMismatch,
            ));
        }

        let checkpoint_key_message_byte_length = checkpoint_key_message_byte_length(
            sharing_geometry.authorized_subset_count_per_participant,
        )?;
        let checkpoint_key_derivation = RepeatedKmacCallShape320 {
            call: KmacCallShape320::fixed_output(
                PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_KEY_CUSTOMIZATION,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
                checkpoint_key_message_byte_length,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
            )?,
            semantic_call_count: participant_count_u64,
            successful_physical_call_count: participant_count_u64,
        };
        let checkpoint_tag_byte_length = usize_to_u64(CHECKPOINT_AUTHENTICATION_TAG_BYTE_LENGTH)?;
        let mut checkpoint_tag_semantic_call_count = 0_u64;
        let mut cumulative_checkpoint_body_byte_length = 0_u64;
        let mut minimum_checkpoint_body_byte_length = u64::MAX;
        let mut maximum_checkpoint_body_byte_length = 0_u64;
        for participant_position in 0..participant_count {
            let cursor = PseudorandomZeroSharingCursorResourceModel320::derive(
                participant_count,
                participant_position,
                zero_sharing_count,
            )?;
            checkpoint_tag_semantic_call_count = checked_add(
                checkpoint_tag_semantic_call_count,
                cursor.checkpoint_tag_generation_kmac256_count,
            )?;
            cumulative_checkpoint_body_byte_length = checked_add(
                cumulative_checkpoint_body_byte_length,
                cursor.cumulative_checkpoint_authenticated_body_byte_length,
            )?;
            minimum_checkpoint_body_byte_length = minimum_checkpoint_body_byte_length.min(
                cursor
                    .minimum_completed_step_checkpoint_byte_length
                    .checked_sub(checkpoint_tag_byte_length)
                    .ok_or(PreparationKmacCallCensusError320::ArithmeticOverflow)?,
            );
            maximum_checkpoint_body_byte_length = maximum_checkpoint_body_byte_length.max(
                cursor
                    .maximum_completed_step_checkpoint_byte_length
                    .checked_sub(checkpoint_tag_byte_length)
                    .ok_or(PreparationKmacCallCensusError320::ArithmeticOverflow)?,
            );
        }
        let checkpoint_tag = VariableMessageKmacCallFamily320 {
            minimum_message_call: KmacCallShape320::fixed_output(
                PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_TAG_CUSTOMIZATION,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
                minimum_checkpoint_body_byte_length,
                checkpoint_tag_byte_length,
            )?,
            maximum_message_call: KmacCallShape320::fixed_output(
                PSEUDORANDOM_ZERO_SHARING_CURSOR_CHECKPOINT_TAG_CUSTOMIZATION,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
                maximum_checkpoint_body_byte_length,
                checkpoint_tag_byte_length,
            )?,
            semantic_call_count: checkpoint_tag_semantic_call_count,
            successful_physical_call_count: checkpoint_tag_semantic_call_count,
            cumulative_message_byte_length: cumulative_checkpoint_body_byte_length,
        };

        let semantic_call_count = checked_sum(&[
            seed_mailbox_key_derivation.semantic_call_count,
            seed_mailbox_nonce_derivation.semantic_call_count,
            full_field_stream_output.semantic_call_count,
            final_field_stream_output.semantic_call_count,
            checkpoint_key_derivation.semantic_call_count,
            checkpoint_tag.semantic_call_count,
        ])?;
        let successful_physical_call_count = checked_sum(&[
            seed_mailbox_key_derivation.successful_physical_call_count,
            seed_mailbox_nonce_derivation.successful_physical_call_count,
            full_field_stream_output.successful_physical_call_count,
            final_field_stream_output.successful_physical_call_count,
            checkpoint_key_derivation.successful_physical_call_count,
            checkpoint_tag.successful_physical_call_count,
        ])?;

        Ok(Self {
            participant_count: participant_count_u64,
            zero_sharing_count,
            seed_mailbox_key_derivation,
            seed_mailbox_nonce_derivation,
            full_field_stream_output,
            final_field_stream_output,
            checkpoint_key_derivation,
            checkpoint_tag,
            semantic_call_count,
            successful_physical_call_count,
            additional_physical_call_count_per_cold_restore: 2,
        })
    }
}

fn checkpoint_key_message_byte_length(
    authorized_subset_count_per_participant: u64,
) -> Result<u64, PreparationKmacCallCensusError320> {
    checked_sum(&[
        CHECKPOINT_VERSION_BYTE_LENGTH,
        checked_multiply(
            CHECKPOINT_SCOPE_HASH_COUNT,
            usize_to_u64(Hash512::BYTE_LENGTH)?,
        )?,
        CHECKPOINT_PARTICIPANT_COUNT_BYTE_LENGTH,
        CHECKPOINT_PARTICIPANT_POSITION_BYTE_LENGTH,
        CHECKPOINT_MASTER_COUNT_BYTE_LENGTH,
        checked_multiply(
            authorized_subset_count_per_participant,
            checked_add(
                CHECKPOINT_SUBSET_MASK_BYTE_LENGTH,
                usize_to_u64(PSEUDORANDOM_ZERO_SHARING_SUBSET_MASTER_BYTE_LENGTH)?,
            )?,
        )?,
    ])
}

fn encode_string_byte_length(
    payload_byte_length: u64,
    payload_bit_length: u64,
) -> Result<u64, PreparationKmacCallCensusError320> {
    checked_add(
        left_encode_byte_length(payload_bit_length),
        payload_byte_length,
    )
}

const fn left_encode_byte_length(value: u64) -> u64 {
    integer_byte_length(value) + 1
}

const fn right_encode_byte_length(value: u64) -> u64 {
    integer_byte_length(value) + 1
}

const fn integer_byte_length(mut value: u64) -> u64 {
    let mut byte_length = 1_u64;
    while value > 0xff {
        value >>= 8;
        byte_length += 1;
    }
    byte_length
}

fn checked_ceiling_divide(
    dividend: u64,
    divisor: u64,
) -> Result<u64, PreparationKmacCallCensusError320> {
    if divisor == 0 {
        return Err(PreparationKmacCallCensusError320::ArithmeticOverflow);
    }
    checked_add(
        dividend / divisor,
        u64::from(!dividend.is_multiple_of(divisor)),
    )
}

fn checked_add(left: u64, right: u64) -> Result<u64, PreparationKmacCallCensusError320> {
    left.checked_add(right)
        .ok_or(PreparationKmacCallCensusError320::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, PreparationKmacCallCensusError320> {
    left.checked_mul(right)
        .ok_or(PreparationKmacCallCensusError320::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, PreparationKmacCallCensusError320> {
    values
        .iter()
        .try_fold(0_u64, |sum, value| checked_add(sum, *value))
}

fn usize_to_u64(value: usize) -> Result<u64, PreparationKmacCallCensusError320> {
    u64::try_from(value).map_err(|_| PreparationKmacCallCensusError320::IntegerConversion)
}
