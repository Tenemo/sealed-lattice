//! Inputs for reducing a caller-owned committed linear relation with HVZK-WHIR.
//!
//! The outer protocol commits these mask groups before it samples the
//! relation-batching challenge. WHIR must therefore carry the existing
//! commitments and their linear claims into the base case without observing
//! the roots a second time.
//!
//! Local modification. See `../../../UPSTREAM.md`.

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{ExtensionField, TwoAdicField};
use p3_multilinear_util::poly::Poly;
use thiserror::Error;

use super::base_case::MaskProverData;
use super::mask::MaskGroupShape;

/// Prover-owned state for one mask group committed by an outer reduction.
pub struct PrecommittedMaskProverGroup<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Shared code shape and number of interleaved masks.
    pub shape: MaskGroupShape,
    /// Secret messages, in the group's committed column order.
    pub messages: Vec<Vec<EF>>,
    /// Encoding randomness corresponding to each message.
    pub randomness: Vec<Vec<EF>>,
    /// Batched linear covector corresponding to each message.
    pub covectors: Vec<Vec<EF>>,
    /// Merkle prover data created with the outer commitment.
    pub data: MaskProverData<F, EF, MT>,
}

/// Verifier-owned state for one mask group committed by an outer reduction.
pub struct PrecommittedMaskVerifierGroup<EF, Commitment> {
    /// Shared code shape and number of interleaved masks.
    pub shape: MaskGroupShape,
    /// Batched linear covector corresponding to each committed mask.
    pub covectors: Vec<Vec<EF>>,
    /// Commitment already observed by the outer transcript.
    pub commitment: Commitment,
}

/// One already-batched committed relation supplied to the prover.
///
/// The caller constructs this value after WHIR samples the batching challenge.
/// Its target must equal the source term plus every precommitted-mask term.
pub struct CombinedRelationProverInput<F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Dense covector paired with the committed source message.
    pub source_covector: Poly<EF>,
    /// Batched right-hand side of the committed relation.
    pub target: EF,
    /// Outer mask groups in their original commitment order.
    pub precommitted_mask_groups: Vec<PrecommittedMaskProverGroup<F, EF, MT>>,
}

/// One already-batched committed relation supplied to the verifier.
pub struct CombinedRelationVerifierInput<EF, Commitment> {
    /// Dense covector paired with the committed source message.
    pub source_covector: Poly<EF>,
    /// Batched right-hand side of the committed relation.
    pub target: EF,
    /// Outer mask groups in their original commitment order.
    pub precommitted_mask_groups: Vec<PrecommittedMaskVerifierGroup<EF, Commitment>>,
}

/// Malformed caller-owned relation input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HidingWhirRelationInputError {
    /// The source covector does not span the committed multilinear table.
    #[error("source covector length mismatch: expected {expected}, got {actual}")]
    SourceCovectorLengthMismatch { expected: usize, actual: usize },

    /// A mask group has no committed columns.
    #[error("precommitted mask group {group} has zero width")]
    EmptyMaskGroup { group: usize },

    /// The mask code cannot contain its message and encoding randomness.
    #[error(
        "precommitted mask group {group} has invalid code shape: message {message_length}, randomness {randomness_length}, domain {domain_size}"
    )]
    InvalidMaskCodeShape {
        group: usize,
        message_length: usize,
        randomness_length: usize,
        domain_size: usize,
    },

    /// The prover-side arrays do not contain exactly one entry per column.
    #[error(
        "precommitted mask group {group} width mismatch: expected {expected}, messages {message_count}, randomness {randomness_count}, covectors {covector_count}"
    )]
    ProverMaskGroupWidthMismatch {
        group: usize,
        expected: usize,
        message_count: usize,
        randomness_count: usize,
        covector_count: usize,
    },

    /// The verifier-side covector list does not contain one entry per column.
    #[error(
        "precommitted mask group {group} covector count mismatch: expected {expected}, got {actual}"
    )]
    VerifierMaskGroupWidthMismatch {
        group: usize,
        expected: usize,
        actual: usize,
    },

    /// A mask message has the wrong number of coefficients.
    #[error(
        "precommitted mask group {group}, member {member}: message length mismatch: expected {expected}, got {actual}"
    )]
    MaskMessageLengthMismatch {
        group: usize,
        member: usize,
        expected: usize,
        actual: usize,
    },

    /// A mask randomness vector has the wrong number of coefficients.
    #[error(
        "precommitted mask group {group}, member {member}: randomness length mismatch: expected {expected}, got {actual}"
    )]
    MaskRandomnessLengthMismatch {
        group: usize,
        member: usize,
        expected: usize,
        actual: usize,
    },

    /// A mask covector does not span the corresponding message.
    #[error(
        "precommitted mask group {group}, member {member}: covector length mismatch: expected {expected}, got {actual}"
    )]
    MaskCovectorLengthMismatch {
        group: usize,
        member: usize,
        expected: usize,
        actual: usize,
    },
}

pub(super) fn validate_source_covector<EF>(
    source_covector: &Poly<EF>,
    expected_length: usize,
) -> Result<(), HidingWhirRelationInputError> {
    if source_covector.num_evals() != expected_length {
        return Err(HidingWhirRelationInputError::SourceCovectorLengthMismatch {
            expected: expected_length,
            actual: source_covector.num_evals(),
        });
    }
    Ok(())
}

pub(super) fn validate_mask_shape(
    group: usize,
    shape: MaskGroupShape,
) -> Result<(), HidingWhirRelationInputError> {
    if shape.width == 0 {
        return Err(HidingWhirRelationInputError::EmptyMaskGroup { group });
    }
    if !shape.shape.domain_size.is_power_of_two()
        || shape.shape.message_len == 0
        || shape.shape.randomness_len == 0
        || shape.shape.message_len + shape.shape.randomness_len > shape.shape.domain_size
    {
        return Err(HidingWhirRelationInputError::InvalidMaskCodeShape {
            group,
            message_length: shape.shape.message_len,
            randomness_length: shape.shape.randomness_len,
            domain_size: shape.shape.domain_size,
        });
    }
    Ok(())
}
