//! Mask-claim bookkeeping for the HVZK-WHIR verifier replay.
//!
//! The symbolic counterpart of the prover's `ProverMasks`: the verifier
//! reconstructs the same mask covectors, group shapes, and commitments round
//! by round, then hands them to the base case.
//!
//! Local modification: caller-precommitted groups are replayed before WHIR's
//! internal groups. See `../../../../UPSTREAM.md`.

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};
use p3_multilinear_util::point::Point;
use p3_sumcheck::zk::mask_residual_covectors_from_shape;

use crate::pcs::zk::constraint::MaskClaims;
use crate::pcs::zk::mask::{MaskCodeShape, MaskGroupShape};
use crate::pcs::zk::relation::{
    HidingWhirRelationInputError, PrecommittedMaskVerifierGroup, validate_mask_shape,
};

/// Verifier-side mask state carried to the base case.
///
/// One covector, group shape, and commitment per mask oracle, in commit order.
pub(super) struct VerifierMasks<F, EF, MT>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Dense covectors with their accumulated scales.
    pub(super) claims: MaskClaims<EF>,
    /// Group widths and codes, in commit order.
    pub(super) groups: Vec<MaskGroupShape>,
    /// One commitment per mask group, matching `groups`.
    pub(super) commitments: Vec<MT::Commitment>,
}

impl<F, EF, MT> VerifierMasks<F, EF, MT>
where
    F: Field,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    pub(super) const fn new() -> Self {
        Self {
            claims: MaskClaims::new(),
            groups: Vec::new(),
            commitments: Vec::new(),
        }
    }

    /// Starts from mask commitments made by an outer reduction.
    pub(super) fn from_precommitted(
        groups: Vec<PrecommittedMaskVerifierGroup<EF, MT::Commitment>>,
    ) -> Result<Self, HidingWhirRelationInputError> {
        let mut masks = Self::new();
        for (group_ordinal, group) in groups.into_iter().enumerate() {
            validate_mask_shape(group_ordinal, group.shape)?;
            if group.covectors.len() != group.shape.width {
                return Err(
                    HidingWhirRelationInputError::VerifierMaskGroupWidthMismatch {
                        group: group_ordinal,
                        expected: group.shape.width,
                        actual: group.covectors.len(),
                    },
                );
            }
            for (member_ordinal, covector) in group.covectors.iter().enumerate() {
                if covector.len() != group.shape.shape.message_len {
                    return Err(HidingWhirRelationInputError::MaskCovectorLengthMismatch {
                        group: group_ordinal,
                        member: member_ordinal,
                        expected: group.shape.shape.message_len,
                        actual: covector.len(),
                    });
                }
                masks.claims.push(covector.clone());
            }
            masks.groups.push(group.shape);
            masks.commitments.push(group.commitment);
        }
        Ok(masks)
    }

    /// Records one masked sumcheck batch.
    ///
    /// The carried covectors absorb `eps * 2^{-k}`; the batch's `k` fresh
    /// sumcheck masks enter at scale one as power covectors of the round
    /// randomness.
    pub(super) fn record_sumcheck_batch(
        &mut self,
        eps: EF,
        folding: usize,
        ell_zk: usize,
        randomness: &Point<EF>,
        shape: MaskCodeShape,
        commitment: MT::Commitment,
    ) {
        self.claims.absorb_sumcheck(eps, folding);
        let gammas: Vec<EF> = randomness.iter().copied().collect();
        for covector in mask_residual_covectors_from_shape(folding, ell_zk, &gammas) {
            self.claims.push(covector);
        }
        self.groups.push(MaskGroupShape {
            shape,
            width: folding,
        });
        self.commitments.push(commitment);
    }

    /// Records one code-switch round's fresh mask as a width-one group.
    pub(super) fn push_switch_mask(
        &mut self,
        covector: Vec<EF>,
        shape: MaskCodeShape,
        commitment: MT::Commitment,
    ) {
        self.claims.push(covector);
        self.groups.push(MaskGroupShape { shape, width: 1 });
        self.commitments.push(commitment);
    }
}
