use super::super::{
    CLAIM_MASK_DIGIT_COUNT, CONSISTENCY_REPETITIONS, TRACE_SPLIT, invalid_succinct_setup_proof,
};
use super::statement_types::TrusteeEvaluationKeyStatement;
use crate::bgv::setup::commitment::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
    SETUP_COMMITMENT_ROW_COUNT,
};
use crate::encoding::CanonicalResult;

pub(crate) const QUOTIENT_COLUMN_ROW_CHECK_LOW: usize = 0;
pub(crate) const QUOTIENT_COLUMN_ROW_CHECK_HIGH: usize = 1;
pub(crate) const QUOTIENT_COLUMN_SUMCHECK_VANISHING: usize = 2;
pub(crate) const QUOTIENT_COLUMN_SUMCHECK_RESIDUAL: usize = 3;
pub(crate) const PHASE_TWO_COLUMN_COUNT: usize = 4;

pub(crate) struct LimbColumnLayout {
    pub(crate) ring_degree: usize,
    pub(crate) trace_size: usize,
    pub(crate) private_vss_coefficient_columns: usize,
    pub(crate) private_vss_randomness_columns: usize,
    claim_mask_digit_counts: Vec<usize>,
    claim_mask_slot_offsets: Vec<usize>,
    pub(crate) mask_column_count: usize,
}

impl LimbColumnLayout {
    pub(crate) fn new(
        statement: &TrusteeEvaluationKeyStatement,
        limb_index: usize,
    ) -> CanonicalResult<Self> {
        let private_vss_share = statement
            .private_vss_share()
            .filter(|_| limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .ok_or_else(|| {
                invalid_succinct_setup_proof(
                    "the shared per-limb layout accepts only active private VSS limbs",
                )
            })?;
        let private_vss_coefficient_columns = private_vss_share.coefficient_commitments.len();
        let private_vss_randomness_columns = private_vss_coefficient_columns
            .checked_mul(SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS column count overflowed"))?;
        let ring_degree = statement.ring_degree;
        let claim_mask_digit_counts = vec![CLAIM_MASK_DIGIT_COUNT; CONSISTENCY_REPETITIONS];
        let mut claim_mask_slot_offsets = Vec::with_capacity(CONSISTENCY_REPETITIONS + 1);
        let mut mask_slot_count = 0_usize;
        claim_mask_slot_offsets.push(mask_slot_count);
        for digit_count in &claim_mask_digit_counts {
            mask_slot_count = mask_slot_count.checked_add(*digit_count).ok_or_else(|| {
                invalid_succinct_setup_proof("claim mask column count overflowed")
            })?;
            claim_mask_slot_offsets.push(mask_slot_count);
        }

        Ok(Self {
            ring_degree,
            trace_size: ring_degree / TRACE_SPLIT,
            private_vss_coefficient_columns,
            private_vss_randomness_columns,
            claim_mask_digit_counts,
            claim_mask_slot_offsets,
            mask_column_count: mask_slot_count.div_ceil(ring_degree),
        })
    }

    pub(crate) fn private_vss_logical_columns(&self) -> usize {
        self.private_vss_coefficient_columns + 1 + self.private_vss_randomness_columns
    }

    pub(crate) fn private_vss_relation_count(&self) -> usize {
        self.private_vss_coefficient_columns * SETUP_COMMITMENT_ROW_COUNT + 1
    }

    pub(crate) const fn claim_count(&self) -> usize {
        CONSISTENCY_REPETITIONS
    }

    pub(crate) fn physical_private_vss_message(
        &self,
        coefficient_index: usize,
        half: usize,
    ) -> usize {
        debug_assert!(coefficient_index < self.private_vss_coefficient_columns);
        TRACE_SPLIT * coefficient_index + half
    }

    pub(crate) fn physical_private_vss_carry(&self, half: usize) -> usize {
        TRACE_SPLIT * self.private_vss_coefficient_columns + half
    }

    pub(crate) fn physical_private_vss_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(randomness_position < self.private_vss_randomness_columns);
        TRACE_SPLIT * (self.private_vss_coefficient_columns + 1 + randomness_position) + half
    }

    pub(crate) fn physical_mask(&self, mask_column: usize, half: usize) -> usize {
        TRACE_SPLIT * (self.private_vss_logical_columns() + mask_column) + half
    }

    pub(crate) fn phase_one_physical_count(&self) -> usize {
        TRACE_SPLIT * (self.private_vss_logical_columns() + self.mask_column_count)
    }

    pub(crate) fn row_check_constraint_count(&self) -> usize {
        TRACE_SPLIT * (self.private_vss_randomness_columns + self.mask_column_count)
    }

    pub(crate) fn claim_mask_digit_count(&self, claim_index: usize) -> usize {
        self.claim_mask_digit_counts[claim_index]
    }

    pub(crate) fn mask_slot(
        &self,
        claim_index: usize,
        digit_index: usize,
    ) -> (usize, usize, usize) {
        debug_assert!(claim_index < self.claim_mask_digit_counts.len());
        debug_assert!(digit_index < self.claim_mask_digit_count(claim_index));
        let slot = self.claim_mask_slot_offsets[claim_index] + digit_index;
        let logical_column = slot / self.ring_degree;
        let position = slot % self.ring_degree;
        let half = position / self.trace_size;
        let row = position % self.trace_size;
        (logical_column, half, row)
    }
}
