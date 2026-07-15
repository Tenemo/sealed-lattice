use super::super::{LINCHECK_REPETITIONS, TRACE_SPLIT, invalid_succinct_setup_proof};
use super::family_shape_and_validation::SuccinctSetupProofFamilyShape;
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
    pub(crate) limb_index: usize,
    pub(crate) base_ring_degree: usize,
    pub(crate) ring_degree: usize,
    pub(crate) trace_size: usize,
    pub(crate) family_shape: SuccinctSetupProofFamilyShape,
    pub(crate) consistency_repetitions: usize,
    pub(crate) active_keys: Vec<(usize, usize)>,
    pub(crate) total_error_columns: usize,
    pub(crate) private_vss_coefficient_columns: usize,
    pub(crate) linkage_randomness_columns: usize,
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
        let family_shape = statement.family_shape();
        let active_keys = statement
            .active_key_indices(limb_index)
            .into_iter()
            .map(|key_index| (key_index, statement.keys()[key_index].digit_count()))
            .collect::<Vec<_>>();
        let private_vss_coefficient_columns = statement
            .private_vss_share()
            .filter(|_| limb_index < SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
            .map(|private_vss_share| private_vss_share.coefficient_commitments.len())
            .unwrap_or(0);
        let linkage_randomness_columns = statement.linkage_randomness_count(limb_index);
        let private_vss_randomness_columns = statement.private_vss_randomness_count(limb_index);
        if active_keys.is_empty()
            && linkage_randomness_columns == 0
            && private_vss_coefficient_columns == 0
        {
            return Err(invalid_succinct_setup_proof(
                "limb layout requires an active key or active private relation",
            ));
        }
        let total_error_columns = active_keys.iter().map(|(_, digits)| *digits).sum::<usize>();
        let base_ring_degree = statement.ring_degree;
        let ring_degree = base_ring_degree;
        let consistency_repetitions = family_shape.consistency_repetitions();
        let consistency_vector_count = match family_shape {
            SuccinctSetupProofFamilyShape::PrivateVssShare => 1 + private_vss_randomness_columns,
            SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
                1 + total_error_columns
                    + if linkage_randomness_columns > 0 {
                        1 + linkage_randomness_columns
                    } else {
                        0
                    }
            }
        };
        let claim_count = consistency_vector_count
            .checked_mul(consistency_repetitions)
            .ok_or_else(|| invalid_succinct_setup_proof("consistency claim count overflowed"))?;
        let claim_mask_digit_counts = vec![family_shape.claim_mask_digit_count(); claim_count];
        let mut claim_mask_slot_offsets = Vec::with_capacity(claim_count + 1);
        let mut mask_slot_count = 0_usize;
        claim_mask_slot_offsets.push(mask_slot_count);
        for digit_count in &claim_mask_digit_counts {
            mask_slot_count = mask_slot_count.checked_add(*digit_count).ok_or_else(|| {
                invalid_succinct_setup_proof("claim mask column count overflowed")
            })?;
            claim_mask_slot_offsets.push(mask_slot_count);
        }
        let mask_column_count = mask_slot_count.div_ceil(ring_degree);

        Ok(Self {
            limb_index,
            base_ring_degree,
            ring_degree,
            trace_size: ring_degree / TRACE_SPLIT,
            family_shape,
            consistency_repetitions,
            active_keys,
            total_error_columns,
            private_vss_coefficient_columns,
            linkage_randomness_columns,
            private_vss_randomness_columns,
            claim_mask_digit_counts,
            claim_mask_slot_offsets,
            mask_column_count,
        })
    }

    pub(crate) fn linkage_active(&self) -> bool {
        self.linkage_randomness_columns > 0
    }

    fn linkage_logical_columns(&self) -> usize {
        usize::from(self.linkage_active()) + self.linkage_randomness_columns
    }

    pub(crate) fn private_vss_active(&self) -> bool {
        self.family_shape == SuccinctSetupProofFamilyShape::PrivateVssShare
    }

    pub(crate) fn private_vss_logical_columns(&self) -> usize {
        if self.private_vss_active() {
            self.private_vss_coefficient_columns + 1 + self.private_vss_randomness_columns
        } else {
            0
        }
    }

    pub(crate) fn private_vss_relation_count(&self) -> usize {
        if self.private_vss_active() {
            self.private_vss_coefficient_columns * SETUP_COMMITMENT_ROW_COUNT + 1
        } else {
            0
        }
    }

    pub(crate) fn consistency_vector_count(&self) -> usize {
        if self.private_vss_active() {
            1 + self.private_vss_randomness_columns
        } else {
            1 + self.total_error_columns + self.linkage_logical_columns()
        }
    }

    pub(crate) fn claim_count(&self) -> usize {
        self.consistency_vector_count() * self.consistency_repetitions
    }

    pub(crate) fn linkage_relation_count(&self) -> usize {
        if self.linkage_active() {
            let commitment_count =
                self.linkage_randomness_columns / SETUP_COMMITMENT_RANDOMNESS_WIDTH;
            commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS
        } else {
            0
        }
    }

    pub(crate) fn physical_secret(&self, half: usize) -> usize {
        debug_assert!(!self.private_vss_active());
        half
    }

    pub(crate) fn physical_error(&self, error_position: usize, half: usize) -> usize {
        debug_assert!(error_position < self.total_error_columns);
        TRACE_SPLIT * (1 + error_position) + half
    }

    pub(crate) fn physical_error_square(&self, error_position: usize, half: usize) -> usize {
        debug_assert!(error_position < self.total_error_columns);
        TRACE_SPLIT * (1 + self.total_error_columns + error_position) + half
    }

    pub(crate) fn physical_negative_indicator(&self, half: usize) -> usize {
        debug_assert!(self.linkage_active());
        TRACE_SPLIT * (1 + 2 * self.total_error_columns) + half
    }

    pub(crate) fn physical_linkage_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.linkage_active());
        debug_assert!(randomness_position < self.linkage_randomness_columns);
        TRACE_SPLIT * (2 + 2 * self.total_error_columns + randomness_position) + half
    }

    pub(crate) fn physical_private_vss_message(
        &self,
        coefficient_index: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.private_vss_active());
        debug_assert!(coefficient_index < self.private_vss_coefficient_columns);
        TRACE_SPLIT * coefficient_index + half
    }

    pub(crate) fn physical_private_vss_carry(&self, half: usize) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * self.private_vss_coefficient_columns + half
    }

    pub(crate) fn physical_private_vss_randomness(
        &self,
        randomness_position: usize,
        half: usize,
    ) -> usize {
        debug_assert!(self.private_vss_active());
        TRACE_SPLIT * (self.private_vss_coefficient_columns + 1 + randomness_position) + half
    }

    pub(crate) fn physical_mask(&self, mask_column: usize, half: usize) -> usize {
        let logical_prefix = if self.private_vss_active() {
            self.private_vss_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + mask_column) + half
    }

    pub(crate) fn phase_one_physical_count(&self) -> usize {
        let logical_prefix = if self.private_vss_active() {
            self.private_vss_logical_columns()
        } else {
            1 + 2 * self.total_error_columns + self.linkage_logical_columns()
        };
        TRACE_SPLIT * (logical_prefix + self.mask_column_count)
    }

    pub(crate) fn row_check_constraint_count(&self) -> usize {
        if self.private_vss_active() {
            TRACE_SPLIT * (self.private_vss_randomness_columns + self.mask_column_count)
        } else {
            TRACE_SPLIT
                * (1 + 2 * self.total_error_columns
                    + usize::from(self.linkage_active())
                    + self.linkage_randomness_columns
                    + self.mask_column_count)
        }
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
