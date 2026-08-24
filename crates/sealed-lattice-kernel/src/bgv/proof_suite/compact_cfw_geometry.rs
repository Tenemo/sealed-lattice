//! Verifier-owned geometry for the compact constrained-function reduction.

pub(crate) const COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH: usize = 4;
pub(crate) const COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH: usize = 8;
pub(crate) const COMPACT_CFW_MATRIX_COUNT: usize = 3;
pub(crate) const COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT: usize = 2;
pub(crate) const COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER: u64 = 2;
pub(crate) const COMPACT_CFW_ZERO_EVADER_EXPONENTS: [u32; COMPACT_CFW_MATRIX_COUNT] = [0, 1, 2];
#[cfg(test)]
pub(crate) const COMPACT_CFW_LAST_ROUND_EXCLUDED_ELEMENT_COUNT: u64 = 2;
const COMPACT_CFW_GLOBAL_COMMITTED_RELATION_CLAIM_COUNT: u64 = 1;
const COMPACT_CFW_AUXILIARY_TARGET_COUNT: u64 = 1;
const COMPACT_CFW_OUTER_REVEALED_EVALUATION_COUNT: u64 = 1;
const COMPACT_CFW_CROSS_EPOCH_PRECEDING_CLAIM_COUNT: u64 = 2;
const COMPACT_CFW_CROSS_EPOCH_MASK_MESSAGE_COUNT: u64 = 2;
const COMPACT_CFW_CROSS_EPOCH_DISCLOSED_SCALAR_COUNT: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwGeometry {
    witness_length: usize,
    r1cs_row_count: usize,
    sumcheck_round_count: usize,
    inner_mask_count: usize,
    outer_mask_count: usize,
    generalized_committed_relation_claim_count: usize,
}

impl CompactCfwGeometry {
    pub(crate) fn derive(witness_length: usize) -> Result<Self, CompactCfwGeometryError> {
        if witness_length == 0 || !witness_length.is_power_of_two() {
            return Err(CompactCfwGeometryError::InvalidGeometry);
        }
        let r1cs_row_count = witness_length
            .checked_mul(2)
            .ok_or(CompactCfwGeometryError::CountOverflow)?;
        let sumcheck_round_count = usize::try_from(r1cs_row_count.ilog2())
            .map_err(|_| CompactCfwGeometryError::CountOverflow)?;
        let inner_mask_count = sumcheck_round_count
            .checked_mul(COMPACT_CFW_MATRIX_COUNT)
            .ok_or(CompactCfwGeometryError::CountOverflow)?;
        let outer_mask_count = sumcheck_round_count;
        let generalized_committed_relation_claim_count = 1_usize
            .checked_add(
                inner_mask_count
                    .checked_mul(COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT)
                    .ok_or(CompactCfwGeometryError::CountOverflow)?,
            )
            .and_then(|count| count.checked_add(outer_mask_count))
            .ok_or(CompactCfwGeometryError::CountOverflow)?;
        Ok(Self {
            witness_length,
            r1cs_row_count,
            sumcheck_round_count,
            inner_mask_count,
            outer_mask_count,
            generalized_committed_relation_claim_count,
        })
    }

    pub(crate) const fn witness_length(self) -> usize {
        self.witness_length
    }

    pub(crate) const fn r1cs_row_count(self) -> usize {
        self.r1cs_row_count
    }

    pub(crate) const fn sumcheck_round_count(self) -> usize {
        self.sumcheck_round_count
    }

    pub(crate) const fn inner_mask_count(self) -> usize {
        self.inner_mask_count
    }

    pub(crate) const fn outer_mask_count(self) -> usize {
        self.outer_mask_count
    }

    pub(crate) const fn generalized_committed_relation_claim_count(self) -> usize {
        self.generalized_committed_relation_claim_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwGeometryError {
    InvalidGeometry,
    CountOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwCrossEpochVerifierGeometry {
    pub(crate) copied_ring_vector_count: u64,
    pub(crate) copied_element_count: u64,
    pub(crate) pre_challenge_message_element_count: u64,
    pub(crate) main_message_element_count: u64,
    pub(crate) point_coordinate_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwVerifierConfiguration {
    geometry: CompactCfwGeometry,
    cross_epoch: CompactCfwCrossEpochVerifierGeometry,
}

impl CompactCfwVerifierConfiguration {
    pub(crate) fn derive(
        witness_length: usize,
        cross_epoch: CompactCfwCrossEpochVerifierGeometry,
    ) -> Result<Self, CompactCfwGeometryError> {
        let geometry = CompactCfwGeometry::derive(witness_length)?;
        if cross_epoch.copied_ring_vector_count == 0
            || cross_epoch.copied_element_count == 0
            || cross_epoch.pre_challenge_message_element_count == 0
            || !cross_epoch
                .pre_challenge_message_element_count
                .is_power_of_two()
            || cross_epoch.main_message_element_count
                != u64::try_from(geometry.witness_length)
                    .map_err(|_| CompactCfwGeometryError::CountOverflow)?
            || cross_epoch
                .pre_challenge_message_element_count
                .checked_mul(2)
                .ok_or(CompactCfwGeometryError::CountOverflow)?
                != cross_epoch.main_message_element_count
            || cross_epoch.point_coordinate_count
                != cross_epoch.pre_challenge_message_element_count.ilog2()
        {
            return Err(CompactCfwGeometryError::InvalidGeometry);
        }
        Ok(Self {
            geometry,
            cross_epoch,
        })
    }

    pub(crate) const fn geometry(self) -> CompactCfwGeometry {
        self.geometry
    }

    pub(crate) const fn cross_epoch(self) -> CompactCfwCrossEpochVerifierGeometry {
        self.cross_epoch
    }

    pub(crate) const fn matrix_role_tags(self) -> [u8; COMPACT_CFW_MATRIX_COUNT] {
        [1, 2, 3]
    }

    pub(crate) const fn inner_mask_message_length(self) -> u64 {
        COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH as u64
    }

    pub(crate) const fn inner_mask_application_multiplier(self) -> u64 {
        COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER
    }

    pub(crate) const fn inner_evaluation_at_zero_covector(
        self,
    ) -> [u64; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH] {
        [1, 0, 0, 0]
    }

    pub(crate) const fn inner_evaluation_at_one_covector(
        self,
    ) -> [u64; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH] {
        [1, 1, 1, 1]
    }

    pub(crate) const fn inner_endpoint_targets(
        self,
    ) -> [u64; COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT] {
        [0, 0]
    }

    pub(crate) const fn outer_mask_message_length(self) -> u64 {
        COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH as u64
    }

    pub(crate) const fn outer_revealed_evaluation_count(self) -> u64 {
        COMPACT_CFW_OUTER_REVEALED_EVALUATION_COUNT
    }

    pub(crate) const fn global_committed_relation_claim_count(self) -> u64 {
        COMPACT_CFW_GLOBAL_COMMITTED_RELATION_CLAIM_COUNT
    }

    pub(crate) const fn auxiliary_target_count(self) -> u64 {
        COMPACT_CFW_AUXILIARY_TARGET_COUNT
    }

    pub(crate) const fn zero_evader_exponents(self) -> [u32; COMPACT_CFW_MATRIX_COUNT] {
        COMPACT_CFW_ZERO_EVADER_EXPONENTS
    }

    pub(crate) const fn initial_constraint_combining_range(self) -> [u64; 2] {
        [0, 1]
    }

    pub(crate) fn initial_equality_point_range(self) -> Result<[u64; 2], CompactCfwGeometryError> {
        Ok([
            1,
            u64::try_from(self.geometry.sumcheck_round_count)
                .map_err(|_| CompactCfwGeometryError::CountOverflow)?
                .checked_add(1)
                .ok_or(CompactCfwGeometryError::CountOverflow)?,
        ])
    }

    pub(crate) const fn per_round_challenge_count(self) -> u64 {
        1
    }

    pub(crate) const fn last_round_excluded_canonical_elements(self) -> [u64; 2] {
        [0, 1]
    }

    pub(crate) const fn joint_constraint_range(self) -> [u64; 2] {
        [0, 1]
    }

    pub(crate) const fn cross_epoch_preceding_claim_count(self) -> u64 {
        COMPACT_CFW_CROSS_EPOCH_PRECEDING_CLAIM_COUNT
    }

    pub(crate) const fn cross_epoch_mask_message_count(self) -> u64 {
        COMPACT_CFW_CROSS_EPOCH_MASK_MESSAGE_COUNT
    }

    pub(crate) const fn cross_epoch_disclosed_scalar_count(self) -> u64 {
        COMPACT_CFW_CROSS_EPOCH_DISCLOSED_SCALAR_COUNT
    }
}
