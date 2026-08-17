//! CFW reduction algebra for the compact extension-field R1CS path.
//!
//! This module owns the exact mask normalization, masked sumcheck, final
//! consistency check, and generalized linear-claim ordering needed by the
//! compact constrained-code handoff. It deliberately does not own transcript
//! sampling or commitments: the caller must commit the inner masks, main
//! source, and outer masks before supplying the corresponding challenges.

use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

#[cfg(test)]
pub(crate) use super::compact_cfw_geometry::COMPACT_CFW_INNER_ENDPOINT_CLAIM_COUNT;
#[cfg(test)]
pub(crate) use super::compact_cfw_geometry::COMPACT_CFW_LAST_ROUND_EXCLUDED_ELEMENT_COUNT;
pub(crate) use super::compact_cfw_geometry::{
    COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER, COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH,
    COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwGeometry,
    CompactCfwGeometryError,
};
use super::field::{PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement};

pub(crate) type CompactChallengeField = BinomialExtensionField<Goldilocks, 5>;
const COMPACT_CFW_CROSS_EPOCH_MASK_COVECTOR_COUNT: usize = 2;

pub(crate) fn compact_challenge_from_production(
    value: ProofChallengeExtensionElement,
) -> CompactChallengeField {
    CompactChallengeField::new(value.canonical_coordinates().map(Goldilocks::from_u64))
}

pub(crate) fn compact_challenge_to_production(
    value: CompactChallengeField,
) -> Result<ProofChallengeExtensionElement, CompactCfwError> {
    let coefficients =
        <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
            &value,
        );
    if coefficients.len() != PROOF_CHALLENGE_EXTENSION_DEGREE {
        return Err(CompactCfwError::IncompatibleChallengeField);
    }
    let coordinates = core::array::from_fn(|ordinal| coefficients[ordinal].as_canonical_u64());
    ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
        .map_err(|_| CompactCfwError::IncompatibleChallengeField)
}

pub(crate) fn compact_cfw_final_challenge_is_allowed(challenge: CompactChallengeField) -> bool {
    challenge != CompactChallengeField::ZERO && challenge != CompactChallengeField::ONE
}

pub(crate) fn compact_cfw_zero_evader_weights(
    challenge: CompactChallengeField,
) -> [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] {
    [CompactChallengeField::ONE, challenge, challenge * challenge]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwMatrixRole {
    LeftMultiplicand,
    RightMultiplicand,
    Product,
}

impl CompactCfwMatrixRole {
    pub(crate) const ALL: [Self; COMPACT_CFW_MATRIX_COUNT] = [
        Self::LeftMultiplicand,
        Self::RightMultiplicand,
        Self::Product,
    ];

    pub(crate) const fn ordinal(self) -> usize {
        match self {
            Self::LeftMultiplicand => 0,
            Self::RightMultiplicand => 1,
            Self::Product => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwError {
    InvalidGeometry,
    CountOverflow,
    AllocationLimitExceeded,
    IncompatibleChallengeField,
    InvalidMaskMaterial,
    InvalidMatrixSource,
    WrongProverPhase,
    SumcheckConsistency { round_ordinal: usize },
    FinalConsistency,
    InvalidFinalChallenge,
    InvalidClaimInput,
}

impl From<CompactCfwGeometryError> for CompactCfwError {
    fn from(error: CompactCfwGeometryError) -> Self {
        match error {
            CompactCfwGeometryError::InvalidGeometry => Self::InvalidGeometry,
            CompactCfwGeometryError::CountOverflow => Self::CountOverflow,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwMaskMaterial {
    inner_masks: Vec<[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]>,
    outer_masks: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
}

impl CompactCfwMaskMaterial {
    pub(crate) fn from_canonical_messages(
        geometry: CompactCfwGeometry,
        inner_masks: Vec<[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]>,
        outer_masks: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
    ) -> Result<Self, CompactCfwError> {
        let material = Self {
            inner_masks,
            outer_masks,
        };
        material.check(geometry)?;
        Ok(material)
    }

    pub(crate) fn sample(
        geometry: CompactCfwGeometry,
        mut sample_extension_element: impl FnMut() -> CompactChallengeField,
    ) -> Result<Self, CompactCfwError> {
        let mut inner_masks = Vec::new();
        inner_masks
            .try_reserve_exact(geometry.inner_mask_count())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        for _round_ordinal in 0..geometry.sumcheck_round_count() {
            for _matrix_role in CompactCfwMatrixRole::ALL {
                let first_independent_coefficient = sample_extension_element();
                let second_independent_coefficient = sample_extension_element();
                inner_masks.push([
                    CompactChallengeField::ZERO,
                    first_independent_coefficient,
                    second_independent_coefficient,
                    -(first_independent_coefficient + second_independent_coefficient),
                ]);
            }
        }
        let mut outer_masks = Vec::new();
        outer_masks
            .try_reserve_exact(geometry.outer_mask_count())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        for _round_ordinal in 0..geometry.outer_mask_count() {
            outer_masks.push(core::array::from_fn(|_| sample_extension_element()));
        }
        let material = Self {
            inner_masks,
            outer_masks,
        };
        if material.inner_masks.capacity() != geometry.inner_mask_count()
            || material.outer_masks.capacity() != geometry.outer_mask_count()
        {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        material.check(geometry)?;
        Ok(material)
    }

    pub(crate) fn check(&self, geometry: CompactCfwGeometry) -> Result<(), CompactCfwError> {
        if self.inner_masks.len() != geometry.inner_mask_count()
            || self.outer_masks.len() != geometry.outer_mask_count()
            || self.inner_masks.iter().any(|mask| {
                evaluate_polynomial(mask, CompactChallengeField::ZERO)
                    != CompactChallengeField::ZERO
                    || evaluate_polynomial(mask, CompactChallengeField::ONE)
                        != CompactChallengeField::ZERO
            })
        {
            return Err(CompactCfwError::InvalidMaskMaterial);
        }
        Ok(())
    }

    pub(crate) fn inner_masks(
        &self,
    ) -> &[[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]] {
        &self.inner_masks
    }

    pub(crate) fn outer_masks(
        &self,
    ) -> &[[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]] {
        &self.outer_masks
    }

    pub(crate) fn auxiliary_target(
        &self,
        geometry: CompactCfwGeometry,
    ) -> Result<CompactChallengeField, CompactCfwError> {
        auxiliary_target(geometry, self)
    }

    fn inner_mask(
        &self,
        round_ordinal: usize,
        matrix_role: CompactCfwMatrixRole,
    ) -> Result<&[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH], CompactCfwError>
    {
        let mask_ordinal = round_ordinal
            .checked_mul(COMPACT_CFW_MATRIX_COUNT)
            .and_then(|ordinal| ordinal.checked_add(matrix_role.ordinal()))
            .ok_or(CompactCfwError::CountOverflow)?;
        self.inner_masks
            .get(mask_ordinal)
            .ok_or(CompactCfwError::InvalidMaskMaterial)
    }
}

/// Verifier-owned structured R1CS operations used by the CFW reduction.
///
/// A production implementation derives every result from the canonical public
/// input and matrix compiler. No value returned through this interface is read
/// from proof bytes.
pub(crate) trait CompactCfwR1csMatrices {
    fn witness_length(&self) -> usize;

    fn evaluate_assignment_rows(
        &self,
        matrix_role: CompactCfwMatrixRole,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactCfwError>;

    fn public_contribution_at_row_point(
        &self,
        matrix_role: CompactCfwMatrixRole,
        row_point: &[CompactChallengeField],
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError>;

    fn accumulate_weighted_witness_covector_at_row_point(
        &self,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError>;
}

pub(crate) struct PreparedCompactCfwProver {
    geometry: CompactCfwGeometry,
    mask_material: CompactCfwMaskMaterial,
    matrix_row_evaluations: [Vec<CompactChallengeField>; COMPACT_CFW_MATRIX_COUNT],
    auxiliary_target: CompactChallengeField,
}

impl PreparedCompactCfwProver {
    pub(crate) fn prepare(
        matrices: &impl CompactCfwR1csMatrices,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
        mask_material: CompactCfwMaskMaterial,
    ) -> Result<Self, CompactCfwError> {
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())?;
        if public_input.len() != geometry.witness_length()
            || witness.len() != geometry.witness_length()
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        mask_material.check(geometry)?;
        let left_rows = matrices.evaluate_assignment_rows(
            CompactCfwMatrixRole::LeftMultiplicand,
            public_input,
            witness,
        )?;
        let right_rows = matrices.evaluate_assignment_rows(
            CompactCfwMatrixRole::RightMultiplicand,
            public_input,
            witness,
        )?;
        let product_rows = matrices.evaluate_assignment_rows(
            CompactCfwMatrixRole::Product,
            public_input,
            witness,
        )?;
        if left_rows.len() != geometry.r1cs_row_count()
            || right_rows.len() != geometry.r1cs_row_count()
            || product_rows.len() != geometry.r1cs_row_count()
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let matrix_row_evaluations = [left_rows, right_rows, product_rows];
        let auxiliary_target = auxiliary_target(geometry, &mask_material)?;
        Ok(Self {
            geometry,
            mask_material,
            matrix_row_evaluations,
            auxiliary_target,
        })
    }

    pub(crate) const fn auxiliary_target(&self) -> CompactChallengeField {
        self.auxiliary_target
    }

    pub(crate) fn begin(
        self,
        constraint_combining_challenge: CompactChallengeField,
        equality_point: Vec<CompactChallengeField>,
    ) -> Result<CompactCfwProverState, CompactCfwError> {
        let scalar_state = CompactCfwScalarProverState::begin(
            self.geometry,
            self.mask_material,
            constraint_combining_challenge,
            equality_point,
        )?;
        if scalar_state.auxiliary_target() != self.auxiliary_target {
            return Err(CompactCfwError::InvalidMaskMaterial);
        }
        Ok(CompactCfwProverState {
            matrix_row_evaluations: self.matrix_row_evaluations,
            scalar_state,
        })
    }
}

/// Derives the true masked-sumcheck polynomial after an arbitrary prefix of
/// verifier challenges, without trusting any prover-supplied round polynomial.
///
/// This is the executable knowledge-state owner used by the relaxed
/// round-by-round theorem. It deliberately bypasses transcript consistency:
/// the caller compares this independently derived polynomial with the wire
/// polynomial at the selected challenge.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compact_cfw_semantic_round_polynomial(
    matrices: &impl CompactCfwR1csMatrices,
    public_input: &[CompactChallengeField],
    witness: &[CompactChallengeField],
    mask_material: &CompactCfwMaskMaterial,
    constraint_combining_challenge: CompactChallengeField,
    equality_point: &[CompactChallengeField],
    prior_round_challenges: &[CompactChallengeField],
    round_ordinal: usize,
) -> Result<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH], CompactCfwError> {
    let geometry = CompactCfwGeometry::derive(matrices.witness_length())?;
    if public_input.len() != geometry.witness_length()
        || witness.len() != geometry.witness_length()
        || equality_point.len() != geometry.sumcheck_round_count()
        || prior_round_challenges.len() != round_ordinal
        || round_ordinal >= geometry.sumcheck_round_count()
    {
        return Err(CompactCfwError::InvalidGeometry);
    }
    mask_material.check(geometry)?;
    let mut matrix_rows = CompactCfwMatrixRole::ALL
        .map(|matrix_role| matrices.evaluate_assignment_rows(matrix_role, public_input, witness))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if matrix_rows
        .iter()
        .any(|rows| rows.len() != geometry.r1cs_row_count())
    {
        return Err(CompactCfwError::InvalidMatrixSource);
    }
    for &challenge in prior_round_challenges {
        for rows in &mut matrix_rows {
            if rows.len() % 2 != 0 {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            *rows = rows
                .chunks_exact(2)
                .map(|pair| compact_cfw_fold_row_pair(pair[0], pair[1], challenge))
                .collect();
        }
    }

    let mut equality_prefix_evaluation = CompactChallengeField::ONE;
    let mut past_inner_mask_evaluations = [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT];
    let mut past_outer_mask_evaluation = CompactChallengeField::ZERO;
    for (prior_ordinal, &challenge) in prior_round_challenges.iter().enumerate() {
        let equality_coordinate = equality_point[prior_ordinal];
        equality_prefix_evaluation *= (CompactChallengeField::ONE - equality_coordinate)
            + challenge
                * (CompactChallengeField::from_u64(2) * equality_coordinate
                    - CompactChallengeField::ONE);
        for matrix_role in CompactCfwMatrixRole::ALL {
            past_inner_mask_evaluations[matrix_role.ordinal()] +=
                CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER)
                    * evaluate_polynomial(
                        mask_material.inner_mask(prior_ordinal, matrix_role)?,
                        challenge,
                    );
        }
        past_outer_mask_evaluation += evaluate_polynomial(
            mask_material
                .outer_masks()
                .get(prior_ordinal)
                .ok_or(CompactCfwError::InvalidMaskMaterial)?,
            challenge,
        );
    }

    let mut accumulator = CompactCfwRoundAccumulator::new(
        geometry,
        mask_material,
        round_ordinal,
        constraint_combining_challenge,
        equality_point,
        CompactCfwRoundHistory {
            equality_prefix_evaluation,
            past_inner_mask_evaluations,
            past_outer_mask_evaluation,
        },
    )?;
    let suffix_count = accumulator.expected_suffix_count;
    if matrix_rows
        .iter()
        .any(|rows| rows.len() != suffix_count.saturating_mul(2))
    {
        return Err(CompactCfwError::InvalidMatrixSource);
    }
    for suffix_ordinal in 0..suffix_count {
        let first_row = suffix_ordinal
            .checked_mul(2)
            .ok_or(CompactCfwError::CountOverflow)?;
        let values_at_zero =
            core::array::from_fn(|matrix_ordinal| matrix_rows[matrix_ordinal][first_row]);
        let values_at_one =
            core::array::from_fn(|matrix_ordinal| matrix_rows[matrix_ordinal][first_row + 1]);
        accumulator.absorb_next_row_pair(values_at_zero, values_at_one)?;
    }
    accumulator.finish()
}

/// Independently folds the production matrix rows and evaluates every inner
/// and outer mask at a complete sumcheck point.
pub(crate) fn compact_cfw_semantic_final_message(
    matrices: &impl CompactCfwR1csMatrices,
    public_input: &[CompactChallengeField],
    witness: &[CompactChallengeField],
    mask_material: &CompactCfwMaskMaterial,
    sumcheck_point: &[CompactChallengeField],
) -> Result<CompactCfwProverFinish, CompactCfwError> {
    let geometry = CompactCfwGeometry::derive(matrices.witness_length())?;
    if public_input.len() != geometry.witness_length()
        || witness.len() != geometry.witness_length()
        || sumcheck_point.len() != geometry.sumcheck_round_count()
    {
        return Err(CompactCfwError::InvalidGeometry);
    }
    mask_material.check(geometry)?;
    let mut matrix_rows = CompactCfwMatrixRole::ALL
        .map(|matrix_role| matrices.evaluate_assignment_rows(matrix_role, public_input, witness))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    for &challenge in sumcheck_point {
        for rows in &mut matrix_rows {
            if rows.len() % 2 != 0 {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            *rows = rows
                .chunks_exact(2)
                .map(|pair| compact_cfw_fold_row_pair(pair[0], pair[1], challenge))
                .collect();
        }
    }
    if matrix_rows.iter().any(|rows| rows.len() != 1) {
        return Err(CompactCfwError::InvalidMatrixSource);
    }
    let mut final_values = core::array::from_fn(|matrix_ordinal| matrix_rows[matrix_ordinal][0]);
    for (round_ordinal, &challenge) in sumcheck_point.iter().enumerate() {
        for matrix_role in CompactCfwMatrixRole::ALL {
            final_values[matrix_role.ordinal()] +=
                CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER)
                    * evaluate_polynomial(
                        mask_material.inner_mask(round_ordinal, matrix_role)?,
                        challenge,
                    );
        }
    }
    let outer_evaluations = mask_material
        .outer_masks()
        .iter()
        .zip(sumcheck_point)
        .map(|(mask, &challenge)| evaluate_polynomial(mask, challenge))
        .collect();
    Ok(CompactCfwProverFinish {
        mask_material: mask_material.clone(),
        outer_evaluations,
        final_values,
    })
}

pub(crate) struct CompactCfwProverState {
    matrix_row_evaluations: [Vec<CompactChallengeField>; COMPACT_CFW_MATRIX_COUNT],
    scalar_state: CompactCfwScalarProverState,
}

/// Transcript-facing CFW state shared by resident and external-memory provers.
///
/// Matrix rows are deliberately absent. The state derives each accumulator,
/// checks the round endpoint relation, binds the caller-supplied challenge,
/// and owns the final masked consistency check. A storage-backed prover must
/// supply the same canonical row pairs and final folded values as the resident
/// reference prover.
pub(crate) struct CompactCfwScalarProverState {
    geometry: CompactCfwGeometry,
    mask_material: CompactCfwMaskMaterial,
    constraint_combining_challenge: CompactChallengeField,
    equality_point: Vec<CompactChallengeField>,
    round_challenges: Vec<CompactChallengeField>,
    round_ordinal: usize,
    auxiliary_target: CompactChallengeField,
    previous_claim: CompactChallengeField,
    equality_prefix_evaluation: CompactChallengeField,
    past_inner_mask_evaluations: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    past_outer_mask_evaluation: CompactChallengeField,
    pending_round_polynomial:
        Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
}

/// Incremental owner of one CFW sumcheck round.
///
/// Row pairs must arrive in canonical suffix order. The accumulator derives
/// every equality weight and mask contribution from the checked geometry and
/// committed mask material, so an external-memory executor only supplies the
/// two matrix values at each row-pair endpoint.
pub(crate) struct CompactCfwRoundAccumulator {
    expected_suffix_count: usize,
    absorbed_suffix_count: usize,
    constraint_combining_challenge: CompactChallengeField,
    equality_coordinate: CompactChallengeField,
    equality_suffix_point: Vec<CompactChallengeField>,
    equality_prefix_evaluation: CompactChallengeField,
    past_inner_mask_evaluations: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    current_inner_masks:
        [[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH]; COMPACT_CFW_MATRIX_COUNT],
    past_outer_mask_evaluation: CompactChallengeField,
    current_outer_mask: [CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
    future_outer_endpoint_sum: CompactChallengeField,
    round_polynomial: [CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
}

#[derive(Clone, Copy)]
struct CompactCfwRoundHistory {
    equality_prefix_evaluation: CompactChallengeField,
    past_inner_mask_evaluations: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    past_outer_mask_evaluation: CompactChallengeField,
}

impl CompactCfwRoundAccumulator {
    fn new(
        geometry: CompactCfwGeometry,
        mask_material: &CompactCfwMaskMaterial,
        round_ordinal: usize,
        constraint_combining_challenge: CompactChallengeField,
        equality_point: &[CompactChallengeField],
        history: CompactCfwRoundHistory,
    ) -> Result<Self, CompactCfwError> {
        if equality_point.len() != geometry.sumcheck_round_count()
            || round_ordinal >= geometry.sumcheck_round_count()
        {
            return Err(CompactCfwError::InvalidGeometry);
        }
        mask_material.check(geometry)?;
        let remaining_round_count = geometry
            .sumcheck_round_count()
            .checked_sub(round_ordinal + 1)
            .ok_or(CompactCfwError::WrongProverPhase)?;
        let expected_suffix_count = 1_usize
            .checked_shl(
                u32::try_from(remaining_round_count).map_err(|_| CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        let mut current_inner_masks = [[CompactChallengeField::ZERO;
            COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH];
            COMPACT_CFW_MATRIX_COUNT];
        for matrix_role in CompactCfwMatrixRole::ALL {
            current_inner_masks[matrix_role.ordinal()] =
                *mask_material.inner_mask(round_ordinal, matrix_role)?;
        }
        let current_outer_mask = *mask_material
            .outer_masks()
            .get(round_ordinal)
            .ok_or(CompactCfwError::InvalidMaskMaterial)?;
        let future_outer_endpoint_sum = mask_material.outer_masks()[round_ordinal + 1..]
            .iter()
            .map(|future_mask| {
                evaluate_polynomial(future_mask, CompactChallengeField::ZERO)
                    + evaluate_polynomial(future_mask, CompactChallengeField::ONE)
            })
            .sum();
        let equality_suffix = &equality_point[round_ordinal + 1..];
        let mut equality_suffix_point = Vec::new();
        equality_suffix_point
            .try_reserve_exact(equality_suffix.len())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        equality_suffix_point.extend_from_slice(equality_suffix);
        if equality_suffix_point.capacity() != equality_suffix.len() {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        let CompactCfwRoundHistory {
            equality_prefix_evaluation,
            past_inner_mask_evaluations,
            past_outer_mask_evaluation,
        } = history;
        Ok(Self {
            expected_suffix_count,
            absorbed_suffix_count: 0,
            constraint_combining_challenge,
            equality_coordinate: equality_point[round_ordinal],
            equality_suffix_point,
            equality_prefix_evaluation,
            past_inner_mask_evaluations,
            current_inner_masks,
            past_outer_mask_evaluation,
            current_outer_mask,
            future_outer_endpoint_sum,
            round_polynomial: [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
        })
    }

    pub(crate) fn absorb_next_row_pair(
        &mut self,
        values_at_zero: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        values_at_one: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    ) -> Result<(), CompactCfwError> {
        if self.absorbed_suffix_count >= self.expected_suffix_count {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let left = compact_cfw_matrix_factor_polynomial(
            values_at_zero[CompactCfwMatrixRole::LeftMultiplicand.ordinal()],
            values_at_one[CompactCfwMatrixRole::LeftMultiplicand.ordinal()],
            self.past_inner_mask_evaluations[CompactCfwMatrixRole::LeftMultiplicand.ordinal()],
            &self.current_inner_masks[CompactCfwMatrixRole::LeftMultiplicand.ordinal()],
        );
        let right = compact_cfw_matrix_factor_polynomial(
            values_at_zero[CompactCfwMatrixRole::RightMultiplicand.ordinal()],
            values_at_one[CompactCfwMatrixRole::RightMultiplicand.ordinal()],
            self.past_inner_mask_evaluations[CompactCfwMatrixRole::RightMultiplicand.ordinal()],
            &self.current_inner_masks[CompactCfwMatrixRole::RightMultiplicand.ordinal()],
        );
        let product = compact_cfw_matrix_factor_polynomial(
            values_at_zero[CompactCfwMatrixRole::Product.ordinal()],
            values_at_one[CompactCfwMatrixRole::Product.ordinal()],
            self.past_inner_mask_evaluations[CompactCfwMatrixRole::Product.ordinal()],
            &self.current_inner_masks[CompactCfwMatrixRole::Product.ordinal()],
        );
        let mut constraint_polynomial = multiply_polynomials::<
            COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH,
            COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH,
            7,
        >(&left, &right);
        for coefficient_ordinal in 0..COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH {
            constraint_polynomial[coefficient_ordinal] -= product[coefficient_ordinal];
        }
        let equality_polynomial = [
            CompactChallengeField::ONE - self.equality_coordinate,
            CompactChallengeField::from_u64(2) * self.equality_coordinate
                - CompactChallengeField::ONE,
        ];
        let weighted_constraint =
            multiply_polynomials::<7, 2, 8>(&constraint_polynomial, &equality_polynomial);
        let suffix_equality = cfw_little_endian_boolean_point_weight(
            &self.equality_suffix_point,
            self.absorbed_suffix_count,
        );
        let scale =
            self.constraint_combining_challenge * self.equality_prefix_evaluation * suffix_equality;
        for (destination, coefficient) in self.round_polynomial.iter_mut().zip(weighted_constraint)
        {
            *destination += scale * coefficient;
        }
        self.absorbed_suffix_count = self
            .absorbed_suffix_count
            .checked_add(1)
            .ok_or(CompactCfwError::CountOverflow)?;
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
    ) -> Result<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH], CompactCfwError>
    {
        if self.absorbed_suffix_count != self.expected_suffix_count {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let suffix_count_field = field_from_usize(self.expected_suffix_count)?;
        self.round_polynomial[0] += suffix_count_field * self.past_outer_mask_evaluation;
        for (destination, coefficient) in self
            .round_polynomial
            .iter_mut()
            .zip(self.current_outer_mask)
        {
            *destination += suffix_count_field * coefficient;
        }
        if self.expected_suffix_count > 1 {
            self.round_polynomial[0] +=
                field_from_usize(self.expected_suffix_count / 2)? * self.future_outer_endpoint_sum;
        }
        Ok(self.round_polynomial)
    }
}

impl CompactCfwScalarProverState {
    pub(crate) fn begin(
        geometry: CompactCfwGeometry,
        mask_material: CompactCfwMaskMaterial,
        constraint_combining_challenge: CompactChallengeField,
        equality_point: Vec<CompactChallengeField>,
    ) -> Result<Self, CompactCfwError> {
        if equality_point.len() != geometry.sumcheck_round_count() {
            return Err(CompactCfwError::InvalidGeometry);
        }
        mask_material.check(geometry)?;
        let auxiliary_target = auxiliary_target(geometry, &mask_material)?;
        let mut exact_equality_point = Vec::new();
        exact_equality_point
            .try_reserve_exact(geometry.sumcheck_round_count())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        exact_equality_point.extend(equality_point);
        let mut round_challenges = Vec::new();
        round_challenges
            .try_reserve_exact(geometry.sumcheck_round_count())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        if exact_equality_point.capacity() != geometry.sumcheck_round_count()
            || round_challenges.capacity() != geometry.sumcheck_round_count()
        {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        Ok(Self {
            geometry,
            mask_material,
            constraint_combining_challenge,
            equality_point: exact_equality_point,
            round_challenges,
            round_ordinal: 0,
            auxiliary_target,
            previous_claim: auxiliary_target,
            equality_prefix_evaluation: CompactChallengeField::ONE,
            past_inner_mask_evaluations: [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT],
            past_outer_mask_evaluation: CompactChallengeField::ZERO,
            pending_round_polynomial: None,
        })
    }

    pub(crate) const fn auxiliary_target(&self) -> CompactChallengeField {
        self.auxiliary_target
    }

    pub(crate) const fn round_ordinal(&self) -> usize {
        self.round_ordinal
    }

    pub(crate) const fn geometry(&self) -> CompactCfwGeometry {
        self.geometry
    }

    pub(crate) fn round_accumulator(&self) -> Result<CompactCfwRoundAccumulator, CompactCfwError> {
        if self.pending_round_polynomial.is_some()
            || self.round_ordinal >= self.geometry.sumcheck_round_count()
        {
            return Err(CompactCfwError::WrongProverPhase);
        }
        CompactCfwRoundAccumulator::new(
            self.geometry,
            &self.mask_material,
            self.round_ordinal,
            self.constraint_combining_challenge,
            &self.equality_point,
            CompactCfwRoundHistory {
                equality_prefix_evaluation: self.equality_prefix_evaluation,
                past_inner_mask_evaluations: self.past_inner_mask_evaluations,
                past_outer_mask_evaluation: self.past_outer_mask_evaluation,
            },
        )
    }

    pub(crate) fn accept_round_polynomial(
        &mut self,
        polynomial: [CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
    ) -> Result<(), CompactCfwError> {
        if self.pending_round_polynomial.is_some()
            || self.round_ordinal >= self.geometry.sumcheck_round_count()
        {
            return Err(CompactCfwError::WrongProverPhase);
        }
        if polynomial_endpoint_sum(&polynomial) != self.previous_claim {
            return Err(CompactCfwError::SumcheckConsistency {
                round_ordinal: self.round_ordinal,
            });
        }
        self.pending_round_polynomial = Some(polynomial);
        Ok(())
    }

    pub(crate) fn bind_round_challenge(
        &mut self,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactCfwError> {
        let polynomial = self
            .pending_round_polynomial
            .take()
            .ok_or(CompactCfwError::WrongProverPhase)?;
        if self.round_ordinal + 1 == self.geometry.sumcheck_round_count()
            && !compact_cfw_final_challenge_is_allowed(challenge)
        {
            self.pending_round_polynomial = Some(polynomial);
            return Err(CompactCfwError::InvalidFinalChallenge);
        }

        let current_equality_coordinate = self.equality_point[self.round_ordinal];
        let equality_factor = (CompactChallengeField::ONE - current_equality_coordinate)
            + challenge
                * (CompactChallengeField::from_u64(2) * current_equality_coordinate
                    - CompactChallengeField::ONE);
        self.equality_prefix_evaluation *= equality_factor;

        for matrix_role in CompactCfwMatrixRole::ALL {
            self.past_inner_mask_evaluations[matrix_role.ordinal()] +=
                CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER)
                    * evaluate_polynomial(
                        self.mask_material
                            .inner_mask(self.round_ordinal, matrix_role)?,
                        challenge,
                    );
        }
        self.past_outer_mask_evaluation += evaluate_polynomial(
            self.mask_material
                .outer_masks()
                .get(self.round_ordinal)
                .ok_or(CompactCfwError::InvalidMaskMaterial)?,
            challenge,
        );
        self.previous_claim = evaluate_polynomial(&polynomial, challenge);
        self.round_challenges.push(challenge);
        self.round_ordinal = self
            .round_ordinal
            .checked_add(1)
            .ok_or(CompactCfwError::CountOverflow)?;
        Ok(())
    }

    pub(crate) fn finish(
        self,
        folded_matrix_values: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    ) -> Result<CompactCfwProverFinish, CompactCfwError> {
        if self.pending_round_polynomial.is_some()
            || self.round_ordinal != self.geometry.sumcheck_round_count()
            || self.round_challenges.len() != self.geometry.sumcheck_round_count()
        {
            return Err(CompactCfwError::WrongProverPhase);
        }
        let final_values = core::array::from_fn(|matrix_ordinal| {
            folded_matrix_values[matrix_ordinal] + self.past_inner_mask_evaluations[matrix_ordinal]
        });
        let outer_evaluations = self
            .mask_material
            .outer_masks()
            .iter()
            .zip(&self.round_challenges)
            .map(|(mask, &challenge)| evaluate_polynomial(mask, challenge))
            .collect::<Vec<_>>();
        let final_sumcheck_value = self.constraint_combining_challenge
            * (final_values[CompactCfwMatrixRole::LeftMultiplicand.ordinal()]
                * final_values[CompactCfwMatrixRole::RightMultiplicand.ordinal()]
                - final_values[CompactCfwMatrixRole::Product.ordinal()])
            * self.equality_prefix_evaluation
            + outer_evaluations
                .iter()
                .copied()
                .sum::<CompactChallengeField>();
        if final_sumcheck_value != self.previous_claim {
            return Err(CompactCfwError::FinalConsistency);
        }
        Ok(CompactCfwProverFinish {
            mask_material: self.mask_material,
            outer_evaluations,
            final_values,
        })
    }
}

impl CompactCfwProverState {
    pub(crate) fn next_round_polynomial(
        &mut self,
    ) -> Result<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH], CompactCfwError>
    {
        let polynomial = self.derive_current_round_polynomial()?;
        self.scalar_state.accept_round_polynomial(polynomial)?;
        Ok(polynomial)
    }

    pub(crate) fn bind_round_challenge(
        &mut self,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactCfwError> {
        if self
            .matrix_row_evaluations
            .iter()
            .any(|matrix_rows| matrix_rows.len() % 2 != 0)
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        self.scalar_state.bind_round_challenge(challenge)?;
        for matrix_rows in &mut self.matrix_row_evaluations {
            let mut folded_rows = Vec::with_capacity(matrix_rows.len() / 2);
            for pair in matrix_rows.chunks_exact(2) {
                folded_rows.push(compact_cfw_fold_row_pair(pair[0], pair[1], challenge));
            }
            *matrix_rows = folded_rows;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<CompactCfwProverFinish, CompactCfwError> {
        if self
            .matrix_row_evaluations
            .iter()
            .any(|rows| rows.len() != 1)
        {
            return Err(CompactCfwError::WrongProverPhase);
        }
        let folded_matrix_values =
            core::array::from_fn(|matrix_ordinal| self.matrix_row_evaluations[matrix_ordinal][0]);
        self.scalar_state.finish(folded_matrix_values)
    }

    fn derive_current_round_polynomial(
        &self,
    ) -> Result<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH], CompactCfwError>
    {
        let mut accumulator = self.scalar_state.round_accumulator()?;
        let suffix_count = accumulator.expected_suffix_count;
        if self
            .matrix_row_evaluations
            .iter()
            .any(|rows| rows.len() != suffix_count.saturating_mul(2))
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        for suffix_ordinal in 0..suffix_count {
            let first_row = suffix_ordinal
                .checked_mul(2)
                .ok_or(CompactCfwError::CountOverflow)?;
            let values_at_zero = core::array::from_fn(|matrix_ordinal| {
                self.matrix_row_evaluations[matrix_ordinal][first_row]
            });
            let values_at_one = core::array::from_fn(|matrix_ordinal| {
                self.matrix_row_evaluations[matrix_ordinal][first_row + 1]
            });
            accumulator.absorb_next_row_pair(values_at_zero, values_at_one)?;
        }
        accumulator.finish()
    }
}

pub(crate) struct CompactCfwProverFinish {
    mask_material: CompactCfwMaskMaterial,
    outer_evaluations: Vec<CompactChallengeField>,
    final_values: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
}

impl CompactCfwProverFinish {
    pub(crate) fn outer_evaluations(&self) -> &[CompactChallengeField] {
        &self.outer_evaluations
    }

    pub(crate) const fn final_values(&self) -> [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] {
        self.final_values
    }

    pub(crate) fn into_mask_material(self) -> CompactCfwMaskMaterial {
        self.mask_material
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwTranscript {
    auxiliary_target: CompactChallengeField,
    round_polynomials: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
    outer_evaluations: Vec<CompactChallengeField>,
    final_values: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
}

impl CompactCfwTranscript {
    pub(crate) fn new(
        auxiliary_target: CompactChallengeField,
        round_polynomials: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        outer_evaluations: Vec<CompactChallengeField>,
        final_values: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    ) -> Self {
        Self {
            auxiliary_target,
            round_polynomials,
            outer_evaluations,
            final_values,
        }
    }

    pub(crate) const fn auxiliary_target(&self) -> CompactChallengeField {
        self.auxiliary_target
    }

    pub(crate) fn round_polynomials(
        &self,
    ) -> &[[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]] {
        &self.round_polynomials
    }

    pub(crate) fn outer_evaluations(&self) -> &[CompactChallengeField] {
        &self.outer_evaluations
    }

    pub(crate) const fn final_values(&self) -> [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] {
        self.final_values
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwMultilinearOpeningClaim {
    point: Vec<CompactChallengeField>,
    target: CompactChallengeField,
}

impl CompactCfwMultilinearOpeningClaim {
    pub(crate) fn new(point: Vec<CompactChallengeField>, target: CompactChallengeField) -> Self {
        Self { point, target }
    }
}

/// Main-epoch claims for the masked cross-epoch copy relation.
///
/// Let `z_pre` and `z_main` be the two independent one-element messages in the
/// shared cross-epoch mask group. The caller discloses
///
/// ```text
/// masked_pre_challenge_evaluation = <pre_copy_covector, source> + z_pre
/// masked_main_evaluation = <main_copy_covector, witness> + z_main
/// mask_difference = z_pre - z_main.
/// ```
///
/// The pre-challenge WHIR relation separately proves its masked evaluation
/// with `z_pre`. Comparing the three disclosed values therefore reveals only
/// the required copied-message equality. The mask group is committed before
/// `point` is sampled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwMaskedCrossEpochClaims {
    point: Vec<CompactChallengeField>,
    copied_main_source_element_count: usize,
    masked_pre_challenge_evaluation: CompactChallengeField,
    masked_main_evaluation: CompactChallengeField,
    mask_difference: CompactChallengeField,
}

impl CompactCfwMaskedCrossEpochClaims {
    pub(crate) fn new(
        point: Vec<CompactChallengeField>,
        copied_main_source_element_count: usize,
        masked_pre_challenge_evaluation: CompactChallengeField,
        masked_main_evaluation: CompactChallengeField,
        mask_difference: CompactChallengeField,
    ) -> Self {
        Self {
            point,
            copied_main_source_element_count,
            masked_pre_challenge_evaluation,
            masked_main_evaluation,
            mask_difference,
        }
    }

    pub(crate) fn from_copied_source_evaluation(
        point: Vec<CompactChallengeField>,
        copied_main_source_element_count: usize,
        copied_source_evaluation: CompactChallengeField,
        pre_challenge_mask: CompactChallengeField,
        main_mask: CompactChallengeField,
    ) -> Result<Self, CompactCfwError> {
        if point.is_empty() || copied_main_source_element_count == 0 {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        Ok(Self::new(
            point,
            copied_main_source_element_count,
            copied_source_evaluation + pre_challenge_mask,
            copied_source_evaluation + main_mask,
            pre_challenge_mask - main_mask,
        ))
    }

    pub(crate) const fn disclosed_values(&self) -> [CompactChallengeField; 3] {
        [
            self.masked_pre_challenge_evaluation,
            self.masked_main_evaluation,
            self.mask_difference,
        ]
    }
}

#[derive(Clone, Copy)]
struct CompactCfwPrefixEvaluationNode {
    coordinate_ordinal: usize,
    first_leaf_ordinal: usize,
    accumulated_weight: CompactChallengeField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwPrefixEvaluationProgress {
    processed_work_unit_count: u64,
    evaluated_source_element_count: u64,
}

impl CompactCfwPrefixEvaluationProgress {
    pub(crate) const fn processed_work_unit_count(self) -> u64 {
        self.processed_work_unit_count
    }

    pub(crate) const fn evaluated_source_element_count(self) -> u64 {
        self.evaluated_source_element_count
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwPrefixEvaluationError<SourceError> {
    Cfw(CompactCfwError),
    Source(SourceError),
}

impl<SourceError> From<CompactCfwError> for CompactCfwPrefixEvaluationError<SourceError> {
    fn from(error: CompactCfwError) -> Self {
        Self::Cfw(error)
    }
}

/// Bounded-memory evaluation of the multilinear equality covector over the
/// copied prefix shared by the pre-challenge and main sources.
///
/// The depth-first traversal follows the same most-significant-coordinate
/// ordering as the CFW verifier coefficient map. Subtrees beyond the exact
/// copied prefix are skipped without materializing the full covector.
pub(crate) struct CompactCfwPrefixEvaluationState {
    point: Box<[CompactChallengeField]>,
    copied_source_element_count: usize,
    pending_nodes: Vec<CompactCfwPrefixEvaluationNode>,
    accumulated_evaluation: CompactChallengeField,
    evaluated_source_element_count: usize,
    complete: bool,
}

impl CompactCfwPrefixEvaluationState {
    pub(crate) fn new(
        point: &[CompactChallengeField],
        copied_source_element_count: usize,
    ) -> Result<Self, CompactCfwError> {
        let point_domain_length = 1_usize
            .checked_shl(u32::try_from(point.len()).map_err(|_| CompactCfwError::CountOverflow)?)
            .ok_or(CompactCfwError::CountOverflow)?;
        if point.is_empty()
            || copied_source_element_count == 0
            || copied_source_element_count > point_domain_length
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        let maximum_pending_node_count = point
            .len()
            .checked_add(1)
            .ok_or(CompactCfwError::CountOverflow)?;
        let mut pending_nodes = Vec::new();
        pending_nodes
            .try_reserve_exact(maximum_pending_node_count)
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        pending_nodes.push(CompactCfwPrefixEvaluationNode {
            coordinate_ordinal: 0,
            first_leaf_ordinal: 0,
            accumulated_weight: CompactChallengeField::ONE,
        });
        Ok(Self {
            point: point.into(),
            copied_source_element_count,
            pending_nodes,
            accumulated_evaluation: CompactChallengeField::ZERO,
            evaluated_source_element_count: 0,
            complete: false,
        })
    }

    pub(crate) fn poll<SourceError>(
        &mut self,
        maximum_work_unit_count: u64,
        mut source_value: impl FnMut(u64) -> Result<CompactChallengeField, SourceError>,
    ) -> Result<CompactCfwPrefixEvaluationProgress, CompactCfwPrefixEvaluationError<SourceError>>
    {
        let maximum_work_unit_count =
            usize::try_from(maximum_work_unit_count).map_err(|_| CompactCfwError::CountOverflow)?;
        if maximum_work_unit_count == 0 || self.complete || self.pending_nodes.is_empty() {
            return Err(CompactCfwError::WrongProverPhase.into());
        }
        let mut processed_work_unit_count = 0_usize;
        let initial_evaluated_source_element_count = self.evaluated_source_element_count;
        while processed_work_unit_count < maximum_work_unit_count {
            let Some(node) = self.pending_nodes.pop() else {
                break;
            };
            processed_work_unit_count += 1;
            if node.coordinate_ordinal == self.point.len() {
                let value = source_value(
                    u64::try_from(node.first_leaf_ordinal)
                        .map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map_err(CompactCfwPrefixEvaluationError::Source)?;
                self.accumulated_evaluation += node.accumulated_weight * value;
                self.evaluated_source_element_count = self
                    .evaluated_source_element_count
                    .checked_add(1)
                    .ok_or(CompactCfwError::CountOverflow)?;
                continue;
            }

            let remaining_coordinate_count = self
                .point
                .len()
                .checked_sub(node.coordinate_ordinal + 1)
                .ok_or(CompactCfwError::CountOverflow)?;
            let right_first_leaf_ordinal = node
                .first_leaf_ordinal
                .checked_add(
                    1_usize
                        .checked_shl(
                            u32::try_from(remaining_coordinate_count)
                                .map_err(|_| CompactCfwError::CountOverflow)?,
                        )
                        .ok_or(CompactCfwError::CountOverflow)?,
                )
                .ok_or(CompactCfwError::CountOverflow)?;
            let coordinate = self.point[node.coordinate_ordinal];
            let next_coordinate_ordinal = node
                .coordinate_ordinal
                .checked_add(1)
                .ok_or(CompactCfwError::CountOverflow)?;
            if right_first_leaf_ordinal < self.copied_source_element_count {
                self.pending_nodes.push(CompactCfwPrefixEvaluationNode {
                    coordinate_ordinal: next_coordinate_ordinal,
                    first_leaf_ordinal: right_first_leaf_ordinal,
                    accumulated_weight: node.accumulated_weight * coordinate,
                });
            }
            self.pending_nodes.push(CompactCfwPrefixEvaluationNode {
                coordinate_ordinal: next_coordinate_ordinal,
                first_leaf_ordinal: node.first_leaf_ordinal,
                accumulated_weight: node.accumulated_weight
                    * (CompactChallengeField::ONE - coordinate),
            });
        }
        if self.pending_nodes.is_empty() {
            if self.evaluated_source_element_count != self.copied_source_element_count {
                return Err(CompactCfwError::InvalidClaimInput.into());
            }
            self.complete = true;
        }
        Ok(CompactCfwPrefixEvaluationProgress {
            processed_work_unit_count: u64::try_from(processed_work_unit_count)
                .map_err(|_| CompactCfwError::CountOverflow)?,
            evaluated_source_element_count: u64::try_from(
                self.evaluated_source_element_count - initial_evaluated_source_element_count,
            )
            .map_err(|_| CompactCfwError::CountOverflow)?,
        })
    }

    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn evaluation(&self) -> Result<CompactChallengeField, CompactCfwError> {
        self.complete
            .then_some(self.accumulated_evaluation)
            .ok_or(CompactCfwError::WrongProverPhase)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwClaimBatch {
    geometry: CompactCfwGeometry,
    joint_target: CompactChallengeField,
    joint_inner_mask_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    sumcheck_point: Vec<CompactChallengeField>,
    outer_evaluations: Vec<CompactChallengeField>,
}

pub(crate) struct CompactCfwMatrixClaimCombination {
    continuation: CompactCfwClaimCombinationContinuation,
    source_covector: Vec<CompactChallengeField>,
}

pub(crate) struct CompactCfwClaimCombinationContinuation {
    claim_batch: CompactCfwClaimBatch,
    payload_geometry: CompactCfwToWhirPayloadGeometry,
    preceding_target: CompactChallengeField,
    preceding_mask_covectors: Vec<Vec<CompactChallengeField>>,
    batching_challenge: CompactChallengeField,
    joint_batching_coefficient: CompactChallengeField,
    preceding_opening_claim_count: usize,
}

/// Target-free public coefficient seed for the selected main WHIR opening.
///
/// This is coefficient algebra only. It is derived from verifier challenges
/// and contract geometry and cannot replace the separate CFW target and
/// endpoint checks on the proof-verification path.
pub(crate) struct CompactCfwPublicMainCovectorCombination {
    continuation: CompactCfwPublicMainCovectorContinuation,
    source_covector: Vec<CompactChallengeField>,
}

pub(crate) struct CompactCfwPublicMainCovectorContinuation {
    geometry: CompactCfwGeometry,
    retained_source_element_count: usize,
    sumcheck_point: Vec<CompactChallengeField>,
    joint_inner_mask_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    batching_challenge: CompactChallengeField,
    joint_batching_coefficient: CompactChallengeField,
    cross_mask_covectors: Vec<Vec<CompactChallengeField>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwPublicMainCovectors {
    pub(crate) source: Vec<CompactChallengeField>,
    pub(crate) inner_masks: Vec<Vec<CompactChallengeField>>,
    pub(crate) outer_masks: Vec<Vec<CompactChallengeField>>,
    pub(crate) cross_epoch_masks: Vec<Vec<CompactChallengeField>>,
}

impl CompactCfwPublicMainCovectors {
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<CompactChallengeField>,
        Vec<Vec<CompactChallengeField>>,
        Vec<Vec<CompactChallengeField>>,
        Vec<Vec<CompactChallengeField>>,
    ) {
        (
            self.source,
            self.inner_masks,
            self.outer_masks,
            self.cross_epoch_masks,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwToWhirPayloadGeometry {
    source_variable_count: usize,
    preceding_opening_claim_extension_element_count: usize,
    cfw_claim_batch_extension_element_count: usize,
    source_covector_extension_element_count: usize,
    preceding_mask_covector_extension_element_count: usize,
    inner_mask_covector_extension_element_count: usize,
    outer_mask_covector_extension_element_count: usize,
    combined_relation_extension_element_count: usize,
    transition_live_extension_element_count: usize,
}

impl CompactCfwToWhirPayloadGeometry {
    pub(crate) fn derive(
        geometry: CompactCfwGeometry,
        preceding_opening_claim_count: usize,
    ) -> Result<Self, CompactCfwError> {
        Self::derive_with_preceding_mask_covector_element_count(
            geometry,
            preceding_opening_claim_count,
            0,
        )
    }

    pub(crate) fn derive_with_preceding_mask_covector_element_count(
        geometry: CompactCfwGeometry,
        preceding_opening_claim_count: usize,
        preceding_mask_covector_extension_element_count: usize,
    ) -> Result<Self, CompactCfwError> {
        let source_variable_count = usize::try_from(geometry.witness_length().ilog2())
            .map_err(|_| CompactCfwError::CountOverflow)?;
        let preceding_opening_claim_extension_element_count = preceding_opening_claim_count
            .checked_mul(
                source_variable_count
                    .checked_add(1)
                    .ok_or(CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        let cfw_claim_batch_extension_element_count = 1_usize
            .checked_add(COMPACT_CFW_MATRIX_COUNT)
            .and_then(|count| count.checked_add(geometry.sumcheck_round_count()))
            .and_then(|count| count.checked_add(geometry.outer_mask_count()))
            .ok_or(CompactCfwError::CountOverflow)?;
        let source_covector_extension_element_count = geometry.witness_length();
        let inner_mask_covector_extension_element_count = geometry
            .inner_mask_count()
            .checked_mul(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
            .ok_or(CompactCfwError::CountOverflow)?;
        let outer_mask_covector_extension_element_count = geometry
            .outer_mask_count()
            .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .ok_or(CompactCfwError::CountOverflow)?;
        let combined_relation_extension_element_count = source_covector_extension_element_count
            .checked_add(1)
            .and_then(|count| count.checked_add(preceding_mask_covector_extension_element_count))
            .and_then(|count| count.checked_add(inner_mask_covector_extension_element_count))
            .and_then(|count| count.checked_add(outer_mask_covector_extension_element_count))
            .ok_or(CompactCfwError::CountOverflow)?;
        let transition_live_extension_element_count = combined_relation_extension_element_count
            .checked_add(preceding_opening_claim_extension_element_count)
            .and_then(|count| count.checked_add(cfw_claim_batch_extension_element_count))
            .ok_or(CompactCfwError::CountOverflow)?;

        Ok(Self {
            source_variable_count,
            preceding_opening_claim_extension_element_count,
            cfw_claim_batch_extension_element_count,
            source_covector_extension_element_count,
            preceding_mask_covector_extension_element_count,
            inner_mask_covector_extension_element_count,
            outer_mask_covector_extension_element_count,
            combined_relation_extension_element_count,
            transition_live_extension_element_count,
        })
    }

    pub(crate) const fn source_variable_count(self) -> usize {
        self.source_variable_count
    }

    pub(crate) const fn preceding_opening_claim_extension_element_count(self) -> usize {
        self.preceding_opening_claim_extension_element_count
    }

    pub(crate) const fn cfw_claim_batch_extension_element_count(self) -> usize {
        self.cfw_claim_batch_extension_element_count
    }

    pub(crate) const fn source_covector_extension_element_count(self) -> usize {
        self.source_covector_extension_element_count
    }

    pub(crate) const fn preceding_mask_covector_extension_element_count(self) -> usize {
        self.preceding_mask_covector_extension_element_count
    }

    pub(crate) const fn inner_mask_covector_extension_element_count(self) -> usize {
        self.inner_mask_covector_extension_element_count
    }

    pub(crate) const fn outer_mask_covector_extension_element_count(self) -> usize {
        self.outer_mask_covector_extension_element_count
    }

    pub(crate) const fn combined_relation_extension_element_count(self) -> usize {
        self.combined_relation_extension_element_count
    }

    pub(crate) const fn transition_live_extension_element_count(self) -> usize {
        self.transition_live_extension_element_count
    }
}

impl CompactCfwClaimBatch {
    pub(crate) fn combine_with_preceding_opening_claims(
        self,
        matrices: &impl CompactCfwR1csMatrices,
        preceding_opening_claims: &[CompactCfwMultilinearOpeningClaim],
        batching_challenge: CompactChallengeField,
    ) -> Result<CompactCfwCombinedRelation, CompactCfwError> {
        if matrices.witness_length() != self.geometry.witness_length() {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let combination = self.begin_combining_with_preceding_opening_claims(
            preceding_opening_claims,
            batching_challenge,
        )?;
        let (continuation, mut source_covector) = combination.into_parts();
        matrices.accumulate_weighted_witness_covector_at_row_point(
            continuation.row_point(),
            continuation.matrix_role_weights(),
            &mut source_covector,
        )?;
        continuation.finish_after_matrix_accumulation(source_covector)
    }

    pub(crate) fn begin_combining_with_preceding_opening_claims(
        self,
        preceding_opening_claims: &[CompactCfwMultilinearOpeningClaim],
        batching_challenge: CompactChallengeField,
    ) -> Result<CompactCfwMatrixClaimCombination, CompactCfwError> {
        if self.sumcheck_point.len() != self.geometry.sumcheck_round_count()
            || self.outer_evaluations.len() != self.geometry.outer_mask_count()
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        if self.sumcheck_point.capacity() != self.sumcheck_point.len()
            || self.outer_evaluations.capacity() != self.outer_evaluations.len()
        {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        let payload_geometry =
            CompactCfwToWhirPayloadGeometry::derive(self.geometry, preceding_opening_claims.len())?;
        if preceding_opening_claims
            .iter()
            .any(|claim| claim.point.len() != payload_geometry.source_variable_count())
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        let mut source_covector = Vec::new();
        source_covector
            .try_reserve_exact(payload_geometry.source_covector_extension_element_count())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        source_covector.resize(
            payload_geometry.source_covector_extension_element_count(),
            CompactChallengeField::ZERO,
        );
        if source_covector.capacity() != payload_geometry.source_covector_extension_element_count()
        {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        let mut preceding_target = CompactChallengeField::ZERO;
        let mut batching_coefficient = CompactChallengeField::ONE;
        for claim in preceding_opening_claims {
            accumulate_scaled_multilinear_equality_covector(
                &mut source_covector,
                &claim.point,
                batching_coefficient,
            )?;
            preceding_target += batching_coefficient * claim.target;
            batching_coefficient *= batching_challenge;
        }

        Ok(CompactCfwMatrixClaimCombination {
            continuation: CompactCfwClaimCombinationContinuation {
                claim_batch: self,
                payload_geometry,
                preceding_target,
                preceding_mask_covectors: Vec::new(),
                batching_challenge,
                joint_batching_coefficient: batching_coefficient,
                preceding_opening_claim_count: preceding_opening_claims.len(),
            },
            source_covector,
        })
    }

    pub(crate) fn begin_combining_with_masked_cross_epoch_claims(
        self,
        claims: CompactCfwMaskedCrossEpochClaims,
        batching_challenge: CompactChallengeField,
    ) -> Result<CompactCfwMatrixClaimCombination, CompactCfwError> {
        const CROSS_EPOCH_CLAIM_COUNT: usize = 2;
        if self.sumcheck_point.len() != self.geometry.sumcheck_round_count()
            || self.outer_evaluations.len() != self.geometry.outer_mask_count()
            || self.sumcheck_point.capacity() != self.sumcheck_point.len()
            || self.outer_evaluations.capacity() != self.outer_evaluations.len()
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        let payload_geometry =
            CompactCfwToWhirPayloadGeometry::derive_with_preceding_mask_covector_element_count(
                self.geometry,
                CROSS_EPOCH_CLAIM_COUNT,
                COMPACT_CFW_CROSS_EPOCH_MASK_COVECTOR_COUNT,
            )?;
        let expected_cross_epoch_point_coordinate_count = payload_geometry
            .source_variable_count()
            .checked_sub(1)
            .ok_or(CompactCfwError::InvalidClaimInput)?;
        let pre_challenge_message_element_count = 1_usize
            .checked_shl(
                u32::try_from(expected_cross_epoch_point_coordinate_count)
                    .map_err(|_| CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        if claims.point.len() != expected_cross_epoch_point_coordinate_count
            || claims.copied_main_source_element_count == 0
            || claims.copied_main_source_element_count > pre_challenge_message_element_count
            || claims.masked_pre_challenge_evaluation
                - claims.masked_main_evaluation
                - claims.mask_difference
                != CompactChallengeField::ZERO
            || self.geometry.witness_length()
                != pre_challenge_message_element_count
                    .checked_mul(2)
                    .ok_or(CompactCfwError::CountOverflow)?
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }

        let mut source_covector = Vec::new();
        source_covector
            .try_reserve_exact(payload_geometry.source_covector_extension_element_count())
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        source_covector.resize(
            payload_geometry.source_covector_extension_element_count(),
            CompactChallengeField::ZERO,
        );
        if source_covector.capacity() != payload_geometry.source_covector_extension_element_count()
        {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        accumulate_scaled_multilinear_prefix_covector(
            &mut source_covector,
            &claims.point,
            claims.copied_main_source_element_count,
            CompactChallengeField::ONE,
        )?;

        let preceding_target =
            claims.masked_main_evaluation + batching_challenge * claims.mask_difference;
        let preceding_mask_covectors = vec![
            vec![batching_challenge],
            vec![CompactChallengeField::ONE - batching_challenge],
        ];
        let joint_batching_coefficient = batching_challenge * batching_challenge;

        Ok(CompactCfwMatrixClaimCombination {
            continuation: CompactCfwClaimCombinationContinuation {
                claim_batch: self,
                payload_geometry,
                preceding_target,
                preceding_mask_covectors,
                batching_challenge,
                joint_batching_coefficient,
                preceding_opening_claim_count: CROSS_EPOCH_CLAIM_COUNT,
            },
            source_covector,
        })
    }
}

impl CompactCfwPublicMainCovectorCombination {
    pub(crate) fn from_public_challenges_before_whir_fold(
        geometry: CompactCfwGeometry,
        cross_epoch_point: &[CompactChallengeField],
        copied_main_source_element_count: usize,
        sumcheck_point: &[CompactChallengeField],
        joint_challenge: CompactChallengeField,
        batching_challenge: CompactChallengeField,
    ) -> Result<Self, CompactCfwError> {
        Self::from_public_challenges(
            geometry,
            cross_epoch_point,
            copied_main_source_element_count,
            sumcheck_point,
            joint_challenge,
            batching_challenge,
            None,
        )
    }

    pub(crate) fn from_public_challenges_after_first_whir_fold(
        geometry: CompactCfwGeometry,
        cross_epoch_point: &[CompactChallengeField],
        copied_main_source_element_count: usize,
        sumcheck_point: &[CompactChallengeField],
        joint_challenge: CompactChallengeField,
        batching_challenge: CompactChallengeField,
        first_fold_challenges: &[CompactChallengeField],
    ) -> Result<Self, CompactCfwError> {
        if first_fold_challenges.is_empty() {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        Self::from_public_challenges(
            geometry,
            cross_epoch_point,
            copied_main_source_element_count,
            sumcheck_point,
            joint_challenge,
            batching_challenge,
            Some(first_fold_challenges),
        )
    }

    fn from_public_challenges(
        geometry: CompactCfwGeometry,
        cross_epoch_point: &[CompactChallengeField],
        copied_main_source_element_count: usize,
        sumcheck_point: &[CompactChallengeField],
        joint_challenge: CompactChallengeField,
        batching_challenge: CompactChallengeField,
        first_fold_challenges: Option<&[CompactChallengeField]>,
    ) -> Result<Self, CompactCfwError> {
        let expected_cross_epoch_point_coordinate_count =
            usize::try_from(geometry.witness_length().ilog2())
                .map_err(|_| CompactCfwError::CountOverflow)?
                .checked_sub(1)
                .ok_or(CompactCfwError::InvalidClaimInput)?;
        let pre_challenge_message_element_count = 1_usize
            .checked_shl(
                u32::try_from(expected_cross_epoch_point_coordinate_count)
                    .map_err(|_| CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        let retained_source_element_count = match first_fold_challenges {
            Some(challenges) => geometry
                .witness_length()
                .checked_shr(
                    u32::try_from(challenges.len()).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .ok_or(CompactCfwError::CountOverflow)?,
            None => geometry.witness_length(),
        };
        if retained_source_element_count == 0
            || !retained_source_element_count.is_power_of_two()
            || cross_epoch_point.len() != expected_cross_epoch_point_coordinate_count
            || copied_main_source_element_count == 0
            || copied_main_source_element_count > pre_challenge_message_element_count
            || geometry.witness_length()
                != pre_challenge_message_element_count
                    .checked_mul(2)
                    .ok_or(CompactCfwError::CountOverflow)?
            || sumcheck_point.len() != geometry.sumcheck_round_count()
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }

        let mut source_covector = Vec::new();
        source_covector
            .try_reserve_exact(retained_source_element_count)
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        source_covector.resize(retained_source_element_count, CompactChallengeField::ZERO);
        if source_covector.capacity() != retained_source_element_count {
            return Err(CompactCfwError::AllocationLimitExceeded);
        }
        match first_fold_challenges {
            Some(challenges) => accumulate_projected_multilinear_prefix_covector(
                &mut source_covector,
                cross_epoch_point,
                copied_main_source_element_count,
                challenges,
            )?,
            None => accumulate_scaled_multilinear_prefix_covector(
                &mut source_covector,
                cross_epoch_point,
                copied_main_source_element_count,
                CompactChallengeField::ONE,
            )?,
        }
        let joint_batching_coefficient = batching_challenge * batching_challenge;
        Ok(Self {
            continuation: CompactCfwPublicMainCovectorContinuation {
                geometry,
                retained_source_element_count,
                sumcheck_point: sumcheck_point.to_vec(),
                joint_inner_mask_weights: compact_cfw_zero_evader_weights(joint_challenge),
                batching_challenge,
                joint_batching_coefficient,
                cross_mask_covectors: vec![
                    vec![batching_challenge],
                    vec![CompactChallengeField::ONE - batching_challenge],
                ],
            },
            source_covector,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CompactCfwPublicMainCovectorContinuation,
        Vec<CompactChallengeField>,
    ) {
        (self.continuation, self.source_covector)
    }
}

impl CompactCfwPublicMainCovectorContinuation {
    pub(crate) fn row_point(&self) -> &[CompactChallengeField] {
        &self.sumcheck_point
    }

    pub(crate) fn matrix_role_weights(&self) -> [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] {
        self.joint_inner_mask_weights
            .map(|weight| weight * self.joint_batching_coefficient)
    }

    pub(crate) const fn batching_challenge(&self) -> CompactChallengeField {
        self.batching_challenge
    }

    pub(crate) fn finish_after_matrix_accumulation(
        self,
        source_covector: Vec<CompactChallengeField>,
    ) -> Result<CompactCfwPublicMainCovectors, CompactCfwError> {
        if source_covector.len() != self.retained_source_element_count
            || source_covector.capacity() != self.retained_source_element_count
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        let inner_mask_multiplier =
            CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
        let mut batching_coefficient = self.joint_batching_coefficient * self.batching_challenge;
        let mut inner_mask_covectors = Vec::with_capacity(self.geometry.inner_mask_count());
        for &point_coordinate in &self.sumcheck_point {
            for matrix_role in CompactCfwMatrixRole::ALL {
                let mut covector = polynomial_evaluation_covector::<
                    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH,
                >(point_coordinate);
                let joint_scale = self.joint_batching_coefficient
                    * inner_mask_multiplier
                    * self.joint_inner_mask_weights[matrix_role.ordinal()];
                for coefficient in &mut covector {
                    *coefficient *= joint_scale;
                }
                covector[0] += batching_coefficient;
                batching_coefficient *= self.batching_challenge;
                for coefficient in &mut covector {
                    *coefficient += batching_coefficient;
                }
                batching_coefficient *= self.batching_challenge;
                inner_mask_covectors.push(covector.to_vec());
            }
        }
        let mut outer_mask_covectors = Vec::with_capacity(self.geometry.outer_mask_count());
        for &point_coordinate in &self.sumcheck_point {
            let mut covector = polynomial_evaluation_covector::<
                COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
            >(point_coordinate);
            for coefficient in &mut covector {
                *coefficient *= batching_coefficient;
            }
            batching_coefficient *= self.batching_challenge;
            outer_mask_covectors.push(covector.to_vec());
        }
        if self.cross_mask_covectors.len() != COMPACT_CFW_CROSS_EPOCH_MASK_COVECTOR_COUNT {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        Ok(CompactCfwPublicMainCovectors {
            source: source_covector,
            inner_masks: inner_mask_covectors,
            outer_masks: outer_mask_covectors,
            cross_epoch_masks: self.cross_mask_covectors,
        })
    }
}

impl CompactCfwMatrixClaimCombination {
    pub(crate) fn into_parts(
        self,
    ) -> (
        CompactCfwClaimCombinationContinuation,
        Vec<CompactChallengeField>,
    ) {
        (self.continuation, self.source_covector)
    }
}

impl CompactCfwClaimCombinationContinuation {
    pub(crate) fn row_point(&self) -> &[CompactChallengeField] {
        &self.claim_batch.sumcheck_point
    }

    pub(crate) fn matrix_role_weights(&self) -> [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] {
        self.claim_batch
            .joint_inner_mask_weights
            .map(|weight| weight * self.joint_batching_coefficient)
    }

    pub(crate) fn finish_after_matrix_accumulation(
        self,
        source_covector: Vec<CompactChallengeField>,
    ) -> Result<CompactCfwCombinedRelation, CompactCfwError> {
        if source_covector.len()
            != self
                .payload_geometry
                .source_covector_extension_element_count()
            || source_covector.capacity()
                != self
                    .payload_geometry
                    .source_covector_extension_element_count()
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        let mut target =
            self.preceding_target + self.joint_batching_coefficient * self.claim_batch.joint_target;
        let mut batching_coefficient = self.joint_batching_coefficient * self.batching_challenge;

        let inner_mask_multiplier =
            CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
        let mut inner_mask_covectors =
            Vec::with_capacity(self.claim_batch.geometry.inner_mask_count());
        for round_ordinal in 0..self.claim_batch.geometry.sumcheck_round_count() {
            for matrix_role in CompactCfwMatrixRole::ALL {
                let mut covector = polynomial_evaluation_covector::<
                    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH,
                >(self.claim_batch.sumcheck_point[round_ordinal]);
                let joint_scale = self.joint_batching_coefficient
                    * inner_mask_multiplier
                    * self.claim_batch.joint_inner_mask_weights[matrix_role.ordinal()];
                for coefficient in &mut covector {
                    *coefficient *= joint_scale;
                }

                covector[0] += batching_coefficient;
                batching_coefficient *= self.batching_challenge;
                for coefficient in &mut covector {
                    *coefficient += batching_coefficient;
                }
                batching_coefficient *= self.batching_challenge;
                inner_mask_covectors.push(covector.to_vec());
            }
        }

        let mut outer_mask_covectors =
            Vec::with_capacity(self.claim_batch.geometry.outer_mask_count());
        for (&point_coordinate, &evaluation) in self
            .claim_batch
            .sumcheck_point
            .iter()
            .zip(&self.claim_batch.outer_evaluations)
        {
            let mut covector = polynomial_evaluation_covector::<
                COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
            >(point_coordinate);
            for coefficient in &mut covector {
                *coefficient *= batching_coefficient;
            }
            target += batching_coefficient * evaluation;
            batching_coefficient *= self.batching_challenge;
            outer_mask_covectors.push(covector.to_vec());
        }

        let claim_count = self
            .preceding_opening_claim_count
            .checked_add(
                self.claim_batch
                    .geometry
                    .generalized_committed_relation_claim_count(),
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        let combined_relation = CompactCfwCombinedRelation {
            source_covector,
            target,
            preceding_mask_covectors: self.preceding_mask_covectors,
            inner_mask_covectors,
            outer_mask_covectors,
            claim_count,
        };
        if combined_relation.extension_element_count()?
            != self
                .payload_geometry
                .combined_relation_extension_element_count()
        {
            return Err(CompactCfwError::InvalidClaimInput);
        }
        Ok(combined_relation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwCombinedRelation {
    source_covector: Vec<CompactChallengeField>,
    target: CompactChallengeField,
    preceding_mask_covectors: Vec<Vec<CompactChallengeField>>,
    inner_mask_covectors: Vec<Vec<CompactChallengeField>>,
    outer_mask_covectors: Vec<Vec<CompactChallengeField>>,
    claim_count: usize,
}

type CompactCfwCombinedRelationParts = (
    Vec<CompactChallengeField>,
    CompactChallengeField,
    Vec<Vec<CompactChallengeField>>,
    Vec<Vec<CompactChallengeField>>,
    Vec<Vec<CompactChallengeField>>,
    usize,
);

impl CompactCfwCombinedRelation {
    fn extension_element_count(&self) -> Result<usize, CompactCfwError> {
        self.source_covector
            .len()
            .checked_add(1)
            .and_then(|count| {
                self.preceding_mask_covectors
                    .iter()
                    .try_fold(count, |total, covector| total.checked_add(covector.len()))
            })
            .and_then(|count| {
                self.inner_mask_covectors
                    .iter()
                    .try_fold(count, |total, covector| total.checked_add(covector.len()))
            })
            .and_then(|count| {
                self.outer_mask_covectors
                    .iter()
                    .try_fold(count, |total, covector| total.checked_add(covector.len()))
            })
            .ok_or(CompactCfwError::CountOverflow)
    }

    pub(crate) fn into_parts(self) -> CompactCfwCombinedRelationParts {
        (
            self.source_covector,
            self.target,
            self.preceding_mask_covectors,
            self.inner_mask_covectors,
            self.outer_mask_covectors,
            self.claim_count,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_compact_cfw_transcript(
    matrices: &impl CompactCfwR1csMatrices,
    public_input: &[CompactChallengeField],
    transcript: &CompactCfwTranscript,
    constraint_combining_challenge: CompactChallengeField,
    equality_point: &[CompactChallengeField],
    sumcheck_point: &[CompactChallengeField],
    joint_constraint_challenge: CompactChallengeField,
) -> Result<CompactCfwClaimBatch, CompactCfwError> {
    let geometry = CompactCfwGeometry::derive(matrices.witness_length())?;
    if public_input.len() != geometry.witness_length()
        || equality_point.len() != geometry.sumcheck_round_count()
        || sumcheck_point.len() != geometry.sumcheck_round_count()
        || transcript.round_polynomials().len() != geometry.sumcheck_round_count()
        || transcript.outer_evaluations().len() != geometry.outer_mask_count()
    {
        return Err(CompactCfwError::InvalidGeometry);
    }
    if sumcheck_point
        .last()
        .is_none_or(|challenge| !compact_cfw_final_challenge_is_allowed(*challenge))
    {
        return Err(CompactCfwError::InvalidFinalChallenge);
    }

    let mut expected_claim = transcript.auxiliary_target();
    for (round_ordinal, (round_polynomial, &round_challenge)) in transcript
        .round_polynomials()
        .iter()
        .zip(sumcheck_point)
        .enumerate()
    {
        if polynomial_endpoint_sum(round_polynomial) != expected_claim {
            return Err(CompactCfwError::SumcheckConsistency { round_ordinal });
        }
        expected_claim = evaluate_polynomial(round_polynomial, round_challenge);
    }

    let equality_evaluation = equality_polynomial_evaluation(equality_point, sumcheck_point)?;
    let final_values = transcript.final_values();
    let final_sumcheck_value = constraint_combining_challenge
        * (final_values[CompactCfwMatrixRole::LeftMultiplicand.ordinal()]
            * final_values[CompactCfwMatrixRole::RightMultiplicand.ordinal()]
            - final_values[CompactCfwMatrixRole::Product.ordinal()])
        * equality_evaluation
        + transcript
            .outer_evaluations()
            .iter()
            .copied()
            .sum::<CompactChallengeField>();
    if final_sumcheck_value != expected_claim {
        return Err(CompactCfwError::FinalConsistency);
    }

    let joint_inner_mask_weights = compact_cfw_zero_evader_weights(joint_constraint_challenge);
    let mut joint_target = CompactChallengeField::ZERO;
    for matrix_role in CompactCfwMatrixRole::ALL {
        let public_contribution =
            matrices.public_contribution_at_row_point(matrix_role, sumcheck_point, public_input)?;
        let weight = joint_inner_mask_weights[matrix_role.ordinal()];
        joint_target += weight * (final_values[matrix_role.ordinal()] - public_contribution);
    }

    Ok(CompactCfwClaimBatch {
        geometry,
        joint_target,
        joint_inner_mask_weights,
        sumcheck_point: sumcheck_point.to_vec(),
        outer_evaluations: transcript.outer_evaluations().to_vec(),
    })
}

fn auxiliary_target(
    geometry: CompactCfwGeometry,
    mask_material: &CompactCfwMaskMaterial,
) -> Result<CompactChallengeField, CompactCfwError> {
    if geometry.sumcheck_round_count() == 0 {
        return Err(CompactCfwError::InvalidGeometry);
    }
    let endpoint_multiplicity = 1_usize
        .checked_shl(
            u32::try_from(geometry.sumcheck_round_count() - 1)
                .map_err(|_| CompactCfwError::CountOverflow)?,
        )
        .ok_or(CompactCfwError::CountOverflow)?;
    let endpoint_sum = mask_material
        .outer_masks()
        .iter()
        .map(|mask| {
            evaluate_polynomial(mask, CompactChallengeField::ZERO)
                + evaluate_polynomial(mask, CompactChallengeField::ONE)
        })
        .sum::<CompactChallengeField>();
    Ok(field_from_usize(endpoint_multiplicity)? * endpoint_sum)
}

fn equality_polynomial_evaluation(
    equality_point: &[CompactChallengeField],
    evaluation_point: &[CompactChallengeField],
) -> Result<CompactChallengeField, CompactCfwError> {
    if equality_point.len() != evaluation_point.len() {
        return Err(CompactCfwError::InvalidGeometry);
    }
    Ok(equality_point
        .iter()
        .zip(evaluation_point)
        .map(|(&equality_coordinate, &evaluation_coordinate)| {
            (CompactChallengeField::ONE - equality_coordinate)
                * (CompactChallengeField::ONE - evaluation_coordinate)
                + equality_coordinate * evaluation_coordinate
        })
        .product())
}

pub(crate) fn compact_cfw_fold_row_pair(
    value_at_zero: CompactChallengeField,
    value_at_one: CompactChallengeField,
    challenge: CompactChallengeField,
) -> CompactChallengeField {
    value_at_zero + challenge * (value_at_one - value_at_zero)
}

fn compact_cfw_matrix_factor_polynomial(
    value_at_zero: CompactChallengeField,
    value_at_one: CompactChallengeField,
    past_inner_mask_evaluation: CompactChallengeField,
    current_inner_mask: &[CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH],
) -> [CompactChallengeField; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH] {
    let inner_mask_multiplier =
        CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
    let mut polynomial = [
        value_at_zero + past_inner_mask_evaluation,
        value_at_one - value_at_zero,
        CompactChallengeField::ZERO,
        CompactChallengeField::ZERO,
    ];
    for (destination, coefficient) in polynomial.iter_mut().zip(current_inner_mask) {
        *destination += inner_mask_multiplier * *coefficient;
    }
    polynomial
}

fn cfw_little_endian_boolean_point_weight(
    point: &[CompactChallengeField],
    boolean_ordinal: usize,
) -> CompactChallengeField {
    point
        .iter()
        .enumerate()
        .map(|(coordinate_ordinal, coordinate)| {
            if (boolean_ordinal >> coordinate_ordinal) & 1 == 0 {
                CompactChallengeField::ONE - *coordinate
            } else {
                *coordinate
            }
        })
        .product()
}

fn whir_multilinear_point_weight(
    point: &[CompactChallengeField],
    boolean_ordinal: usize,
) -> CompactChallengeField {
    point
        .iter()
        .enumerate()
        .map(|(coordinate_ordinal, coordinate)| {
            let boolean_bit_ordinal = point.len() - coordinate_ordinal - 1;
            if (boolean_ordinal >> boolean_bit_ordinal) & 1 == 0 {
                CompactChallengeField::ONE - *coordinate
            } else {
                *coordinate
            }
        })
        .product()
}

fn polynomial_endpoint_sum<const COEFFICIENT_COUNT: usize>(
    coefficients: &[CompactChallengeField; COEFFICIENT_COUNT],
) -> CompactChallengeField {
    evaluate_polynomial(coefficients, CompactChallengeField::ZERO)
        + evaluate_polynomial(coefficients, CompactChallengeField::ONE)
}

fn polynomial_evaluation_covector<const COEFFICIENT_COUNT: usize>(
    point: CompactChallengeField,
) -> [CompactChallengeField; COEFFICIENT_COUNT] {
    let mut power = CompactChallengeField::ONE;
    core::array::from_fn(|_| {
        let coefficient = power;
        power *= point;
        coefficient
    })
}

fn evaluate_polynomial<const COEFFICIENT_COUNT: usize>(
    coefficients: &[CompactChallengeField; COEFFICIENT_COUNT],
    point: CompactChallengeField,
) -> CompactChallengeField {
    coefficients
        .iter()
        .rev()
        .fold(CompactChallengeField::ZERO, |evaluation, &coefficient| {
            evaluation * point + coefficient
        })
}

fn multiply_polynomials<
    const LEFT_COEFFICIENT_COUNT: usize,
    const RIGHT_COEFFICIENT_COUNT: usize,
    const OUTPUT_COEFFICIENT_COUNT: usize,
>(
    left: &[CompactChallengeField; LEFT_COEFFICIENT_COUNT],
    right: &[CompactChallengeField; RIGHT_COEFFICIENT_COUNT],
) -> [CompactChallengeField; OUTPUT_COEFFICIENT_COUNT] {
    debug_assert_eq!(
        OUTPUT_COEFFICIENT_COUNT,
        LEFT_COEFFICIENT_COUNT + RIGHT_COEFFICIENT_COUNT - 1,
    );
    let mut output = [CompactChallengeField::ZERO; OUTPUT_COEFFICIENT_COUNT];
    for (left_ordinal, &left_coefficient) in left.iter().enumerate() {
        for (right_ordinal, &right_coefficient) in right.iter().enumerate() {
            output[left_ordinal + right_ordinal] += left_coefficient * right_coefficient;
        }
    }
    output
}

fn accumulate_scaled_multilinear_equality_covector(
    destination: &mut [CompactChallengeField],
    point: &[CompactChallengeField],
    scale: CompactChallengeField,
) -> Result<(), CompactCfwError> {
    let expected_length = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| CompactCfwError::CountOverflow)?)
        .ok_or(CompactCfwError::CountOverflow)?;
    if destination.len() != expected_length {
        return Err(CompactCfwError::InvalidClaimInput);
    }

    fn accumulate_subtree(
        destination: &mut [CompactChallengeField],
        point: &[CompactChallengeField],
        coordinate_ordinal: usize,
        boolean_ordinal: usize,
        partial_weight: CompactChallengeField,
        scale: CompactChallengeField,
    ) -> Result<(), CompactCfwError> {
        if coordinate_ordinal == point.len() {
            let destination_value = destination
                .get_mut(boolean_ordinal)
                .ok_or(CompactCfwError::InvalidClaimInput)?;
            *destination_value += scale * partial_weight;
            return Ok(());
        }
        let coordinate = point[coordinate_ordinal];
        accumulate_subtree(
            destination,
            point,
            coordinate_ordinal + 1,
            boolean_ordinal,
            partial_weight * (CompactChallengeField::ONE - coordinate),
            scale,
        )?;
        let boolean_bit_ordinal = point
            .len()
            .checked_sub(coordinate_ordinal + 1)
            .ok_or(CompactCfwError::CountOverflow)?;
        let one_ordinal = boolean_ordinal
            .checked_add(
                1_usize
                    .checked_shl(
                        u32::try_from(boolean_bit_ordinal)
                            .map_err(|_| CompactCfwError::CountOverflow)?,
                    )
                    .ok_or(CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        accumulate_subtree(
            destination,
            point,
            coordinate_ordinal + 1,
            one_ordinal,
            partial_weight * coordinate,
            scale,
        )
    }

    accumulate_subtree(destination, point, 0, 0, CompactChallengeField::ONE, scale)
}

fn accumulate_scaled_multilinear_prefix_covector(
    destination: &mut [CompactChallengeField],
    point: &[CompactChallengeField],
    copied_element_count: usize,
    scale: CompactChallengeField,
) -> Result<(), CompactCfwError> {
    let point_domain_length = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| CompactCfwError::CountOverflow)?)
        .ok_or(CompactCfwError::CountOverflow)?;
    if copied_element_count == 0
        || copied_element_count > point_domain_length
        || destination.len() < point_domain_length
    {
        return Err(CompactCfwError::InvalidClaimInput);
    }

    fn accumulate_prefix_subtree(
        destination: &mut [CompactChallengeField],
        point: &[CompactChallengeField],
        coordinate_ordinal: usize,
        first_leaf_ordinal: usize,
        copied_element_count: usize,
        accumulated_weight: CompactChallengeField,
    ) {
        if first_leaf_ordinal >= copied_element_count {
            return;
        }
        if coordinate_ordinal == point.len() {
            destination[first_leaf_ordinal] += accumulated_weight;
            return;
        }
        let remaining_coordinate_count = point.len() - coordinate_ordinal - 1;
        let right_first_leaf_ordinal = first_leaf_ordinal + (1 << remaining_coordinate_count);
        let coordinate = point[coordinate_ordinal];
        accumulate_prefix_subtree(
            destination,
            point,
            coordinate_ordinal + 1,
            first_leaf_ordinal,
            copied_element_count,
            accumulated_weight * (CompactChallengeField::ONE - coordinate),
        );
        accumulate_prefix_subtree(
            destination,
            point,
            coordinate_ordinal + 1,
            right_first_leaf_ordinal,
            copied_element_count,
            accumulated_weight * coordinate,
        );
    }

    accumulate_prefix_subtree(destination, point, 0, 0, copied_element_count, scale);
    Ok(())
}

/// Applies the known leading WHIR block fold while constructing the public
/// cross-epoch prefix covector. The full CFW source has one leading zero-half
/// selector followed by `point`; consequently the first folding coordinate
/// selects that half and each remaining folded coordinate aligns with the
/// leading coordinates of `point`.
fn accumulate_projected_multilinear_prefix_covector(
    destination: &mut [CompactChallengeField],
    point: &[CompactChallengeField],
    copied_element_count: usize,
    folding_challenges: &[CompactChallengeField],
) -> Result<(), CompactCfwError> {
    let folded_coordinate_count = folding_challenges.len();
    if folded_coordinate_count == 0 || folded_coordinate_count > point.len() + 1 {
        return Err(CompactCfwError::InvalidClaimInput);
    }
    let high_point_coordinate_count = folded_coordinate_count - 1;
    let low_point = &point[high_point_coordinate_count..];
    let projected_element_count = 1_usize
        .checked_shl(u32::try_from(low_point.len()).map_err(|_| CompactCfwError::CountOverflow)?)
        .ok_or(CompactCfwError::CountOverflow)?;
    let source_element_count = 1_usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| CompactCfwError::CountOverflow)?)
        .ok_or(CompactCfwError::CountOverflow)?;
    if destination.len() != projected_element_count
        || copied_element_count == 0
        || copied_element_count > source_element_count
    {
        return Err(CompactCfwError::InvalidClaimInput);
    }

    let complete_block_count = copied_element_count / projected_element_count;
    let partial_block_element_count = copied_element_count % projected_element_count;
    let high_point = &point[..high_point_coordinate_count];
    let maximum_source_block_count = 1_usize
        .checked_shl(
            u32::try_from(high_point_coordinate_count)
                .map_err(|_| CompactCfwError::CountOverflow)?,
        )
        .ok_or(CompactCfwError::CountOverflow)?;
    if complete_block_count > maximum_source_block_count
        || (complete_block_count == maximum_source_block_count && partial_block_element_count != 0)
    {
        return Err(CompactCfwError::InvalidClaimInput);
    }

    let mut complete_block_scale = CompactChallengeField::ZERO;
    for block_ordinal in 0..complete_block_count {
        complete_block_scale += whir_multilinear_point_weight(folding_challenges, block_ordinal)
            * whir_multilinear_point_weight(high_point, block_ordinal);
    }
    if complete_block_scale != CompactChallengeField::ZERO {
        accumulate_scaled_multilinear_equality_covector(
            destination,
            low_point,
            complete_block_scale,
        )?;
    }
    if partial_block_element_count != 0 {
        let block_scale = whir_multilinear_point_weight(folding_challenges, complete_block_count)
            * whir_multilinear_point_weight(high_point, complete_block_count);
        accumulate_scaled_multilinear_prefix_covector(
            destination,
            low_point,
            partial_block_element_count,
            block_scale,
        )?;
    }
    Ok(())
}

fn field_from_usize(value: usize) -> Result<CompactChallengeField, CompactCfwError> {
    u64::try_from(value)
        .map(CompactChallengeField::from_u64)
        .map_err(|_| CompactCfwError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::field::PROOF_BASE_FIELD_MODULUS;
    use p3_field::{BasedVectorSpace, Field};
    use p3_multilinear_util::poly::Poly;

    #[test]
    fn bounded_cross_epoch_prefix_evaluation_matches_dense_covectors() {
        let points = [
            vec![CompactChallengeField::ZERO],
            vec![CompactChallengeField::ONE],
            [3_u64, 5, 7, 11, 13]
                .map(CompactChallengeField::from_u64)
                .to_vec(),
        ];
        for point in points {
            let dense_covector = Poly::new_from_point(&point, CompactChallengeField::ONE)
                .as_slice()
                .to_vec();
            let source = (0..dense_covector.len())
                .map(|source_ordinal| {
                    CompactChallengeField::from_u64(
                        u64::try_from(source_ordinal * 17 + 9).expect("small source value"),
                    )
                })
                .collect::<Vec<_>>();
            let copied_element_counts = [1, dense_covector.len() / 2 + 1, dense_covector.len()];
            for copied_source_element_count in copied_element_counts {
                let expected = dense_covector
                    .iter()
                    .copied()
                    .zip(source.iter().copied())
                    .take(copied_source_element_count)
                    .map(|(coefficient, value)| coefficient * value)
                    .sum::<CompactChallengeField>();
                for maximum_work_unit_count in [1_u64, 2, 7, 64] {
                    let mut state =
                        CompactCfwPrefixEvaluationState::new(&point, copied_source_element_count)
                            .expect("valid copied prefix");
                    let mut visited_source_ordinals = Vec::new();
                    let mut processed_work_unit_count = 0_u64;
                    let mut evaluated_source_element_count = 0_u64;
                    while !state.is_complete() {
                        let progress = state
                            .poll(maximum_work_unit_count, |source_ordinal| {
                                visited_source_ordinals.push(source_ordinal);
                                Ok::<_, ()>(
                                    source[usize::try_from(source_ordinal)
                                        .expect("small source ordinal")],
                                )
                            })
                            .expect("bounded evaluation advances");
                        assert!(
                            (1..=maximum_work_unit_count)
                                .contains(&progress.processed_work_unit_count())
                        );
                        processed_work_unit_count += progress.processed_work_unit_count();
                        evaluated_source_element_count += progress.evaluated_source_element_count();
                    }
                    assert!(processed_work_unit_count >= evaluated_source_element_count);
                    assert_eq!(
                        evaluated_source_element_count,
                        u64::try_from(copied_source_element_count).unwrap()
                    );
                    assert_eq!(
                        visited_source_ordinals,
                        (0..u64::try_from(copied_source_element_count).unwrap())
                            .collect::<Vec<_>>()
                    );
                    assert_eq!(state.evaluation().unwrap(), expected);
                    assert_eq!(
                        state.poll(1, |_| Ok::<_, ()>(CompactChallengeField::ZERO)),
                        Err(CompactCfwPrefixEvaluationError::Cfw(
                            CompactCfwError::WrongProverPhase
                        ))
                    );

                    let claims = CompactCfwMaskedCrossEpochClaims::from_copied_source_evaluation(
                        point.clone(),
                        copied_source_element_count,
                        expected,
                        CompactChallengeField::from_u64(19),
                        CompactChallengeField::from_u64(23),
                    )
                    .expect("masked claims derive");
                    let [masked_pre_challenge, masked_main, mask_difference] =
                        claims.disclosed_values();
                    assert_eq!(
                        masked_pre_challenge - masked_main - mask_difference,
                        CompactChallengeField::ZERO
                    );
                }
            }
        }

        assert!(CompactCfwPrefixEvaluationState::new(&[], 1).is_err());
        assert!(CompactCfwPrefixEvaluationState::new(&[CompactChallengeField::ONE], 0).is_err());
        assert!(CompactCfwPrefixEvaluationState::new(&[CompactChallengeField::ONE], 3).is_err());
        assert!(
            CompactCfwMaskedCrossEpochClaims::from_copied_source_evaluation(
                Vec::new(),
                1,
                CompactChallengeField::ZERO,
                CompactChallengeField::ZERO,
                CompactChallengeField::ZERO,
            )
            .is_err()
        );
    }

    #[test]
    fn projected_public_prefix_matches_dense_first_whir_fold() {
        let point = [3_u64, 5, 7, 11, 13].map(CompactChallengeField::from_u64);
        let folding_challenges = [17_u64, 19, 23].map(CompactChallengeField::from_u64);
        let full_source_element_count = 1_usize << (point.len() + 1);
        let projected_element_count = full_source_element_count >> folding_challenges.len();

        for copied_element_count in [1_usize, 8, 21, 1 << point.len()] {
            let mut dense = vec![CompactChallengeField::ZERO; full_source_element_count];
            accumulate_scaled_multilinear_prefix_covector(
                &mut dense,
                &point,
                copied_element_count,
                CompactChallengeField::ONE,
            )
            .expect("dense public prefix");
            let expected = (0..projected_element_count)
                .map(|coefficient_ordinal| {
                    (0..(1_usize << folding_challenges.len())).fold(
                        CompactChallengeField::ZERO,
                        |value, block_ordinal| {
                            value
                                + whir_multilinear_point_weight(&folding_challenges, block_ordinal)
                                    * dense[block_ordinal * projected_element_count
                                        + coefficient_ordinal]
                        },
                    )
                })
                .collect::<Vec<_>>();
            let mut actual = vec![CompactChallengeField::ZERO; projected_element_count];
            accumulate_projected_multilinear_prefix_covector(
                &mut actual,
                &point,
                copied_element_count,
                &folding_challenges,
            )
            .expect("projected public prefix");

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn production_and_compact_challenge_fields_have_identical_canonical_arithmetic() {
        let mut deterministic_state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next_coordinates = || {
            core::array::from_fn(|coordinate_ordinal| {
                deterministic_state ^= deterministic_state << 7;
                deterministic_state ^= deterministic_state >> 9;
                deterministic_state ^= deterministic_state << 8;
                deterministic_state
                    .wrapping_add((coordinate_ordinal as u64).wrapping_mul(0x1000_0000_01b3))
                    % PROOF_BASE_FIELD_MODULUS
            })
        };

        let canonical_boundaries = [
            [0, 0, 0, 0, 0],
            [1, 0, 0, 0, 0],
            [0, 1, 0, 0, 0],
            [
                PROOF_BASE_FIELD_MODULUS - 1,
                PROOF_BASE_FIELD_MODULUS - 2,
                PROOF_BASE_FIELD_MODULUS - 3,
                PROOF_BASE_FIELD_MODULUS - 4,
                PROOF_BASE_FIELD_MODULUS - 5,
            ],
        ];
        let mut coordinate_rows = canonical_boundaries.to_vec();
        coordinate_rows.extend((0..257).map(|_| next_coordinates()));

        for (ordinal, coordinates) in coordinate_rows.iter().copied().enumerate() {
            let other_coordinates = coordinate_rows[(ordinal + 73) % coordinate_rows.len()];
            let production_left =
                ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                    .expect("canonical production challenge");
            let production_right =
                ProofChallengeExtensionElement::from_canonical_coordinates(other_coordinates)
                    .expect("canonical production challenge");
            let compact_left = compact_challenge_from_production(production_left);
            let compact_right = compact_challenge_from_production(production_right);

            assert_eq!(
                compact_challenge_to_production(compact_left)
                    .expect("compact challenge returns to production coordinates"),
                production_left,
            );
            assert_eq!(
                compact_challenge_to_production(compact_left + compact_right)
                    .expect("compact sum returns to production coordinates"),
                production_left.add(production_right),
            );
            assert_eq!(
                compact_challenge_to_production(compact_left - compact_right)
                    .expect("compact difference returns to production coordinates"),
                production_left.subtract(production_right),
            );
            assert_eq!(
                compact_challenge_to_production(compact_left * compact_right)
                    .expect("compact product returns to production coordinates"),
                production_left.multiply(production_right),
            );
            if !production_left.is_zero() {
                assert_eq!(
                    compact_challenge_to_production(compact_left.inverse())
                        .expect("compact inverse returns to production coordinates"),
                    production_left
                        .inverse()
                        .expect("nonzero production challenge is invertible"),
                );
            }
        }

        let extension_generator =
            ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
                .expect("canonical extension generator");
        assert_eq!(
            compact_challenge_to_production(
                compact_challenge_from_production(extension_generator).exp_u64(5),
            )
            .expect("quintic relation returns to production coordinates"),
            ProofChallengeExtensionElement::from_canonical_coordinates([3, 0, 0, 0, 0])
                .expect("canonical binomial constant"),
        );
    }

    #[derive(Clone)]
    struct DiagonalBooleanR1cs {
        witness_length: usize,
    }

    impl CompactCfwR1csMatrices for DiagonalBooleanR1cs {
        fn witness_length(&self) -> usize {
            self.witness_length
        }

        fn evaluate_assignment_rows(
            &self,
            _matrix_role: CompactCfwMatrixRole,
            public_input: &[CompactChallengeField],
            witness: &[CompactChallengeField],
        ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
            if public_input.len() != self.witness_length || witness.len() != self.witness_length {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            Ok(public_input.iter().chain(witness).copied().collect())
        }

        fn public_contribution_at_row_point(
            &self,
            _matrix_role: CompactCfwMatrixRole,
            row_point: &[CompactChallengeField],
            public_input: &[CompactChallengeField],
        ) -> Result<CompactChallengeField, CompactCfwError> {
            if row_point.len() != self.witness_length.ilog2() as usize + 1
                || public_input.len() != self.witness_length
            {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            Ok(public_input
                .iter()
                .enumerate()
                .map(|(column_ordinal, &value)| {
                    value * cfw_little_endian_boolean_point_weight(row_point, column_ordinal)
                })
                .sum())
        }

        fn accumulate_weighted_witness_covector_at_row_point(
            &self,
            row_point: &[CompactChallengeField],
            matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
            destination: &mut [CompactChallengeField],
        ) -> Result<(), CompactCfwError> {
            if row_point.len() != self.witness_length.ilog2() as usize + 1
                || destination.len() != self.witness_length
            {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            let combined_weight = matrix_role_weights
                .into_iter()
                .sum::<CompactChallengeField>();
            for (column_ordinal, destination_value) in destination.iter_mut().enumerate() {
                *destination_value += combined_weight
                    * cfw_little_endian_boolean_point_weight(
                        row_point,
                        self.witness_length + column_ordinal,
                    );
            }
            Ok(())
        }
    }

    fn extension_value(seed: u64) -> CompactChallengeField {
        CompactChallengeField::from_basis_coefficients_fn(|coordinate_ordinal| {
            Goldilocks::from_u64(seed + coordinate_ordinal as u64 * 17)
        })
    }

    fn run_complete_transcript(
        matrices: &DiagonalBooleanR1cs,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
        mask_material: CompactCfwMaskMaterial,
    ) -> Result<
        (
            CompactCfwTranscript,
            Vec<CompactChallengeField>,
            Vec<CompactChallengeField>,
            CompactCfwMaskMaterial,
        ),
        CompactCfwError,
    > {
        let prepared =
            PreparedCompactCfwProver::prepare(matrices, public_input, witness, mask_material)?;
        let auxiliary_target = prepared.auxiliary_target();
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())?;
        let equality_point = (0..geometry.sumcheck_round_count())
            .map(|ordinal| extension_value(1_000 + ordinal as u64 * 19))
            .collect::<Vec<_>>();
        let sumcheck_point = (0..geometry.sumcheck_round_count())
            .map(|ordinal| extension_value(2_000 + ordinal as u64 * 23))
            .collect::<Vec<_>>();
        let mut prover = prepared.begin(extension_value(701), equality_point.clone())?;
        let mut round_polynomials = Vec::with_capacity(geometry.sumcheck_round_count());
        for &challenge in &sumcheck_point {
            round_polynomials.push(prover.next_round_polynomial()?);
            prover.bind_round_challenge(challenge)?;
        }
        let finish = prover.finish()?;
        let transcript = CompactCfwTranscript::new(
            auxiliary_target,
            round_polynomials,
            finish.outer_evaluations().to_vec(),
            finish.final_values(),
        );
        Ok((
            transcript,
            equality_point,
            sumcheck_point,
            finish.into_mask_material(),
        ))
    }

    fn independently_derive_first_round_polynomial(
        prepared: &PreparedCompactCfwProver,
        constraint_combining_challenge: CompactChallengeField,
        equality_point: &[CompactChallengeField],
    ) -> Result<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH], CompactCfwError>
    {
        let suffix_count = prepared.geometry.r1cs_row_count() / 2;
        let mut round_polynomial =
            [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH];
        for suffix_ordinal in 0..suffix_count {
            let first_row = suffix_ordinal * 2;
            let mut factors = [[CompactChallengeField::ZERO; COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH];
                COMPACT_CFW_MATRIX_COUNT];
            for matrix_role in CompactCfwMatrixRole::ALL {
                let value_at_zero =
                    prepared.matrix_row_evaluations[matrix_role.ordinal()][first_row];
                let value_at_one =
                    prepared.matrix_row_evaluations[matrix_role.ordinal()][first_row + 1];
                factors[matrix_role.ordinal()][0] = value_at_zero;
                factors[matrix_role.ordinal()][1] = value_at_one - value_at_zero;
                for (factor_coefficient, mask_coefficient) in factors[matrix_role.ordinal()]
                    .iter_mut()
                    .zip(prepared.mask_material.inner_mask(0, matrix_role)?)
                {
                    *factor_coefficient += CompactChallengeField::from_u64(
                        COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER,
                    ) * *mask_coefficient;
                }
            }
            let mut constraint_polynomial = multiply_polynomials::<4, 4, 7>(
                &factors[CompactCfwMatrixRole::LeftMultiplicand.ordinal()],
                &factors[CompactCfwMatrixRole::RightMultiplicand.ordinal()],
            );
            for (constraint_coefficient, product_coefficient) in constraint_polynomial
                .iter_mut()
                .zip(&factors[CompactCfwMatrixRole::Product.ordinal()])
                .take(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
            {
                *constraint_coefficient -= *product_coefficient;
            }
            let equality_polynomial = [
                CompactChallengeField::ONE - equality_point[0],
                CompactChallengeField::from_u64(2) * equality_point[0] - CompactChallengeField::ONE,
            ];
            let weighted_constraint =
                multiply_polynomials::<7, 2, 8>(&constraint_polynomial, &equality_polynomial);
            let scale = constraint_combining_challenge
                * cfw_little_endian_boolean_point_weight(&equality_point[1..], suffix_ordinal);
            for (destination, coefficient) in round_polynomial.iter_mut().zip(weighted_constraint) {
                *destination += scale * coefficient;
            }
        }
        let suffix_count_field = field_from_usize(suffix_count)?;
        for (destination, coefficient) in round_polynomial
            .iter_mut()
            .zip(prepared.mask_material.outer_masks()[0])
        {
            *destination += suffix_count_field * coefficient;
        }
        let future_endpoint_sum = prepared.mask_material.outer_masks()[1..]
            .iter()
            .map(|mask| {
                evaluate_polynomial(mask, CompactChallengeField::ZERO)
                    + evaluate_polynomial(mask, CompactChallengeField::ONE)
            })
            .sum::<CompactChallengeField>();
        round_polynomial[0] += field_from_usize(suffix_count / 2)? * future_endpoint_sum;
        Ok(round_polynomial)
    }

    #[test]
    fn geometry_and_mask_material_derive_every_cfw_claim() {
        let geometry = CompactCfwGeometry::derive(1 << 10).expect("valid compact CFW geometry");
        let mut next_seed = 1_u64;
        let material = CompactCfwMaskMaterial::sample(geometry, || {
            let value = extension_value(next_seed);
            next_seed += 1;
            value
        })
        .expect("complete compact CFW masks");

        assert_eq!(geometry.r1cs_row_count(), 1 << 11);
        assert_eq!(geometry.sumcheck_round_count(), 11);
        assert_eq!(geometry.inner_mask_count(), 33);
        assert_eq!(geometry.outer_mask_count(), 11);
        assert_eq!(geometry.generalized_committed_relation_claim_count(), 78);
        assert!(material.inner_masks().iter().all(|mask| {
            evaluate_polynomial(mask, CompactChallengeField::ZERO) == CompactChallengeField::ZERO
                && evaluate_polynomial(mask, CompactChallengeField::ONE)
                    == CompactChallengeField::ZERO
        }));
    }

    #[test]
    fn factor_two_inner_mask_normalization_is_bijective_and_preserves_endpoints() {
        let geometry = CompactCfwGeometry::derive(1 << 4).expect("valid compact CFW geometry");
        let mut next_seed = 101_u64;
        let material = CompactCfwMaskMaterial::sample(geometry, || {
            let value = extension_value(next_seed);
            next_seed += 13;
            value
        })
        .expect("complete compact CFW masks");
        let multiplier =
            CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
        let multiplier_inverse = multiplier.inverse();

        assert_eq!(multiplier * multiplier_inverse, CompactChallengeField::ONE);
        for mask in material.inner_masks() {
            let normalized_mask = mask.map(|coefficient| multiplier * coefficient);
            let recovered_mask =
                normalized_mask.map(|coefficient| multiplier_inverse * coefficient);
            assert_eq!(recovered_mask, *mask);
            assert_eq!(
                evaluate_polynomial(&normalized_mask, CompactChallengeField::ZERO),
                CompactChallengeField::ZERO,
            );
            assert_eq!(
                evaluate_polynomial(&normalized_mask, CompactChallengeField::ONE),
                CompactChallengeField::ZERO,
            );
        }
    }

    #[test]
    fn streaming_round_accumulator_matches_direct_round_and_refuses_wrong_lengths() {
        let matrices = DiagonalBooleanR1cs {
            witness_length: 1 << 5,
        };
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())
            .expect("valid compact CFW geometry");
        let public_input = (0..matrices.witness_length())
            .map(|ordinal| extension_value(40_000 + ordinal as u64 * 3))
            .collect::<Vec<_>>();
        let witness = (0..matrices.witness_length())
            .map(|ordinal| extension_value(50_000 + ordinal as u64 * 5))
            .collect::<Vec<_>>();
        let mut next_seed = 60_000_u64;
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || {
            let value = extension_value(next_seed);
            next_seed += 37;
            value
        })
        .expect("complete compact CFW masks");
        let prepared =
            PreparedCompactCfwProver::prepare(&matrices, &public_input, &witness, mask_material)
                .expect("prepared compact CFW matrices");
        let constraint_combining_challenge = extension_value(70_001);
        let equality_point = (0..geometry.sumcheck_round_count())
            .map(|ordinal| extension_value(71_000 + ordinal as u64 * 41))
            .collect::<Vec<_>>();
        let expected = independently_derive_first_round_polynomial(
            &prepared,
            constraint_combining_challenge,
            &equality_point,
        )
        .expect("direct first-round polynomial");

        let new_accumulator = || {
            CompactCfwRoundAccumulator::new(
                geometry,
                &prepared.mask_material,
                0,
                constraint_combining_challenge,
                &equality_point,
                CompactCfwRoundHistory {
                    equality_prefix_evaluation: CompactChallengeField::ONE,
                    past_inner_mask_evaluations: [CompactChallengeField::ZERO;
                        COMPACT_CFW_MATRIX_COUNT],
                    past_outer_mask_evaluation: CompactChallengeField::ZERO,
                },
            )
            .expect("first-round accumulator")
        };
        let values_for_suffix = |suffix_ordinal: usize| {
            let first_row = suffix_ordinal * 2;
            (
                core::array::from_fn(|matrix_ordinal| {
                    prepared.matrix_row_evaluations[matrix_ordinal][first_row]
                }),
                core::array::from_fn(|matrix_ordinal| {
                    prepared.matrix_row_evaluations[matrix_ordinal][first_row + 1]
                }),
            )
        };

        let mut accumulator = new_accumulator();
        let mut next_suffix_ordinal = 0_usize;
        for chunk_size in [1_usize, 7, 3, 11, 2, 8] {
            for suffix_ordinal in next_suffix_ordinal..next_suffix_ordinal + chunk_size {
                let (values_at_zero, values_at_one) = values_for_suffix(suffix_ordinal);
                accumulator
                    .absorb_next_row_pair(values_at_zero, values_at_one)
                    .expect("canonical row pair");
            }
            next_suffix_ordinal += chunk_size;
        }
        assert_eq!(next_suffix_ordinal, geometry.r1cs_row_count() / 2);
        assert_eq!(
            accumulator.finish().expect("complete streamed round"),
            expected
        );

        let mut truncated = new_accumulator();
        for suffix_ordinal in 0..geometry.r1cs_row_count() / 2 - 1 {
            let (values_at_zero, values_at_one) = values_for_suffix(suffix_ordinal);
            truncated
                .absorb_next_row_pair(values_at_zero, values_at_one)
                .expect("canonical truncated prefix");
        }
        assert_eq!(
            truncated.finish(),
            Err(CompactCfwError::InvalidMatrixSource)
        );

        let mut overlong = new_accumulator();
        for suffix_ordinal in 0..geometry.r1cs_row_count() / 2 {
            let (values_at_zero, values_at_one) = values_for_suffix(suffix_ordinal);
            overlong
                .absorb_next_row_pair(values_at_zero, values_at_one)
                .expect("canonical complete prefix");
        }
        let (values_at_zero, values_at_one) = values_for_suffix(0);
        assert_eq!(
            overlong.absorb_next_row_pair(values_at_zero, values_at_one),
            Err(CompactCfwError::InvalidMatrixSource)
        );

        let arbitrary_challenge = extension_value(72_003);
        assert_eq!(
            compact_cfw_fold_row_pair(public_input[0], witness[0], CompactChallengeField::ZERO,),
            public_input[0]
        );
        assert_eq!(
            compact_cfw_fold_row_pair(public_input[0], witness[0], CompactChallengeField::ONE,),
            witness[0]
        );
        assert_eq!(
            compact_cfw_fold_row_pair(public_input[0], witness[0], arbitrary_challenge),
            public_input[0] + arbitrary_challenge * (witness[0] - public_input[0])
        );
    }

    #[test]
    fn complete_masked_sumcheck_verifies_and_refuses_mutations() {
        let matrices = DiagonalBooleanR1cs {
            witness_length: 1 << 6,
        };
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())
            .expect("valid compact CFW geometry");
        let public_input = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64((ordinal & 1) as u64))
            .collect::<Vec<_>>();
        let witness = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64(((ordinal >> 1) & 1) as u64))
            .collect::<Vec<_>>();
        let mut next_seed = 10_000_u64;
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || {
            let value = extension_value(next_seed);
            next_seed += 29;
            value
        })
        .expect("complete compact CFW masks");
        let (transcript, equality_point, sumcheck_point, _) =
            run_complete_transcript(&matrices, &public_input, &witness, mask_material)
                .expect("complete compact CFW transcript");

        let claims = verify_compact_cfw_transcript(
            &matrices,
            &public_input,
            &transcript,
            extension_value(701),
            &equality_point,
            &sumcheck_point,
            extension_value(909),
        )
        .expect("independent compact CFW replay");
        assert_eq!(
            claims.geometry.generalized_committed_relation_claim_count(),
            50,
        );

        let mut changed_round = transcript.clone();
        changed_round.round_polynomials[2][5] += CompactChallengeField::ONE;
        assert!(matches!(
            verify_compact_cfw_transcript(
                &matrices,
                &public_input,
                &changed_round,
                extension_value(701),
                &equality_point,
                &sumcheck_point,
                extension_value(909),
            ),
            Err(CompactCfwError::SumcheckConsistency { .. })
                | Err(CompactCfwError::FinalConsistency)
        ));

        let mut changed_final_values = transcript.clone();
        changed_final_values.final_values[1] += CompactChallengeField::ONE;
        assert_eq!(
            verify_compact_cfw_transcript(
                &matrices,
                &public_input,
                &changed_final_values,
                extension_value(701),
                &equality_point,
                &sumcheck_point,
                extension_value(909),
            ),
            Err(CompactCfwError::FinalConsistency),
        );
    }

    #[test]
    fn canonical_claim_batch_matches_source_and_mask_messages() {
        let matrices = DiagonalBooleanR1cs {
            witness_length: 1 << 5,
        };
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())
            .expect("valid compact CFW geometry");
        let public_input = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64((ordinal & 1) as u64))
            .collect::<Vec<_>>();
        let witness = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64(((ordinal >> 2) & 1) as u64))
            .collect::<Vec<_>>();
        let mut next_seed = 20_000_u64;
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || {
            let value = extension_value(next_seed);
            next_seed += 31;
            value
        })
        .expect("complete compact CFW masks");
        let (transcript, equality_point, sumcheck_point, mask_material) =
            run_complete_transcript(&matrices, &public_input, &witness, mask_material)
                .expect("complete compact CFW transcript");
        let claims = verify_compact_cfw_transcript(
            &matrices,
            &public_input,
            &transcript,
            extension_value(701),
            &equality_point,
            &sumcheck_point,
            extension_value(909),
        )
        .expect("independent compact CFW replay");
        let preceding_point = (0..matrices.witness_length().ilog2())
            .map(|ordinal| extension_value(30_000 + u64::from(ordinal)))
            .collect::<Vec<_>>();
        let preceding_target = witness
            .iter()
            .enumerate()
            .map(|(ordinal, &value)| {
                whir_multilinear_point_weight(&preceding_point, ordinal) * value
            })
            .sum();
        assert_eq!(
            claims.clone().combine_with_preceding_opening_claims(
                &matrices,
                &[CompactCfwMultilinearOpeningClaim::new(
                    preceding_point[..preceding_point.len() - 1].to_vec(),
                    preceding_target,
                )],
                extension_value(1_313),
            ),
            Err(CompactCfwError::InvalidClaimInput)
        );
        let preceding_claim =
            CompactCfwMultilinearOpeningClaim::new(preceding_point, preceding_target);
        let batching_challenge = extension_value(1_313);
        let synchronously_combined = claims
            .clone()
            .combine_with_preceding_opening_claims(
                &matrices,
                core::slice::from_ref(&preceding_claim),
                batching_challenge,
            )
            .expect("synchronous canonical CFW claim batch");
        let pending_matrix_combination = claims
            .begin_combining_with_preceding_opening_claims(
                core::slice::from_ref(&preceding_claim),
                batching_challenge,
            )
            .expect("pending canonical CFW claim batch");
        let (continuation, mut source_covector) = pending_matrix_combination.into_parts();
        matrices
            .accumulate_weighted_witness_covector_at_row_point(
                continuation.row_point(),
                continuation.matrix_role_weights(),
                &mut source_covector,
            )
            .expect("independent matrix accumulation");
        let combined = continuation
            .finish_after_matrix_accumulation(source_covector)
            .expect("continued canonical CFW claim batch");
        assert_eq!(combined, synchronously_combined);
        let (
            source_covector,
            target,
            preceding_mask_covectors,
            inner_mask_covectors,
            outer_mask_covectors,
            claim_count,
        ) = combined.into_parts();
        assert!(preceding_mask_covectors.is_empty());
        let evaluated_relation = source_covector
            .iter()
            .zip(&witness)
            .map(|(&coefficient, &value)| coefficient * value)
            .sum::<CompactChallengeField>()
            + inner_mask_covectors
                .iter()
                .zip(mask_material.inner_masks())
                .map(|(covector, message)| {
                    covector
                        .iter()
                        .zip(message)
                        .map(|(&coefficient, &value)| coefficient * value)
                        .sum::<CompactChallengeField>()
                })
                .sum::<CompactChallengeField>()
            + outer_mask_covectors
                .iter()
                .zip(mask_material.outer_masks())
                .map(|(covector, message)| {
                    covector
                        .iter()
                        .zip(message)
                        .map(|(&coefficient, &value)| coefficient * value)
                        .sum::<CompactChallengeField>()
                })
                .sum::<CompactChallengeField>();

        assert_eq!(evaluated_relation, target);
        assert_eq!(
            claim_count,
            1 + geometry.generalized_committed_relation_claim_count(),
        );
    }

    #[test]
    fn masked_cross_epoch_claims_reveal_only_the_copy_relation() {
        let matrices = DiagonalBooleanR1cs {
            witness_length: 1 << 5,
        };
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())
            .expect("valid compact CFW geometry");
        let masked_payload_geometry =
            CompactCfwToWhirPayloadGeometry::derive_with_preceding_mask_covector_element_count(
                geometry, 2, 2,
            )
            .expect("masked cross-epoch payload geometry");
        assert_eq!(
            masked_payload_geometry.preceding_mask_covector_extension_element_count(),
            2
        );
        let public_input = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64((ordinal & 1) as u64))
            .collect::<Vec<_>>();
        let witness = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64(((ordinal >> 2) & 1) as u64))
            .collect::<Vec<_>>();
        let mut next_seed = 40_000_u64;
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || {
            let value = extension_value(next_seed);
            next_seed += 37;
            value
        })
        .expect("complete compact CFW masks");
        let (transcript, equality_point, sumcheck_point, mask_material) =
            run_complete_transcript(&matrices, &public_input, &witness, mask_material)
                .expect("complete compact CFW transcript");
        let claims = verify_compact_cfw_transcript(
            &matrices,
            &public_input,
            &transcript,
            extension_value(701),
            &equality_point,
            &sumcheck_point,
            extension_value(909),
        )
        .expect("independent compact CFW replay");

        let cross_epoch_point = (0..4)
            .map(|ordinal| extension_value(50_000 + ordinal))
            .collect::<Vec<_>>();
        let copied_element_count = 11;
        let point_covector = Poly::new_from_point(&cross_epoch_point, CompactChallengeField::ONE);
        let copied_evaluation = witness[..copied_element_count]
            .iter()
            .zip(&point_covector.as_slice()[..copied_element_count])
            .map(|(&value, &coefficient)| value * coefficient)
            .sum::<CompactChallengeField>();
        let pre_challenge_mask = extension_value(51_001);
        let main_mask = extension_value(51_101);
        let masked_pre_challenge_evaluation = copied_evaluation + pre_challenge_mask;
        let masked_main_evaluation = copied_evaluation + main_mask;
        let mask_difference = pre_challenge_mask - main_mask;
        assert_eq!(
            masked_pre_challenge_evaluation - masked_main_evaluation - mask_difference,
            CompactChallengeField::ZERO
        );

        let batching_challenge = extension_value(51_301);
        assert!(matches!(
            claims
                .clone()
                .begin_combining_with_masked_cross_epoch_claims(
                    CompactCfwMaskedCrossEpochClaims::new(
                        cross_epoch_point.clone(),
                        copied_element_count,
                        masked_pre_challenge_evaluation + CompactChallengeField::ONE,
                        masked_main_evaluation,
                        mask_difference,
                    ),
                    batching_challenge,
                ),
            Err(CompactCfwError::InvalidClaimInput)
        ));
        let combination = claims
            .begin_combining_with_masked_cross_epoch_claims(
                CompactCfwMaskedCrossEpochClaims::new(
                    cross_epoch_point,
                    copied_element_count,
                    masked_pre_challenge_evaluation,
                    masked_main_evaluation,
                    mask_difference,
                ),
                batching_challenge,
            )
            .expect("masked cross-epoch CFW combination");
        let (continuation, mut source_covector) = combination.into_parts();
        matrices
            .accumulate_weighted_witness_covector_at_row_point(
                continuation.row_point(),
                continuation.matrix_role_weights(),
                &mut source_covector,
            )
            .expect("independent matrix accumulation");
        let combined = continuation
            .finish_after_matrix_accumulation(source_covector)
            .expect("complete masked cross-epoch relation");
        let (
            source_covector,
            target,
            cross_epoch_mask_covectors,
            inner_mask_covectors,
            outer_mask_covectors,
            claim_count,
        ) = combined.into_parts();
        assert_eq!(
            cross_epoch_mask_covectors,
            vec![
                vec![batching_challenge],
                vec![CompactChallengeField::ONE - batching_challenge],
            ]
        );
        assert_eq!(
            claim_count,
            2 + geometry.generalized_committed_relation_claim_count()
        );

        let source_term = source_covector
            .iter()
            .zip(&witness)
            .map(|(&coefficient, &value)| coefficient * value)
            .sum::<CompactChallengeField>();
        let remaining_terms = cross_epoch_mask_covectors[0][0] * pre_challenge_mask
            + cross_epoch_mask_covectors[1][0] * main_mask
            + inner_mask_covectors
                .iter()
                .zip(mask_material.inner_masks())
                .map(|(covector, message)| {
                    covector
                        .iter()
                        .zip(message)
                        .map(|(&coefficient, &value)| coefficient * value)
                        .sum::<CompactChallengeField>()
                })
                .sum::<CompactChallengeField>()
            + outer_mask_covectors
                .iter()
                .zip(mask_material.outer_masks())
                .map(|(covector, message)| {
                    covector
                        .iter()
                        .zip(message)
                        .map(|(&coefficient, &value)| coefficient * value)
                        .sum::<CompactChallengeField>()
                })
                .sum::<CompactChallengeField>();
        assert_eq!(source_term + remaining_terms, target);

        let mut substituted_witness = witness.clone();
        substituted_witness[copied_element_count - 1] += CompactChallengeField::ONE;
        let substituted_source_term = source_covector
            .iter()
            .zip(substituted_witness)
            .map(|(&coefficient, value)| coefficient * value)
            .sum::<CompactChallengeField>();
        assert_ne!(substituted_source_term + remaining_terms, target);
    }

    #[test]
    fn selected_size_cfw_to_whir_payload_retains_only_one_dense_covector() {
        let geometry = CompactCfwGeometry::derive(1 << 22).expect("selected CFW geometry");
        let payload = CompactCfwToWhirPayloadGeometry::derive(geometry, 2)
            .expect("selected CFW-to-WHIR payload geometry");

        assert_eq!(
            (
                payload.source_variable_count(),
                payload.preceding_opening_claim_extension_element_count(),
                payload.cfw_claim_batch_extension_element_count(),
                payload.source_covector_extension_element_count(),
                payload.inner_mask_covector_extension_element_count(),
                payload.outer_mask_covector_extension_element_count(),
                payload.combined_relation_extension_element_count(),
                payload.transition_live_extension_element_count(),
            ),
            (22, 46, 50, 4_194_304, 276, 184, 4_194_765, 4_194_861)
        );
    }

    #[test]
    fn preceding_opening_covector_uses_whir_multilinear_point_order() {
        let point = [
            extension_value(17),
            extension_value(29),
            extension_value(43),
        ];
        let scale = extension_value(61);
        let mut actual = vec![CompactChallengeField::ZERO; 1 << point.len()];
        accumulate_scaled_multilinear_equality_covector(&mut actual, &point, scale)
            .expect("canonical WHIR equality covector");
        let expected = Poly::new_from_point(&point, scale);

        assert_eq!(actual, expected.as_slice());
        for (ordinal, &coefficient) in actual.iter().enumerate() {
            assert_eq!(
                coefficient,
                scale * whir_multilinear_point_weight(&point, ordinal)
            );
        }
    }
}
