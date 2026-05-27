use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[cfg(test)]
use super::rng::sample_linear_proof_uniform_u64_values;
use super::{
    polynomial_ring::PolynomialRing, sparse_polynomial_matrix::SparsePolynomialMatrix,
    sparse_polynomial_vector::SparsePolynomialVector,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProofQuadraticEquation {
    quadratic_terms: SparsePolynomialMatrix,
    linear_terms: SparsePolynomialVector,
    constant_term: Option<Vec<u64>>,
}

impl LinearProofQuadraticEquation {
    pub(crate) fn new(
        quadratic_terms: SparsePolynomialMatrix,
        linear_terms: SparsePolynomialVector,
        constant_term: Option<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        if quadratic_terms.rows() != quadratic_terms.columns() {
            return Err(invalid_quadratic(
                "quadratic equation matrix must be square",
            ));
        }
        if quadratic_terms.rows() != linear_terms.length() {
            return Err(invalid_quadratic(
                "quadratic equation matrix dimension must match the linear vector length",
            ));
        }
        if quadratic_terms.ring() != linear_terms.ring() {
            return Err(invalid_quadratic(
                "quadratic equation matrix and vector rings do not match",
            ));
        }
        if !quadratic_terms.is_upper_diagonal() {
            return Err(invalid_quadratic(
                "quadratic equation matrix must be upper-diagonal",
            ));
        }
        if let Some(constant_term) = constant_term.as_deref() {
            quadratic_terms
                .ring()
                .validate_coefficients(constant_term)?;
        }

        Ok(Self {
            quadratic_terms,
            linear_terms,
            constant_term,
        })
    }

    pub(crate) fn zero(ring: PolynomialRing, dimension: usize) -> CanonicalResult<Self> {
        Self::new(
            SparsePolynomialMatrix::zero(ring, dimension, dimension)?,
            SparsePolynomialVector::zero(ring, dimension)?,
            Some(vec![0_u64; ring.degree()]),
        )
    }

    pub(crate) fn ring(&self) -> PolynomialRing {
        self.quadratic_terms.ring()
    }

    pub(crate) fn quadratic_terms(&self) -> &SparsePolynomialMatrix {
        &self.quadratic_terms
    }

    pub(crate) fn linear_terms(&self) -> &SparsePolynomialVector {
        &self.linear_terms
    }

    pub(crate) fn constant_term(&self) -> Option<&[u64]> {
        self.constant_term.as_deref()
    }

    pub(crate) fn dimension(&self) -> usize {
        self.quadratic_terms.rows()
    }

    pub(crate) fn resize_dimension(&self, resized_dimension: usize) -> CanonicalResult<Self> {
        if resized_dimension < self.dimension() {
            return Err(invalid_quadratic(
                "quadratic equation resize cannot shrink existing entries",
            ));
        }

        Self::new(
            self.quadratic_terms
                .resize(resized_dimension, resized_dimension)?,
            self.linear_terms.resize(resized_dimension)?,
            self.constant_term.clone(),
        )
    }

    pub(crate) fn add_linear_polynomial_term(
        &self,
        position: usize,
        coefficients: Vec<u64>,
    ) -> CanonicalResult<Self> {
        let ring = self.ring();
        ring.validate_coefficients(&coefficients)?;
        if position >= self.dimension() {
            return Err(invalid_quadratic(
                "linear term position is outside the quadratic equation dimension",
            ));
        }

        let added_linear_terms = if coefficients.iter().all(|coefficient| *coefficient == 0) {
            SparsePolynomialVector::zero(ring, self.dimension())?
        } else {
            SparsePolynomialVector::new(
                ring,
                self.dimension(),
                vec![
                    super::sparse_polynomial_vector::SparsePolynomialVectorEntry::new(
                        position,
                        coefficients,
                    ),
                ],
            )?
        };

        Self::new(
            self.quadratic_terms.clone(),
            self.linear_terms.add(&added_linear_terms)?,
            self.constant_term.clone(),
        )
    }

    pub(crate) fn sub_constant_polynomial(&self, polynomial: &[u64]) -> CanonicalResult<Self> {
        let ring = self.ring();
        ring.validate_coefficients(polynomial)?;
        let updated_constant = match &self.constant_term {
            Some(constant_term) => Some(ring.sub(constant_term, polynomial)?),
            None => {
                return Err(invalid_quadratic(
                    "cannot subtract a constant polynomial from a constant-free equation",
                ));
            }
        };

        Self::new(
            self.quadratic_terms.clone(),
            self.linear_terms.clone(),
            updated_constant,
        )
    }

    pub(crate) fn schwartz_zippel_auto_fold_with(
        &self,
        paired_equation: &Self,
    ) -> CanonicalResult<Self> {
        self.require_same_shape(paired_equation)?;

        let ring = self.ring();
        let inverse_two = inverse_two_modulus(ring)?;
        let half_degree = ring.degree() / 2;

        let shuffled_quadratic_terms = self
            .quadratic_terms
            .shuffle_upper_diagonal_automorphism_by_pairs()?;
        let rotated_paired_quadratic_terms = paired_equation
            .quadratic_terms
            .left_rotate_negacyclic(half_degree)?;
        let shuffled_rotated_paired_quadratic_terms = paired_equation
            .quadratic_terms
            .shuffle_upper_diagonal_automorphism_by_pairs()?
            .left_rotate_negacyclic(half_degree)?;
        let folded_quadratic_terms = self
            .quadratic_terms
            .add(&shuffled_quadratic_terms)?
            .add(&rotated_paired_quadratic_terms)?
            .add(&shuffled_rotated_paired_quadratic_terms)?
            .scale(inverse_two)?;

        let shuffled_linear_terms = self.linear_terms.shuffle_automorphism_by_pairs()?;
        let rotated_paired_linear_terms = paired_equation
            .linear_terms
            .left_rotate_negacyclic(half_degree)?;
        let shuffled_rotated_paired_linear_terms = paired_equation
            .linear_terms
            .shuffle_automorphism_by_pairs()?
            .left_rotate_negacyclic(half_degree)?;
        let folded_linear_terms = self
            .linear_terms
            .add(&shuffled_linear_terms)?
            .add(&rotated_paired_linear_terms)?
            .add(&shuffled_rotated_paired_linear_terms)?
            .scale(inverse_two)?;

        let folded_constant_term = match (&self.constant_term, &paired_equation.constant_term) {
            (Some(constant_term), Some(paired_constant_term)) => Some(fold_constant_terms(
                ring,
                inverse_two,
                constant_term,
                paired_constant_term,
            )?),
            (None, None) => None,
            _ => {
                return Err(invalid_quadratic(
                    "quadratic equation constants must either both be present or both be absent",
                ));
            }
        };

        Self::new(
            folded_quadratic_terms,
            folded_linear_terms,
            folded_constant_term,
        )
    }

    #[cfg(test)]
    pub(crate) fn accumulate_weighted_equations(
        &self,
        weighted_equations: &[WeightedLinearProofQuadraticEquation<'_>],
    ) -> CanonicalResult<Self> {
        let mut accumulated_equation = self.clone();
        for weighted_equation in weighted_equations {
            accumulated_equation.require_same_shape(weighted_equation.equation)?;
            let scaled_equation = weighted_equation
                .equation
                .scale(weighted_equation.challenge_scalar)?;
            accumulated_equation = accumulated_equation.add(&scaled_equation)?;
        }

        Ok(accumulated_equation)
    }

    pub(crate) fn accumulate_weighted_partial_equations(
        &self,
        weighted_equations: &[WeightedLinearProofQuadraticEquation<'_>],
    ) -> CanonicalResult<Self> {
        let mut accumulated_equation = self.clone();
        for weighted_equation in weighted_equations {
            accumulated_equation.require_same_shape(weighted_equation.equation)?;
            accumulated_equation = accumulated_equation.add_scaled_partial(
                weighted_equation.equation,
                weighted_equation.challenge_scalar,
            )?;
        }

        Ok(accumulated_equation)
    }

    #[cfg(test)]
    pub(crate) fn accumulate_schwartz_zippel_pair_sets(
        primary_accumulators: &[Self],
        secondary_accumulators: &[Self],
        input_equations: &[&Self],
        challenge_seed: &[u8; 32],
        challenge_domain: u32,
        modulus_bit_length: usize,
    ) -> CanonicalResult<QuadraticAccumulatorPairs> {
        if primary_accumulators.len() != secondary_accumulators.len() {
            return Err(invalid_quadratic(
                "primary and secondary accumulator counts must match",
            ));
        }
        if input_equations.is_empty() {
            return Err(invalid_quadratic(
                "Schwartz-Zippel accumulation requires at least one input equation",
            ));
        }

        let input_count = input_equations.len();
        let first_input = input_equations[0];
        let ring = first_input.ring();
        let mut primary_outputs = Vec::with_capacity(primary_accumulators.len());
        let mut secondary_outputs = Vec::with_capacity(secondary_accumulators.len());
        let mut challenge_scalars_by_pair = Vec::with_capacity(primary_accumulators.len());

        for (primary_accumulator, secondary_accumulator) in
            primary_accumulators.iter().zip(secondary_accumulators)
        {
            primary_accumulator.require_same_shape(secondary_accumulator)?;
            primary_accumulator.require_same_shape(first_input)?;
            let challenge_scalars = sample_linear_proof_uniform_u64_values(
                input_count
                    .checked_mul(2)
                    .ok_or_else(|| invalid_quadratic("challenge count overflowed"))?,
                ring.modulus(),
                modulus_bit_length,
                challenge_seed,
                u64::from(challenge_domain),
            )?;
            let primary_weighted_inputs = input_equations
                .iter()
                .zip(&challenge_scalars[..input_count])
                .map(
                    |(equation, challenge_scalar)| WeightedLinearProofQuadraticEquation {
                        challenge_scalar: *challenge_scalar,
                        equation,
                    },
                )
                .collect::<Vec<_>>();
            let secondary_weighted_inputs = input_equations
                .iter()
                .zip(&challenge_scalars[input_count..])
                .map(
                    |(equation, challenge_scalar)| WeightedLinearProofQuadraticEquation {
                        challenge_scalar: *challenge_scalar,
                        equation,
                    },
                )
                .collect::<Vec<_>>();

            primary_outputs
                .push(primary_accumulator.accumulate_weighted_equations(&primary_weighted_inputs)?);
            secondary_outputs.push(
                secondary_accumulator.accumulate_weighted_equations(&secondary_weighted_inputs)?,
            );
            challenge_scalars_by_pair.push(challenge_scalars);
        }

        Ok(QuadraticAccumulatorPairs {
            primary_accumulators: primary_outputs,
            secondary_accumulators: secondary_outputs,
            challenge_scalars_by_pair,
        })
    }

    #[cfg(test)]
    pub(crate) fn accumulate_unweighted_equations(
        &self,
        equations: &[&LinearProofQuadraticEquation],
    ) -> CanonicalResult<Self> {
        let mut accumulated_equation = self.clone();
        for equation in equations {
            accumulated_equation.require_same_shape(equation)?;
            accumulated_equation = accumulated_equation.add(equation)?;
        }

        Ok(accumulated_equation)
    }

    pub(crate) fn add(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;

        Ok(Self {
            quadratic_terms: self.quadratic_terms.add(&other.quadratic_terms)?,
            linear_terms: self.linear_terms.add(&other.linear_terms)?,
            constant_term: add_optional_constants(
                self.ring(),
                &self.constant_term,
                &other.constant_term,
            )?,
        })
    }

    fn add_scaled_partial(&self, partial: &Self, scalar: u64) -> CanonicalResult<Self> {
        self.require_same_shape(partial)?;
        let ring = self.ring();
        let constant_term = match (&self.constant_term, &partial.constant_term) {
            (Some(accumulated_constant), Some(partial_constant)) => {
                let scaled_partial_constant = ring.scale(scalar, partial_constant)?;
                Some(ring.add(accumulated_constant, &scaled_partial_constant)?)
            }
            (Some(accumulated_constant), None) => Some(accumulated_constant.clone()),
            (None, None) => None,
            (None, Some(_)) => {
                return Err(invalid_quadratic(
                    "quadratic partial with a constant cannot be added to a constant-free accumulator",
                ));
            }
        };

        Ok(Self {
            quadratic_terms: self
                .quadratic_terms
                .add(&partial.quadratic_terms.scale(scalar)?)?,
            linear_terms: self
                .linear_terms
                .add(&partial.linear_terms.scale(scalar)?)?,
            constant_term,
        })
    }

    #[cfg(test)]
    pub(crate) fn scale(&self, scalar: u64) -> CanonicalResult<Self> {
        let ring = self.ring();

        Ok(Self {
            quadratic_terms: self.quadratic_terms.scale(scalar)?,
            linear_terms: self.linear_terms.scale(scalar)?,
            constant_term: self
                .constant_term
                .as_ref()
                .map(|constant_term| ring.scale(scalar, constant_term))
                .transpose()?,
        })
    }

    pub(crate) fn scale_by_polynomial(&self, polynomial: &[u64]) -> CanonicalResult<Self> {
        let ring = self.ring();
        ring.validate_coefficients(polynomial)?;

        Ok(Self {
            quadratic_terms: self.quadratic_terms.scale_by_polynomial(polynomial)?,
            linear_terms: self.linear_terms.scale_by_polynomial(polynomial)?,
            constant_term: self
                .constant_term
                .as_ref()
                .map(|constant_term| ring.mul_negacyclic(polynomial, constant_term))
                .transpose()?,
        })
    }

    fn require_same_shape(&self, other: &Self) -> CanonicalResult<()> {
        if self.quadratic_terms.rows() != other.quadratic_terms.rows()
            || self.quadratic_terms.columns() != other.quadratic_terms.columns()
            || self.linear_terms.length() != other.linear_terms.length()
            || self.ring() != other.ring()
        {
            return Err(invalid_quadratic(
                "quadratic equations must have the same shape",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WeightedLinearProofQuadraticEquation<'equation> {
    pub(crate) challenge_scalar: u64,
    pub(crate) equation: &'equation LinearProofQuadraticEquation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct QuadraticAccumulatorPairs {
    pub(crate) primary_accumulators: Vec<LinearProofQuadraticEquation>,
    pub(crate) secondary_accumulators: Vec<LinearProofQuadraticEquation>,
    pub(crate) challenge_scalars_by_pair: Vec<Vec<u64>>,
}

#[cfg(test)]
pub(crate) fn validate_quadratic_helper_self_check() -> CanonicalResult<()> {
    let ring = PolynomialRing::new(4, 17)?;
    let first_equation = LinearProofQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            ring,
            4,
            4,
            vec![
                super::sparse_polynomial_matrix::SparsePolynomialMatrixEntry::new(
                    0,
                    0,
                    vec![1, 2, 3, 4],
                ),
                super::sparse_polynomial_matrix::SparsePolynomialMatrixEntry::new(
                    0,
                    1,
                    vec![2, 0, 0, 0],
                ),
                super::sparse_polynomial_matrix::SparsePolynomialMatrixEntry::new(
                    1,
                    3,
                    vec![3, 0, 0, 0],
                ),
            ],
        )?,
        SparsePolynomialVector::new(
            ring,
            4,
            vec![
                super::sparse_polynomial_vector::SparsePolynomialVectorEntry::new(
                    0,
                    vec![1, 1, 0, 0],
                ),
                super::sparse_polynomial_vector::SparsePolynomialVectorEntry::new(
                    3,
                    vec![2, 0, 0, 0],
                ),
            ],
        )?,
        Some(vec![1, 2, 0, 0]),
    )?;
    let second_equation = LinearProofQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            ring,
            4,
            4,
            vec![
                super::sparse_polynomial_matrix::SparsePolynomialMatrixEntry::new(
                    0,
                    2,
                    vec![4, 0, 0, 0],
                ),
                super::sparse_polynomial_matrix::SparsePolynomialMatrixEntry::new(
                    2,
                    2,
                    vec![5, 0, 0, 0],
                ),
            ],
        )?,
        SparsePolynomialVector::new(
            ring,
            4,
            vec![
                super::sparse_polynomial_vector::SparsePolynomialVectorEntry::new(
                    1,
                    vec![3, 0, 0, 0],
                ),
                super::sparse_polynomial_vector::SparsePolynomialVectorEntry::new(
                    2,
                    vec![0, 4, 0, 0],
                ),
            ],
        )?,
        Some(vec![3, 0, 1, 0]),
    )?;
    let folded_equation = first_equation.schwartz_zippel_auto_fold_with(&second_equation)?;
    if folded_equation.quadratic_terms().entries().len() != 7
        || folded_equation.linear_terms().entries().len() != 4
        || folded_equation
            .constant_term()
            .is_none_or(|constant_term| constant_term != [1, 1, 3, 16])
    {
        return Err(invalid_quadratic(
            "quadratic auto-fold helper self-check did not match the expected formula",
        ));
    }
    let unweighted_equation =
        first_equation.accumulate_unweighted_equations(&[&second_equation])?;
    if unweighted_equation
        .constant_term()
        .is_none_or(|constant_term| constant_term != [4, 2, 1, 0])
    {
        return Err(invalid_quadratic(
            "quadratic unweighted accumulator self-check did not match the expected formula",
        ));
    }
    let accumulator_pairs = LinearProofQuadraticEquation::accumulate_schwartz_zippel_pair_sets(
        &[LinearProofQuadraticEquation::zero(ring, 4)?],
        &[LinearProofQuadraticEquation::zero(ring, 4)?],
        &[&first_equation, &second_equation],
        &[9_u8; 32],
        7,
        5,
    )?;
    if accumulator_pairs.primary_accumulators.len() != 1
        || accumulator_pairs.secondary_accumulators.len() != 1
        || accumulator_pairs.challenge_scalars_by_pair.len() != 1
        || accumulator_pairs.challenge_scalars_by_pair[0].len() != 4
        || !accumulator_pairs.challenge_scalars_by_pair[0]
            .iter()
            .all(|challenge_scalar| *challenge_scalar < ring.modulus())
    {
        return Err(invalid_quadratic(
            "quadratic Schwartz-Zippel challenge self-check did not match the demo sampler",
        ));
    }

    Ok(())
}

fn add_optional_constants(
    ring: PolynomialRing,
    left_constant: &Option<Vec<u64>>,
    right_constant: &Option<Vec<u64>>,
) -> CanonicalResult<Option<Vec<u64>>> {
    match (left_constant, right_constant) {
        (Some(left_constant), Some(right_constant)) => {
            Ok(Some(ring.add(left_constant, right_constant)?))
        }
        (None, None) => Ok(None),
        _ => Err(invalid_quadratic(
            "quadratic equation constants must either both be present or both be absent",
        )),
    }
}

fn fold_constant_terms(
    ring: PolynomialRing,
    inverse_two: u64,
    constant_term: &[u64],
    paired_constant_term: &[u64],
) -> CanonicalResult<Vec<u64>> {
    let automorphic_constant_term = ring.automorphism(constant_term)?;
    let rotated_paired_constant_term =
        ring.left_rotate_negacyclic(paired_constant_term, ring.degree() / 2)?;
    let automorphic_rotated_paired_constant_term =
        ring.left_rotate_negacyclic(&ring.automorphism(paired_constant_term)?, ring.degree() / 2)?;
    let folded_sum = ring.add(
        &ring.add(constant_term, &automorphic_constant_term)?,
        &ring.add(
            &rotated_paired_constant_term,
            &automorphic_rotated_paired_constant_term,
        )?,
    )?;

    ring.scale(inverse_two, &folded_sum)
}

fn inverse_two_modulus(ring: PolynomialRing) -> CanonicalResult<u64> {
    if ring.modulus().is_multiple_of(2) {
        return Err(invalid_quadratic(
            "quadratic equation auto fold requires an odd modulus",
        ));
    }

    Ok(ring.modulus().div_ceil(2))
}

fn invalid_quadratic(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests;
