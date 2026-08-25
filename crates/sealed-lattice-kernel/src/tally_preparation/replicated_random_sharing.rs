use crate::foundation::derive_foundation_roster_parameters;

use super::{BinaryFieldElement256, TallyPreparationError};

pub(crate) const PSEUDORANDOM_SHARING_KEY_BYTE_LENGTH: u64 = 64;

/// Exact replicated-key geometry for local random Shamir and zero sharing.
///
/// This is an unactivated algebra and resource owner. It assumes independent
/// pseudorandom-function keys have already been established for every named
/// subset and does not claim that a real key ceremony or fixed hash function
/// realizes that assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedRandomSharingGeometry {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) authorized_subset_size: u64,
    pub(crate) authorized_subset_count: u64,
    pub(crate) authorized_subset_count_per_participant: u64,
    pub(crate) random_sharing_key_count_per_subset: u64,
    pub(crate) zero_sharing_key_count_per_subset: u64,
    pub(crate) total_key_count: u64,
    pub(crate) key_count_per_participant: u64,
    pub(crate) key_byte_length: u64,
    pub(crate) all_member_contribution_count: u64,
    pub(crate) remote_key_component_delivery_count: u64,
    pub(crate) remote_key_component_byte_length: u64,
}

impl ReplicatedRandomSharingGeometry {
    pub(crate) fn derive(participant_count: u16) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let participant_count = u64::from(participant_count);
        let active_fault_bound = u64::from(roster_parameters.active_fault_bound);
        if participant_count <= checked_multiply(active_fault_bound, 3)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let authorized_subset_size = participant_count
            .checked_sub(active_fault_bound)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let authorized_subset_count =
            checked_binomial_coefficient(participant_count, active_fault_bound)?;
        let authorized_subset_count_per_participant = checked_binomial_coefficient(
            participant_count
                .checked_sub(1)
                .ok_or(TallyPreparationError::GeometryMismatch)?,
            active_fault_bound,
        )?;
        let random_sharing_key_count_per_subset = 1;
        let zero_sharing_key_count_per_subset = active_fault_bound;
        let key_count_per_subset = checked_add(
            random_sharing_key_count_per_subset,
            zero_sharing_key_count_per_subset,
        )?;
        let total_key_count = checked_multiply(authorized_subset_count, key_count_per_subset)?;
        let key_count_per_participant = checked_multiply(
            authorized_subset_count_per_participant,
            key_count_per_subset,
        )?;
        let all_member_contribution_count =
            checked_multiply(total_key_count, authorized_subset_size)?;
        let remote_recipient_count = authorized_subset_size
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let remote_key_component_delivery_count =
            checked_multiply(all_member_contribution_count, remote_recipient_count)?;
        let remote_key_component_byte_length = checked_multiply(
            remote_key_component_delivery_count,
            PSEUDORANDOM_SHARING_KEY_BYTE_LENGTH,
        )?;

        Ok(Self {
            participant_count,
            active_fault_bound,
            authorized_subset_size,
            authorized_subset_count,
            authorized_subset_count_per_participant,
            random_sharing_key_count_per_subset,
            zero_sharing_key_count_per_subset,
            total_key_count,
            key_count_per_participant,
            key_byte_length: PSEUDORANDOM_SHARING_KEY_BYTE_LENGTH,
            all_member_contribution_count,
            remote_key_component_delivery_count,
            remote_key_component_byte_length,
        })
    }

    pub(crate) fn field_outputs_per_participant_for_one_triple(
        self,
    ) -> Result<u64, TallyPreparationError> {
        // Three random degree-t sharings supply a, b, and the degree-t
        // reduction mask. One degree-2t zero sharing supplies t more outputs
        // per authorized subset.
        checked_multiply(
            self.authorized_subset_count_per_participant,
            checked_add(3, self.zero_sharing_key_count_per_subset)?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedRandomSharingSubset {
    participant_count: u16,
    active_fault_bound: u16,
    excluded_position_mask: u32,
}

impl ReplicatedRandomSharingSubset {
    pub(crate) fn all(participant_count: u16) -> Result<Vec<Self>, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let mask_limit = 1_u32
            .checked_shl(u32::from(participant_count))
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let mut subsets = Vec::new();
        for excluded_position_mask in 0..mask_limit {
            if excluded_position_mask.count_ones()
                == u32::from(roster_parameters.active_fault_bound)
            {
                subsets.push(Self {
                    participant_count,
                    active_fault_bound: roster_parameters.active_fault_bound,
                    excluded_position_mask,
                });
            }
        }
        Ok(subsets)
    }

    pub(crate) fn from_excluded_positions(
        participant_count: u16,
        excluded_positions: &[u16],
    ) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        if excluded_positions.len() != usize::from(roster_parameters.active_fault_bound) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let mut excluded_position_mask = 0_u32;
        for excluded_position in excluded_positions {
            if *excluded_position >= participant_count {
                return Err(TallyPreparationError::RosterPositionOutOfRange {
                    roster_position: *excluded_position,
                    participant_count,
                });
            }
            let position_bit = 1_u32
                .checked_shl(u32::from(*excluded_position))
                .ok_or(TallyPreparationError::ArithmeticOverflow)?;
            if excluded_position_mask & position_bit != 0 {
                return Err(TallyPreparationError::GeometryMismatch);
            }
            excluded_position_mask |= position_bit;
        }
        Ok(Self {
            participant_count,
            active_fault_bound: roster_parameters.active_fault_bound,
            excluded_position_mask,
        })
    }

    pub(crate) fn contains(self, roster_position: u16) -> Result<bool, TallyPreparationError> {
        if roster_position >= self.participant_count {
            return Err(TallyPreparationError::RosterPositionOutOfRange {
                roster_position,
                participant_count: self.participant_count,
            });
        }
        let position_bit = 1_u32
            .checked_shl(u32::from(roster_position))
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        Ok(self.excluded_position_mask & position_bit == 0)
    }

    pub(crate) fn excluded_positions(self) -> Vec<u16> {
        (0..self.participant_count)
            .filter(|roster_position| {
                let position_bit = 1_u32 << u32::from(*roster_position);
                self.excluded_position_mask & position_bit != 0
            })
            .collect()
    }

    pub(crate) fn random_sharing_polynomial(
        self,
        secret_component: BinaryFieldElement256,
    ) -> Result<BinaryFieldPolynomial, TallyPreparationError> {
        let excluded_root_polynomial = self.excluded_root_polynomial()?;
        let constant_inverse = excluded_root_polynomial
            .coefficient(0)
            .multiplicative_inverse()?;
        Ok(excluded_root_polynomial.scale(secret_component.multiply(constant_inverse)))
    }

    pub(crate) fn zero_sharing_polynomial(
        self,
        pseudorandom_components: &[BinaryFieldElement256],
    ) -> Result<BinaryFieldPolynomial, TallyPreparationError> {
        if pseudorandom_components.len() != usize::from(self.active_fault_bound) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let component_polynomial = BinaryFieldPolynomial::new(pseudorandom_components.to_vec());
        Ok(self
            .excluded_root_polynomial()?
            .multiply(&BinaryFieldPolynomial::monomial(
                1,
                BinaryFieldElement256::ONE,
            ))
            .multiply(&component_polynomial))
    }

    fn excluded_root_polynomial(self) -> Result<BinaryFieldPolynomial, TallyPreparationError> {
        self.excluded_positions().into_iter().try_fold(
            BinaryFieldPolynomial::one(),
            |polynomial, excluded_position| {
                let evaluation_point = super::output_sharing::canonical_evaluation_point(
                    self.participant_count,
                    excluded_position,
                )?;
                Ok(polynomial.multiply(&BinaryFieldPolynomial::new(vec![
                    evaluation_point,
                    BinaryFieldElement256::ONE,
                ])))
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BinaryFieldPolynomial {
    coefficients: Vec<BinaryFieldElement256>,
}

impl BinaryFieldPolynomial {
    pub(crate) fn new(mut coefficients: Vec<BinaryFieldElement256>) -> Self {
        while coefficients.len() > 1
            && coefficients
                .last()
                .is_some_and(|coefficient| coefficient.is_zero())
        {
            coefficients.pop();
        }
        if coefficients.is_empty() {
            coefficients.push(BinaryFieldElement256::ZERO);
        }
        Self { coefficients }
    }

    pub(crate) fn zero() -> Self {
        Self::new(vec![BinaryFieldElement256::ZERO])
    }

    pub(crate) fn one() -> Self {
        Self::new(vec![BinaryFieldElement256::ONE])
    }

    pub(crate) fn constant(value: BinaryFieldElement256) -> Self {
        Self::new(vec![value])
    }

    pub(crate) fn monomial(degree: usize, coefficient: BinaryFieldElement256) -> Self {
        let mut coefficients = vec![BinaryFieldElement256::ZERO; degree + 1];
        coefficients[degree] = coefficient;
        Self::new(coefficients)
    }

    pub(crate) fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    pub(crate) fn coefficient(&self, degree: usize) -> BinaryFieldElement256 {
        self.coefficients
            .get(degree)
            .copied()
            .unwrap_or(BinaryFieldElement256::ZERO)
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        let coefficient_count = self.coefficients.len().max(other.coefficients.len());
        Self::new(
            (0..coefficient_count)
                .map(|degree| self.coefficient(degree).add(other.coefficient(degree)))
                .collect(),
        )
    }

    pub(crate) fn multiply(&self, other: &Self) -> Self {
        let mut product_coefficients = vec![
            BinaryFieldElement256::ZERO;
            self.coefficients.len() + other.coefficients.len() - 1
        ];
        for (left_degree, left_coefficient) in self.coefficients.iter().copied().enumerate() {
            for (right_degree, right_coefficient) in other.coefficients.iter().copied().enumerate()
            {
                let product_degree = left_degree + right_degree;
                product_coefficients[product_degree] = product_coefficients[product_degree]
                    .add(left_coefficient.multiply(right_coefficient));
            }
        }
        Self::new(product_coefficients)
    }

    pub(crate) fn scale(&self, scalar: BinaryFieldElement256) -> Self {
        Self::new(
            self.coefficients
                .iter()
                .map(|coefficient| coefficient.multiply(scalar))
                .collect(),
        )
    }

    pub(crate) fn evaluate(
        &self,
        evaluation_point: BinaryFieldElement256,
    ) -> BinaryFieldElement256 {
        self.coefficients.iter().rev().copied().fold(
            BinaryFieldElement256::ZERO,
            |evaluated_value, coefficient| {
                evaluated_value.multiply(evaluation_point).add(coefficient)
            },
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CanonicalPolynomialConsistencyVerifier {
    participant_count: u16,
    maximum_degree: usize,
    interpolation_polynomials: Vec<BinaryFieldPolynomial>,
}

impl CanonicalPolynomialConsistencyVerifier {
    pub(crate) fn new(
        participant_count: u16,
        maximum_degree: usize,
    ) -> Result<Self, TallyPreparationError> {
        if maximum_degree >= usize::from(participant_count) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let basis_point_count = maximum_degree + 1;
        let evaluation_points = (0..basis_point_count)
            .map(|roster_position| {
                super::output_sharing::canonical_evaluation_point(
                    participant_count,
                    u16::try_from(roster_position)
                        .map_err(|_| TallyPreparationError::IntegerConversion)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let interpolation_polynomials = evaluation_points
            .iter()
            .enumerate()
            .map(|(selected_position, selected_point)| {
                let mut numerator = BinaryFieldPolynomial::one();
                let mut denominator = BinaryFieldElement256::ONE;
                for (other_position, other_point) in evaluation_points.iter().enumerate() {
                    if other_position == selected_position {
                        continue;
                    }
                    numerator = numerator.multiply(&BinaryFieldPolynomial::new(vec![
                        *other_point,
                        BinaryFieldElement256::ONE,
                    ]));
                    denominator = denominator.multiply(selected_point.add(*other_point));
                }
                Ok(numerator.scale(denominator.multiplicative_inverse()?))
            })
            .collect::<Result<Vec<_>, TallyPreparationError>>()?;
        Ok(Self {
            participant_count,
            maximum_degree,
            interpolation_polynomials,
        })
    }

    pub(crate) fn interpolate_and_verify(
        &self,
        values: &[BinaryFieldElement256],
    ) -> Result<Option<BinaryFieldPolynomial>, TallyPreparationError> {
        if values.len() != usize::from(self.participant_count) {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let polynomial = self
            .interpolation_polynomials
            .iter()
            .zip(values.iter().take(self.maximum_degree + 1))
            .fold(BinaryFieldPolynomial::zero(), |sum, (basis, value)| {
                sum.add(&basis.scale(*value))
            });
        for (roster_position, value) in values.iter().enumerate() {
            let evaluation_point = super::output_sharing::canonical_evaluation_point(
                self.participant_count,
                u16::try_from(roster_position)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
            )?;
            if polynomial.evaluate(evaluation_point) != *value {
                return Ok(None);
            }
        }
        Ok(Some(polynomial))
    }
}

fn checked_binomial_coefficient(
    total_count: u64,
    selected_count: u64,
) -> Result<u64, TallyPreparationError> {
    if selected_count > total_count {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let selected_count = selected_count.min(total_count - selected_count);
    let mut coefficient = 1_u64;
    for selected_position in 1..=selected_count {
        let numerator = total_count - selected_count + selected_position;
        coefficient = checked_multiply(coefficient, numerator)?
            .checked_div(selected_position)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
    }
    Ok(coefficient)
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
