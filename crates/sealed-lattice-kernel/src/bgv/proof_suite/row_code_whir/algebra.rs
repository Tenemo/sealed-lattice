//! Algebraic reduction from coset Reed-Solomon queries to multilinear openings.

use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::point::Point;

use super::ChallengeField;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PolynomialOpeningReduction {
    pub(super) multilinear_point: Point<ChallengeField>,
    pub(super) multilinear_to_polynomial_scale: ChallengeField,
}

/// Returns the natural-order point at `column_index` in the selected coset.
///
/// The multiplicative generator retains a non-trivial odd-order component.
/// Consequently no point in this coset has a power-of-two power equal to
/// minus one, which keeps every multilinear reduction denominator non-zero.
pub(super) fn coset_point(
    log_domain_size: usize,
    column_index: usize,
) -> Result<Goldilocks, String> {
    if log_domain_size > Goldilocks::TWO_ADICITY {
        return Err(format!(
            "coset domain 2^{log_domain_size} exceeds Goldilocks two-adicity 2^{}",
            Goldilocks::TWO_ADICITY
        ));
    }
    let domain_size = 1_usize
        .checked_shl(log_domain_size as u32)
        .ok_or_else(|| format!("coset domain 2^{log_domain_size} exceeds usize"))?;
    if column_index >= domain_size {
        return Err(format!(
            "coset column index {column_index} is outside domain size {domain_size}"
        ));
    }
    Ok(Goldilocks::GENERATOR
        * Goldilocks::two_adic_generator(log_domain_size).exp_u64(column_index as u64))
}

/// Reduces one coefficient-form polynomial evaluation to one MLE opening.
///
/// For `P(X) = sum_k message[k] X^k`, set
/// `z_i = x^(2^i) / (1 + x^(2^i))`. Then
/// `P(x) = MLE(message)(z) * product_i (1 + x^(2^i))`.
pub(super) fn polynomial_opening_reduction(
    evaluation_point: Goldilocks,
    coefficient_variable_count: usize,
) -> Result<PolynomialOpeningReduction, String> {
    polynomial_extension_opening_reduction(
        ChallengeField::from(evaluation_point),
        coefficient_variable_count,
    )
}

pub(super) fn polynomial_extension_opening_reduction(
    evaluation_point: ChallengeField,
    coefficient_variable_count: usize,
) -> Result<PolynomialOpeningReduction, String> {
    let mut power = evaluation_point;
    let mut multilinear_to_polynomial_scale = ChallengeField::ONE;
    let mut coordinates = Vec::with_capacity(coefficient_variable_count);
    for variable_index in 0..coefficient_variable_count {
        let denominator = ChallengeField::ONE + power;
        if denominator == ChallengeField::ZERO {
            return Err(format!(
                "polynomial opening reduction denominator is zero at variable {variable_index}"
            ));
        }
        coordinates.push(power * denominator.inverse());
        multilinear_to_polynomial_scale *= denominator;
        power = power.square();
    }
    // `Poly` consumes point coordinates from the most-significant table bit
    // to the least-significant bit, while coefficient exponents use the
    // ordinary least-significant-bit-first binary expansion.
    coordinates.reverse();
    Ok(PolynomialOpeningReduction {
        multilinear_point: Point::new(coordinates),
        multilinear_to_polynomial_scale,
    })
}

/// Extends the polynomial reduction with the selector for two concatenated
/// aggregate messages.
///
/// If `H = G_left || G_right`, opening `H` at selector `b` authenticates
/// `(1-b) G_left(x) + b G_right(x)`. This form has no exceptional batching
/// challenge and retains a one-over-field batching error.
#[cfg(test)]
pub(super) fn aggregate_opening_reduction(
    evaluation_point: Goldilocks,
    coefficient_variable_count: usize,
    batching_challenge: ChallengeField,
) -> Result<PolynomialOpeningReduction, String> {
    let mut reduction = polynomial_opening_reduction(evaluation_point, coefficient_variable_count)?;
    let mut coordinates = Vec::with_capacity(coefficient_variable_count + 1);
    // Concatenation makes this selector the most-significant table bit.
    coordinates.push(batching_challenge);
    coordinates.extend_from_slice(reduction.multilinear_point.as_slice());
    reduction.multilinear_point = Point::new(coordinates);
    Ok(reduction)
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_multilinear_util::poly::Poly;

    use super::*;

    fn evaluate_coefficients(
        coefficients: &[ChallengeField],
        point: ChallengeField,
    ) -> ChallengeField {
        coefficients
            .iter()
            .rev()
            .fold(ChallengeField::ZERO, |evaluation, coefficient| {
                evaluation * point + *coefficient
            })
    }

    #[test]
    fn polynomial_reduction_matches_direct_evaluation_across_geometries() {
        for coefficient_variable_count in 1..=9 {
            let coefficient_count = 1_usize << coefficient_variable_count;
            let coefficients = (0..coefficient_count)
                .map(|coefficient_index| {
                    ChallengeField::new(core::array::from_fn(|limb_index| {
                        Goldilocks::from_u64(
                            (coefficient_index as u64 + 3) * (limb_index as u64 + 5),
                        )
                    }))
                })
                .collect::<Vec<_>>();
            let polynomial = Poly::new(coefficients.clone());
            for column_index in [0, 1, 3, 7] {
                let evaluation_point = coset_point(10, column_index).expect("valid coset point");
                let reduction =
                    polynomial_opening_reduction(evaluation_point, coefficient_variable_count)
                        .expect("coset point has no zero reduction denominator");
                let direct =
                    evaluate_coefficients(&coefficients, ChallengeField::from(evaluation_point));
                let reduced = polynomial.eval_ext::<ChallengeField>(&reduction.multilinear_point)
                    * reduction.multilinear_to_polynomial_scale;
                assert_eq!(reduced, direct);
            }
        }
    }

    #[test]
    fn aggregate_reduction_matches_batched_codeword_values() {
        let coefficient_variable_count = 8;
        let coefficient_count = 1_usize << coefficient_variable_count;
        let left = (0..coefficient_count)
            .map(|index| ChallengeField::from_u64(index as u64 * 11 + 7))
            .collect::<Vec<_>>();
        let right = (0..coefficient_count)
            .map(|index| ChallengeField::from_u64(index as u64 * 13 + 17))
            .collect::<Vec<_>>();
        let mut concatenated = left.clone();
        concatenated.extend_from_slice(&right);
        let aggregate = Poly::new(concatenated);
        let batching_challenge = ChallengeField::new([
            Goldilocks::from_u64(19),
            Goldilocks::from_u64(23),
            Goldilocks::from_u64(29),
            Goldilocks::from_u64(31),
            Goldilocks::from_u64(37),
        ]);

        for column_index in [0, 2, 5, 127, 511] {
            let evaluation_point = coset_point(10, column_index).expect("valid coset point");
            let reduction = aggregate_opening_reduction(
                evaluation_point,
                coefficient_variable_count,
                batching_challenge,
            )
            .expect("valid aggregate opening reduction");
            let extension_evaluation_point = ChallengeField::from(evaluation_point);
            let expected = (ChallengeField::ONE - batching_challenge)
                * evaluate_coefficients(&left, extension_evaluation_point)
                + batching_challenge * evaluate_coefficients(&right, extension_evaluation_point);
            let actual = aggregate.eval_ext::<ChallengeField>(&reduction.multilinear_point)
                * reduction.multilinear_to_polynomial_scale;
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn generator_coset_avoids_every_reduction_pole() {
        for log_domain_size in 1..=12 {
            let domain_size = 1_usize << log_domain_size;
            for column_index in 0..domain_size {
                let point = coset_point(log_domain_size, column_index).expect("valid coset point");
                polynomial_opening_reduction(point, log_domain_size)
                    .expect("generator coset avoids every power-of-two pole");
            }
        }
    }

    #[test]
    fn reduction_rejects_an_actual_pole_and_out_of_range_columns() {
        assert!(polynomial_opening_reduction(-Goldilocks::ONE, 1).is_err());
        assert!(coset_point(8, 256).is_err());
        assert!(coset_point(Goldilocks::TWO_ADICITY + 1, 0).is_err());
    }
}
