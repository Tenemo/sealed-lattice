use super::*;
use crate::bgv::evaluator::engine::signed_residue;

// Lagrange interpolation over the plaintext field: given f(0), f(1), ...,
// f(n-1), return the coefficients (lowest degree first) of the unique degree
// (n-1) interpolating polynomial.
pub(crate) fn interpolate_coefficients(values: &[u64]) -> CanonicalResult<Vec<u64>> {
    let point_count = values.len();
    let mut coefficients = vec![0_u64; point_count];
    for (point, value) in values.iter().enumerate() {
        let mut numerator = vec![1_u64];
        let mut denominator = 1_u64;
        for other in 0..point_count {
            if other == point {
                continue;
            }
            numerator = multiply_by_linear_root(&numerator, other as u64)?;
            let difference = signed_residue(point as i64 - other as i64, PLAINTEXT_MODULUS);
            denominator = mul_mod(denominator, difference, PLAINTEXT_MODULUS)?;
        }
        let scale = mul_mod(
            *value,
            inverse_mod(denominator, PLAINTEXT_MODULUS)?,
            PLAINTEXT_MODULUS,
        )?;
        for (degree, numerator_coefficient) in numerator.iter().enumerate() {
            coefficients[degree] = add_mod(
                coefficients[degree],
                mul_mod(*numerator_coefficient, scale, PLAINTEXT_MODULUS)?,
                PLAINTEXT_MODULUS,
            )?;
        }
    }

    Ok(coefficients)
}

// Multiply a polynomial by (x - root) over the plaintext field.
pub(crate) fn multiply_by_linear_root(polynomial: &[u64], root: u64) -> CanonicalResult<Vec<u64>> {
    let mut product = vec![0_u64; polynomial.len() + 1];
    for (degree, coefficient) in polynomial.iter().enumerate() {
        product[degree + 1] = add_mod(product[degree + 1], *coefficient, PLAINTEXT_MODULUS)?;
        let scaled_root = mul_mod(*coefficient, root, PLAINTEXT_MODULUS)?;
        product[degree] = sub_mod(product[degree], scaled_root, PLAINTEXT_MODULUS)?;
    }

    Ok(product)
}
