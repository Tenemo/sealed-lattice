//! Dense univariate polynomial helpers over an atom proof field, for the
//! composition layer (sumcheck decomposition, vanishing quotients, DEEP
//! quotients). Coefficients are low-to-high; the field is the multi-limb
//! Montgomery field of `proof_field`.

use super::super::proof_field::ProofFieldParameters;
#[cfg(test)]
use super::domain::CyclicDomain;

// Product via cyclic NTT: evaluate both operands on a subgroup at least as
// large as the product degree (so cyclic convolution equals the true product
// with no wraparound), multiply pointwise, and interpolate. This is the
// `O(n log n)` replacement for the schoolbook `multiply` in the hot sumcheck
// and support-constraint paths. It agrees with `multiply` exactly (tested), and
// requires the product length to fit the field's two-adic order (65536); the
// caller falls back to schoolbook for tiny inputs where the NTT setup does not
// pay off.
#[cfg(test)]
pub(super) fn multiply_via_ntt<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    left: &[[u64; LIMB_COUNT]],
    right: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    if left.is_empty() || right.is_empty() {
        return vec![parameters.zero()];
    }
    let product_len = left.len() + right.len() - 1;
    let domain_size = product_len.next_power_of_two();
    // Small inputs, or products beyond the two-adic order, use schoolbook.
    if !(16..=super::domain::MAX_TWO_ADIC_ORDER).contains(&domain_size) {
        return multiply(parameters, left, right);
    }
    let Ok(domain) = CyclicDomain::new(parameters, domain_size) else {
        return multiply(parameters, left, right);
    };
    let mut left_values = domain.evaluate(left);
    let right_values = domain.evaluate(right);
    for (slot, value) in left_values.iter_mut().zip(right_values.iter()) {
        *slot = parameters.multiply(slot, value);
    }
    let mut coefficients = domain.interpolate(&left_values);
    coefficients.truncate(product_len);
    coefficients
}

#[cfg(test)]
pub(super) fn trim<const LIMB_COUNT: usize>(coefficients: &mut Vec<[u64; LIMB_COUNT]>) {
    while coefficients.len() > 1
        && coefficients
            .last()
            .expect("non-empty")
            .iter()
            .all(|limb| *limb == 0)
    {
        coefficients.pop();
    }
}

pub(super) fn evaluate<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    point: &[u64; LIMB_COUNT],
) -> [u64; LIMB_COUNT] {
    let mut accumulator = parameters.zero();
    for coefficient in coefficients.iter().rev() {
        accumulator = parameters.add(&parameters.multiply(&accumulator, point), coefficient);
    }
    accumulator
}

#[cfg(test)]
pub(super) fn add<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    left: &[[u64; LIMB_COUNT]],
    right: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    let length = left.len().max(right.len());
    let mut result = vec![parameters.zero(); length];
    for (index, slot) in result.iter_mut().enumerate() {
        let a = left
            .get(index)
            .copied()
            .unwrap_or_else(|| parameters.zero());
        let b = right
            .get(index)
            .copied()
            .unwrap_or_else(|| parameters.zero());
        *slot = parameters.add(&a, &b);
    }
    result
}

#[cfg(test)]
pub(super) fn subtract<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    left: &[[u64; LIMB_COUNT]],
    right: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    let length = left.len().max(right.len());
    let mut result = vec![parameters.zero(); length];
    for (index, slot) in result.iter_mut().enumerate() {
        let a = left
            .get(index)
            .copied()
            .unwrap_or_else(|| parameters.zero());
        let b = right
            .get(index)
            .copied()
            .unwrap_or_else(|| parameters.zero());
        *slot = parameters.subtract(&a, &b);
    }
    result
}

#[cfg(test)]
pub(super) fn scale<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    scalar: &[u64; LIMB_COUNT],
) -> Vec<[u64; LIMB_COUNT]> {
    coefficients
        .iter()
        .map(|coefficient| parameters.multiply(coefficient, scalar))
        .collect()
}

#[cfg(test)]
pub(super) fn multiply<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    left: &[[u64; LIMB_COUNT]],
    right: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    if left.is_empty() || right.is_empty() {
        return vec![parameters.zero()];
    }
    let mut result = vec![parameters.zero(); left.len() + right.len() - 1];
    for (left_index, left_coefficient) in left.iter().enumerate() {
        if left_coefficient.iter().all(|limb| *limb == 0) {
            continue;
        }
        for (right_index, right_coefficient) in right.iter().enumerate() {
            let term = parameters.multiply(left_coefficient, right_coefficient);
            result[left_index + right_index] =
                parameters.add(&result[left_index + right_index], &term);
        }
    }
    result
}

// Divide by `X - point`, returning the quotient. Requires that `point` is a
// root (the remainder is discarded); callers use this only when the numerator
// vanishes at `point`.
#[cfg(test)]
pub(super) fn divide_by_linear<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    point: &[u64; LIMB_COUNT],
) -> Vec<[u64; LIMB_COUNT]> {
    // Synthetic division by (X - point): quotient q_{i} = c_{i+1} + point*q_{i+1}.
    if coefficients.len() <= 1 {
        return vec![parameters.zero()];
    }
    let mut quotient = vec![parameters.zero(); coefficients.len() - 1];
    let mut carry = parameters.zero();
    for index in (0..coefficients.len()).rev() {
        if index == 0 {
            // The final carry is the remainder; discarded (assumed zero).
            break;
        }
        let value = parameters.add(&coefficients[index], &carry);
        quotient[index - 1] = value;
        carry = parameters.multiply(&value, point);
    }
    quotient
}

// Divide by `Z_H(X) = X^m - 1`, returning the quotient. The subgroup vanishing
// polynomial of a size-`m` multiplicative subgroup. Requires the numerator to
// be divisible (the caller guarantees it vanishes on H); any remainder is
// dropped.
#[cfg(test)]
pub(super) fn divide_by_vanishing<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    subgroup_size: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    // (sum c_i X^i) / (X^m - 1): long division. Since X^m ≡ 1 on the quotient,
    // process from the top: q_{i} = c_{i+m} + q_{i+m} pattern. Implement plainly.
    if coefficients.len() <= subgroup_size {
        return vec![parameters.zero()];
    }
    let mut remainder = coefficients.to_vec();
    let quotient_len = coefficients.len() - subgroup_size;
    let mut quotient = vec![parameters.zero(); quotient_len];
    for index in (0..quotient_len).rev() {
        let leading = remainder[index + subgroup_size];
        quotient[index] = leading;
        // Subtract leading * (X^m - 1) * X^index: cancels the top term and adds
        // `leading` back at position `index` (because -(-1) = +1).
        remainder[index + subgroup_size] = parameters.zero();
        remainder[index] = parameters.add(&remainder[index], &leading);
    }
    quotient
}

// Divisor value `Z_H(z) = z^m - 1` at a point.
pub(super) fn vanishing_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    point: &[u64; LIMB_COUNT],
    subgroup_size: usize,
) -> [u64; LIMB_COUNT] {
    let mut exponent = [0_u64; LIMB_COUNT];
    exponent[0] = subgroup_size as u64;
    let power = parameters.power(point, &exponent);
    parameters.subtract(&power, &parameters.one())
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::super::domain::CyclicDomain;
    use super::*;

    fn values<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        raw: &[i64],
    ) -> Vec<[u64; LIMB_COUNT]> {
        raw.iter()
            .map(|value| parameters.signed_word_to_element(*value))
            .collect()
    }

    #[test]
    fn multiply_via_ntt_agrees_with_schoolbook() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut state = 0x9e37_u64;
        let mut random = |count: usize| -> Vec<[u64; 13]> {
            (0..count)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    parameters.unsigned_word_to_element(state)
                })
                .collect()
        };
        for (left_len, right_len) in [(1, 1), (3, 5), (64, 64), (128, 257), (500, 300)] {
            let left = random(left_len);
            let right = random(right_len);
            let mut schoolbook = multiply(&parameters, &left, &right);
            let mut ntt = multiply_via_ntt(&parameters, &left, &right);
            trim(&mut schoolbook);
            trim(&mut ntt);
            assert_eq!(ntt, schoolbook, "lengths {left_len}x{right_len}");
        }
    }

    #[test]
    fn multiply_and_evaluate_agree() {
        let parameters = sixteen_limb_group_field_parameters();
        let a = values(&parameters, &[1, 2, 3]);
        let b = values(&parameters, &[4, 5]);
        let product = multiply(&parameters, &a, &b);
        let point = parameters.unsigned_word_to_element(7);
        let expected = parameters.multiply(
            &evaluate(&parameters, &a, &point),
            &evaluate(&parameters, &b, &point),
        );
        assert_eq!(evaluate(&parameters, &product, &point), expected);
    }

    #[test]
    fn divide_by_linear_inverts_multiplication() {
        let parameters = sixteen_limb_group_field_parameters();
        let quotient = values(&parameters, &[3, -1, 2, 5]);
        let root = parameters.unsigned_word_to_element(9);
        let linear = values(&parameters, &[0, 1]); // X
        let linear = subtract(&parameters, &linear, &vec![root, parameters.zero()]); // X - root
        let product = multiply(&parameters, &quotient, &linear);
        let recovered = divide_by_linear(&parameters, &product, &root);
        let mut recovered = recovered;
        trim(&mut recovered);
        let mut expected = quotient.clone();
        trim(&mut expected);
        assert_eq!(recovered, expected);
    }

    #[test]
    fn divide_by_vanishing_inverts_multiplication() {
        let parameters = sixteen_limb_group_field_parameters();
        let subgroup_size = 8;
        let quotient = values(&parameters, &[1, 2, 3, 4, 5]);
        // Z_H = X^8 - 1.
        let mut vanishing = vec![parameters.zero(); subgroup_size + 1];
        vanishing[0] = parameters.negate(&parameters.one());
        vanishing[subgroup_size] = parameters.one();
        let product = multiply(&parameters, &quotient, &vanishing);
        let recovered = divide_by_vanishing(&parameters, &product, subgroup_size);
        let mut recovered = recovered;
        trim(&mut recovered);
        let mut expected = quotient.clone();
        trim(&mut expected);
        assert_eq!(recovered, expected);
    }

    #[test]
    fn vanishing_at_is_zero_on_the_subgroup() {
        let parameters = sixteen_limb_group_field_parameters();
        let subgroup_size = 16;
        let domain = CyclicDomain::new(&parameters, subgroup_size).expect("domain");
        for index in [0_usize, 1, 5, 15] {
            let point = domain.point(index);
            assert_eq!(
                vanishing_at(&parameters, &point, subgroup_size),
                parameters.zero(),
            );
        }
        // Nonzero off the subgroup.
        let off = parameters.unsigned_word_to_element(3);
        assert_ne!(
            vanishing_at(&parameters, &off, subgroup_size),
            parameters.zero()
        );
    }
}
