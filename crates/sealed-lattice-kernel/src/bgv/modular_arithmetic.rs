use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(crate) fn add_mod(left: u64, right: u64, modulus: u64) -> CanonicalResult<u64> {
    validate_modulus(modulus)?;
    if left >= modulus || right >= modulus {
        return Err(out_of_range_error());
    }
    if modulus <= u64::MAX / 2 {
        let sum = left + right;
        return Ok(if sum >= modulus { sum - modulus } else { sum });
    }

    Ok(((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64)
}

pub(crate) fn sub_mod(left: u64, right: u64, modulus: u64) -> CanonicalResult<u64> {
    validate_modulus(modulus)?;
    if left >= modulus || right >= modulus {
        return Err(out_of_range_error());
    }
    if left >= right {
        Ok(left - right)
    } else {
        Ok(modulus - (right - left))
    }
}

pub(crate) fn mul_mod(left: u64, right: u64, modulus: u64) -> CanonicalResult<u64> {
    validate_modulus(modulus)?;
    if left >= modulus || right >= modulus {
        return Err(out_of_range_error());
    }
    if modulus <= u64::from(u32::MAX) {
        return Ok(left.wrapping_mul(right) % modulus);
    }
    if modulus < (1_u64 << 53) {
        return Ok(reduce_u53_product(left, right, modulus));
    }

    Ok(((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64)
}

fn reduce_u53_product(left: u64, right: u64, modulus: u64) -> u64 {
    let product = u128::from(left) * u128::from(right);
    let approximate_quotient = ((left as f64) * (right as f64) / (modulus as f64)) as u64;
    let mut remainder =
        product as i128 - (u128::from(approximate_quotient) * u128::from(modulus)) as i128;
    let modulus_i128 = i128::from(modulus);

    for _ in 0..8 {
        if remainder < 0 {
            remainder += modulus_i128;
            continue;
        }
        if remainder >= modulus_i128 {
            remainder -= modulus_i128;
            continue;
        }

        return remainder as u64;
    }

    (product % u128::from(modulus)) as u64
}

pub(crate) fn pow_mod(base: u64, exponent: u64, modulus: u64) -> CanonicalResult<u64> {
    validate_modulus(modulus)?;
    if base >= modulus {
        return Err(out_of_range_error());
    }
    let mut output = 1_u64;
    let mut power = base;
    let mut remaining_exponent = exponent;
    while remaining_exponent > 0 {
        if remaining_exponent & 1 == 1 {
            output = mul_mod(output, power, modulus)?;
        }
        remaining_exponent >>= 1;
        if remaining_exponent > 0 {
            power = mul_mod(power, power, modulus)?;
        }
    }

    Ok(output)
}

pub(crate) fn inverse_mod(value: u64, modulus: u64) -> CanonicalResult<u64> {
    validate_modulus(modulus)?;
    if value == 0 || value >= modulus {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "modular inverse input must be non-zero and less than the modulus",
        ));
    }

    let mut previous_remainder = i128::from(modulus);
    let mut remainder = i128::from(value);
    let mut previous_coefficient = 0_i128;
    let mut coefficient = 1_i128;
    while remainder != 0 {
        let quotient = previous_remainder / remainder;
        let next_remainder = previous_remainder - quotient * remainder;
        previous_remainder = remainder;
        remainder = next_remainder;

        let next_coefficient = previous_coefficient - quotient * coefficient;
        previous_coefficient = coefficient;
        coefficient = next_coefficient;
    }
    if previous_remainder != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "modular inverse input is not invertible",
        ));
    }

    let modulus_i128 = i128::from(modulus);
    let normalized = previous_coefficient.rem_euclid(modulus_i128);

    Ok(normalized as u64)
}

fn validate_modulus(modulus: u64) -> CanonicalResult<()> {
    if modulus <= 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "modulus must be greater than one",
        ));
    }

    Ok(())
}

fn out_of_range_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        "modular arithmetic operand is outside the canonical residue range",
    )
}

#[cfg(test)]
pub(crate) fn is_prime_for_tests(value: u64) -> bool {
    if value < 2 {
        return false;
    }
    if value.is_multiple_of(2) {
        return value == 2;
    }
    let mut divisor = 3_u64;
    while divisor <= value / divisor {
        if value.is_multiple_of(divisor) {
            return false;
        }
        divisor += 2;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::{add_mod, inverse_mod, mul_mod, pow_mod, sub_mod};
    use crate::bgv::profile::{DATA_PRIMES, SPECIAL_PRIME};

    #[test]
    fn modular_arithmetic_handles_boundaries_for_every_selected_prime() {
        for modulus in DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]) {
            assert_eq!(add_mod(modulus - 1, 1, modulus).expect("add"), 0);
            assert_eq!(
                add_mod(modulus / 2, modulus / 2, modulus).expect("add"),
                modulus - 1
            );
            assert_eq!(sub_mod(0, 1, modulus).expect("sub"), modulus - 1);
            assert_eq!(sub_mod(1, 1, modulus).expect("sub"), 0);
            assert_eq!(mul_mod(modulus - 1, modulus - 1, modulus).expect("mul"), 1);
            assert_eq!(mul_mod(modulus - 1, 2, modulus).expect("mul"), modulus - 2);
            assert_eq!(pow_mod(5, 0, modulus).expect("pow"), 1);
            assert_eq!(pow_mod(5, 1, modulus).expect("pow"), 5);
            assert_eq!(
                mul_mod(5, inverse_mod(5, modulus).expect("inverse"), modulus).expect("mul"),
                1
            );
        }
    }

    #[test]
    fn arithmetic_rejects_noncanonical_residues_for_every_selected_prime() {
        for modulus in DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]) {
            assert!(add_mod(modulus, 0, modulus).is_err());
            assert!(sub_mod(0, modulus, modulus).is_err());
            assert!(mul_mod(1, modulus, modulus).is_err());
            assert!(pow_mod(modulus, 2, modulus).is_err());
            assert!(inverse_mod(0, modulus).is_err());
            assert!(inverse_mod(modulus, modulus).is_err());
        }
    }

    #[test]
    fn optimized_multiplication_matches_generic_modular_arithmetic_for_bgv_primes() {
        for modulus in DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]) {
            let mut state = modulus ^ 0xa076_1d64_78bd_642f;
            let mut cases = vec![
                (0, 0),
                (1, modulus - 1),
                (modulus - 1, modulus - 1),
                (modulus / 2, modulus / 2 + 1),
            ];
            for _ in 0..256 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let left = state % modulus;
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let right = state % modulus;
                cases.push((left, right));
            }

            for (left, right) in cases {
                assert_eq!(
                    mul_mod(left, right, modulus).expect("mul"),
                    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64,
                    "modulus={modulus}, left={left}, right={right}",
                );
            }
        }
    }
}
