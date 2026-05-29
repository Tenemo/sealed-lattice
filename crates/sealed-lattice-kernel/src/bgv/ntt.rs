use crate::{
    bgv::{
        modular_arithmetic::{add_mod, inverse_mod, mul_mod, pow_mod, sub_mod},
        profile::{POLYNOMIAL_DEGREE, root_parameters_for_modulus},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn forward_negacyclic_ntt(
    coefficients: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    transform_negacyclic(coefficients, modulus, TransformDirection::Forward)
}

pub(crate) fn inverse_negacyclic_ntt(values: &[u64], modulus: u64) -> CanonicalResult<Vec<u64>> {
    transform_negacyclic(values, modulus, TransformDirection::Inverse)
}

fn transform_negacyclic(
    values: &[u64],
    modulus: u64,
    direction: TransformDirection,
) -> CanonicalResult<Vec<u64>> {
    validate_transform_length(values.len())?;
    validate_residues(values, modulus)?;
    let root_parameters = root_parameters_for_modulus(modulus).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "modulus is not part of the selected BGV-RNS profile",
        )
    })?;
    let root_exponent = (POLYNOMIAL_DEGREE / values.len()) as u64;
    let mut transformed = values.to_vec();

    match direction {
        TransformDirection::Forward => {
            let negacyclic_root = pow_mod(root_parameters.negacyclic_root, root_exponent, modulus)?;
            multiply_by_powers(&mut transformed, negacyclic_root, modulus)?;
            let cyclic_root = pow_mod(root_parameters.cyclic_root, root_exponent, modulus)?;
            cyclic_ntt(&mut transformed, cyclic_root, modulus, false)?;
        }
        TransformDirection::Inverse => {
            let inverse_cyclic_root =
                pow_mod(root_parameters.inverse_cyclic_root, root_exponent, modulus)?;
            cyclic_ntt(&mut transformed, inverse_cyclic_root, modulus, true)?;
            let inverse_negacyclic_root = pow_mod(
                root_parameters.inverse_negacyclic_root,
                root_exponent,
                modulus,
            )?;
            multiply_by_powers(&mut transformed, inverse_negacyclic_root, modulus)?;
        }
    }

    Ok(transformed)
}

fn cyclic_ntt(
    values: &mut [u64],
    root: u64,
    modulus: u64,
    normalize_inverse: bool,
) -> CanonicalResult<()> {
    bit_reverse_permute(values);
    let length = values.len();
    let mut butterfly_width = 2_usize;
    while butterfly_width <= length {
        let half_width = butterfly_width / 2;
        let step_root = pow_mod(root, (length / butterfly_width) as u64, modulus)?;
        let mut stage_twiddles = Vec::with_capacity(half_width);
        let mut twiddle = 1_u64;
        for _ in 0..half_width {
            stage_twiddles.push(twiddle);
            twiddle = mul_mod(twiddle, step_root, modulus)?;
        }
        let mut block_start = 0_usize;
        while block_start < length {
            for (offset, stage_twiddle) in stage_twiddles.iter().enumerate().take(half_width) {
                let left_index = block_start + offset;
                let right_index = left_index + half_width;
                let right_value = mul_mod(values[right_index], *stage_twiddle, modulus)?;
                let left_value = values[left_index];
                values[left_index] = add_mod(left_value, right_value, modulus)?;
                values[right_index] = sub_mod(left_value, right_value, modulus)?;
            }
            block_start += butterfly_width;
        }
        butterfly_width *= 2;
    }

    if normalize_inverse {
        let inverse_length = inverse_mod(length as u64, modulus)?;
        for value in values {
            *value = mul_mod(*value, inverse_length, modulus)?;
        }
    }

    Ok(())
}

fn multiply_by_powers(values: &mut [u64], root: u64, modulus: u64) -> CanonicalResult<()> {
    let mut power = 1_u64;
    for value in values {
        *value = mul_mod(*value, power, modulus)?;
        power = mul_mod(power, root, modulus)?;
    }

    Ok(())
}

fn bit_reverse_permute(values: &mut [u64]) {
    let length = values.len();
    let mut reversed_index = 0_usize;
    for index in 1..length {
        let mut bit = length >> 1;
        while reversed_index & bit != 0 {
            reversed_index ^= bit;
            bit >>= 1;
        }
        reversed_index ^= bit;
        if index < reversed_index {
            values.swap(index, reversed_index);
        }
    }
}

fn validate_transform_length(length: usize) -> CanonicalResult<()> {
    if length == 0 || !length.is_power_of_two() || !POLYNOMIAL_DEGREE.is_multiple_of(length) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "NTT length must be a non-empty power of two dividing the selected polynomial degree",
        ));
    }

    Ok(())
}

fn validate_residues(values: &[u64], modulus: u64) -> CanonicalResult<()> {
    if values.iter().any(|value| *value >= modulus) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "NTT input contains a non-canonical residue",
        ));
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum TransformDirection {
    Forward,
    Inverse,
}

#[cfg(test)]
pub(crate) fn negacyclic_convolution_for_tests(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if left.len() != right.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "convolution inputs must have the same length",
        ));
    }
    let left_transformed = forward_negacyclic_ntt(left, modulus)?;
    let right_transformed = forward_negacyclic_ntt(right, modulus)?;
    let mut product = Vec::with_capacity(left.len());
    for (left_value, right_value) in left_transformed.iter().zip(right_transformed.iter()) {
        product.push(mul_mod(*left_value, *right_value, modulus)?);
    }

    inverse_negacyclic_ntt(&product, modulus)
}

#[cfg(test)]
mod tests {
    use super::{forward_negacyclic_ntt, inverse_negacyclic_ntt, negacyclic_convolution_for_tests};
    use crate::{
        bgv::{
            modular_arithmetic::sub_mod,
            profile::{DATA_PRIMES, SPECIAL_PRIME},
        },
        encoding::CanonicalResult,
    };

    #[test]
    fn ntt_round_trips_aggressive_small_vectors_for_every_selected_prime() {
        for modulus in selected_ntt_moduli() {
            let inputs = [
                vec![0_u64; 8],
                vec![1, 0, 0, 0, 0, 0, 0, 0],
                vec![modulus - 1, 1, modulus / 2, 17, 99, 1_024, modulus - 2, 7],
            ];

            for input in inputs {
                let transformed = forward_negacyclic_ntt(&input, modulus).expect("NTT should run");
                if input.iter().any(|value| *value != 0) {
                    assert_ne!(transformed, input);
                }
                let recovered =
                    inverse_negacyclic_ntt(&transformed, modulus).expect("INTT should run");
                assert_eq!(recovered, input);
            }
        }
    }

    #[test]
    fn ntt_convolution_matches_direct_negacyclic_product_for_every_selected_prime() {
        for modulus in selected_ntt_moduli() {
            let left = vec![3, 1, 4, 1, 5, 9, 2, 6];
            let right = vec![5, 3, 5, 8, 9, 7, 9, 3];

            let actual =
                negacyclic_convolution_for_tests(&left, &right, modulus).expect("convolution");
            let expected =
                direct_negacyclic_product(&left, &right, modulus).expect("direct product");

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn ntt_rejects_wrong_lengths_residues_and_unselected_moduli() {
        for modulus in selected_ntt_moduli() {
            assert!(forward_negacyclic_ntt(&[], modulus).is_err());
            assert!(forward_negacyclic_ntt(&[1, 2, 3], modulus).is_err());
            assert!(forward_negacyclic_ntt(&[modulus, 0], modulus).is_err());
        }
        assert!(forward_negacyclic_ntt(&[1, 2], 97).is_err());
    }

    fn selected_ntt_moduli() -> Vec<u64> {
        DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]).collect()
    }

    fn direct_negacyclic_product(
        left: &[u64],
        right: &[u64],
        modulus: u64,
    ) -> CanonicalResult<Vec<u64>> {
        let length = left.len();
        let mut output = vec![0_u64; length];
        for (left_index, left_value) in left.iter().enumerate() {
            for (right_index, right_value) in right.iter().enumerate() {
                let product =
                    ((*left_value as u128 * *right_value as u128) % modulus as u128) as u64;
                let raw_index = left_index + right_index;
                if raw_index < length {
                    output[raw_index] = (output[raw_index] + product) % modulus;
                } else {
                    output[raw_index - length] =
                        sub_mod(output[raw_index - length], product, modulus)?;
                }
            }
        }

        Ok(output)
    }
}
