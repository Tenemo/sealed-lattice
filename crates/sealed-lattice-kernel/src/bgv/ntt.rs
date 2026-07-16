use crate::{
    bgv::{
        modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod_fast, pow_mod, sub_mod_fast},
        parameters::{
            POLYNOMIAL_DEGREE, ROOT_PARAMETERS, RootParameters, root_parameters_for_modulus,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};
use std::sync::OnceLock;

static FULL_DEGREE_NTT_PLANS: OnceLock<Vec<NttPlan>> = OnceLock::new();

pub(crate) fn forward_negacyclic_ntt(
    coefficients: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    transform_negacyclic(coefficients, modulus, TransformDirection::Forward)
}

pub(crate) fn forward_negacyclic_ntt_in_place(
    coefficients: &mut [u64],
    modulus: u64,
) -> CanonicalResult<()> {
    transform_negacyclic_in_place(coefficients, modulus, TransformDirection::Forward)
}

pub(crate) fn inverse_negacyclic_ntt(values: &[u64], modulus: u64) -> CanonicalResult<Vec<u64>> {
    transform_negacyclic(values, modulus, TransformDirection::Inverse)
}

pub(crate) fn inverse_negacyclic_ntt_in_place(
    values: &mut [u64],
    modulus: u64,
) -> CanonicalResult<()> {
    transform_negacyclic_in_place(values, modulus, TransformDirection::Inverse)
}

// Negacyclic (X^N+1) transform reduced to a cyclic NTT: weight the input by
// powers of psi (the 2N-th root), run a cyclic NTT, then weight the output. The
// inverse undoes both. `root_exponent = POLYNOMIAL_DEGREE/len` rescales the
// stored full-degree root down to the requested transform length.
fn transform_negacyclic(
    values: &[u64],
    modulus: u64,
    direction: TransformDirection,
) -> CanonicalResult<Vec<u64>> {
    let mut transformed = values.to_vec();
    transform_negacyclic_in_place(&mut transformed, modulus, direction)?;

    Ok(transformed)
}

fn transform_negacyclic_in_place(
    values: &mut [u64],
    modulus: u64,
    direction: TransformDirection,
) -> CanonicalResult<()> {
    validate_transform_length(values.len())?;
    validate_residues(values, modulus)?;
    if values.len() == POLYNOMIAL_DEGREE {
        let plan = full_degree_ntt_plan(modulus)?;

        transform_with_plan_in_place(values, plan, direction);
        return Ok(());
    }

    let root_parameters = root_parameters_for_modulus(modulus).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "modulus is not part of the selected BGV-RNS parameters",
        )
    })?;
    let plan = build_ntt_plan(root_parameters, values.len())?;

    transform_with_plan_in_place(values, &plan, direction);

    Ok(())
}

fn transform_with_plan_in_place(values: &mut [u64], plan: &NttPlan, direction: TransformDirection) {
    match direction {
        TransformDirection::Forward => {
            multiply_by_cached_powers(values, &plan.forward_negacyclic_powers, plan.modulus);
            cyclic_ntt_with_twiddles(
                values,
                &plan.bit_reverse_swaps,
                &plan.forward_stage_twiddles,
                plan.modulus,
                None,
            );
        }
        TransformDirection::Inverse => {
            cyclic_ntt_with_twiddles(
                values,
                &plan.bit_reverse_swaps,
                &plan.inverse_stage_twiddles,
                plan.modulus,
                Some(plan.inverse_length),
            );
            multiply_by_cached_powers(values, &plan.inverse_negacyclic_powers, plan.modulus);
        }
    }
}

fn full_degree_ntt_plans() -> &'static [NttPlan] {
    FULL_DEGREE_NTT_PLANS
        .get_or_init(|| {
            ROOT_PARAMETERS
                .iter()
                .map(|parameters| {
                    build_ntt_plan(*parameters, POLYNOMIAL_DEGREE)
                        .expect("selected root parameters build a full-degree NTT plan")
                })
                .collect()
        })
        .as_slice()
}

fn full_degree_ntt_plan(modulus: u64) -> CanonicalResult<&'static NttPlan> {
    full_degree_ntt_plans()
        .iter()
        .find(|plan| plan.modulus == modulus)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "modulus is not part of the selected BGV-RNS parameters",
            )
        })
}

struct NttPlan {
    modulus: u64,
    forward_negacyclic_powers: Vec<u64>,
    inverse_negacyclic_powers: Vec<u64>,
    bit_reverse_swaps: Vec<(usize, usize)>,
    forward_stage_twiddles: Vec<Vec<u64>>,
    inverse_stage_twiddles: Vec<Vec<u64>>,
    inverse_length: u64,
}

fn build_ntt_plan(root_parameters: RootParameters, length: usize) -> CanonicalResult<NttPlan> {
    let root_exponent = (POLYNOMIAL_DEGREE / length) as u64;
    let modulus = root_parameters.modulus;
    let negacyclic_root = pow_mod(root_parameters.negacyclic_root, root_exponent, modulus)?;
    let inverse_negacyclic_root = pow_mod(
        root_parameters.inverse_negacyclic_root,
        root_exponent,
        modulus,
    )?;
    let cyclic_root = pow_mod(root_parameters.cyclic_root, root_exponent, modulus)?;
    let inverse_cyclic_root = pow_mod(root_parameters.inverse_cyclic_root, root_exponent, modulus)?;

    Ok(NttPlan {
        modulus,
        forward_negacyclic_powers: build_powers(negacyclic_root, length, modulus),
        inverse_negacyclic_powers: build_powers(inverse_negacyclic_root, length, modulus),
        bit_reverse_swaps: build_bit_reverse_swaps(length),
        forward_stage_twiddles: build_stage_twiddles(cyclic_root, length, modulus)?,
        inverse_stage_twiddles: build_stage_twiddles(inverse_cyclic_root, length, modulus)?,
        inverse_length: inverse_mod(length as u64, modulus)?,
    })
}

fn build_powers(root: u64, length: usize, modulus: u64) -> Vec<u64> {
    let mut powers = Vec::with_capacity(length);
    let mut power = 1_u64;
    for _ in 0..length {
        powers.push(power);
        power = mul_mod_fast(power, root, modulus);
    }

    powers
}

fn build_stage_twiddles(root: u64, length: usize, modulus: u64) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut stages = Vec::with_capacity(length.trailing_zeros() as usize);
    let mut butterfly_width = 2_usize;
    while butterfly_width <= length {
        let half_width = butterfly_width / 2;
        let step_root = pow_mod(root, (length / butterfly_width) as u64, modulus)?;
        let mut stage_twiddles = Vec::with_capacity(half_width);
        let mut twiddle = 1_u64;
        for _ in 0..half_width {
            stage_twiddles.push(twiddle);
            twiddle = mul_mod_fast(twiddle, step_root, modulus);
        }
        stages.push(stage_twiddles);
        butterfly_width *= 2;
    }

    Ok(stages)
}

// Decimation-in-time Cooley-Tukey NTT: bit-reversed input -> natural-order
// output, with cached per-stage twiddle factors.
fn cyclic_ntt_with_twiddles(
    values: &mut [u64],
    bit_reverse_swaps: &[(usize, usize)],
    stage_twiddles: &[Vec<u64>],
    modulus: u64,
    inverse_length: Option<u64>,
) {
    apply_bit_reverse_swaps(values, bit_reverse_swaps);
    let length = values.len();
    let mut butterfly_width = 2_usize;
    for twiddles in stage_twiddles {
        let half_width = butterfly_width / 2;
        debug_assert_eq!(twiddles.len(), half_width);
        let mut block_start = 0_usize;
        while block_start < length {
            for (offset, stage_twiddle) in twiddles.iter().enumerate().take(half_width) {
                let left_index = block_start + offset;
                let right_index = left_index + half_width;
                let right_value = mul_mod_fast(values[right_index], *stage_twiddle, modulus);
                let left_value = values[left_index];
                values[left_index] = add_mod_fast(left_value, right_value, modulus);
                values[right_index] = sub_mod_fast(left_value, right_value, modulus);
            }
            block_start += butterfly_width;
        }
        butterfly_width *= 2;
    }

    if let Some(inverse_length) = inverse_length {
        for value in values {
            *value = mul_mod_fast(*value, inverse_length, modulus);
        }
    }
}

fn multiply_by_cached_powers(values: &mut [u64], powers: &[u64], modulus: u64) {
    debug_assert_eq!(values.len(), powers.len());
    for (value, power) in values.iter_mut().zip(powers.iter()) {
        *value = mul_mod_fast(*value, *power, modulus);
    }
}

// Computes the bit-reversal permutation swaps once per transform length.
// `reversed_index` is advanced as a bit-reversed counter: the inner loop
// performs the carry of incrementing the most-significant bit downward, so each
// step yields the next reversed index.
fn build_bit_reverse_swaps(length: usize) -> Vec<(usize, usize)> {
    let mut swaps = Vec::with_capacity(length / 2);
    let mut reversed_index = 0_usize;
    for index in 1..length {
        let mut bit = length >> 1;
        while reversed_index & bit != 0 {
            reversed_index ^= bit;
            bit >>= 1;
        }
        reversed_index ^= bit;
        if index < reversed_index {
            swaps.push((index, reversed_index));
        }
    }

    swaps
}

fn apply_bit_reverse_swaps(values: &mut [u64], swaps: &[(usize, usize)]) {
    let length = values.len();
    for (left_index, right_index) in swaps {
        debug_assert!(*left_index < length);
        debug_assert!(*right_index < length);
        values.swap(*left_index, *right_index);
    }
}

fn validate_transform_length(length: usize) -> CanonicalResult<()> {
    if length == 0 || !length.is_power_of_two() || !POLYNOMIAL_DEGREE.is_multiple_of(length) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "NTT length must be a non-empty power of two dividing the selected polynomial degree",
        ));
    }

    Ok(())
}

fn validate_residues(values: &[u64], modulus: u64) -> CanonicalResult<()> {
    if values.iter().any(|value| *value >= modulus) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
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
            CanonicalErrorCode::InvalidProtocolObject,
            "convolution inputs must have the same length",
        ));
    }
    let left_transformed = forward_negacyclic_ntt(left, modulus)?;
    let right_transformed = forward_negacyclic_ntt(right, modulus)?;
    let mut product = Vec::with_capacity(left.len());
    for (left_value, right_value) in left_transformed.iter().zip(right_transformed.iter()) {
        product.push(mul_mod_fast(*left_value, *right_value, modulus));
    }

    inverse_negacyclic_ntt(&product, modulus)
}

#[cfg(test)]
mod tests {
    use super::{
        forward_negacyclic_ntt, forward_negacyclic_ntt_in_place, inverse_negacyclic_ntt,
        inverse_negacyclic_ntt_in_place, negacyclic_convolution_for_tests,
    };
    use crate::{
        bgv::{
            modular_arithmetic::sub_mod,
            parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
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
    fn ntt_round_trips_full_degree_vectors_for_every_selected_prime() {
        for modulus in selected_ntt_moduli() {
            let input = full_degree_fixture_vector(modulus);
            let transformed = forward_negacyclic_ntt(&input, modulus).expect("full NTT should run");
            assert_ne!(transformed, input);
            let recovered =
                inverse_negacyclic_ntt(&transformed, modulus).expect("full INTT should run");

            assert_eq!(recovered, input);
        }
    }

    #[test]
    fn in_place_ntt_matches_allocating_wrappers_for_every_selected_prime() {
        for modulus in selected_ntt_moduli() {
            let input = full_degree_fixture_vector(modulus);
            let expected_forward =
                forward_negacyclic_ntt(&input, modulus).expect("full NTT should run");
            let mut in_place = input.clone();
            forward_negacyclic_ntt_in_place(&mut in_place, modulus).expect("in-place NTT");
            assert_eq!(in_place, expected_forward);

            inverse_negacyclic_ntt_in_place(&mut in_place, modulus).expect("in-place INTT");
            assert_eq!(in_place, input);
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
        DATA_PRIMES.into_iter().chain(SPECIAL_PRIMES).collect()
    }

    fn full_degree_fixture_vector(modulus: u64) -> Vec<u64> {
        (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| {
                let coefficient = coefficient_index as u64;
                (coefficient * 131 + coefficient.rotate_left(7) + 17) % modulus
            })
            .collect()
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
