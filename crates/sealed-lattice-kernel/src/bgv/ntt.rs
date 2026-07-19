use crate::{
    bgv::{
        modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod_fast, pow_mod, sub_mod_fast},
        parameters::{
            NttTransformParameters, POLYNOMIAL_DEGREE, ROOT_PARAMETERS, RootParameters,
            root_parameters_for_modulus,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};
use std::sync::OnceLock;

static FULL_DEGREE_NTT_PLAN_CACHE: OnceLock<FullDegreeNttPlanCache> = OnceLock::new();
const MAXIMUM_NTT_STAGE_COUNT: usize = POLYNOMIAL_DEGREE.trailing_zeros() as usize;

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
            multiply_by_generated_powers(values, plan.forward_negacyclic_root, plan.modulus);
            cyclic_ntt_with_step_roots(
                values,
                &plan.forward_stage_step_roots[..plan.stage_count],
                plan.modulus,
                None,
            );
        }
        TransformDirection::Inverse => {
            cyclic_ntt_with_step_roots(
                values,
                &plan.inverse_stage_step_roots[..plan.stage_count],
                plan.modulus,
                Some(plan.inverse_length),
            );
            multiply_by_generated_powers(values, plan.inverse_negacyclic_root, plan.modulus);
        }
    }
}

struct FullDegreeNttPlanCache {
    plans: Vec<OnceLock<NttPlan>>,
    transform_length: usize,
}

impl FullDegreeNttPlanCache {
    fn new(transform_length: usize) -> Self {
        Self {
            plans: (0..ROOT_PARAMETERS.len())
                .map(|_| OnceLock::new())
                .collect(),
            transform_length,
        }
    }

    fn plan(&self, root_parameter_index: usize) -> &NttPlan {
        self.plans[root_parameter_index].get_or_init(|| {
            build_ntt_plan(ROOT_PARAMETERS[root_parameter_index], self.transform_length)
                .expect("selected root parameters build an NTT plan for the cached length")
        })
    }

    #[cfg(test)]
    fn initialized_plan_count(&self) -> usize {
        self.plans
            .iter()
            .filter(|plan| plan.get().is_some())
            .count()
    }
}

fn full_degree_ntt_plan(modulus: u64) -> CanonicalResult<&'static NttPlan> {
    let root_parameter_index = ROOT_PARAMETERS
        .iter()
        .position(|parameters| parameters.modulus == modulus)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "modulus is not part of the selected BGV-RNS parameters",
            )
        })?;
    let cache =
        FULL_DEGREE_NTT_PLAN_CACHE.get_or_init(|| FullDegreeNttPlanCache::new(POLYNOMIAL_DEGREE));
    Ok(cache.plan(root_parameter_index))
}

struct NttPlan {
    modulus: u64,
    forward_negacyclic_root: u64,
    inverse_negacyclic_root: u64,
    forward_stage_step_roots: [u64; MAXIMUM_NTT_STAGE_COUNT],
    inverse_stage_step_roots: [u64; MAXIMUM_NTT_STAGE_COUNT],
    stage_count: usize,
    inverse_length: u64,
}

fn build_ntt_plan(root_parameters: RootParameters, length: usize) -> CanonicalResult<NttPlan> {
    build_ntt_plan_for_transform(
        NttTransformParameters {
            transform_degree: POLYNOMIAL_DEGREE,
            roots: root_parameters,
        },
        length,
    )
}

fn build_ntt_plan_for_transform(
    parameters: NttTransformParameters,
    length: usize,
) -> CanonicalResult<NttPlan> {
    validate_transform_length_for_degree(length, parameters.transform_degree)?;
    let root_parameters = parameters.roots;
    let root_exponent = (parameters.transform_degree / length) as u64;
    let modulus = root_parameters.modulus;
    let negacyclic_root = pow_mod(root_parameters.negacyclic_root, root_exponent, modulus)?;
    let inverse_negacyclic_root = pow_mod(
        root_parameters.inverse_negacyclic_root,
        root_exponent,
        modulus,
    )?;
    let cyclic_root = pow_mod(root_parameters.cyclic_root, root_exponent, modulus)?;
    let inverse_cyclic_root = pow_mod(root_parameters.inverse_cyclic_root, root_exponent, modulus)?;
    let stage_count = length.trailing_zeros() as usize;

    Ok(NttPlan {
        modulus,
        forward_negacyclic_root: negacyclic_root,
        inverse_negacyclic_root,
        forward_stage_step_roots: build_stage_step_roots(cyclic_root, length, modulus)?,
        inverse_stage_step_roots: build_stage_step_roots(inverse_cyclic_root, length, modulus)?,
        stage_count,
        inverse_length: inverse_mod(length as u64, modulus)?,
    })
}

fn build_stage_step_roots(
    root: u64,
    length: usize,
    modulus: u64,
) -> CanonicalResult<[u64; MAXIMUM_NTT_STAGE_COUNT]> {
    let mut stage_step_roots = [0_u64; MAXIMUM_NTT_STAGE_COUNT];
    let mut butterfly_width = 2_usize;
    let mut stage_index = 0_usize;
    while butterfly_width <= length {
        stage_step_roots[stage_index] = pow_mod(root, (length / butterfly_width) as u64, modulus)?;
        stage_index += 1;
        butterfly_width *= 2;
    }

    Ok(stage_step_roots)
}

// Decimation-in-time Cooley-Tukey NTT: bit-reversed input -> natural-order
// output. One transform-local twiddle frontier retains at most half a
// polynomial, while the persistent per-modulus plan keeps only one step root
// per stage instead of four full polynomial-sized tables.
fn cyclic_ntt_with_step_roots(
    values: &mut [u64],
    stage_step_roots: &[u64],
    modulus: u64,
    inverse_length: Option<u64>,
) {
    apply_bit_reverse_permutation(values);
    let length = values.len();
    let mut stage_twiddles = Vec::with_capacity(length / 2);
    let mut butterfly_width = 2_usize;
    for step_root in stage_step_roots {
        let half_width = butterfly_width / 2;
        stage_twiddles.clear();
        let mut twiddle = 1_u64;
        for _ in 0..half_width {
            stage_twiddles.push(twiddle);
            twiddle = mul_mod_fast(twiddle, *step_root, modulus);
        }
        let mut block_start = 0_usize;
        while block_start < length {
            for (offset, stage_twiddle) in stage_twiddles.iter().enumerate() {
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

fn multiply_by_generated_powers(values: &mut [u64], root: u64, modulus: u64) {
    let mut power = 1_u64;
    for value in values {
        *value = mul_mod_fast(*value, power, modulus);
        power = mul_mod_fast(power, root, modulus);
    }
}

// `reversed_index` advances as a bit-reversed counter. Computing the
// permutation directly removes the process-lifetime swap table without
// changing the exact swap order.
fn apply_bit_reverse_permutation(values: &mut [u64]) {
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
    validate_transform_length_for_degree(length, POLYNOMIAL_DEGREE)
}

fn validate_transform_length_for_degree(
    length: usize,
    maximum_transform_degree: usize,
) -> CanonicalResult<()> {
    if maximum_transform_degree == 0
        || !maximum_transform_degree.is_power_of_two()
        || !POLYNOMIAL_DEGREE.is_multiple_of(maximum_transform_degree)
        || length == 0
        || !length.is_power_of_two()
        || !maximum_transform_degree.is_multiple_of(length)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "NTT length must be a non-empty power of two dividing its operative transform degree",
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
        FullDegreeNttPlanCache, forward_negacyclic_ntt, forward_negacyclic_ntt_in_place,
        inverse_negacyclic_ntt, inverse_negacyclic_ntt_in_place, negacyclic_convolution_for_tests,
    };
    use crate::{
        bgv::{
            modular_arithmetic::sub_mod,
            parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, ROOT_PARAMETERS, SPECIAL_PRIMES},
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

    #[test]
    fn full_degree_cache_builds_only_requested_compact_modulus_plans() {
        let cache = FullDegreeNttPlanCache::new(8);
        assert_eq!(cache.initialized_plan_count(), 0);

        let first_plan = cache.plan(0);
        assert_eq!(first_plan.modulus, ROOT_PARAMETERS[0].modulus);
        assert_eq!(cache.initialized_plan_count(), 1);
        assert!(std::ptr::eq(first_plan, cache.plan(0)));
        assert_eq!(cache.initialized_plan_count(), 1);
        assert_eq!(first_plan.stage_count, 3);
        assert!(
            first_plan.forward_stage_step_roots[..first_plan.stage_count]
                .iter()
                .all(|root| *root != 0)
        );
        assert!(
            first_plan.forward_stage_step_roots[first_plan.stage_count..]
                .iter()
                .all(|root| *root == 0)
        );

        let last_parameter_index = ROOT_PARAMETERS.len() - 1;
        let last_plan = cache.plan(last_parameter_index);
        assert_eq!(
            last_plan.modulus,
            ROOT_PARAMETERS[last_parameter_index].modulus,
        );
        assert_eq!(cache.initialized_plan_count(), 2);
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
