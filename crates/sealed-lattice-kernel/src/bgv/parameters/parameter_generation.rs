use core::fmt;
use std::sync::OnceLock;

use super::root_parameters::MULTIPLICATIVE_GROUP_PRIME_FACTORS;
use super::{
    DATA_PRIMES, LOGICAL_SLOT_GENERATOR, NttTransformParameters, PLAINTEXT_EXTENSION_DEGREE,
    PLAINTEXT_EXTENSION_LANE_COUNT, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, ROOT_PARAMETERS,
    RootParameters, SPECIAL_PRIMES,
};

const DATA_PRIME_COUNT: usize = DATA_PRIMES.len();
const SPECIAL_PRIME_COUNT: usize = SPECIAL_PRIMES.len();
const TWICE_POLYNOMIAL_DEGREE: u64 = 2 * POLYNOMIAL_DEGREE as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParameterGenerationError {
    #[cfg(test)]
    PrimitiveGeneratorNotFound,
    InvalidCertificate,
}

impl fmt::Display for ParameterGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            #[cfg(test)]
            Self::PrimitiveGeneratorNotFound => {
                "a full-order multiplicative generator was not found"
            }
            Self::InvalidCertificate => "generated root parameters failed verification",
        })
    }
}

impl std::error::Error for ParameterGenerationError {}

/// Deterministically regenerates the complete supported data basis and the
/// root certificate consumed by every NTT implementation.
#[cfg(test)]
pub(crate) fn regenerate_supported_data_root_parameters()
-> Result<[RootParameters; DATA_PRIME_COUNT], ParameterGenerationError> {
    DATA_PRIMES
        .into_iter()
        .map(|modulus| derive_root_parameters(modulus, verify_data_root_parameters))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| ParameterGenerationError::InvalidCertificate)
}

/// Deterministically regenerates the complete special basis used by hybrid
/// key switching.
#[cfg(test)]
pub(crate) fn regenerate_supported_special_root_parameters()
-> Result<[RootParameters; SPECIAL_PRIME_COUNT], ParameterGenerationError> {
    SPECIAL_PRIMES
        .into_iter()
        .map(|modulus| derive_root_parameters(modulus, verify_ntt_root_parameters))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| ParameterGenerationError::InvalidCertificate)
}

pub(crate) fn verify_ntt_root_parameters(parameters: RootParameters) -> bool {
    let Some(parameter_index) = ROOT_PARAMETERS
        .iter()
        .position(|supported| supported.modulus == parameters.modulus)
    else {
        return false;
    };
    verify_ntt_transform_parameters_with_factors(
        NttTransformParameters {
            transform_degree: POLYNOMIAL_DEGREE,
            roots: parameters,
        },
        MULTIPLICATIVE_GROUP_PRIME_FACTORS[parameter_index],
    )
}

fn verify_ntt_transform_parameters_with_factors(
    parameters: NttTransformParameters,
    multiplicative_group_prime_factors: &[u64],
) -> bool {
    let roots = parameters.roots;
    let Some(twice_transform_degree) = parameters.transform_degree.checked_mul(2) else {
        return false;
    };
    let Ok(twice_transform_degree) = u64::try_from(twice_transform_degree) else {
        return false;
    };
    if parameters.transform_degree == 0
        || !parameters.transform_degree.is_power_of_two()
        || !POLYNOMIAL_DEGREE.is_multiple_of(parameters.transform_degree)
        || !is_prime(roots.modulus)
        || roots.modulus % twice_transform_degree != 1
        || roots.primitive_generator <= 1
        || roots.primitive_generator >= roots.modulus
        || [
            roots.negacyclic_root,
            roots.cyclic_root,
            roots.inverse_negacyclic_root,
            roots.inverse_cyclic_root,
            roots.inverse_polynomial_degree,
        ]
        .into_iter()
        .any(|component| component == 0 || component >= roots.modulus)
    {
        return false;
    }

    let multiplicative_group_order = roots.modulus - 1;
    if !verify_complete_prime_factor_certificate(
        multiplicative_group_order,
        multiplicative_group_prime_factors,
    ) || modular_power(
        roots.primitive_generator,
        multiplicative_group_order,
        roots.modulus,
    ) != 1
        || multiplicative_group_prime_factors
            .iter()
            .copied()
            .any(|prime_factor| {
                modular_power(
                    roots.primitive_generator,
                    multiplicative_group_order / prime_factor,
                    roots.modulus,
                ) == 1
            })
    {
        return false;
    }

    modular_power(
        roots.negacyclic_root,
        parameters.transform_degree as u64,
        roots.modulus,
    ) == roots.modulus - 1
        && modular_power(roots.negacyclic_root, twice_transform_degree, roots.modulus) == 1
        && roots.cyclic_root
            == multiply_modular(roots.negacyclic_root, roots.negacyclic_root, roots.modulus)
        && modular_power(
            roots.cyclic_root,
            parameters.transform_degree as u64,
            roots.modulus,
        ) == 1
        && modular_power(
            roots.cyclic_root,
            (parameters.transform_degree / 2) as u64,
            roots.modulus,
        ) != 1
        && multiply_modular(
            roots.negacyclic_root,
            roots.inverse_negacyclic_root,
            roots.modulus,
        ) == 1
        && multiply_modular(roots.cyclic_root, roots.inverse_cyclic_root, roots.modulus) == 1
        && multiply_modular(
            parameters.transform_degree as u64,
            roots.inverse_polynomial_degree,
            roots.modulus,
        ) == 1
}

fn verify_complete_prime_factor_certificate(
    multiplicative_group_order: u64,
    prime_factors: &[u64],
) -> bool {
    if prime_factors.is_empty() || prime_factors.windows(2).any(|pair| pair[0] >= pair[1]) {
        return false;
    }

    let mut remaining_group_order = multiplicative_group_order;
    for prime_factor in prime_factors {
        if !is_prime(*prime_factor) || !remaining_group_order.is_multiple_of(*prime_factor) {
            return false;
        }
        while remaining_group_order.is_multiple_of(*prime_factor) {
            remaining_group_order /= *prime_factor;
        }
    }
    remaining_group_order == 1
}

pub(crate) fn verify_data_root_parameters(parameters: RootParameters) -> bool {
    parameters.modulus % PLAINTEXT_MODULUS == 1 && verify_ntt_root_parameters(parameters)
}

/// Reproduces every algebraic prerequisite that is consumed by the fixed
/// browser runtime. This checks the stored certificates rather than trusting
/// a successful NTT round trip.
pub(crate) fn validate_supported_algebraic_parameters() -> Result<(), ParameterGenerationError> {
    static VALIDATION: OnceLock<Result<(), ParameterGenerationError>> = OnceLock::new();
    *VALIDATION.get_or_init(validate_supported_algebraic_parameters_uncached)
}

fn validate_supported_algebraic_parameters_uncached() -> Result<(), ParameterGenerationError> {
    if !verify_plaintext_extension_lane_layout() {
        return Err(ParameterGenerationError::InvalidCertificate);
    }

    for (expected_modulus, parameters) in DATA_PRIMES
        .iter()
        .copied()
        .zip(ROOT_PARAMETERS[..DATA_PRIME_COUNT].iter().copied())
    {
        if parameters.modulus != expected_modulus || !verify_data_root_parameters(parameters) {
            return Err(ParameterGenerationError::InvalidCertificate);
        }
    }

    for (expected_modulus, parameters) in SPECIAL_PRIMES.iter().copied().zip(
        ROOT_PARAMETERS[DATA_PRIME_COUNT..DATA_PRIME_COUNT + SPECIAL_PRIME_COUNT]
            .iter()
            .copied(),
    ) {
        if parameters.modulus != expected_modulus || !verify_ntt_root_parameters(parameters) {
            return Err(ParameterGenerationError::InvalidCertificate);
        }
    }

    let mut ordered_moduli = Vec::with_capacity(DATA_PRIME_COUNT + SPECIAL_PRIME_COUNT + 1);
    ordered_moduli.push(PLAINTEXT_MODULUS);
    ordered_moduli.extend(DATA_PRIMES);
    ordered_moduli.extend(SPECIAL_PRIMES);
    ordered_moduli.sort_unstable();
    if ordered_moduli.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ParameterGenerationError::InvalidCertificate);
    }

    Ok(())
}

fn verify_plaintext_extension_lane_layout() -> bool {
    let Some((extension_order, lane_count)) =
        plaintext_extension_lane_dimensions(PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
    else {
        return false;
    };
    if extension_order != PLAINTEXT_EXTENSION_DEGREE
        || lane_count != PLAINTEXT_EXTENSION_LANE_COUNT
    {
        return false;
    }
    let positive_lane_count = lane_count / 2;
    if LOGICAL_SLOT_GENERATOR <= 1
        || LOGICAL_SLOT_GENERATOR >= extension_order
        || LOGICAL_SLOT_GENERATOR.is_multiple_of(2)
        || modular_power(
            LOGICAL_SLOT_GENERATOR as u64,
            positive_lane_count as u64,
            extension_order as u64,
        ) != 1
        || modular_power(
            LOGICAL_SLOT_GENERATOR as u64,
            (positive_lane_count / 2) as u64,
            extension_order as u64,
        ) == 1
    {
        return false;
    }

    let mut seen_odd_exponents = vec![false; PLAINTEXT_EXTENSION_LANE_COUNT];
    let mut exponent = 1_usize;
    for _ in 0..positive_lane_count {
        if exponent.is_multiple_of(2) || exponent == extension_order - 1 {
            return false;
        }
        for represented_exponent in [exponent, extension_order - exponent] {
            let natural_transform_index = (represented_exponent - 1) / 2;
            let Some(was_seen) = seen_odd_exponents.get_mut(natural_transform_index) else {
                return false;
            };
            if *was_seen {
                return false;
            }
            *was_seen = true;
        }
        exponent = exponent * LOGICAL_SLOT_GENERATOR % extension_order;
    }

    exponent == 1 && seen_odd_exponents.into_iter().all(|was_seen| was_seen)
}

fn plaintext_extension_lane_dimensions(
    plaintext_modulus: u64,
    polynomial_degree: usize,
) -> Option<(usize, usize)> {
    if polynomial_degree == 0
        || !polynomial_degree.is_power_of_two()
        || !is_prime(plaintext_modulus)
    {
        return None;
    }
    let twice_polynomial_degree = u64::try_from(polynomial_degree).ok()?.checked_mul(2)?;
    let extension_degree = usize::try_from(multiplicative_order_modulo_power_of_two(
        plaintext_modulus,
        twice_polynomial_degree,
    )?)
    .ok()?;
    if extension_degree == 0 || !polynomial_degree.is_multiple_of(extension_degree) {
        return None;
    }
    Some((extension_degree, polynomial_degree / extension_degree))
}

fn multiplicative_order_modulo_power_of_two(value: u64, modulus: u64) -> Option<u64> {
    if modulus < 4 || !modulus.is_power_of_two() || value.is_multiple_of(2) {
        return None;
    }

    // The unit group modulo 2^k has order 2^(k - 1). Every element order
    // therefore divides this power of two, so repeated halving finds the exact
    // order without trusting a stored factorization result.
    let mut order = modulus / 2;
    if modular_power(value, order, modulus) != 1 {
        return None;
    }
    while order > 1 && modular_power(value, order / 2, modulus) == 1 {
        order /= 2;
    }
    Some(order)
}

#[cfg(test)]
fn derive_root_parameters(
    modulus: u64,
    verifier: fn(RootParameters) -> bool,
) -> Result<RootParameters, ParameterGenerationError> {
    let multiplicative_group_order = modulus - 1;
    let prime_factors = distinct_prime_factors(multiplicative_group_order);
    let primitive_generator = (2..modulus)
        .find(|candidate| {
            prime_factors.iter().all(|prime_factor| {
                modular_power(
                    *candidate,
                    multiplicative_group_order / *prime_factor,
                    modulus,
                ) != 1
            })
        })
        .ok_or(ParameterGenerationError::PrimitiveGeneratorNotFound)?;
    let negacyclic_root = modular_power(
        primitive_generator,
        multiplicative_group_order / TWICE_POLYNOMIAL_DEGREE,
        modulus,
    );
    let cyclic_root = multiply_modular(negacyclic_root, negacyclic_root, modulus);
    let parameters = RootParameters {
        modulus,
        primitive_generator,
        negacyclic_root,
        cyclic_root,
        inverse_negacyclic_root: modular_power(negacyclic_root, modulus - 2, modulus),
        inverse_cyclic_root: modular_power(cyclic_root, modulus - 2, modulus),
        inverse_polynomial_degree: modular_power(POLYNOMIAL_DEGREE as u64, modulus - 2, modulus),
    };
    if !verifier(parameters) {
        return Err(ParameterGenerationError::InvalidCertificate);
    }
    Ok(parameters)
}

fn is_prime(candidate: u64) -> bool {
    if candidate < 2 {
        return false;
    }
    for small_prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if candidate == small_prime {
            return true;
        }
        if candidate.is_multiple_of(small_prime) {
            return false;
        }
    }

    let trailing_zero_count = (candidate - 1).trailing_zeros();
    let odd_component = (candidate - 1) >> trailing_zero_count;
    for witness in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let reduced_witness = witness % candidate;
        if reduced_witness == 0 {
            continue;
        }
        let mut witness_power = modular_power(reduced_witness, odd_component, candidate);
        if witness_power == 1 || witness_power == candidate - 1 {
            continue;
        }
        let mut reached_minus_one = false;
        for _ in 1..trailing_zero_count {
            witness_power = multiply_modular(witness_power, witness_power, candidate);
            if witness_power == candidate - 1 {
                reached_minus_one = true;
                break;
            }
        }
        if !reached_minus_one {
            return false;
        }
    }
    true
}

#[cfg(test)]
fn distinct_prime_factors(mut value: u64) -> Vec<u64> {
    let mut prime_factors = Vec::new();
    for small_prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if value.is_multiple_of(small_prime) {
            prime_factors.push(small_prime);
            while value.is_multiple_of(small_prime) {
                value /= small_prime;
            }
        }
    }

    collect_prime_factors(value, &mut prime_factors);
    prime_factors.sort_unstable();
    prime_factors.dedup();
    prime_factors
}

#[cfg(test)]
fn collect_prime_factors(value: u64, prime_factors: &mut Vec<u64>) {
    if value == 1 {
        return;
    }
    if is_prime(value) {
        prime_factors.push(value);
        return;
    }

    let factor = deterministic_nontrivial_factor(value);
    collect_prime_factors(factor, prime_factors);
    collect_prime_factors(value / factor, prime_factors);
}

#[cfg(test)]
fn deterministic_nontrivial_factor(composite: u64) -> u64 {
    debug_assert!(composite > 1 && !is_prime(composite));
    for small_prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if composite.is_multiple_of(small_prime) {
            return small_prime;
        }
    }

    let mut polynomial_constant = 1_u64;
    loop {
        let mut slow_sequence_value = 2_u64;
        let mut fast_sequence_value = 2_u64;
        for _ in 0..1_000_000 {
            slow_sequence_value =
                pollard_rho_step(slow_sequence_value, polynomial_constant, composite);
            fast_sequence_value = pollard_rho_step(
                pollard_rho_step(fast_sequence_value, polynomial_constant, composite),
                polynomial_constant,
                composite,
            );
            let sequence_difference = slow_sequence_value.abs_diff(fast_sequence_value);
            let divisor = greatest_common_divisor(sequence_difference, composite);
            if divisor > 1 && divisor < composite {
                return divisor;
            }
            if divisor == composite {
                break;
            }
        }
        polynomial_constant = polynomial_constant
            .checked_add(1)
            .expect("a u64 composite must yield a nontrivial factor");
    }
}

#[cfg(test)]
fn pollard_rho_step(value: u64, polynomial_constant: u64, modulus: u64) -> u64 {
    ((u128::from(multiply_modular(value, value, modulus)) + u128::from(polynomial_constant))
        % u128::from(modulus)) as u64
}

#[cfg(test)]
fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn modular_power(base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    let mut current_power = base % modulus;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = multiply_modular(result, current_power, modulus);
        }
        current_power = multiply_modular(current_power, current_power, modulus);
        exponent >>= 1;
    }
    result
}

fn multiply_modular(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::parameters::{
        DATA_PRIMES, ROOT_PARAMETERS, SPECIAL_PRIMES, root_parameters_for_modulus,
    };

    #[test]
    fn deterministic_generation_reproduces_the_complete_data_basis() {
        let generated = regenerate_supported_data_root_parameters()
            .expect("the supported data basis regenerates");
        assert_eq!(generated.map(|parameters| parameters.modulus), DATA_PRIMES);
        assert_eq!(generated.as_slice(), &ROOT_PARAMETERS[..DATA_PRIME_COUNT]);
        assert!(
            generated
                .iter()
                .all(|parameters| verify_data_root_parameters(*parameters))
        );
    }

    #[test]
    fn deterministic_generation_reproduces_the_complete_special_basis() {
        let generated = regenerate_supported_special_root_parameters()
            .expect("the supported special basis regenerates");
        assert_eq!(
            generated.map(|parameters| parameters.modulus),
            SPECIAL_PRIMES
        );
        assert_eq!(
            generated.as_slice(),
            &ROOT_PARAMETERS[DATA_PRIME_COUNT..DATA_PRIME_COUNT + SPECIAL_PRIME_COUNT]
        );
        assert!(
            generated
                .iter()
                .all(|parameters| verify_ntt_root_parameters(*parameters))
        );
    }

    #[test]
    fn every_selected_data_basis_prefix_has_unit_plaintext_conversion_multiplier() {
        let mut prefix_product_modulo_plaintext = 1_u64;
        for modulus in DATA_PRIMES {
            prefix_product_modulo_plaintext = multiply_modular(
                prefix_product_modulo_plaintext,
                modulus % PLAINTEXT_MODULUS,
                PLAINTEXT_MODULUS,
            );
            assert_eq!(prefix_product_modulo_plaintext, 1);
        }
    }

    #[test]
    fn certificate_verification_rejects_each_mutated_root_component() {
        let valid = ROOT_PARAMETERS[0];
        for mutated in [
            RootParameters {
                primitive_generator: valid.primitive_generator + 1,
                ..valid
            },
            RootParameters {
                negacyclic_root: valid.negacyclic_root + 1,
                ..valid
            },
            RootParameters {
                cyclic_root: valid.cyclic_root + 1,
                ..valid
            },
            RootParameters {
                inverse_negacyclic_root: valid.inverse_negacyclic_root + 1,
                ..valid
            },
            RootParameters {
                inverse_cyclic_root: valid.inverse_cyclic_root + 1,
                ..valid
            },
            RootParameters {
                inverse_polynomial_degree: valid.inverse_polynomial_degree + 1,
                ..valid
            },
        ] {
            assert!(!verify_data_root_parameters(mutated));
        }
    }

    #[test]
    fn every_ciphertext_modulus_requires_its_authenticated_root_certificate() {
        const DATA_MODULUS_MUTATION_INCREMENT: u64 = 65_536 * 257;
        const SPECIAL_MODULUS_MUTATION_INCREMENT: u64 = 65_536;

        for valid in ROOT_PARAMETERS[..DATA_PRIME_COUNT].iter().copied() {
            let mutated = RootParameters {
                modulus: valid
                    .modulus
                    .checked_add(DATA_MODULUS_MUTATION_INCREMENT)
                    .expect("the data-modulus mutation fits u64"),
                ..valid
            };
            assert_eq!(mutated.modulus % TWICE_POLYNOMIAL_DEGREE, 1);
            assert_eq!(mutated.modulus % PLAINTEXT_MODULUS, 1);
            assert!(!verify_data_root_parameters(mutated));
        }

        for valid in ROOT_PARAMETERS
            [DATA_PRIME_COUNT..DATA_PRIME_COUNT + SPECIAL_PRIME_COUNT]
            .iter()
            .copied()
        {
            let mutated = RootParameters {
                modulus: valid
                    .modulus
                    .checked_add(SPECIAL_MODULUS_MUTATION_INCREMENT)
                    .expect("the special-modulus mutation fits u64"),
                ..valid
            };
            assert_eq!(mutated.modulus % TWICE_POLYNOMIAL_DEGREE, 1);
            assert!(!verify_ntt_root_parameters(mutated));
        }
    }

    #[test]
    fn complete_algebraic_certificate_reproduces() {
        validate_supported_algebraic_parameters()
            .expect("the fixed algebraic parameter certificate must reproduce");
    }

    #[test]
    fn plaintext_extension_lane_certificate_reproduces_exactly() {
        assert_eq!(PLAINTEXT_MODULUS, 257);
        assert_eq!(PLAINTEXT_EXTENSION_DEGREE, 256);
        assert_eq!(PLAINTEXT_EXTENSION_LANE_COUNT, 128);
        assert_eq!(
            plaintext_extension_lane_dimensions(PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE),
            Some((PLAINTEXT_EXTENSION_DEGREE, PLAINTEXT_EXTENSION_LANE_COUNT))
        );
        assert!(verify_plaintext_extension_lane_layout());
        assert!(root_parameters_for_modulus(PLAINTEXT_MODULUS).is_none());
    }

    #[test]
    fn plaintext_extension_lane_certificate_rejects_a_prime_with_the_wrong_order() {
        const WRONG_ORDER_PLAINTEXT_MODULUS: u64 = 251;

        assert!(is_prime(WRONG_ORDER_PLAINTEXT_MODULUS));
        assert_eq!(
            plaintext_extension_lane_dimensions(
                WRONG_ORDER_PLAINTEXT_MODULUS,
                POLYNOMIAL_DEGREE
            ),
            Some((16_384, 2))
        );
        assert_ne!(
            plaintext_extension_lane_dimensions(
                WRONG_ORDER_PLAINTEXT_MODULUS,
                POLYNOMIAL_DEGREE
            ),
            Some((PLAINTEXT_EXTENSION_DEGREE, PLAINTEXT_EXTENSION_LANE_COUNT))
        );
    }

    #[test]
    fn every_multiplicative_group_factor_certificate_is_prime_and_complete() {
        for (parameters, prime_factors) in ROOT_PARAMETERS
            .iter()
            .zip(MULTIPLICATIVE_GROUP_PRIME_FACTORS)
        {
            assert!(verify_complete_prime_factor_certificate(
                parameters.modulus - 1,
                prime_factors,
            ));
        }

        let group_order = ROOT_PARAMETERS[0].modulus - 1;
        let complete_factors = MULTIPLICATIVE_GROUP_PRIME_FACTORS[0];
        assert!(!verify_complete_prime_factor_certificate(
            group_order,
            &complete_factors[..complete_factors.len() - 1],
        ));
        assert!(!verify_complete_prime_factor_certificate(
            group_order,
            &[2, 2, 29, 257],
        ));
        assert!(!verify_complete_prime_factor_certificate(
            group_order,
            &[2, 29, 257, 514],
        ));
    }

    #[test]
    fn deterministic_primality_test_rejects_strong_pseudoprimes() {
        for composite in [341_u64, 3_215_031_751, 382_512_305_654_641_305, u64::MAX] {
            assert!(!is_prime(composite), "{composite} must be composite");
        }
    }
}
