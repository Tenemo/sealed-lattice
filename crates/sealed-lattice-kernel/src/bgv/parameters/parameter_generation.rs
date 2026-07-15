use core::fmt;
use std::sync::OnceLock;

use super::{
    DATA_PRIMES, LOGICAL_SLOT_GENERATOR, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE,
    ROOT_PARAMETERS, RootParameters, SPECIAL_PRIME,
};

const DATA_PRIME_BIT_LENGTH: u32 = 47;
const DATA_PRIME_COUNT: usize = 17;
const TWICE_POLYNOMIAL_DEGREE: u64 = 2 * POLYNOMIAL_DEGREE as u64;
const COMPATIBILITY_CONGRUENCE_MODULUS: u64 = PLAINTEXT_MODULUS * TWICE_POLYNOMIAL_DEGREE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParameterGenerationError {
    ArithmeticOverflow,
    CandidateSearchExhausted,
    PrimitiveGeneratorNotFound,
    InvalidCertificate,
}

impl fmt::Display for ParameterGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArithmeticOverflow => "parameter generation arithmetic overflowed",
            Self::CandidateSearchExhausted => "compatible data-prime search was exhausted",
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
pub(crate) fn regenerate_supported_data_root_parameters(
) -> Result<[RootParameters; DATA_PRIME_COUNT], ParameterGenerationError> {
    let maximum_candidate = (1_u64 << DATA_PRIME_BIT_LENGTH) - 1;
    let mut multiplier = maximum_candidate
        .checked_sub(1)
        .ok_or(ParameterGenerationError::ArithmeticOverflow)?
        / COMPATIBILITY_CONGRUENCE_MODULUS;
    let mut generated = Vec::with_capacity(DATA_PRIME_COUNT);

    while generated.len() < DATA_PRIME_COUNT {
        let candidate_modulus = multiplier
            .checked_mul(COMPATIBILITY_CONGRUENCE_MODULUS)
            .and_then(|value| value.checked_add(1))
            .ok_or(ParameterGenerationError::ArithmeticOverflow)?;
        if is_prime(candidate_modulus) {
            generated.push(derive_root_parameters(candidate_modulus)?);
        }
        multiplier = multiplier
            .checked_sub(1)
            .ok_or(ParameterGenerationError::CandidateSearchExhausted)?;
    }

    generated
        .try_into()
        .map_err(|_| ParameterGenerationError::CandidateSearchExhausted)
}

pub(crate) fn verify_ntt_root_parameters(parameters: RootParameters) -> bool {
    if !is_prime(parameters.modulus)
        || parameters.modulus % TWICE_POLYNOMIAL_DEGREE != 1
        || parameters.primitive_generator <= 1
        || parameters.primitive_generator >= parameters.modulus
    {
        return false;
    }

    let multiplicative_group_order = parameters.modulus - 1;
    if modular_power(
        parameters.primitive_generator,
        multiplicative_group_order,
        parameters.modulus,
    ) != 1
        || distinct_prime_factors(multiplicative_group_order)
            .into_iter()
            .any(|prime_factor| {
                modular_power(
                    parameters.primitive_generator,
                    multiplicative_group_order / prime_factor,
                    parameters.modulus,
                ) == 1
            })
    {
        return false;
    }

    modular_power(
        parameters.negacyclic_root,
        POLYNOMIAL_DEGREE as u64,
        parameters.modulus,
    ) == parameters.modulus - 1
        && modular_power(
            parameters.negacyclic_root,
            TWICE_POLYNOMIAL_DEGREE,
            parameters.modulus,
        ) == 1
        && parameters.cyclic_root
            == multiply_modular(
                parameters.negacyclic_root,
                parameters.negacyclic_root,
                parameters.modulus,
            )
        && modular_power(
            parameters.cyclic_root,
            POLYNOMIAL_DEGREE as u64,
            parameters.modulus,
        ) == 1
        && modular_power(
            parameters.cyclic_root,
            (POLYNOMIAL_DEGREE / 2) as u64,
            parameters.modulus,
        ) != 1
        && multiply_modular(
            parameters.negacyclic_root,
            parameters.inverse_negacyclic_root,
            parameters.modulus,
        ) == 1
        && multiply_modular(
            parameters.cyclic_root,
            parameters.inverse_cyclic_root,
            parameters.modulus,
        ) == 1
        && multiply_modular(
            POLYNOMIAL_DEGREE as u64,
            parameters.inverse_polynomial_degree,
            parameters.modulus,
        ) == 1
}

pub(crate) fn verify_data_root_parameters(parameters: RootParameters) -> bool {
    parameters.modulus % PLAINTEXT_MODULUS == 1 && verify_ntt_root_parameters(parameters)
}

/// Reproduces every algebraic prerequisite that is consumed by the fixed
/// browser runtime. This checks the stored certificates rather than trusting
/// a successful NTT round trip.
pub(crate) fn validate_supported_algebraic_parameters(
) -> Result<(), ParameterGenerationError> {
    static VALIDATION: OnceLock<Result<(), ParameterGenerationError>> = OnceLock::new();
    *VALIDATION.get_or_init(validate_supported_algebraic_parameters_uncached)
}

fn validate_supported_algebraic_parameters_uncached(
) -> Result<(), ParameterGenerationError> {
    let plaintext_parameters = ROOT_PARAMETERS[0];
    if plaintext_parameters.modulus != PLAINTEXT_MODULUS
        || !verify_ntt_root_parameters(plaintext_parameters)
        || !verify_logical_slot_layout()
    {
        return Err(ParameterGenerationError::InvalidCertificate);
    }

    for (expected_modulus, parameters) in DATA_PRIMES
        .iter()
        .copied()
        .zip(ROOT_PARAMETERS[1..=DATA_PRIME_COUNT].iter().copied())
    {
        if parameters.modulus != expected_modulus || !verify_data_root_parameters(parameters) {
            return Err(ParameterGenerationError::InvalidCertificate);
        }
    }

    let special_parameters = ROOT_PARAMETERS[DATA_PRIME_COUNT + 1];
    if special_parameters.modulus != SPECIAL_PRIME
        || !verify_ntt_root_parameters(special_parameters)
    {
        return Err(ParameterGenerationError::InvalidCertificate);
    }

    let mut ordered_moduli = Vec::with_capacity(DATA_PRIME_COUNT + 2);
    ordered_moduli.push(PLAINTEXT_MODULUS);
    ordered_moduli.extend(DATA_PRIMES);
    ordered_moduli.push(SPECIAL_PRIME);
    ordered_moduli.sort_unstable();
    if ordered_moduli.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ParameterGenerationError::InvalidCertificate);
    }

    Ok(())
}

fn verify_logical_slot_layout() -> bool {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let positive_slot_count = POLYNOMIAL_DEGREE / 2;
    if LOGICAL_SLOT_GENERATOR <= 1
        || LOGICAL_SLOT_GENERATOR >= ring_order
        || LOGICAL_SLOT_GENERATOR.is_multiple_of(2)
        || modular_power(
            LOGICAL_SLOT_GENERATOR as u64,
            positive_slot_count as u64,
            ring_order as u64,
        ) != 1
        || modular_power(
            LOGICAL_SLOT_GENERATOR as u64,
            (positive_slot_count / 2) as u64,
            ring_order as u64,
        ) == 1
    {
        return false;
    }

    let mut seen_odd_exponents = vec![false; POLYNOMIAL_DEGREE];
    let mut exponent = 1_usize;
    for _ in 0..positive_slot_count {
        if exponent.is_multiple_of(2) || exponent == ring_order - 1 {
            return false;
        }
        for represented_exponent in [exponent, ring_order - exponent] {
            let natural_transform_index = (represented_exponent - 1) / 2;
            let Some(was_seen) = seen_odd_exponents.get_mut(natural_transform_index) else {
                return false;
            };
            if *was_seen {
                return false;
            }
            *was_seen = true;
        }
        exponent = exponent * LOGICAL_SLOT_GENERATOR % ring_order;
    }

    exponent == 1 && seen_odd_exponents.into_iter().all(|was_seen| was_seen)
}

fn derive_root_parameters(modulus: u64) -> Result<RootParameters, ParameterGenerationError> {
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
        inverse_polynomial_degree: modular_power(
            POLYNOMIAL_DEGREE as u64,
            modulus - 2,
            modulus,
        ),
    };
    if !verify_data_root_parameters(parameters) {
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
    for witness in [
        2_u64,
        325,
        9_375,
        28_178,
        450_775,
        9_780_504,
        1_795_265_022,
    ] {
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

fn distinct_prime_factors(mut value: u64) -> Vec<u64> {
    let mut factors = Vec::new();
    let mut candidate_factor = 2_u64;
    while candidate_factor <= value / candidate_factor {
        if value.is_multiple_of(candidate_factor) {
            factors.push(candidate_factor);
            while value.is_multiple_of(candidate_factor) {
                value /= candidate_factor;
            }
        }
        candidate_factor += if candidate_factor == 2 { 1 } else { 2 };
    }
    if value > 1 {
        factors.push(value);
    }
    factors
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
    use crate::bgv::parameters::{DATA_PRIMES, ROOT_PARAMETERS};

    #[test]
    fn deterministic_generation_reproduces_the_complete_data_basis() {
        let generated = regenerate_supported_data_root_parameters()
            .expect("the supported data basis regenerates");
        assert_eq!(
            generated.map(|parameters| parameters.modulus),
            DATA_PRIMES
        );
        assert_eq!(generated.as_slice(), &ROOT_PARAMETERS[1..=DATA_PRIME_COUNT]);
        assert!(generated
            .iter()
            .all(|parameters| verify_data_root_parameters(*parameters)));
    }

    #[test]
    fn every_target_prefix_has_exact_plaintext_conversion_congruence() {
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
        let valid = ROOT_PARAMETERS[1];
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
    fn complete_algebraic_certificate_reproduces() {
        validate_supported_algebraic_parameters()
            .expect("the fixed algebraic parameter certificate must reproduce");
    }

    #[test]
    fn deterministic_primality_test_rejects_strong_pseudoprimes() {
        for composite in [
            341_u64,
            3_215_031_751,
            382_512_305_654_641_305,
            u64::MAX,
        ] {
            assert!(!is_prime(composite), "{composite} must be composite");
        }
    }
}
