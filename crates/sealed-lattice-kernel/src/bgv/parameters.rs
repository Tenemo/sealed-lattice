use serde_json::{Value, json};

use crate::{encoding::CanonicalResult, hashing::derive_canonical_object_hash};

// Ring degree N. Powers of two are NTT-friendly; 2N divides each modulus-1.
pub(crate) const POLYNOMIAL_DEGREE: usize = 32_768;
// Plaintext modulus t. 65537 is the Fermat prime 2^16+1; t-1 = 2^16 is
// divisible by 2N, so a length-2N NTT exists for batch (slot) encoding.
pub(crate) const PLAINTEXT_MODULUS: u64 = 65_537;
pub(crate) const DATA_BASIS_ID: &str = "sealed-lattice-bgv-rns-data-basis-v1";
pub(crate) const EXTENDED_BASIS_ID: &str = "sealed-lattice-bgv-rns-extended-basis-v1";
pub(crate) const SPECIAL_BASIS_ID: &str = "sealed-lattice-bgv-rns-special-basis-v1";

mod root_parameters;

pub(crate) use root_parameters::{
    BgvBasisKind, DATA_PRIMES, ROOT_PARAMETERS, RootParameters, SPECIAL_PRIME,
    data_basis_modulus_bits, data_prime_bit_length, extended_basis_modulus_bits,
    root_parameters_for_modulus,
};
// The single canonical identity for the fixed BGV parameter set, in the style of
// a SEAL parms_id: one object that unions the full BGV configuration. It binds
// the ring parameters, the ballot/score/layout data, the aggregate/comparison
// flags, the ciphertext convention flags, and the evaluator operation policy.
// Every part is a pure deterministic function of the fixed parameters, so one
// hash over the whole set is the strongest identity and replaces the former
// collection of per-component hashes.
pub(crate) fn bgv_parameters_value() -> Value {
    json!({
        "objectType": "BgvParameters",
        "objectVersion": 1,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataPrimes": DATA_PRIMES,
        "specialPrime": SPECIAL_PRIME,
        "dataPrimeBitLength": data_prime_bit_length(),
        "dataLevels": DATA_PRIMES.len(),
        "extendedLevels": DATA_PRIMES.len() + 1,
        "nttRootParameters": ROOT_PARAMETERS.iter().map(|parameters| json!({
            "modulus": parameters.modulus,
            "primitiveGenerator": parameters.primitive_generator,
            "negacyclicRoot": parameters.negacyclic_root,
            "cyclicRoot": parameters.cyclic_root,
            "inverseNegacyclicRoot": parameters.inverse_negacyclic_root,
            "inverseCyclicRoot": parameters.inverse_cyclic_root,
            "inversePolynomialDegree": parameters.inverse_polynomial_degree,
        })).collect::<Vec<_>>(),
        "scoreRange": {
            "minimum": 1,
            "maximum": 10
        },
        "bucketCount": 10,
        "coordinatesPerOption": 11,
        "slotCount": POLYNOMIAL_DEGREE,
        "scalarOnlyAggregateLayout": false,
        "rejectScalarOnlyAggregateLayouts": true,
        "coefficientDomainOnly": true,
        "lattigoSerializationAccepted": false,
        "allowedOperations": ALLOWED_EVALUATOR_OPERATIONS,
        "forbiddenOperations": FORBIDDEN_EVALUATOR_OPERATIONS,
    })
}

pub(crate) fn bgv_parameters_hash() -> CanonicalResult<String> {
    derive_canonical_object_hash(&bgv_parameters_value())
}

// Layout data only, with no embedded sub-hashes. Used by the encode command's
// layout-binding equality check.
pub(crate) fn batch_layout_binding_value() -> CanonicalResult<Value> {
    Ok(json!({
        "scoreRange": {
            "minimum": 1,
            "maximum": 10
        },
        "bucketCount": 10,
        "slotCount": POLYNOMIAL_DEGREE,
        "coordinatesPerOption": 11,
        "scalarOnlyAggregateLayout": false,
    }))
}

const ALLOWED_EVALUATOR_OPERATIONS: &[&str] = &[
    "encodeDirectEncryptedBallotAggregate",
    "validateCoefficientDomainPlaintext",
    "validateCoefficientDomainCiphertext",
    "homomorphicEncryptedBallotAggregation",
    "interpolationCoefficientScalarMultiplication",
    "comparisonInputDerivationCircuitInputPreparation",
    "encryptedRankAccumulationSupport",
    "encryptedSparseTargetProjectionSupport",
    "canonicalTargetCiphertextSelection",
];

const FORBIDDEN_EVALUATOR_OPERATIONS: &[&str] = &[
    "rawDecrypt",
    "rawThresholdDecrypt",
    "rawRnsLimbAccess",
    "rawNttTranscriptRoot",
    "scalarDegree360Comparator",
    "uncertifiedComparisonInputDerivationOperation",
    "lattigoRuntimeObjectImport",
    "referenceOracleVectorAcceptance",
    "genericFheApiSurface",
];

// Operations-list data only. Used by validate_bgv_evaluator_operation.
pub(crate) fn allowed_operation_registry_value() -> CanonicalResult<Value> {
    Ok(json!({
        "allowedOperations": ALLOWED_EVALUATOR_OPERATIONS,
        "forbiddenOperations": FORBIDDEN_EVALUATOR_OPERATIONS,
    }))
}

#[cfg(test)]
mod tests {
    use super::root_parameters::moduli_bit_length_sum;
    use super::{
        BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIME,
        batch_layout_binding_value, bgv_parameters_hash, data_basis_modulus_bits,
        extended_basis_modulus_bits, root_parameters_for_modulus,
    };
    use crate::bgv::modular_arithmetic::is_prime_for_tests;

    fn pow_mod(base: u64, mut exponent: u64, modulus: u64) -> u64 {
        let mut result = 1_u128;
        let modulus_wide = u128::from(modulus);
        let mut base_wide = u128::from(base) % modulus_wide;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = (result * base_wide) % modulus_wide;
            }
            base_wide = (base_wide * base_wide) % modulus_wide;
            exponent >>= 1;
        }

        u64::try_from(result).expect("modular exponentiation result fits in u64")
    }

    fn prime_factor_bases(mut value: u64) -> Vec<u64> {
        let mut factors = Vec::new();
        let mut divisor = 2_u64;
        while divisor <= value / divisor {
            if value.is_multiple_of(divisor) {
                factors.push(divisor);
                while value.is_multiple_of(divisor) {
                    value /= divisor;
                }
            }
            divisor += if divisor == 2 { 1 } else { 2 };
        }
        if value > 1 {
            factors.push(value);
        }

        factors
    }

    #[test]
    fn selected_moduli_are_ntt_ready_primes() {
        assert_eq!(POLYNOMIAL_DEGREE, 32_768);
        assert_eq!(PLAINTEXT_MODULUS, 65_537);
        for modulus in DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]) {
            assert_eq!((modulus - 1) % (2 * POLYNOMIAL_DEGREE as u64), 0);
            assert!(is_prime_for_tests(modulus));
            assert!(root_parameters_for_modulus(modulus).is_some());
        }
        assert!(root_parameters_for_modulus(PLAINTEXT_MODULUS).is_some());
    }

    #[test]
    fn primitive_generators_have_full_multiplicative_order() {
        for parameters in super::ROOT_PARAMETERS {
            let group_order = parameters.modulus - 1;
            assert!(parameters.primitive_generator > 1);
            assert!(parameters.primitive_generator < parameters.modulus);
            assert_eq!(
                pow_mod(
                    parameters.primitive_generator,
                    group_order,
                    parameters.modulus
                ),
                1,
                "primitive generator must be in the multiplicative group for modulus {}",
                parameters.modulus
            );
            for prime_factor in prime_factor_bases(group_order) {
                assert_ne!(
                    pow_mod(
                        parameters.primitive_generator,
                        group_order / prime_factor,
                        parameters.modulus
                    ),
                    1,
                    "primitive generator must not lie in the subgroup of index {prime_factor} for modulus {}",
                    parameters.modulus
                );
            }
        }
    }

    #[test]
    fn selected_root_parameters_have_negacyclic_orders_and_inverses() {
        for parameters in super::ROOT_PARAMETERS {
            assert_eq!(
                pow_mod(
                    parameters.negacyclic_root,
                    POLYNOMIAL_DEGREE as u64,
                    parameters.modulus
                ),
                parameters.modulus - 1,
                "negacyclic root must have half-order -1 for modulus {}",
                parameters.modulus
            );
            assert_eq!(
                pow_mod(
                    parameters.negacyclic_root,
                    2 * POLYNOMIAL_DEGREE as u64,
                    parameters.modulus
                ),
                1,
                "negacyclic root must have full 2N order for modulus {}",
                parameters.modulus
            );
            assert_eq!(
                pow_mod(
                    parameters.cyclic_root,
                    POLYNOMIAL_DEGREE as u64,
                    parameters.modulus
                ),
                1,
                "cyclic root must have N order for modulus {}",
                parameters.modulus
            );
            assert_ne!(
                pow_mod(
                    parameters.cyclic_root,
                    (POLYNOMIAL_DEGREE / 2) as u64,
                    parameters.modulus
                ),
                1,
                "cyclic root must not have order N/2 for modulus {}",
                parameters.modulus
            );
            assert_eq!(
                (u128::from(parameters.negacyclic_root)
                    * u128::from(parameters.inverse_negacyclic_root))
                    % u128::from(parameters.modulus),
                1,
                "inverse negacyclic root mismatch for modulus {}",
                parameters.modulus
            );
            assert_eq!(
                (u128::from(parameters.cyclic_root) * u128::from(parameters.inverse_cyclic_root))
                    % u128::from(parameters.modulus),
                1,
                "inverse cyclic root mismatch for modulus {}",
                parameters.modulus
            );
            assert_eq!(
                (u128::from(POLYNOMIAL_DEGREE as u64)
                    * u128::from(parameters.inverse_polynomial_degree))
                    % u128::from(parameters.modulus),
                1,
                "inverse degree mismatch for modulus {}",
                parameters.modulus
            );
        }
    }

    #[test]
    fn basis_levels_are_canonical() {
        assert_eq!(
            BgvBasisKind::Data.moduli_for_level(0).expect("level 0"),
            vec![DATA_PRIMES[0]]
        );
        assert_eq!(
            BgvBasisKind::Data
                .moduli_for_level(DATA_PRIMES.len() - 1)
                .expect("full data basis")
                .len(),
            DATA_PRIMES.len()
        );
        assert!(
            BgvBasisKind::Data
                .moduli_for_level(DATA_PRIMES.len())
                .is_none()
        );
        assert_eq!(
            BgvBasisKind::Special
                .moduli_for_level(0)
                .expect("special basis level zero"),
            vec![SPECIAL_PRIME]
        );
        assert!(BgvBasisKind::Special.moduli_for_level(1).is_none());
        assert!(BgvBasisKind::Special.moduli_for_level(99).is_none());
    }

    #[test]
    fn modulus_bit_accounting_sums_actual_modulus_widths() {
        assert_eq!(moduli_bit_length_sum([0, 1, 255, 256]), 18);
        assert_eq!(
            data_basis_modulus_bits(),
            DATA_PRIMES
                .iter()
                .map(
                    |modulus| usize::try_from(u64::BITS - modulus.leading_zeros())
                        .expect("bit length fits usize")
                )
                .sum::<usize>()
        );
        assert_eq!(
            extended_basis_modulus_bits(),
            data_basis_modulus_bits()
                + usize::try_from(u64::BITS - SPECIAL_PRIME.leading_zeros())
                    .expect("bit length fits usize")
        );
    }

    #[test]
    fn bgv_parameters_hash_is_a_lower_case_hex_root() {
        let actual_hash = bgv_parameters_hash().expect("hash should derive");
        assert_eq!(
            actual_hash.len(),
            128,
            "BGV parameters hash should be a SHA-512 hex root"
        );
        assert!(
            actual_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "BGV parameters hash should be lower-case hex"
        );
    }

    #[test]
    fn batch_layout_binding_rejects_scalar_only_layouts_by_construction() {
        let binding = batch_layout_binding_value().expect("layout binding");

        assert_eq!(binding["scalarOnlyAggregateLayout"], false);
        assert_eq!(binding["bucketCount"], 10);
        assert_eq!(binding["slotCount"], POLYNOMIAL_DEGREE);
        assert_eq!(binding["coordinatesPerOption"], 11);
    }
}
