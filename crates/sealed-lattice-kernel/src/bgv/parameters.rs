use serde_json::{Value, json};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

// Ring degree N. Powers of two are NTT-friendly; 2N divides every ciphertext
// and key-switch modulus minus one.
pub(crate) const POLYNOMIAL_DEGREE: usize = 32_768;
// The plaintext ring is F_257[X]/(X^N + 1). Since 257 has order 256 modulo
// 2N, it factors into 128 degree-256 extension lanes. Pair characters use
// monomials inside those lanes; there is no scalar-slot NTT for this suite.
pub(crate) const PLAINTEXT_MODULUS: u64 = 257;
pub(crate) const PLAINTEXT_EXTENSION_DEGREE: usize = 256;
pub(crate) const PLAINTEXT_EXTENSION_LANE_COUNT: usize =
    POLYNOMIAL_DEGREE / PLAINTEXT_EXTENSION_DEGREE;
// These two generators have distinct algebraic roles even though the selected
// suite represents both by the integer three. The root generator has order
// 256 in F_257^*, while the orbit generator has order 64 modulo 256 and
// enumerates one bank of irreducible factors before their inverse bank.
pub(crate) const PLAINTEXT_LANE_ROOT_GENERATOR: u64 = 3;
pub(crate) const PLAINTEXT_LANE_ORBIT_GENERATOR: usize = 3;
pub(crate) const PLAINTEXT_LANE_IDEMPOTENT_SCALE: u64 = PLAINTEXT_MODULUS - 2;
pub(crate) const DATA_BASIS_ID: &str = "sealed-lattice-bgv-rns-data-basis";
#[cfg(test)]
pub(crate) const EXTENDED_BASIS_ID: &str = "sealed-lattice-bgv-rns-extended-basis";
#[cfg(test)]
pub(crate) const SPECIAL_BASIS_ID: &str = "sealed-lattice-bgv-rns-special-basis";

mod parameter_generation;
mod root_parameters;

pub(crate) use parameter_generation::{
    plaintext_extension_lane_root, validate_supported_algebraic_parameters,
};
pub(crate) use root_parameters::{
    BgvBasisKind, DATA_PRIMES, NttTransformParameters, ROOT_PARAMETERS, RootParameters,
    SPECIAL_PRIMES, root_parameters_for_modulus,
};

/// JSON has no lossless unsigned-64-bit integer type. Protocol descriptions
/// therefore carry moduli and field elements as canonical base-ten strings.
/// Counts and indexes remain JSON numbers because their selected maxima are
/// inside the JavaScript-safe integer range.
pub(crate) fn canonical_bgv_parameter_integer_decimal_string(value: u64) -> String {
    value.to_string()
}

// The single canonical identity for the fixed BGV parameter set. It binds the
// ring arithmetic and the fixed score and batch layout used by the protocol.
pub(crate) fn bgv_parameters_value() -> Value {
    let data_primes = DATA_PRIMES
        .into_iter()
        .map(canonical_bgv_parameter_integer_decimal_string)
        .collect::<Vec<_>>();
    let special_primes = SPECIAL_PRIMES
        .into_iter()
        .map(canonical_bgv_parameter_integer_decimal_string)
        .collect::<Vec<_>>();
    json!({
        "objectType": "BgvParameters",
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": canonical_bgv_parameter_integer_decimal_string(PLAINTEXT_MODULUS),
        "dataPrimes": data_primes,
        "specialPrimes": special_primes,
        "nttRootParameters": ROOT_PARAMETERS.iter().map(|parameters| json!({
            "modulus": canonical_bgv_parameter_integer_decimal_string(parameters.modulus),
            "primitiveGenerator": canonical_bgv_parameter_integer_decimal_string(parameters.primitive_generator),
            "negacyclicRoot": canonical_bgv_parameter_integer_decimal_string(parameters.negacyclic_root),
            "cyclicRoot": canonical_bgv_parameter_integer_decimal_string(parameters.cyclic_root),
            "inverseNegacyclicRoot": canonical_bgv_parameter_integer_decimal_string(parameters.inverse_negacyclic_root),
            "inverseCyclicRoot": canonical_bgv_parameter_integer_decimal_string(parameters.inverse_cyclic_root),
            "inversePolynomialDegree": canonical_bgv_parameter_integer_decimal_string(parameters.inverse_polynomial_degree),
        })).collect::<Vec<_>>(),
        "plaintextExtension": {
            "degree": PLAINTEXT_EXTENSION_DEGREE,
            "laneCount": PLAINTEXT_EXTENSION_LANE_COUNT,
        },
        "pairCharacterCiphertextCount": 2,
        "pairCharacterCounts": [93, 97],
    })
}

pub(crate) fn bgv_parameters_hash() -> CanonicalResult<String> {
    validate_supported_algebraic_parameters().map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("BGV algebraic parameter certificate failed: {error}"),
        )
    })?;
    derive_canonical_object_hash(&bgv_parameters_value())
}

#[cfg(test)]
mod tests {
    use super::{
        BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, ROOT_PARAMETERS,
        SPECIAL_PRIMES, bgv_parameters_hash, bgv_parameters_value, root_parameters_for_modulus,
    };
    use crate::bgv::modular_arithmetic::is_prime_for_tests;

    #[test]
    fn parameter_description_preserves_every_unsigned_64_bit_value_as_decimal_text() {
        let parameters = bgv_parameters_value();
        assert_eq!(
            parameters["plaintextModulus"].as_str(),
            Some(PLAINTEXT_MODULUS.to_string().as_str())
        );
        let described_data_primes = parameters["dataPrimes"]
            .as_array()
            .expect("data primes are an array");
        assert_eq!(described_data_primes.len(), DATA_PRIMES.len());
        for (described, expected) in described_data_primes.iter().zip(DATA_PRIMES) {
            assert_eq!(
                described
                    .as_str()
                    .expect("data prime is canonical decimal text")
                    .parse::<u64>()
                    .expect("data prime decimal text parses exactly"),
                expected
            );
        }
        let described_special_primes = parameters["specialPrimes"]
            .as_array()
            .expect("special primes are an array");
        assert_eq!(described_special_primes.len(), SPECIAL_PRIMES.len());
        for (described, expected) in described_special_primes.iter().zip(SPECIAL_PRIMES) {
            assert_eq!(
                described
                    .as_str()
                    .expect("special prime is canonical decimal text")
                    .parse::<u64>()
                    .expect("special prime decimal text parses exactly"),
                expected
            );
        }
        let described_roots = parameters["nttRootParameters"]
            .as_array()
            .expect("root parameters are an array");
        assert_eq!(described_roots.len(), ROOT_PARAMETERS.len());
        for (described, expected) in described_roots.iter().zip(ROOT_PARAMETERS) {
            for (field_name, expected_value) in [
                ("modulus", expected.modulus),
                ("primitiveGenerator", expected.primitive_generator),
                ("negacyclicRoot", expected.negacyclic_root),
                ("cyclicRoot", expected.cyclic_root),
                ("inverseNegacyclicRoot", expected.inverse_negacyclic_root),
                ("inverseCyclicRoot", expected.inverse_cyclic_root),
                (
                    "inversePolynomialDegree",
                    expected.inverse_polynomial_degree,
                ),
            ] {
                assert_eq!(
                    described[field_name]
                        .as_str()
                        .expect("root parameter is canonical decimal text")
                        .parse::<u64>()
                        .expect("root parameter decimal text parses exactly"),
                    expected_value
                );
            }
        }
        assert!(bgv_parameters_hash().is_ok());
    }

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
        assert_eq!(PLAINTEXT_MODULUS, 257);
        assert!(
            is_prime_for_tests(PLAINTEXT_MODULUS),
            "the selected plaintext modulus must reproduce as prime"
        );
        for modulus in DATA_PRIMES.into_iter().chain(SPECIAL_PRIMES) {
            assert_eq!((modulus - 1) % (2 * POLYNOMIAL_DEGREE as u64), 0);
            assert!(is_prime_for_tests(modulus));
            assert!(root_parameters_for_modulus(modulus).is_some());
        }
        assert!(
            DATA_PRIMES
                .iter()
                .chain(&SPECIAL_PRIMES)
                .all(|modulus| modulus % PLAINTEXT_MODULUS == 1)
        );
        assert!(root_parameters_for_modulus(PLAINTEXT_MODULUS).is_none());
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
            vec![SPECIAL_PRIMES[0]]
        );
        assert_eq!(
            BgvBasisKind::Special
                .moduli_for_level(SPECIAL_PRIMES.len() - 1)
                .expect("full special basis"),
            SPECIAL_PRIMES
        );
        assert!(
            BgvBasisKind::Special
                .moduli_for_level(SPECIAL_PRIMES.len())
                .is_none()
        );
        assert_eq!(
            BgvBasisKind::Extended
                .moduli_for_level(DATA_PRIMES.len() + SPECIAL_PRIMES.len() - 1)
                .expect("full extended basis")
                .len(),
            DATA_PRIMES.len() + SPECIAL_PRIMES.len()
        );
        assert!(BgvBasisKind::Special.moduli_for_level(99).is_none());
    }
}
