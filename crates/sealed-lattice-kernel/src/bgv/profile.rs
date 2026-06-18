use serde_json::{Value, json};

use crate::{
    encoding::CanonicalResult,
    hashing::{derive_protocol_hash, hash512_hex},
};

pub(crate) const PROFILE_ID: &str = "sealed-lattice-bgv-rns-v1";
pub(crate) const BACKEND_PROFILE_ID: &str = "sealed-lattice-rust-wasm-bgv-rns-v1";
// Ring degree N. Powers of two are NTT-friendly; 2N divides each modulus-1.
pub(crate) const POLYNOMIAL_DEGREE: usize = 32_768;
// Plaintext modulus t. 65537 is the Fermat prime 2^16+1; t-1 = 2^16 is
// divisible by 2N, so a length-2N NTT exists for batch (slot) encoding.
pub(crate) const PLAINTEXT_MODULUS: u64 = 65_537;
pub(crate) const DATA_BASIS_ID: &str = "sealed-lattice-bgv-rns-data-basis-v1";
pub(crate) const EXTENDED_BASIS_ID: &str = "sealed-lattice-bgv-rns-extended-basis-v1";
pub(crate) const SPECIAL_BASIS_ID: &str = "sealed-lattice-bgv-rns-special-basis-v1";
pub(crate) const ENCRYPTED_BALLOT_AGGREGATE_LAYOUT_ID: &str =
    "direct-encrypted-ballot-aggregate-layout-v1";
pub(crate) const BATCH_ENCODER_ID: &str = "BGVBatchEncode_65537-v1";
pub(crate) const CANONICAL_CIPHERTEXT_CONVENTION_ID: &str =
    "sealed-lattice-coefficient-domain-rns-ciphertext-v1";
pub(crate) const OPERATION_REGISTRY_ID: &str = "sealed-lattice-bgv-allowed-ops-v1";
pub(crate) const BATCH_LAYOUT_KIND: &str = "DirectEncryptedBallotAggregateLayout-v1";
pub(crate) const BALLOT_SCORE_ENCODING_PROFILE_ID: &str =
    "ballot-score-encoding-profile-hidden-one-hot-v1";
pub(crate) const ENCRYPTED_BALLOT_LAYOUT_PROFILE_ID: &str = "direct-encrypted-ballot-layout-v1";
pub(crate) const ENCRYPTED_BALLOT_AGGREGATE_PROFILE_ID: &str =
    "direct-encrypted-ballot-aggregate-v1";
pub(crate) const DIRECT_AGGREGATE_LAYOUT_ID: &str = "direct-aggregate-layout-v1";
pub(crate) const DIRECT_COMPARISON_PROFILE_ID: &str = "direct-encrypted-ballot-comparison-v1";

mod root_parameters;

pub(crate) use root_parameters::{
    BgvBasisKind, DATA_PRIMES, ROOT_PARAMETERS, RootParameters, SPECIAL_PRIME,
    data_basis_modulus_bits, data_prime_bit_length, extended_basis_modulus_bits,
    root_parameters_for_modulus,
};
pub(crate) fn selected_profile_value() -> Value {
    json!({
        "profileId": PROFILE_ID,
        "backendProfileId": BACKEND_PROFILE_ID,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "dataBasisId": DATA_BASIS_ID,
        "extendedBasisId": EXTENDED_BASIS_ID,
        "specialBasisId": SPECIAL_BASIS_ID,
        "dataPrimes": DATA_PRIMES,
        "specialPrime": SPECIAL_PRIME,
        "dataPrimeBitLength": data_prime_bit_length(),
        "dataLevels": DATA_PRIMES.len(),
        "extendedLevels": DATA_PRIMES.len() + 1,
        "encryptedBallotAggregateLayoutId": ENCRYPTED_BALLOT_AGGREGATE_LAYOUT_ID,
        "batchEncoderId": BATCH_ENCODER_ID,
        "canonicalCiphertextConventionId": CANONICAL_CIPHERTEXT_CONVENTION_ID,
        "nttRootParameters": ROOT_PARAMETERS.iter().map(|parameters| json!({
            "modulus": parameters.modulus,
            "primitiveGenerator": parameters.primitive_generator,
            "negacyclicRoot": parameters.negacyclic_root,
            "cyclicRoot": parameters.cyclic_root,
            "inverseNegacyclicRoot": parameters.inverse_negacyclic_root,
            "inverseCyclicRoot": parameters.inverse_cyclic_root,
            "inversePolynomialDegree": parameters.inverse_polynomial_degree,
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash("BGVProfileHash", &selected_profile_value())
}

pub(crate) fn backend_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "RustBgvBackendProfileHash",
        &json!({
            "backendProfileId": BACKEND_PROFILE_ID,
            "profileHash": profile_hash()?,
            "ownedBy": "sealed-lattice-rust-wasm",
            "referenceOracleStatus": "development-only-not-runtime",
        }),
    )
}

pub(crate) fn batch_encoder_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BGVBatchEncoderHash",
        &json!({
            "encoderId": BATCH_ENCODER_ID,
            "profileHash": profile_hash()?,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "layoutId": ENCRYPTED_BALLOT_AGGREGATE_LAYOUT_ID,
            "layoutBindingHash": batch_layout_binding_hash()?,
        }),
    )
}

pub(crate) fn encrypted_ballot_aggregate_layout_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedBallotAggregateLayoutHash",
        &json!({
            "layoutId": ENCRYPTED_BALLOT_AGGREGATE_LAYOUT_ID,
            "profileHash": profile_hash()?,
            "slotCount": POLYNOMIAL_DEGREE,
            "coordinateField": "GF(65537)",
            "source": "DirectEncryptedBallotAggregate",
            "ballotPrivacy": "ciphertext-only-direct-ballots",
        }),
    )
}

pub(crate) fn ballot_score_encoding_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotScoreEncodingProfileHash",
        &json!({
            "profileId": BALLOT_SCORE_ENCODING_PROFILE_ID,
            "scoreRange": {
                "minimum": 1,
                "maximum": 10
            },
            "encoding": "score-share-plus-hidden-one-hot-buckets",
            "bucketCount": 10,
            "field": "GF(65537)",
        }),
    )
}

pub(crate) fn encrypted_ballot_layout_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedBallotLayoutHash",
        &json!({
            "profileId": ENCRYPTED_BALLOT_LAYOUT_PROFILE_ID,
            "coordinateOrder": "encrypted-score-then-one-hot-score-buckets-per-option",
            "coordinatesPerOption": 11,
            "field": "GF(65537)",
        }),
    )
}

pub(crate) fn encrypted_ballot_aggregate_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedBallotAggregateProfileHash",
        &json!({
            "profileId": ENCRYPTED_BALLOT_AGGREGATE_PROFILE_ID,
            "sourceRelation": "direct encrypted ballot aggregation",
            "sourceObject": "DirectEncryptedBallotCiphertexts",
            "ballotPrivacy": "ciphertext-only-direct-ballots",
        }),
    )
}

pub(crate) fn direct_aggregate_layout_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "DirectAggregateLayoutHash",
        &json!({
            "layoutId": DIRECT_AGGREGATE_LAYOUT_ID,
            "encryptedBallotAggregateLayoutHash": encrypted_ballot_aggregate_layout_hash()?,
            "encryptedBallotAggregateProfileHash": encrypted_ballot_aggregate_profile_hash()?,
            "slotCount": POLYNOMIAL_DEGREE,
            "scalarOnlyAggregateLayout": false,
        }),
    )
}

pub(crate) fn direct_comparison_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "DirectComparisonProfileHash",
        &json!({
            "layoutId": DIRECT_COMPARISON_PROFILE_ID,
            "encryptedBallotAggregateLayoutHash": encrypted_ballot_aggregate_layout_hash()?,
            "directAggregateLayoutHash": direct_aggregate_layout_hash()?,
            "acceptedEvaluatorInput": "direct-encrypted-ballot-aggregate-score-coordinates",
            "rejectScalarOnlyAggregateLayouts": true,
        }),
    )
}

pub(crate) fn batch_layout_binding_value() -> CanonicalResult<Value> {
    Ok(json!({
        "layoutKind": BATCH_LAYOUT_KIND,
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
        "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()?,
        "encryptedBallotAggregateProfileHash": encrypted_ballot_aggregate_profile_hash()?,
        "directAggregateLayoutHash": direct_aggregate_layout_hash()?,
        "encryptedBallotAggregateLayoutHash": encrypted_ballot_aggregate_layout_hash()?,
        "directComparisonProfileHash": direct_comparison_profile_hash()?,
        "coordinateOrder": "encrypted-score-then-one-hot-score-buckets-per-option",
        "oneHotBucketOrder": "ascending-score-1-through-10",
        "scoreBucketCount": 10,
        "scoreRange": {
            "minimum": 1,
            "maximum": 10
        },
        "scalarOnlyAggregateLayout": false,
    }))
}

pub(crate) fn batch_layout_binding_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BGVBatchEncoderLayoutBindingHash",
        &batch_layout_binding_value()?,
    )
}

pub(crate) fn canonical_ciphertext_convention_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "CanonicalCiphertextConventionHash",
        &json!({
            "conventionId": CANONICAL_CIPHERTEXT_CONVENTION_ID,
            "profileHash": profile_hash()?,
            "coefficientDomainOnly": true,
            "publicKeyRelation": "componentZero=p*e-a*s,componentOne=a",
            "encryptionRelation": "c0=componentZero*u+p*e0+m,c1=componentOne*u+p*e1",
            "messageEmbedding": "least-significant-residue-mod-plaintext-modulus",
            "lattigoSerializationAccepted": false,
        }),
    )
}

pub(crate) fn allowed_operation_registry_value() -> CanonicalResult<Value> {
    Ok(json!({
        "operationRegistryId": OPERATION_REGISTRY_ID,
        "profileHash": profile_hash()?,
        "batchEncoderHash": batch_encoder_hash()?,
        "allowedOperations": [
            "encodeDirectEncryptedBallotAggregate",
            "validateCoefficientDomainPlaintext",
            "validateCoefficientDomainCiphertext",
            "homomorphicEncryptedBallotAggregation",
            "interpolationCoefficientScalarMultiplication",
            "comparisonInputDerivationCircuitInputPreparation",
            "encryptedRankAccumulationSupport",
            "encryptedSparseTargetProjectionSupport",
            "canonicalTargetCiphertextSelection"
        ],
        "forbiddenOperations": [
            "rawDecrypt",
            "rawThresholdDecrypt",
            "rawRnsLimbAccess",
            "rawNttTranscriptRoot",
            "scalarDegree360Comparator",
            "uncertifiedComparisonInputDerivationOperation",
            "lattigoRuntimeObjectImport",
            "referenceOracleVectorAcceptance",
            "genericFheApiSurface"
        ],
    }))
}

pub(crate) fn allowed_operation_registry_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "AllowedEvaluatorOpsHash",
        &allowed_operation_registry_value()?,
    )
}

pub(crate) fn security_estimator_input_hash() -> CanonicalResult<String> {
    Ok(hash512_hex(
        "sealed-lattice-bgv-rns/security-estimator-input-v1",
        &[
            PROFILE_ID.as_bytes(),
            POLYNOMIAL_DEGREE.to_string().as_bytes(),
            PLAINTEXT_MODULUS.to_string().as_bytes(),
            DATA_PRIMES
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
            SPECIAL_PRIME.to_string().as_bytes(),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::root_parameters::moduli_bit_length_sum;
    use super::{
        BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIME,
        allowed_operation_registry_hash, ballot_score_encoding_profile_hash, batch_encoder_hash,
        batch_layout_binding_hash, batch_layout_binding_value,
        canonical_ciphertext_convention_hash, data_basis_modulus_bits,
        direct_aggregate_layout_hash, direct_comparison_profile_hash,
        encrypted_ballot_aggregate_layout_hash, encrypted_ballot_aggregate_profile_hash,
        encrypted_ballot_layout_hash, extended_basis_modulus_bits, profile_hash,
        root_parameters_for_modulus, security_estimator_input_hash,
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
    fn selected_profile_hashes_are_hex_roots() {
        let selected_hashes = [
            ("profile", profile_hash()),
            ("batch encoder", batch_encoder_hash()),
            ("layout", encrypted_ballot_aggregate_layout_hash()),
            ("batch layout binding", batch_layout_binding_hash()),
            (
                "ballot score encoding profile",
                ballot_score_encoding_profile_hash(),
            ),
            ("encrypted ballot layout", encrypted_ballot_layout_hash()),
            (
                "encrypted ballot aggregate profile",
                encrypted_ballot_aggregate_profile_hash(),
            ),
            ("direct aggregate layout", direct_aggregate_layout_hash()),
            (
                "top-k evaluator input layout",
                direct_comparison_profile_hash(),
            ),
            (
                "canonical ciphertext convention",
                canonical_ciphertext_convention_hash(),
            ),
            (
                "allowed operation registry",
                allowed_operation_registry_hash(),
            ),
            ("security estimator input", security_estimator_input_hash()),
        ];

        for (profile_hash_label, actual_hash) in selected_hashes {
            let actual_hash = actual_hash.expect("hash should derive");
            assert_eq!(
                actual_hash.len(),
                128,
                "{profile_hash_label} should be a SHA-512 hex root"
            );
            assert!(
                actual_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "{profile_hash_label} should be lower-case hex"
            );
        }
    }

    #[test]
    fn batch_layout_binding_rejects_scalar_only_layouts_by_construction() {
        let binding = batch_layout_binding_value().expect("layout binding");

        assert_eq!(
            binding["layoutKind"],
            "DirectEncryptedBallotAggregateLayout-v1"
        );
        assert_eq!(binding["scalarOnlyAggregateLayout"], false);
        assert_eq!(
            binding["coordinateOrder"],
            "encrypted-score-then-one-hot-score-buckets-per-option"
        );
        assert_eq!(binding["scoreBucketCount"], 10);
        assert!(
            binding["encryptedBallotAggregateLayoutHash"]
                .as_str()
                .expect("target hash")
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }
}
