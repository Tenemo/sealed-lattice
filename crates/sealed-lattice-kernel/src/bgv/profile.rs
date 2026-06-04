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
pub(crate) const AGGREGATE_SHARE_LAYOUT_ID: &str = "encrypted-aggregate-input-layout-v1";
pub(crate) const BATCH_ENCODER_ID: &str = "BGVBatchEncode_65537-v1";
pub(crate) const CANONICAL_CIPHERTEXT_CONVENTION_ID: &str =
    "sealed-lattice-coefficient-domain-rns-ciphertext-v1";
pub(crate) const OPERATION_REGISTRY_ID: &str = "sealed-lattice-bgv-allowed-ops-v1";
pub(crate) const BATCH_LAYOUT_KIND: &str = "EncryptedAggregateInputEncodedScoreLayout-v1";
pub(crate) const BALLOT_SCORE_ENCODING_PROFILE_ID: &str =
    "ballot-score-encoding-profile-hidden-one-hot-v1";
pub(crate) const BALLOT_SHARE_LAYOUT_PROFILE_ID: &str =
    "ballot-share-layout-score-plus-one-hot-buckets-v1";
pub(crate) const AGGREGATE_INPUT_ENCODING_PROFILE_ID: &str =
    "aggregate-input-encoding-profile-aggregate-derivation-shares-v1";
pub(crate) const ENCODED_AGGREGATE_LAYOUT_ID: &str =
    "encoded-aggregate-layout-encrypted-aggregate-input-v1";
pub(crate) const TOP_K_EVALUATOR_INPUT_LAYOUT_ID: &str =
    "top-k-evaluator-input-layout-encrypted-aggregate-input-v1";

// RNS data basis: 17 distinct ~47-bit primes (~2^47), each chosen so that
// p == 1 (mod 2N), guaranteeing a 2N-th root of unity exists (NTT-friendly).
pub(crate) const DATA_PRIMES: [u64; 17] = [
    140_737_487_306_753,
    140_737_486_716_929,
    140_737_486_520_321,
    140_737_485_864_961,
    140_737_484_685_313,
    140_737_483_898_881,
    140_737_482_981_377,
    140_737_481_801_729,
    140_737_481_342_977,
    140_737_480_949_761,
    140_737_480_359_937,
    140_737_479_639_041,
    140_737_476_100_097,
    140_737_472_299_009,
    140_737_471_971_329,
    140_737_471_774_721,
    140_737_471_578_113,
];

// Extra ~47-bit NTT-friendly prime (p == 1 mod 2N) for the "special" basis;
// the extended basis is the data primes plus this one (see all_moduli).
pub(crate) const SPECIAL_PRIME: u64 = 140_737_471_512_577;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BgvBasisKind {
    Data,
    Extended,
    Special,
}

impl BgvBasisKind {
    pub(crate) fn basis_id(self) -> &'static str {
        match self {
            Self::Data => DATA_BASIS_ID,
            Self::Extended => EXTENDED_BASIS_ID,
            Self::Special => SPECIAL_BASIS_ID,
        }
    }

    pub(crate) fn from_basis_id(basis_id: &str) -> Option<Self> {
        match basis_id {
            DATA_BASIS_ID => Some(Self::Data),
            EXTENDED_BASIS_ID => Some(Self::Extended),
            SPECIAL_BASIS_ID => Some(Self::Special),
            _ => None,
        }
    }

    pub(crate) fn all_moduli(self) -> Vec<u64> {
        match self {
            Self::Data => DATA_PRIMES.to_vec(),
            Self::Extended => {
                let mut moduli = DATA_PRIMES.to_vec();
                moduli.push(SPECIAL_PRIME);
                moduli
            }
            Self::Special => vec![SPECIAL_PRIME],
        }
    }

    pub(crate) fn moduli_for_level(self, level: usize) -> Option<Vec<u64>> {
        let moduli = self.all_moduli();
        let required_count = match self {
            Self::Special => {
                if level != 0 {
                    return None;
                }
                1
            }
            Self::Data | Self::Extended => level.checked_add(1)?,
        };
        if required_count == 0 || required_count > moduli.len() {
            return None;
        }

        Some(moduli.into_iter().take(required_count).collect())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RootParameters {
    pub(crate) modulus: u64,
    pub(crate) primitive_generator: u64,
    pub(crate) negacyclic_root: u64,
    pub(crate) cyclic_root: u64,
    pub(crate) inverse_negacyclic_root: u64,
    pub(crate) inverse_cyclic_root: u64,
    pub(crate) inverse_polynomial_degree: u64,
}

// Precomputed NTT roots per modulus: the negacyclic root (order 2N), the cyclic
// root (order N), both inverses, and N^{-1} mod p (`inverse_polynomial_degree`).
// Entry [0] is the plaintext modulus 65537 used by the batch (slot) encoder, NOT
// an RNS limb; entries [1..] cover the 17 data primes then the special prime.
pub(crate) const ROOT_PARAMETERS: [RootParameters; 19] = [
    RootParameters {
        modulus: 65_537,
        primitive_generator: 3,
        negacyclic_root: 3,
        cyclic_root: 9,
        inverse_negacyclic_root: 21_846,
        inverse_cyclic_root: 7_282,
        inverse_polynomial_degree: 65_535,
    },
    RootParameters {
        modulus: 140_737_487_306_753,
        primitive_generator: 5,
        negacyclic_root: 12_911_451_507_226,
        cyclic_root: 93_723_309_552_712,
        inverse_negacyclic_root: 130_505_950_573_576,
        inverse_cyclic_root: 44_699_367_863_049,
        inverse_polynomial_degree: 140_733_192_339_489,
    },
    RootParameters {
        modulus: 140_737_486_716_929,
        primitive_generator: 3,
        negacyclic_root: 102_030_113_402_742,
        cyclic_root: 17_242_864_935_881,
        inverse_negacyclic_root: 83_371_813_877_832,
        inverse_cyclic_root: 11_739_273_959_365,
        inverse_polynomial_degree: 140_733_191_749_683,
    },
    RootParameters {
        modulus: 140_737_486_520_321,
        primitive_generator: 3,
        negacyclic_root: 90_131_535_017_298,
        cyclic_root: 38_688_039_901_800,
        inverse_negacyclic_root: 131_445_856_353_889,
        inverse_cyclic_root: 88_985_802_969_849,
        inverse_polynomial_degree: 140_733_191_553_081,
    },
    RootParameters {
        modulus: 140_737_485_864_961,
        primitive_generator: 22,
        negacyclic_root: 67_019_031_613_957,
        cyclic_root: 14_447_980_014_284,
        inverse_negacyclic_root: 52_209_697_772_723,
        inverse_cyclic_root: 19_682_454_666_548,
        inverse_polynomial_degree: 140_733_190_897_741,
    },
    RootParameters {
        modulus: 140_737_484_685_313,
        primitive_generator: 7,
        negacyclic_root: 121_280_566_540_378,
        cyclic_root: 30_577_516_082_999,
        inverse_negacyclic_root: 119_751_583_459_724,
        inverse_cyclic_root: 118_052_601_370_180,
        inverse_polynomial_degree: 140_733_189_718_129,
    },
    RootParameters {
        modulus: 140_737_483_898_881,
        primitive_generator: 17,
        negacyclic_root: 31_587_914_748_636,
        cyclic_root: 57_552_056_243_204,
        inverse_negacyclic_root: 42_841_533_719_936,
        inverse_cyclic_root: 36_563_235_191_341,
        inverse_polynomial_degree: 140_733_188_931_721,
    },
    RootParameters {
        modulus: 140_737_482_981_377,
        primitive_generator: 3,
        negacyclic_root: 38_870_194_274_647,
        cyclic_root: 133_309_110_277_989,
        inverse_negacyclic_root: 26_238_621_883_931,
        inverse_cyclic_root: 109_897_763_483_833,
        inverse_polynomial_degree: 140_733_188_014_245,
    },
    RootParameters {
        modulus: 140_737_481_801_729,
        primitive_generator: 3,
        negacyclic_root: 41_413_690_248_180,
        cyclic_root: 75_907_514_258_475,
        inverse_negacyclic_root: 113_119_981_893_593,
        inverse_cyclic_root: 132_410_991_928_867,
        inverse_polynomial_degree: 140_733_186_834_633,
    },
    RootParameters {
        modulus: 140_737_481_342_977,
        primitive_generator: 10,
        negacyclic_root: 113_351_319_735_337,
        cyclic_root: 48_619_047_122_976,
        inverse_negacyclic_root: 126_635_937_702_239,
        inverse_cyclic_root: 69_304_163_240_567,
        inverse_polynomial_degree: 140_733_186_375_895,
    },
    RootParameters {
        modulus: 140_737_480_949_761,
        primitive_generator: 7,
        negacyclic_root: 668_139_469_488,
        cyclic_root: 56_166_715_052_059,
        inverse_negacyclic_root: 74_841_578_423_128,
        inverse_cyclic_root: 893_935_249_274,
        inverse_polynomial_degree: 140_733_185_982_691,
    },
    RootParameters {
        modulus: 140_737_480_359_937,
        primitive_generator: 5,
        negacyclic_root: 86_782_835_906_406,
        cyclic_root: 70_531_529_626_640,
        inverse_negacyclic_root: 2_452_176_960_272,
        inverse_cyclic_root: 12_476_317_757_875,
        inverse_polynomial_degree: 140_733_185_392_885,
    },
    RootParameters {
        modulus: 140_737_479_639_041,
        primitive_generator: 3,
        negacyclic_root: 22_776_626_750_770,
        cyclic_root: 114_465_156_464_394,
        inverse_negacyclic_root: 130_866_136_817_411,
        inverse_cyclic_root: 34_945_586_052_847,
        inverse_polynomial_degree: 140_733_184_672_011,
    },
    RootParameters {
        modulus: 140_737_476_100_097,
        primitive_generator: 3,
        negacyclic_root: 64_836_852_493_510,
        cyclic_root: 57_101_089_027_974,
        inverse_negacyclic_root: 123_350_160_863_661,
        inverse_cyclic_root: 119_340_254_097_140,
        inverse_polynomial_degree: 140_733_181_133_175,
    },
    RootParameters {
        modulus: 140_737_472_299_009,
        primitive_generator: 7,
        negacyclic_root: 6_663_473_190_143,
        cyclic_root: 28_371_830_496_152,
        inverse_negacyclic_root: 105_740_921_523_246,
        inverse_cyclic_root: 39_830_562_064_021,
        inverse_polynomial_degree: 140_733_177_332_203,
    },
    RootParameters {
        modulus: 140_737_471_971_329,
        primitive_generator: 3,
        negacyclic_root: 69_340_313_650_758,
        cyclic_root: 54_073_563_441_035,
        inverse_negacyclic_root: 55_017_234_105_836,
        inverse_cyclic_root: 23_656_973_184_513,
        inverse_polynomial_degree: 140_733_177_004_533,
    },
    RootParameters {
        modulus: 140_737_471_774_721,
        primitive_generator: 7,
        negacyclic_root: 31_294_116_819_091,
        cyclic_root: 8_735_737_369_517,
        inverse_negacyclic_root: 111_063_784_814_447,
        inverse_cyclic_root: 51_277_694_429_591,
        inverse_polynomial_degree: 140_733_176_807_931,
    },
    RootParameters {
        modulus: 140_737_471_578_113,
        primitive_generator: 3,
        negacyclic_root: 113_899_374_310_681,
        cyclic_root: 107_051_226_489_680,
        inverse_negacyclic_root: 2_069_711_608_863,
        inverse_cyclic_root: 135_517_210_731_467,
        inverse_polynomial_degree: 140_733_176_611_329,
    },
    RootParameters {
        modulus: 140_737_471_512_577,
        primitive_generator: 5,
        negacyclic_root: 119_544_567_422_932,
        cyclic_root: 23_508_862_735_215,
        inverse_negacyclic_root: 76_118_654_379_715,
        inverse_cyclic_root: 112_606_416_104_320,
        inverse_polynomial_degree: 140_733_176_545_795,
    },
];

pub(crate) fn root_parameters_for_modulus(modulus: u64) -> Option<RootParameters> {
    ROOT_PARAMETERS
        .iter()
        .copied()
        .find(|parameters| parameters.modulus == modulus)
}

pub(crate) fn data_prime_bit_length() -> u32 {
    DATA_PRIMES
        .iter()
        .map(|modulus| modulus_bit_length(*modulus))
        .max()
        .unwrap_or(0)
}

pub(crate) fn modulus_bit_length(modulus: u64) -> u32 {
    u64::BITS - modulus.leading_zeros()
}

pub(crate) fn moduli_bit_length_sum(moduli: impl IntoIterator<Item = u64>) -> usize {
    moduli
        .into_iter()
        .map(|modulus| {
            usize::try_from(modulus_bit_length(modulus)).expect("modulus bit length fits usize")
        })
        .sum()
}

pub(crate) fn data_basis_modulus_bits() -> usize {
    moduli_bit_length_sum(DATA_PRIMES)
}

pub(crate) fn extended_basis_modulus_bits() -> usize {
    moduli_bit_length_sum(DATA_PRIMES.into_iter().chain([SPECIAL_PRIME]))
}

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
        "aggregateShareLayoutId": AGGREGATE_SHARE_LAYOUT_ID,
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
            "layoutId": AGGREGATE_SHARE_LAYOUT_ID,
            "layoutBindingHash": batch_layout_binding_hash()?,
        }),
    )
}

pub(crate) fn layout_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "TargetBasisHash",
        &json!({
            "layoutId": AGGREGATE_SHARE_LAYOUT_ID,
            "profileHash": profile_hash()?,
            "slotCount": POLYNOMIAL_DEGREE,
            "coordinateField": "GF(65537)",
            "source": "AggregateDerivationShareCoordinates",
            "bridgePath": "EncryptedAggregateBridge-v1",
            "witnessPrivacy": "contributor-private-aggregate-shares",
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

pub(crate) fn ballot_share_layout_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "BallotShareLayoutProfileHash",
        &json!({
            "profileId": BALLOT_SHARE_LAYOUT_PROFILE_ID,
            "coordinateOrder": "score-share-then-one-hot-score-buckets-per-option",
            "coordinatesPerOption": 11,
            "field": "GF(65537)",
        }),
    )
}

pub(crate) fn aggregate_input_encoding_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "AggregateInputEncodingProfileHash",
        &json!({
            "profileId": AGGREGATE_INPUT_ENCODING_PROFILE_ID,
            "sourceRelation": "aggregate derivation",
            "sourceObject": "AggregateDerivationShareCoordinates",
            "bridgePath": "EncryptedAggregateBridge-v1",
            "witnessPrivacy": "contributor-private-aggregate-shares",
        }),
    )
}

pub(crate) fn encoded_aggregate_layout_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncodedAggregateLayoutHash",
        &json!({
            "layoutId": ENCODED_AGGREGATE_LAYOUT_ID,
            "encryptedAggregateInputLayoutHash": layout_hash()?,
            "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash()?,
            "slotCount": POLYNOMIAL_DEGREE,
            "scalarOnlyAggregateLayout": false,
        }),
    )
}

pub(crate) fn top_k_evaluator_input_layout_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "TopKEvaluatorInputLayoutHash",
        &json!({
            "layoutId": TOP_K_EVALUATOR_INPUT_LAYOUT_ID,
            "encryptedAggregateInputLayoutHash": layout_hash()?,
            "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
            "acceptedEvaluatorInput": "encrypted-aggregate-histogram-score-coordinates",
            "rejectScalarOnlyAggregateLayouts": true,
        }),
    )
}

pub(crate) fn batch_layout_binding_value() -> CanonicalResult<Value> {
    Ok(json!({
        "layoutKind": BATCH_LAYOUT_KIND,
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()?,
        "ballotShareLayoutProfileHash": ballot_share_layout_profile_hash()?,
        "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash()?,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash()?,
        "encryptedAggregateInputLayoutHash": layout_hash()?,
        "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash()?,
        "coordinateOrder": "score-share-then-one-hot-score-buckets-per-option",
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
            "encodeEncryptedAggregateInput",
            "validateCoefficientDomainPlaintext",
            "validateCoefficientDomainCiphertext",
            "homomorphicAggregateShareAddition",
            "interpolationCoefficientScalarMultiplication",
            "encryptedAggregateReconstruction",
            "scoreBitDerivationCircuitInputPreparation",
            "comparisonInputDerivationCircuitInputPreparation",
            "bitSlicedGreaterThanEqualComparisonSupport",
            "encryptedRankAccumulationSupport",
            "publicSlotMaskApplication",
            "encryptedSparseTargetProjectionSupport",
            "canonicalTargetCiphertextSelection"
        ],
        "forbiddenOperations": [
            "rawDecrypt",
            "rawThresholdDecrypt",
            "rawRnsLimbAccess",
            "rawNttTranscriptRoot",
            "scalarDegree360Comparator",
            "uncertifiedScoreBitDerivationOperation",
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
    use super::{
        BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIME,
        aggregate_input_encoding_profile_hash, allowed_operation_registry_hash,
        ballot_score_encoding_profile_hash, ballot_share_layout_profile_hash, batch_encoder_hash,
        batch_layout_binding_hash, batch_layout_binding_value,
        canonical_ciphertext_convention_hash, data_basis_modulus_bits,
        encoded_aggregate_layout_hash, extended_basis_modulus_bits, layout_hash,
        moduli_bit_length_sum, profile_hash, root_parameters_for_modulus,
        security_estimator_input_hash, top_k_evaluator_input_layout_hash,
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
            ("layout", layout_hash()),
            ("batch layout binding", batch_layout_binding_hash()),
            (
                "ballot score encoding profile",
                ballot_score_encoding_profile_hash(),
            ),
            (
                "ballot share layout profile",
                ballot_share_layout_profile_hash(),
            ),
            (
                "aggregate input encoding profile",
                aggregate_input_encoding_profile_hash(),
            ),
            ("encoded aggregate layout", encoded_aggregate_layout_hash()),
            (
                "top-k evaluator input layout",
                top_k_evaluator_input_layout_hash(),
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
            "EncryptedAggregateInputEncodedScoreLayout-v1"
        );
        assert_eq!(binding["scalarOnlyAggregateLayout"], false);
        assert_eq!(
            binding["coordinateOrder"],
            "score-share-then-one-hot-score-buckets-per-option"
        );
        assert_eq!(binding["scoreBucketCount"], 10);
        assert!(
            binding["encryptedAggregateInputLayoutHash"]
                .as_str()
                .expect("target hash")
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }
}
