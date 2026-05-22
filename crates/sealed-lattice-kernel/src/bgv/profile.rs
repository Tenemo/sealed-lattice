use serde_json::{Value, json};

use crate::{
    encoding::CanonicalResult,
    hashing::{derive_protocol_digest, hash512_hex},
};

pub(crate) const PROFILE_ID: &str = "sealed-lattice-bgv-rns-v1";
pub(crate) const BACKEND_PROFILE_ID: &str = "sealed-lattice-rust-wasm-bgv-rns-v1";
pub(crate) const POLYNOMIAL_DEGREE: usize = 32_768;
pub(crate) const PLAINTEXT_MODULUS: u64 = 65_537;
pub(crate) const DATA_BASIS_ID: &str = "sealed-lattice-bgv-rns-data-basis-v1";
pub(crate) const EXTENDED_BASIS_ID: &str = "sealed-lattice-bgv-rns-extended-basis-v1";
pub(crate) const SPECIAL_BASIS_ID: &str = "sealed-lattice-bgv-rns-special-basis-v1";
pub(crate) const AGGREGATE_SHARE_LAYOUT_ID: &str =
    "encrypted-aggregate-target-basis-data-layout-v1";
pub(crate) const BATCH_ENCODER_ID: &str = "BGVBatchEncode_65537-v1";
pub(crate) const CANONICAL_CIPHERTEXT_CONVENTION_ID: &str =
    "sealed-lattice-coefficient-domain-rns-ciphertext-v1";
pub(crate) const OPERATION_REGISTRY_ID: &str = "sealed-lattice-bgv-allowed-ops-v1";

pub(crate) const DATA_PRIMES: [u64; 16] = [
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
];

pub(crate) const SPECIAL_PRIME: u64 = 140_737_471_578_113;

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
            Self::Special => 1,
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

pub(crate) const ROOT_PARAMETERS: [RootParameters; 18] = [
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
];

pub(crate) fn root_parameters_for_modulus(modulus: u64) -> Option<RootParameters> {
    ROOT_PARAMETERS
        .iter()
        .copied()
        .find(|parameters| parameters.modulus == modulus)
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
        "dataPrimeBitLength": 47,
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

pub(crate) fn profile_digest() -> CanonicalResult<String> {
    derive_protocol_digest("BGVProfileDigest", &selected_profile_value())
}

pub(crate) fn backend_profile_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "RustBgvBackendProfileDigest",
        &json!({
            "backendProfileId": BACKEND_PROFILE_ID,
            "profileDigest": profile_digest()?,
            "ownedBy": "sealed-lattice-rust-wasm",
            "referenceOracleStatus": "development-only-not-runtime",
        }),
    )
}

pub(crate) fn batch_encoder_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "BGVBatchEncoderDigest",
        &json!({
            "encoderId": BATCH_ENCODER_ID,
            "profileDigest": profile_digest()?,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "layoutId": AGGREGATE_SHARE_LAYOUT_ID,
        }),
    )
}

pub(crate) fn layout_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "TargetBasisDigest",
        &json!({
            "layoutId": AGGREGATE_SHARE_LAYOUT_ID,
            "profileDigest": profile_digest()?,
            "slotCount": POLYNOMIAL_DEGREE,
            "coordinateField": "GF(65537)",
            "source": "M6AggregateShareCoordinates",
            "bridgePath": "EncryptedAggregateBridge-v1",
            "witnessPrivacy": "contributor-private-aggregate-shares",
        }),
    )
}

pub(crate) fn canonical_ciphertext_convention_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "CanonicalCiphertextConventionDigest",
        &json!({
            "conventionId": CANONICAL_CIPHERTEXT_CONVENTION_ID,
            "profileDigest": profile_digest()?,
            "coefficientDomainOnly": true,
            "lattigoSerializationAccepted": false,
        }),
    )
}

pub(crate) fn allowed_operation_registry_value() -> CanonicalResult<Value> {
    Ok(json!({
        "operationRegistryId": OPERATION_REGISTRY_ID,
        "profileDigest": profile_digest()?,
        "batchEncoderDigest": batch_encoder_digest()?,
        "allowedOperations": [
            "encodeEncryptedAggregateShareTargetBasisData",
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
            "lattigoRuntimeObjectImport",
            "referenceOracleVectorAcceptance",
            "genericFheApiSurface"
        ],
    }))
}

pub(crate) fn allowed_operation_registry_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "AllowedEvaluatorOpsDigest",
        &allowed_operation_registry_value()?,
    )
}

pub(crate) fn security_estimator_input_digest() -> CanonicalResult<String> {
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
        batch_encoder_digest, layout_digest, profile_digest, root_parameters_for_modulus,
    };
    use crate::bgv::modular_arithmetic::is_prime_for_tests;

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
                .moduli_for_level(99)
                .expect("special basis ignores levels"),
            vec![SPECIAL_PRIME]
        );
    }

    #[test]
    fn selected_profile_digests_are_stable_hex_roots() {
        for digest in [profile_digest(), batch_encoder_digest(), layout_digest()] {
            let digest = digest.expect("digest should derive");
            assert_eq!(digest.len(), 128);
            assert!(
                digest
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
            );
        }
    }
}
