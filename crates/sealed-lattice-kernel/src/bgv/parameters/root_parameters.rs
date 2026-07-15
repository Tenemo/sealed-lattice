use super::{DATA_BASIS_ID, EXTENDED_BASIS_ID, SPECIAL_BASIS_ID};

// RNS data basis: 17 distinct ~47-bit primes. Every prime is one modulo both
// 2N and the plaintext modulus. The first condition supplies the exact-order
// NTT roots; the second makes every target-level prefix product one modulo the
// plaintext modulus, which is required by the exact target conversion.
pub(crate) const DATA_PRIMES: [u64; 17] = [
    140_700_980_543_489,
    140_546_359_361_537,
    140_507_704_066_049,
    140_417_508_376_577,
    140_396_033_212_417,
    140_383_148_113_921,
    140_365_967_982_593,
    140_280_067_325_953,
    140_061_020_651_521,
    139_992_300_126_209,
    139_880_629_272_577,
    139_764_663_386_113,
    139_708_827_959_297,
    139_670_172_663_809,
    139_541_321_678_849,
    139_451_125_989_377,
    139_399_585_595_393,
];

// Extra ~47-bit NTT-friendly prime (p == 1 mod 2N) for the "special" basis;
// the extended basis is the 17 data primes plus this one (see all_moduli).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootParameters {
    pub(crate) modulus: u64,
    // Full multiplicative generator of F_p^* (order p - 1), not merely some root.
    // The trustee evaluation-key FRI proof uses this as the evaluation-coset
    // offset, which must lie outside every 2-power subgroup so the coset stays
    // disjoint from the trace subgroup H; only a full generator guarantees that.
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
        modulus: 140_700_980_543_489,
        primitive_generator: 3,
        negacyclic_root: 16_687_780_685_375,
        cyclic_root: 97_722_610_514_221,
        inverse_negacyclic_root: 89_211_910_258_724,
        inverse_cyclic_root: 44_968_602_890_388,
        inverse_polynomial_degree: 140_696_686_690_323,
    },
    RootParameters {
        modulus: 140_546_359_361_537,
        primitive_generator: 3,
        negacyclic_root: 136_357_786_803_300,
        cyclic_root: 31_318_859_193_247,
        inverse_negacyclic_root: 67_432_909_689_764,
        inverse_cyclic_root: 109_345_400_283_080,
        inverse_polynomial_degree: 140_542_070_227_035,
    },
    RootParameters {
        modulus: 140_507_704_066_049,
        primitive_generator: 3,
        negacyclic_root: 38_328_962_234_904,
        cyclic_root: 41_917_627_780_733,
        inverse_negacyclic_root: 33_150_998_578_665,
        inverse_cyclic_root: 113_380_937_769_991,
        inverse_polynomial_degree: 140_503_416_111_213,
    },
    RootParameters {
        modulus: 140_417_508_376_577,
        primitive_generator: 3,
        negacyclic_root: 126_568_055_701_239,
        cyclic_root: 130_145_597_766_153,
        inverse_negacyclic_root: 115_836_241_950_913,
        inverse_cyclic_root: 101_529_969_324_658,
        inverse_polynomial_degree: 140_413_223_174_295,
    },
    RootParameters {
        modulus: 140_396_033_212_417,
        primitive_generator: 5,
        negacyclic_root: 126_452_383_814_733,
        cyclic_root: 102_832_014_941_841,
        inverse_negacyclic_root: 31_477_384_366_740,
        inverse_cyclic_root: 84_673_156_957_959,
        inverse_polynomial_degree: 140_391_748_665_505,
    },
    RootParameters {
        modulus: 140_383_148_113_921,
        primitive_generator: 7,
        negacyclic_root: 11_770_877_866_783,
        cyclic_root: 47_769_252_738_448,
        inverse_negacyclic_root: 111_401_978_772_712,
        inverse_cyclic_root: 9_833_943_237_684,
        inverse_polynomial_degree: 140_378_863_960_231,
    },
    RootParameters {
        modulus: 140_365_967_982_593,
        primitive_generator: 3,
        negacyclic_root: 86_706_947_507_190,
        cyclic_root: 16_812_016_290_078,
        inverse_negacyclic_root: 97_247_024_152_901,
        inverse_cyclic_root: 94_708_852_841_171,
        inverse_polynomial_degree: 140_361_684_353_199,
    },
    RootParameters {
        modulus: 140_280_067_325_953,
        primitive_generator: 5,
        negacyclic_root: 17_609_970_699_072,
        cyclic_root: 72_791_348_450_429,
        inverse_negacyclic_root: 94_838_627_210_578,
        inverse_cyclic_root: 36_981_325_689_382,
        inverse_polynomial_degree: 140_275_786_318_039,
    },
    RootParameters {
        modulus: 140_061_020_651_521,
        primitive_generator: 13,
        negacyclic_root: 110_213_631_025_001,
        cyclic_root: 69_017_617_532_382,
        inverse_negacyclic_root: 109_519_493_375_659,
        inverse_cyclic_root: 85_462_568_995_950,
        inverse_polynomial_degree: 140_056_746_328_381,
    },
    RootParameters {
        modulus: 139_992_300_126_209,
        primitive_generator: 3,
        negacyclic_root: 58_941_149_320_408,
        cyclic_root: 31_801_618_288_904,
        inverse_negacyclic_root: 25_741_484_799_159,
        inverse_cyclic_root: 46_871_273_056_771,
        inverse_polynomial_degree: 139_988_027_900_253,
    },
    RootParameters {
        modulus: 139_880_629_272_577,
        primitive_generator: 5,
        negacyclic_root: 83_624_812_741_732,
        cyclic_root: 33_658_277_142_102,
        inverse_negacyclic_root: 130_410_567_915_970,
        inverse_cyclic_root: 79_242_117_731_142,
        inverse_polynomial_degree: 139_876_360_454_545,
    },
    RootParameters {
        modulus: 139_764_663_386_113,
        primitive_generator: 5,
        negacyclic_root: 59_898_720_508_603,
        cyclic_root: 13_854_560_121_647,
        inverse_negacyclic_root: 52_361_351_151_504,
        inverse_cyclic_root: 22_469_298_407_859,
        inverse_polynomial_degree: 139_760_398_107_079,
    },
    RootParameters {
        modulus: 139_708_827_959_297,
        primitive_generator: 5,
        negacyclic_root: 31_853_226_156_948,
        cyclic_root: 11_784_646_204_110,
        inverse_negacyclic_root: 132_298_514_270_335,
        inverse_cyclic_root: 28_586_791_526_244,
        inverse_polynomial_degree: 139_704_564_384_225,
    },
    RootParameters {
        modulus: 139_670_172_663_809,
        primitive_generator: 3,
        negacyclic_root: 119_804_178_553_556,
        cyclic_root: 16_666_590_963_331,
        inverse_negacyclic_root: 136_673_138_804_518,
        inverse_cyclic_root: 94_380_633_999_976,
        inverse_polynomial_degree: 139_665_910_268_403,
    },
    RootParameters {
        modulus: 139_541_321_678_849,
        primitive_generator: 3,
        negacyclic_root: 22_276_058_295_617,
        cyclic_root: 30_550_140_409_863,
        inverse_negacyclic_root: 136_517_189_190_270,
        inverse_cyclic_root: 94_548_538_704_024,
        inverse_polynomial_degree: 139_537_063_215_663,
    },
    RootParameters {
        modulus: 139_451_125_989_377,
        primitive_generator: 3,
        negacyclic_root: 20_304_118_977_985,
        cyclic_root: 121_919_583_531_314,
        inverse_negacyclic_root: 69_683_640_852_288,
        inverse_cyclic_root: 123_387_035_280_207,
        inverse_polynomial_degree: 139_446_870_278_745,
    },
    RootParameters {
        modulus: 139_399_585_595_393,
        primitive_generator: 3,
        negacyclic_root: 135_201_556_032_499,
        cyclic_root: 139_255_689_455_295,
        inverse_negacyclic_root: 93_985_186_705_659,
        inverse_cyclic_root: 118_121_655_012_779,
        inverse_polynomial_degree: 139_395_331_457_649,
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
