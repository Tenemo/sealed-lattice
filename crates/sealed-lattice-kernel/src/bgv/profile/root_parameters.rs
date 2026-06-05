use super::{DATA_BASIS_ID, EXTENDED_BASIS_ID, SPECIAL_BASIS_ID};

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
