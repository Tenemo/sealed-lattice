use super::DATA_BASIS_ID;
#[cfg(test)]
use super::{EXTENDED_BASIS_ID, SPECIAL_BASIS_ID};

// Ordered data basis. The eight-prime prefix is the target basis; the
// remaining primes carry only the evaluator depth preceding target release.
pub(crate) const DATA_PRIMES: [u64; 23] = [
    1_953_759_233,
    2_256_928_769,
    2_408_513_537,
    2_610_626_561,
    2_661_154_817,
    3_014_852_609,
    3_031_695_361,
    3_368_550_401,
    84_213_761,
    235_798_529,
    336_855_041,
    1_010_565_121,
    690_552_833,
    1_313_734_657,
    1_397_948_417,
    437_911_553,
    404_226_049,
    606_339_073,
    1_061_093_377,
    1_819_017_217,
    555_810_817,
    1_869_545_473,
    1_903_230_977,
];

// Ordered special basis for the selected three-prime hybrid key switch.
pub(crate) const SPECIAL_PRIMES: [u64; 3] = [275_513_737_217, 275_530_579_969, 275_968_491_521];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BgvBasisKind {
    Data,
    #[cfg(test)]
    Extended,
    #[cfg(test)]
    Special,
}

impl BgvBasisKind {
    pub(crate) fn basis_id(self) -> &'static str {
        match self {
            Self::Data => DATA_BASIS_ID,
            #[cfg(test)]
            Self::Extended => EXTENDED_BASIS_ID,
            #[cfg(test)]
            Self::Special => SPECIAL_BASIS_ID,
        }
    }

    pub(crate) fn from_basis_id(basis_id: &str) -> Option<Self> {
        match basis_id {
            DATA_BASIS_ID => Some(Self::Data),
            #[cfg(test)]
            EXTENDED_BASIS_ID => Some(Self::Extended),
            #[cfg(test)]
            SPECIAL_BASIS_ID => Some(Self::Special),
            _ => None,
        }
    }

    pub(crate) fn all_moduli(self) -> Vec<u64> {
        match self {
            Self::Data => DATA_PRIMES.to_vec(),
            #[cfg(test)]
            Self::Extended => {
                let mut moduli = DATA_PRIMES.to_vec();
                moduli.extend(SPECIAL_PRIMES);
                moduli
            }
            #[cfg(test)]
            Self::Special => SPECIAL_PRIMES.to_vec(),
        }
    }

    pub(crate) fn moduli_for_level(self, level: usize) -> Option<Vec<u64>> {
        let moduli = self.all_moduli();
        let required_count = level.checked_add(1)?;
        if required_count > moduli.len() {
            return None;
        }
        Some(moduli.into_iter().take(required_count).collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootParameters {
    pub(crate) modulus: u64,
    pub(crate) primitive_generator: u64,
    pub(crate) negacyclic_root: u64,
    pub(crate) cyclic_root: u64,
    pub(crate) inverse_negacyclic_root: u64,
    pub(crate) inverse_cyclic_root: u64,
    pub(crate) inverse_polynomial_degree: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NttTransformParameters {
    pub(crate) transform_degree: usize,
    pub(crate) roots: RootParameters,
}

// Exact-order roots for the data and special moduli, in canonical suite order.
// The plaintext modulus is intentionally absent: F_257 does not contain a
// primitive 2N-th root and is used through degree-256 extension lanes.
pub(crate) const ROOT_PARAMETERS: [RootParameters; 26] = [
    RootParameters {
        modulus: 1_953_759_233,
        primitive_generator: 3,
        negacyclic_root: 1_761_859_130,
        cyclic_root: 1_760_935_246,
        inverse_negacyclic_root: 219_990_667,
        inverse_cyclic_root: 1_560_915_740,
        inverse_polynomial_degree: 1_953_699_609,
    },
    RootParameters {
        modulus: 2_256_928_769,
        primitive_generator: 3,
        negacyclic_root: 980_872_601,
        cyclic_root: 1_433_924_009,
        inverse_negacyclic_root: 2_106_951_999,
        inverse_cyclic_root: 958_879_872,
        inverse_polynomial_degree: 2_256_859_893,
    },
    RootParameters {
        modulus: 2_408_513_537,
        primitive_generator: 3,
        negacyclic_root: 1_919_377_906,
        cyclic_root: 1_677_050_648,
        inverse_negacyclic_root: 1_585_374_821,
        inverse_cyclic_root: 1_641_235_976,
        inverse_polynomial_degree: 2_408_440_035,
    },
    RootParameters {
        modulus: 2_610_626_561,
        primitive_generator: 3,
        negacyclic_root: 1_682_935_434,
        cyclic_root: 303_373_158,
        inverse_negacyclic_root: 1_897_325_484,
        inverse_cyclic_root: 2_576_799_511,
        inverse_polynomial_degree: 2_610_546_891,
    },
    RootParameters {
        modulus: 2_661_154_817,
        primitive_generator: 3,
        negacyclic_root: 648_106_888,
        cyclic_root: 2_094_857_510,
        inverse_negacyclic_root: 2_116_662_423,
        inverse_cyclic_root: 526_079_816,
        inverse_polynomial_degree: 2_661_073_605,
    },
    RootParameters {
        modulus: 3_014_852_609,
        primitive_generator: 3,
        negacyclic_root: 2_251_479_593,
        cyclic_root: 76_139_117,
        inverse_negacyclic_root: 2_677_916_699,
        inverse_cyclic_root: 910_507_728,
        inverse_polynomial_degree: 3_014_760_603,
    },
    RootParameters {
        modulus: 3_031_695_361,
        primitive_generator: 13,
        negacyclic_root: 1_079_980_198,
        cyclic_root: 2_384_480_967,
        inverse_negacyclic_root: 464_066_707,
        inverse_cyclic_root: 648_673_818,
        inverse_polynomial_degree: 3_031_602_841,
    },
    RootParameters {
        modulus: 3_368_550_401,
        primitive_generator: 3,
        negacyclic_root: 836_259_172,
        cyclic_root: 1_118_142_540,
        inverse_negacyclic_root: 1_651_651_479,
        inverse_cyclic_root: 2_757_524_809,
        inverse_polynomial_degree: 3_368_447_601,
    },
    RootParameters {
        modulus: 84_213_761,
        primitive_generator: 3,
        negacyclic_root: 69_637_361,
        cyclic_root: 33_743_239,
        inverse_negacyclic_root: 5_536_146,
        inverse_cyclic_root: 72_141_215,
        inverse_polynomial_degree: 84_211_191,
    },
    RootParameters {
        modulus: 235_798_529,
        primitive_generator: 3,
        negacyclic_root: 79_731_215,
        cyclic_root: 82_750_823,
        inverse_negacyclic_root: 87_090_166,
        inverse_cyclic_root: 115_302_382,
        inverse_polynomial_degree: 235_791_333,
    },
    RootParameters {
        modulus: 336_855_041,
        primitive_generator: 3,
        negacyclic_root: 330_773_671,
        cyclic_root: 82_980_551,
        inverse_negacyclic_root: 205_224_299,
        inverse_cyclic_root: 175_408_121,
        inverse_polynomial_degree: 336_844_761,
    },
    RootParameters {
        modulus: 1_010_565_121,
        primitive_generator: 7,
        negacyclic_root: 382_395_118,
        cyclic_root: 988_097_923,
        inverse_negacyclic_root: 308_432_337,
        inverse_cyclic_root: 826_211_861,
        inverse_polynomial_degree: 1_010_534_281,
    },
    RootParameters {
        modulus: 690_552_833,
        primitive_generator: 3,
        negacyclic_root: 93_925_249,
        cyclic_root: 466_464_735,
        inverse_negacyclic_root: 648_136_415,
        inverse_cyclic_root: 666_462_017,
        inverse_polynomial_degree: 690_531_759,
    },
    RootParameters {
        modulus: 1_313_734_657,
        primitive_generator: 10,
        negacyclic_root: 944_282_255,
        cyclic_root: 4_704_563,
        inverse_negacyclic_root: 389_721_370,
        inverse_cyclic_root: 1_270_878_076,
        inverse_polynomial_degree: 1_313_694_565,
    },
    RootParameters {
        modulus: 1_397_948_417,
        primitive_generator: 3,
        negacyclic_root: 889_564_382,
        cyclic_root: 689_809_088,
        inverse_negacyclic_root: 127_540_313,
        inverse_cyclic_root: 864_029_135,
        inverse_polynomial_degree: 1_397_905_755,
    },
    RootParameters {
        modulus: 437_911_553,
        primitive_generator: 3,
        negacyclic_root: 181_891_374,
        cyclic_root: 117_757_136,
        inverse_negacyclic_root: 382_567_537,
        inverse_cyclic_root: 11_073_240,
        inverse_polynomial_degree: 437_898_189,
    },
    RootParameters {
        modulus: 404_226_049,
        primitive_generator: 7,
        negacyclic_root: 305_149_623,
        cyclic_root: 127_844_060,
        inverse_negacyclic_root: 374_458_496,
        inverse_cyclic_root: 55_786_517,
        inverse_polynomial_degree: 404_213_713,
    },
    RootParameters {
        modulus: 606_339_073,
        primitive_generator: 5,
        negacyclic_root: 6_489_195,
        cyclic_root: 9_467_248,
        inverse_negacyclic_root: 436_194_360,
        inverse_cyclic_root: 279_260_856,
        inverse_polynomial_degree: 606_320_569,
    },
    RootParameters {
        modulus: 1_061_093_377,
        primitive_generator: 5,
        negacyclic_root: 1_027_110_081,
        cyclic_root: 86_111_372,
        inverse_negacyclic_root: 369_142_281,
        inverse_cyclic_root: 443_312_685,
        inverse_polynomial_degree: 1_061_060_995,
    },
    RootParameters {
        modulus: 1_819_017_217,
        primitive_generator: 5,
        negacyclic_root: 447_201_012,
        cyclic_root: 454_131_346,
        inverse_negacyclic_root: 802_633_832,
        inverse_cyclic_root: 739_877_170,
        inverse_polynomial_degree: 1_818_961_705,
    },
    RootParameters {
        modulus: 555_810_817,
        primitive_generator: 5,
        negacyclic_root: 549_634_119,
        cyclic_root: 187_893_507,
        inverse_negacyclic_root: 12_408_676,
        inverse_cyclic_root: 81_061_100,
        inverse_polynomial_degree: 555_793_855,
    },
    RootParameters {
        modulus: 1_869_545_473,
        primitive_generator: 19,
        negacyclic_root: 1_423_727_002,
        cyclic_root: 313_757_261,
        inverse_negacyclic_root: 1_424_190_302,
        inverse_cyclic_root: 1_204_948_819,
        inverse_polynomial_degree: 1_869_488_419,
    },
    RootParameters {
        modulus: 1_903_230_977,
        primitive_generator: 3,
        negacyclic_root: 1_676_846_412,
        cyclic_root: 1_618_993_396,
        inverse_negacyclic_root: 423_399_217,
        inverse_cyclic_root: 1_067_027_064,
        inverse_polynomial_degree: 1_903_172_895,
    },
    RootParameters {
        modulus: 275_513_737_217,
        primitive_generator: 3,
        negacyclic_root: 223_610_281_660,
        cyclic_root: 196_699_893_160,
        inverse_negacyclic_root: 58_295_448_179,
        inverse_cyclic_root: 12_953_331_091,
        inverse_polynomial_degree: 275_505_329_205,
    },
    RootParameters {
        modulus: 275_530_579_969,
        primitive_generator: 23,
        negacyclic_root: 165_065_678_069,
        cyclic_root: 260_579_283_330,
        inverse_negacyclic_root: 5_459_293_727,
        inverse_cyclic_root: 28_201_291_854,
        inverse_polynomial_degree: 275_522_171_443,
    },
    RootParameters {
        modulus: 275_968_491_521,
        primitive_generator: 3,
        negacyclic_root: 111_618_999_981,
        cyclic_root: 249_573_721_771,
        inverse_negacyclic_root: 202_057_739_656,
        inverse_cyclic_root: 108_389_161_130,
        inverse_polynomial_degree: 275_960_069_631,
    },
];

pub(super) const MULTIPLICATIVE_GROUP_PRIME_FACTORS: [&[u64]; ROOT_PARAMETERS.len()] = [
    &[2, 29, 257],
    &[2, 67, 257],
    &[2, 11, 13, 257],
    &[2, 5, 31, 257],
    &[2, 79, 257],
    &[2, 179, 257],
    &[2, 3, 5, 257],
    &[2, 5, 257],
    &[2, 5, 257],
    &[2, 7, 257],
    &[2, 5, 257],
    &[2, 3, 5, 257],
    &[2, 41, 257],
    &[2, 3, 13, 257],
    &[2, 83, 257],
    &[2, 13, 257],
    &[2, 3, 257],
    &[2, 3, 257],
    &[2, 3, 7, 257],
    &[2, 3, 257],
    &[2, 3, 11, 257],
    &[2, 3, 37, 257],
    &[2, 113, 257],
    &[2, 257, 8_179],
    &[2, 3, 7, 19, 41, 257],
    &[2, 5, 29, 113, 257],
];

pub(crate) fn root_parameters_for_modulus(modulus: u64) -> Option<RootParameters> {
    ROOT_PARAMETERS
        .iter()
        .copied()
        .find(|parameters| parameters.modulus == modulus)
}
