use super::DATA_BASIS_ID;
#[cfg(test)]
use super::{EXTENDED_BASIS_ID, SPECIAL_BASIS_ID};

// Ordered RNS data basis. Every prime is one modulo 2N and the plaintext
// modulus. The six-prime prefix is the exact target basis; the remaining
// primes carry the evaluator depth before its final projection.
pub(crate) const DATA_PRIMES: [u64; 26] = [
    8_349_427_040_257,
    8_040_189_001_729,
    7_318_633_578_497,
    3_401_618_423_809,
    618_476_077_057,
    9_586_379_194_369,
    16_676_279_703_699_457,
    16_675_970_465_660_929,
    16_675_867_386_314_753,
    16_674_630_434_160_641,
    16_674_115_037_429_761,
    16_673_187_323_314_177,
    16_672_259_609_198_593,
    16_671_331_895_083_009,
    16_667_930_276_659_201,
    16_665_662_531_043_329,
    16_663_807_102_812_161,
    16_661_333_198_503_937,
    16_660_714_722_426_881,
    16_659_787_008_311_297,
    16_657_725_421_387_777,
    16_657_106_945_310_721,
    16_655_766_913_810_433,
    16_653_602_247_540_737,
    27_109_868_044_289,
    25_975_995_236_353,
];

// Ordered special basis for the three-block hybrid key switch.
pub(crate) const SPECIAL_PRIMES: [u64; 9] = [
    9_223_372_036_844_421_121,
    9_223_372_036_836_950_017,
    9_223_372_036_835_770_369,
    9_223_372_036_833_673_217,
    9_223_372_036_833_411_073,
    9_223_372_036_829_347_841,
    9_223_372_036_827_119_617,
    9_223_372_036_824_629_249,
    9_223_372_036_818_075_649,
];

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

// Precomputed exact-order NTT roots for the plaintext, data, and special
// moduli in their canonical suite order.
pub(crate) const ROOT_PARAMETERS: [RootParameters; 36] = [
    RootParameters {
        modulus: 786_433,
        primitive_generator: 10,
        negacyclic_root: 213_567,
        cyclic_root: 108_788,
        inverse_negacyclic_root: 430_889,
        inverse_cyclic_root: 295_516,
        inverse_polynomial_degree: 786_421,
    },
    RootParameters {
        modulus: 8_349_427_040_257,
        primitive_generator: 5,
        negacyclic_root: 4_684_565_936_429,
        cyclic_root: 3_324_145_587_744,
        inverse_negacyclic_root: 5_061_513_331_702,
        inverse_cyclic_root: 3_758_670_978_960,
        inverse_polynomial_degree: 8_349_299_638_111,
    },
    RootParameters {
        modulus: 8_040_189_001_729,
        primitive_generator: 14,
        negacyclic_root: 4_998_008_443_013,
        cyclic_root: 4_049_504_197_441,
        inverse_negacyclic_root: 848_915_674_046,
        inverse_cyclic_root: 219_244_804_825,
        inverse_polynomial_degree: 8_040_066_318_181,
    },
    RootParameters {
        modulus: 7_318_633_578_497,
        primitive_generator: 3,
        negacyclic_root: 2_438_395_357_956,
        cyclic_root: 6_825_752_423_505,
        inverse_negacyclic_root: 7_264_156_878_781,
        inverse_cyclic_root: 7_019_470_544_660,
        inverse_polynomial_degree: 7_318_521_905_011,
    },
    RootParameters {
        modulus: 3_401_618_423_809,
        primitive_generator: 19,
        negacyclic_root: 2_696_798_599_359,
        cyclic_root: 3_328_896_615_395,
        inverse_negacyclic_root: 3_146_134_521_275,
        inverse_cyclic_root: 358_319_469_927,
        inverse_polynomial_degree: 3_401_566_519_231,
    },
    RootParameters {
        modulus: 618_476_077_057,
        primitive_generator: 5,
        negacyclic_root: 451_386_994_344,
        cyclic_root: 32_959_801_825,
        inverse_negacyclic_root: 324_007_732_850,
        inverse_cyclic_root: 426_513_756_026,
        inverse_polynomial_degree: 618_466_639_861,
    },
    RootParameters {
        modulus: 9_586_379_194_369,
        primitive_generator: 7,
        negacyclic_root: 2_197_099_922_110,
        cyclic_root: 6_310_396_598_049,
        inverse_negacyclic_root: 4_894_203_554_817,
        inverse_cyclic_root: 8_371_588_995_040,
        inverse_polynomial_degree: 9_586_232_917_831,
    },
    RootParameters {
        modulus: 16_676_279_703_699_457,
        primitive_generator: 5,
        negacyclic_root: 7_834_768_389_746_096,
        cyclic_root: 5_767_485_884_536_668,
        inverse_negacyclic_root: 13_941_177_528_552_499,
        inverse_cyclic_root: 4_793_380_090_454_602,
        inverse_polynomial_degree: 16_676_025_243_865_111,
    },
    RootParameters {
        modulus: 16_675_970_465_660_929,
        primitive_generator: 13,
        negacyclic_root: 13_445_439_886_948_988,
        cyclic_root: 3_421_737_261_263_805,
        inverse_negacyclic_root: 14_522_614_466_642_609,
        inverse_cyclic_root: 14_157_073_848_122_620,
        inverse_polynomial_degree: 16_675_716_010_545_181,
    },
    RootParameters {
        modulus: 16_675_867_386_314_753,
        primitive_generator: 3,
        negacyclic_root: 13_629_282_752_853_261,
        cyclic_root: 9_817_448_981_373_944,
        inverse_negacyclic_root: 13_278_868_281_128_375,
        inverse_cyclic_root: 8_686_770_651_008_870,
        inverse_polynomial_degree: 16_675_612_932_771_871,
    },
    RootParameters {
        modulus: 16_674_630_434_160_641,
        primitive_generator: 3,
        negacyclic_root: 13_792_028_717_402_223,
        cyclic_root: 13_994_535_088_449_338,
        inverse_negacyclic_root: 3_607_920_553_663_801,
        inverse_cyclic_root: 11_512_560_352_675_102,
        inverse_polynomial_degree: 16_674_375_999_492_151,
    },
    RootParameters {
        modulus: 16_674_115_037_429_761,
        primitive_generator: 31,
        negacyclic_root: 1_361_674_173_445_781,
        cyclic_root: 7_253_592_553_546_521,
        inverse_negacyclic_root: 13_617_816_476_617_351,
        inverse_cyclic_root: 11_360_116_125_782_961,
        inverse_polynomial_degree: 16_673_860_610_625_601,
    },
    RootParameters {
        modulus: 16_673_187_323_314_177,
        primitive_generator: 7,
        negacyclic_root: 6_844_486_411_617_692,
        cyclic_root: 10_418_620_036_869_622,
        inverse_negacyclic_root: 7_659_154_771_519_553,
        inverse_cyclic_root: 3_925_274_668_292_284,
        inverse_polynomial_degree: 16_672_932_910_665_811,
    },
    RootParameters {
        modulus: 16_672_259_609_198_593,
        primitive_generator: 5,
        negacyclic_root: 3_946_240_755_941_072,
        cyclic_root: 4_975_863_570_287_152,
        inverse_negacyclic_root: 13_643_772_052_940_467,
        inverse_cyclic_root: 1_543_790_690_068_208,
        inverse_polynomial_degree: 16_672_005_210_706_021,
    },
    RootParameters {
        modulus: 16_671_331_895_083_009,
        primitive_generator: 17,
        negacyclic_root: 10_300_242_510_888_057,
        cyclic_root: 14_109_855_686_426_628,
        inverse_negacyclic_root: 11_587_088_724_221_160,
        inverse_cyclic_root: 16_566_091_865_380_989,
        inverse_polynomial_degree: 16_671_077_510_746_231,
    },
    RootParameters {
        modulus: 16_667_930_276_659_201,
        primitive_generator: 31,
        negacyclic_root: 6_410_191_870_029_125,
        cyclic_root: 1_279_663_223_140_463,
        inverse_negacyclic_root: 6_685_259_013_951_047,
        inverse_cyclic_root: 3_048_334_296_539_840,
        inverse_polynomial_degree: 16_667_675_944_227_001,
    },
    RootParameters {
        modulus: 16_665_662_531_043_329,
        primitive_generator: 3,
        negacyclic_root: 2_056_355_595_380_760,
        cyclic_root: 5_323_009_480_187_027,
        inverse_negacyclic_root: 15_662_566_421_854_399,
        inverse_cyclic_root: 12_155_275_752_852_075,
        inverse_polynomial_degree: 16_665_408_233_214_181,
    },
    RootParameters {
        modulus: 16_663_807_102_812_161,
        primitive_generator: 6,
        negacyclic_root: 12_830_600_792_146_998,
        cyclic_root: 2_127_340_469_033_852,
        inverse_negacyclic_root: 13_820_738_778_289_574,
        inverse_cyclic_root: 12_273_359_869_599_367,
        inverse_polynomial_degree: 16_663_552_833_294_601,
    },
    RootParameters {
        modulus: 16_661_333_198_503_937,
        primitive_generator: 3,
        negacyclic_root: 3_764_947_790_718_309,
        cyclic_root: 9_421_517_058_707_549,
        inverse_negacyclic_root: 5_883_791_233_129_994,
        inverse_cyclic_root: 14_220_774_889_533_509,
        inverse_polynomial_degree: 16_661_078_966_735_161,
    },
    RootParameters {
        modulus: 16_660_714_722_426_881,
        primitive_generator: 3,
        negacyclic_root: 16_399_416_752_688_008,
        cyclic_root: 11_161_706_347_008_996,
        inverse_negacyclic_root: 8_289_077_232_059_338,
        inverse_cyclic_root: 7_771_156_740_881_906,
        inverse_polynomial_degree: 16_660_460_500_095_301,
    },
    RootParameters {
        modulus: 16_659_787_008_311_297,
        primitive_generator: 3,
        negacyclic_root: 1_802_963_530_684_231,
        cyclic_root: 12_114_537_935_240_088,
        inverse_negacyclic_root: 5_893_995_983_416_804,
        inverse_cyclic_root: 2_050_734_046_889_187,
        inverse_polynomial_degree: 16_659_532_800_135_511,
    },
    RootParameters {
        modulus: 16_657_725_421_387_777,
        primitive_generator: 10,
        negacyclic_root: 6_437_579_306_720_997,
        cyclic_root: 14_323_423_640_515_416,
        inverse_negacyclic_root: 7_172_923_131_021_866,
        inverse_cyclic_root: 7_533_895_284_168_843,
        inverse_polynomial_degree: 16_657_471_244_669_311,
    },
    RootParameters {
        modulus: 16_657_106_945_310_721,
        primitive_generator: 11,
        negacyclic_root: 15_989_380_683_424_978,
        cyclic_root: 2_360_897_350_709_162,
        inverse_negacyclic_root: 1_760_644_408_960_107,
        inverse_cyclic_root: 6_332_705_521_209_465,
        inverse_polynomial_degree: 16_656_852_778_029_451,
    },
    RootParameters {
        modulus: 16_655_766_913_810_433,
        primitive_generator: 3,
        negacyclic_root: 6_724_307_586_239_435,
        cyclic_root: 987_811_972_661_020,
        inverse_negacyclic_root: 4_479_583_344_954_727,
        inverse_cyclic_root: 11_725_599_744_465_924,
        inverse_polynomial_degree: 16_655_512_766_976_421,
    },
    RootParameters {
        modulus: 16_653_602_247_540_737,
        primitive_generator: 3,
        negacyclic_root: 6_368_973_719_132_631,
        cyclic_root: 4_453_423_024_130_023,
        inverse_negacyclic_root: 1_471_605_154_256_492,
        inverse_cyclic_root: 3_938_857_716_094_415,
        inverse_polynomial_degree: 16_653_348_133_736_911,
    },
    RootParameters {
        modulus: 27_109_868_044_289,
        primitive_generator: 3,
        negacyclic_root: 8_641_954_553_461,
        cyclic_root: 9_521_387_765_607,
        inverse_negacyclic_root: 20_251_841_249_706,
        inverse_cyclic_root: 4_877_921_693_281,
        inverse_polynomial_degree: 27_109_454_380_531,
    },
    RootParameters {
        modulus: 25_975_995_236_353,
        primitive_generator: 5,
        negacyclic_root: 16_867_774_021_985,
        cyclic_root: 8_629_206_032_299,
        inverse_negacyclic_root: 1_823_632_353_090,
        inverse_cyclic_root: 17_305_032_821_080,
        inverse_polynomial_degree: 25_975_598_874_121,
    },
    RootParameters {
        modulus: 9_223_372_036_844_421_121,
        primitive_generator: 11,
        negacyclic_root: 131_461_279_243_254_895,
        cyclic_root: 2_488_028_248_958_969_510,
        inverse_negacyclic_root: 1_794_453_693_159_418_542,
        inverse_cyclic_root: 5_888_418_303_546_576_631,
        inverse_polynomial_degree: 9_223_231_299_356_065_951,
    },
    RootParameters {
        modulus: 9_223_372_036_836_950_017,
        primitive_generator: 10,
        negacyclic_root: 6_802_727_386_875_254_773,
        cyclic_root: 6_693_023_659_644_367_588,
        inverse_negacyclic_root: 3_133_639_726_665_778_677,
        inverse_cyclic_root: 4_361_979_657_132_062_761,
        inverse_polynomial_degree: 9_223_231_299_348_594_961,
    },
    RootParameters {
        modulus: 9_223_372_036_835_770_369,
        primitive_generator: 11,
        negacyclic_root: 2_306_305_839_948_063_377,
        cyclic_root: 9_195_512_338_259_968_481,
        inverse_negacyclic_root: 4_356_955_705_307_077_686,
        inverse_cyclic_root: 1_590_766_071_201_539_801,
        inverse_polynomial_degree: 9_223_231_299_347_415_331,
    },
    RootParameters {
        modulus: 9_223_372_036_833_673_217,
        primitive_generator: 3,
        negacyclic_root: 3_497_005_130_920_859_796,
        cyclic_root: 3_252_799_475_403_850_281,
        inverse_negacyclic_root: 386_029_923_398_804_705,
        inverse_cyclic_root: 7_681_383_404_425_398_955,
        inverse_polynomial_degree: 9_223_231_299_345_318_211,
    },
    RootParameters {
        modulus: 9_223_372_036_833_411_073,
        primitive_generator: 13,
        negacyclic_root: 8_359_681_429_216_204_754,
        cyclic_root: 2_337_448_281_486_450_148,
        inverse_negacyclic_root: 6_540_694_417_196_108_949,
        inverse_cyclic_root: 4_047_241_740_953_458_076,
        inverse_polynomial_degree: 9_223_231_299_345_056_071,
    },
    RootParameters {
        modulus: 9_223_372_036_829_347_841,
        primitive_generator: 3,
        negacyclic_root: 2_913_913_535_244_173_777,
        cyclic_root: 367_466_746_625_611_919,
        inverse_negacyclic_root: 125_322_285_682_324_709,
        inverse_cyclic_root: 8_848_994_654_394_359_729,
        inverse_polynomial_degree: 9_223_231_299_340_992_901,
    },
    RootParameters {
        modulus: 9_223_372_036_827_119_617,
        primitive_generator: 5,
        negacyclic_root: 794_262_039_159_953_175,
        cyclic_root: 7_433_991_898_712_744_888,
        inverse_negacyclic_root: 6_999_216_879_141_434_504,
        inverse_cyclic_root: 8_266_125_308_942_074_241,
        inverse_polynomial_degree: 9_223_231_299_338_764_711,
    },
    RootParameters {
        modulus: 9_223_372_036_824_629_249,
        primitive_generator: 3,
        negacyclic_root: 6_939_392_511_529_434_489,
        cyclic_root: 5_459_730_421_523_906_825,
        inverse_negacyclic_root: 3_894_891_680_058_256_022,
        inverse_cyclic_root: 891_334_586_011_272_301,
        inverse_polynomial_degree: 9_223_231_299_336_274_381,
    },
    RootParameters {
        modulus: 9_223_372_036_818_075_649,
        primitive_generator: 11,
        negacyclic_root: 1_457_410_584_570_349_271,
        cyclic_root: 8_848_647_840_206_591_052,
        inverse_negacyclic_root: 8_318_233_396_435_211_720,
        inverse_cyclic_root: 8_208_164_234_870_183_841,
        inverse_polynomial_degree: 9_223_231_299_329_720_881,
    },
];

// Complete distinct prime-factor certificates for p - 1 in the exact
// ROOT_PARAMETERS order. Production validation divides out every certified
// factor and requires a unit remainder, so it proves certificate completeness
// without discovering factors in the browser runtime.
pub(super) const MULTIPLICATIVE_GROUP_PRIME_FACTORS: [&[u64]; ROOT_PARAMETERS.len()] = [
    &[2, 3],
    &[2, 3, 786_433],
    &[2, 3, 13, 786_433],
    &[2, 71, 786_433],
    &[2, 3, 11, 786_433],
    &[2, 3, 786_433],
    &[2, 3, 31, 786_433],
    &[2, 3, 53_927, 786_433],
    &[2, 3, 59, 457, 786_433],
    &[2, 7, 11, 191, 786_433],
    &[2, 5, 32_353, 786_433],
    &[2, 3, 5, 337, 786_433],
    &[2, 3, 53_917, 786_433],
    &[2, 3, 7, 3_851, 786_433],
    &[2, 3, 11, 13, 29, 786_433],
    &[2, 3, 5, 7, 11, 786_433],
    &[2, 11, 7_349, 786_433],
    &[2, 5, 59, 137, 786_433],
    &[2, 17, 2_377, 786_433],
    &[2, 5, 7, 2_309, 786_433],
    &[2, 23, 7_027, 786_433],
    &[2, 3, 11, 59, 83, 786_433],
    &[2, 3, 5, 7, 19, 786_433],
    &[2, 173, 467, 786_433],
    &[2, 161_561, 786_433],
    &[2, 263, 786_433],
    &[2, 3, 7, 786_433],
    &[2, 3, 5, 7, 1_021, 72_932_693],
    &[2, 3, 37, 131, 604_916_651],
    &[2, 3, 43, 13_187, 41_366_053],
    &[2, 61, 10_429, 110_613_287],
    &[2, 3, 7, 11, 107, 3_359, 121_081],
    &[2, 5, 7_036_874_417_747],
    &[2, 3, 23, 128_351, 7_945_687],
    &[2, 227, 421, 368_164_451],
    &[2, 3, 23, 127_479_609_017],
];

pub(crate) fn root_parameters_for_modulus(modulus: u64) -> Option<RootParameters> {
    ROOT_PARAMETERS
        .iter()
        .copied()
        .find(|parameters| parameters.modulus == modulus)
}
