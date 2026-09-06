import { describe, expect, it } from 'vitest';

import { compileCandidateBgvParameterCensus } from '#tests/candidate-bgv-parameter-model.js';

describe('candidate BGV parameter model', () => {
    it('derives the depth-sized modulus and release reserve from the graph', () => {
        expect(compileCandidateBgvParameterCensus()).toEqual({
            auxiliaryModulus:
                1_329_227_995_786_804_821_802_797_429_364_948_993n,
            auxiliaryModulusBitLength: 121n,
            ciphertextModulus:
                9_128_220_280_162_566_810_089_915_511_188_590_614_277_911_672_540_738_800_791_338_809_514_483_453_922_243_241_324_588_326_830_734_899_773_928_328_714_236_383_906_473_015_313_584_567_729_007_531_207_004_593_925_925_992_269_226_475_643_363_327_332_038_475_777n,
            ciphertextModulusBitLength: 642n,
            ciphertextModulusLimbCount: 17n,
            combinedModulus:
                12_133_485_948_100_954_685_939_354_170_161_450_473_086_731_505_634_593_314_300_996_866_475_778_049_360_652_859_009_910_784_008_421_372_065_861_210_251_194_167_412_399_238_502_607_008_697_312_614_948_822_846_306_216_830_680_137_446_225_315_095_760_781_042_955_769_904_883_865_712_042_811_195_705_071_042_561n,
            combinedModulusBitLength: 762n,
            multiplicativeDepth: 14n,
            polynomialModulusDegree: 32_768n,
            retainedBottomModulusBitLength: 166n,
        });
    });
});
