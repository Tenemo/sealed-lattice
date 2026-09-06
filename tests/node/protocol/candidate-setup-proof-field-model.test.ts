import { describe, expect, it } from 'vitest';

import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';

describe('candidate setup-proof field model', () => {
    it('verifies a transform-friendly prime with a Pocklington certificate', () => {
        expect(compileCandidateSetupProofFieldCensus()).toEqual({
            basePrimeFactorCount: 3n,
            modulus:
                299_621_559_211_013_091_364_546_708_655_190_169_722_660_291_316_894_719_225_100_534_155_954_439_701_789_301_642_161_448_967_767_089_671_055_896_202_076_303_958_039_151_890_113_095_580_560_144_473_563_147_565_511_867_054_706_497_038_835_257_011_139_066_447_527_937n,
            modulusBitLength: 657n,
            modulusByteLength: 83n,
            limbByteLength: 88n,
            pocklingtonWitnessCount: 3n,
            powerBase: 1_483_006n,
            powerExponent: 32n,
            transformOrder: 65_536n,
        });
    });
});
