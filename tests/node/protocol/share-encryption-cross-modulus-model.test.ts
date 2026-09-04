import { describe, expect, it } from 'vitest';

import { compileShareEncryptionCrossModulusCensus } from '#tests/share-encryption-cross-modulus-model.js';

describe('share-encryption cross-modulus model', () => {
    it('bounds exact quotient witnesses and rejects a changed residue', () => {
        expect(compileShareEncryptionCrossModulusCensus()).toEqual({
            candidateProofFieldElementBitLength: 657n,
            ciphertextFirstQuotientBound: 16_385n,
            ciphertextSecondQuotientBound: 16_385n,
            maximumEmbeddedEquationMagnitude:
                449_604_616_175_705_018_811_888_822_250_220_009_065_203_154_947n,
            maximumQuotientBound: 16_385n,
            minimumProofFieldElementBitLength: 160n,
            perContributionShareCoefficientBound:
                498_460_498_419_343_452_338_927_647_605_129_217n,
            quotientNormDecompositionLength: 15n,
            quotientSignedEncodingBitLength: 16n,
            quotientNormDigitRingElementCountPerContributor: 315n,
            quotientRingElementCountPerContributor: 21n,
            shareEncryptionKeyQuotientBound: 16_385n,
            shareEncryptionModulus:
                13_720_195_003_462_208_630_022_647_176_022_597_200_838_657n,
            toyCoefficientEquationCount: 120,
            toyMaximumObservedQuotientMagnitude: 1n,
            toyTamperRejected: true,
        });
    });
});
