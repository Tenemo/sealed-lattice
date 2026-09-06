import { describe, expect, it } from 'vitest';

import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';

describe('bounded integer sharing privacy model', () => {
    it('bounds every corrupt view by an integral zero-at-view translation', () => {
        expect(compileBoundedIntegerSharingPrivacyCensus()).toEqual({
            aggregateShareCoefficientBound:
                4_984_604_984_193_434_523_389_276_476_051_292_170n,
            coefficientSamplingBound:
                166_153_499_473_114_484_112_975_882_535_043_072n,
            corruptSubsetsChecked: 176,
            maximumBasisNonconstantOneNorm: 7n,
            maximumBlockTranslationOneNorm: 96n,
            maximumHybridTranslationOneNorm: 3_932_160n,
            maximumProductionTranslationOneNormPerContribution: 393_216n,
            perContributionShareCoefficientBound:
                498_460_498_419_343_452_338_927_647_605_129_217n,
            productionInterpolationPointExponentStride: 4_096n,
            reducedRingBlockCount: 4_096n,
            shareEncryptionModulus:
                13_720_195_003_462_208_630_022_647_176_022_597_200_838_657n,
            shareEncryptionModulusBitLength: 144n,
            sharePlaintextMinimumSpan:
                9_969_209_968_386_869_046_778_552_952_102_584_341n,
            sharePlaintextModulus:
                9_969_209_968_386_870_061_349_477_006_127_923_201n,
            sharePlaintextModulusBitLength: 123n,
            sharePlaintextPrimeCandidateCount: 28n,
            sharePlaintextPrimeMultiplier: 540_431_955_284_459_575n,
            sharePlaintextPrimeWitness: 3n,
            sharePlaintextSpanBitLength: 123n,
            sharePlaintextTransformExponent: 64n,
            statisticalPrivacyBitLength: 96n,
        });
    });
});
