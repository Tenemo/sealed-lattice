import { describe, expect, it } from 'vitest';

import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';

describe('threshold release noise model', () => {
    it('derives the KLLPS dominant flooding reserve for four-of-ten release', () => {
        const census = compileThresholdReleaseNoiseCensus();
        expect(census.interpolationProductBound).toBeCloseTo(
            5_522.644_457_848_916,
            9,
        );
        expect(census).toMatchObject({
            authorizedSubsetCount: 210,
            boundedIntegerSharingReconstructionCount: 210,
            completionParticipantCount: 10,
            exactConservativeSecurityDominantNoiseBudgetLowerBoundBitLength: 154,
            exactInterpolationProduct: 352n,
            exactMaximumScaledReconstructionCoefficientOneNorm: 44n,
            exactMaximumSimulationCoefficientOneNorm: 8n,
            exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength: 106,
            lagrangeCoefficientCount: 840,
            productionInterpolationPointExponentStride: 4_096,
            releaseThreshold: 4,
            spacedInterpolationSize: 16,
            targetSecurityDominantNoiseBudgetLowerBoundBitLength: 110,
            conservativeSecurityDominantNoiseBudgetLowerBoundBitLength: 158,
        });
    });
});
