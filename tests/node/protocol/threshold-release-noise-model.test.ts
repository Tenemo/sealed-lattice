import { describe, expect, it } from 'vitest';

import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';

describe('threshold release noise model', () => {
    it('charges all honest shares using an independent integral interpolation oracle', () => {
        let maximumSum = 0n;
        for (let first = 0; first < 8; first += 1)
            for (let second = first + 1; second < 9; second += 1)
                for (let third = second + 1; third < 10; third += 1) {
                    const corrupt = [first, second, third];
                    let sum = 0n;
                    for (let honest = 0; honest < 10; honest += 1) {
                        if (corrupt.includes(honest)) continue;
                        let coefficients = [1n, ...Array<bigint>(7).fill(0n)];
                        // lambda_0,i = product_(j in C) (1-X^(i-j)) in
                        // Z[X]/(X^8+1), without rational matrix inversion.
                        for (const position of corrupt) {
                            const exponent =
                                (((honest - position) % 16) + 16) % 16;
                            const next = [...coefficients];
                            coefficients.forEach((coefficient, index) => {
                                const target = index + exponent;
                                const sign =
                                    Math.floor(target / 8) % 2 === 0 ? 1n : -1n;
                                next[target % 8] =
                                    next[target % 8] - sign * coefficient;
                            });
                            coefficients = next;
                        }
                        sum += coefficients.reduce(
                            (total, value) =>
                                total + (value < 0n ? -value : value),
                            0n,
                        );
                    }
                    maximumSum = sum > maximumSum ? sum : maximumSum;
                }
        const census = compileThresholdReleaseNoiseCensus();
        expect(census.exactMaximumJointSimulationCoefficientOneNormSum).toBe(
            maximumSum,
        );
        const exactDominantFactor =
            4n * 32_768n * (1n << 79n) * 44n * maximumSum;
        const bits = BigInt(
            census.jointTargetSecurityDominantNoiseReserveBitLength,
        );
        expect(exactDominantFactor).toBeLessThanOrEqual(1n << bits);
        expect(exactDominantFactor).toBeGreaterThan(1n << (bits - 1n));
        expect(bits).toBeGreaterThan(
            BigInt(
                census.exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength,
            ),
        );
    });

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
