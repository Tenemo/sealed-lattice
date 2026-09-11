import { describe, expect, it } from 'vitest';

import {
    compileSigningLoopSourceComparison,
    signingLoopGeometricEstimate,
    signingLoopSourceEstimates,
} from '#tests/signing-loop-estimate-model.js';

describe('Published signing-loop estimates', () => {
    it('reproduces both source limits without treating the older mean as current', () => {
        const [original, updated] = compileSigningLoopSourceComparison();
        for (const model of [original, updated]) {
            expect(model.atSourceLimit.numerator << 256n).toBeLessThanOrEqual(
                model.atSourceLimit.denominator,
            );
            expect(model.beforeSourceLimit.numerator << 256n).toBeGreaterThan(
                model.beforeSourceLimit.denominator,
            );
            expect(model.atCheckedCounter.iterations).toBeGreaterThan(
                model.minimumIterations,
            );
        }
        expect(updated.atOriginalLimit.numerator << 256n).toBeGreaterThan(
            updated.atOriginalLimit.denominator,
        );
        expect(original.atOriginalLimit.failureExponent).toBe(256n);
        expect(updated.atOriginalLimit.failureExponent).toBe(254n);
    });
    it('shows that the same mean does not imply a geometric tail', () => {
        const source = signingLoopSourceEstimates[1],
            late = source.minimumIterations + 1n;
        const tailNumerator = source.meanNumerator - source.meanDenominator,
            tailDenominator = source.meanDenominator * (late - 1n);
        const expectationNumerator =
            tailDenominator - tailNumerator + late * tailNumerator;
        expect(expectationNumerator * source.meanDenominator).toBe(
            source.meanNumerator * tailDenominator,
        );
        expect(tailNumerator << 256n).toBeGreaterThan(tailDenominator);
        expect(tailNumerator << 8n).toBeGreaterThan(tailDenominator);
    });
    it('keeps invalid inputs outside the inspected counter range', () => {
        expect(signingLoopGeometricEstimate(257n, 50n, 0n)).toMatchObject({
            numerator: 1n,
            denominator: 1n,
            failureExponent: 0n,
        });
        expect(() => signingLoopGeometricEstimate(1n, 1n, 1n)).toThrow();
        expect(() => signingLoopGeometricEstimate(257n, 50n, -1n)).toThrow();
        expect(() => signingLoopGeometricEstimate(257n, 50n, 65537n)).toThrow();
    });
});
