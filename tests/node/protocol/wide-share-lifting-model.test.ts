import { describe, expect, it } from 'vitest';

import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

describe('wide sharing and release integer lifting', () => {
    it('preserves power-of-two sharing endpoints and independently decrypts each encrypted evaluation', () => {
        const census = compileWideShareLiftingCensus();
        expect(census.checkedEquations).toBe(32 * 8 * 2);
        expect(census.scale).toBe(119n * (1n << 23n) + 1n);
        expect(census.modulus).toBe(census.proofPrime * census.scale);
        expect(census.residualBound).toBeLessThan(census.proofPrime);
        expect(census.maximumObservedCarry).toBeLessThanOrEqual(
            census.trueCarryBound,
        );
        expect(census.trueCarryBound).toBeLessThan(census.carryBound);
        expect(census.trueQuotientBound).toBeLessThan(census.quotientBound);
        expect(census.privacyNumerator << 96n).toBeLessThanOrEqual(
            2n * census.sharingRadius,
        );
        expect(census.aliasCarry).toBe((1n << 32n) - 1n);
        expect(census.aliasCarry).toBeGreaterThanOrEqual(census.carryBound);
    });

    it('uses the dense-convolution carry bound and rejects its modular alias', () => {
        const census = compileReleaseShareLiftingCensus();
        expect(census.checkedEquations).toBe(32 * 8 * 6);
        expect(census.maximumObservedCarry).toBeGreaterThan(1n << 23n);
        expect(census.maximumObservedCarry).toBeLessThanOrEqual(
            census.trueCarryBound,
        );
        expect(census.trueCarryBound).toBeLessThan(census.carryBound);
        expect(census.trueQuotientBound).toBeLessThan(1n << 143n);
        expect(census.residualBound).toBeLessThan(census.proofPrime);
        // Radix 2^48 divides p-1 exactly for the independently certified prime.
        expect(census.aliasCarry).toBe((1n << 80n) - 133n * (1n << 16n));
        expect(census.aliasCarry).toBeGreaterThan(census.carryBound);
    });
});
