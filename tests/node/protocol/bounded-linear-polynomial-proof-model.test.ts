import { describe, expect, it } from 'vitest';

import { compileBoundedLinearPolynomialProofCensus } from '#tests/bounded-linear-polynomial-proof-model.js';

describe('bounded linear polynomial proof', () => {
    it('matches the two-stage soundness calculation and rejects missing degree binding', () => {
        const census = compileBoundedLinearPolynomialProofCensus();
        // One bad alpha accepts every c; every other alpha accepts only c=0.
        expect(census.falseAcceptanceCount).toBe(2 * census.prime - 1);
        expect(census.trueAcceptanceCount).toBe(census.prime ** 2);
        expect(census.simulatedFalseAcceptanceCount).toBe(census.prime ** 2);
        expect(census.sumMaskDegree).toBe(census.witnessDegree);
        expect(census.sumMaskDegree).toBeLessThan(census.sumDegree);
        // Two witness columns, the mask, and the quotient each expose two
        // values; the separately announced mask sum is the ninth coordinate.
        expect(census.shortMaskViews.minimumRank).toBe(9);
        expect(census.shortMaskViews.checkedViews).toBe(4 * 97 * 5);
        expect(census.shortMaskViews.maximumRankWithoutQuotientMask).toBe(7);
        expect(census.invalidNormTableDegree).toBeGreaterThan(
            2 * census.witnessDegree - census.systematicSize,
        );
        expect(census.tamperedWitnessTableDegree).toBeGreaterThan(
            census.witnessDegree,
        );
    });
});
