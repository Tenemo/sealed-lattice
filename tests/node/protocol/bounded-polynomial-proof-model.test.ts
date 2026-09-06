import { describe, expect, it } from 'vitest';

import { compileBoundedLinearPolynomialProofCensus } from '#tests/bounded-linear-polynomial-proof-model.js';
import { compileBoundedLookupCensus } from '#tests/bounded-lookup-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

describe('bounded polynomial proof components', () => {
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

    it('checks lookup membership and distinguishes field cardinality from characteristic', () => {
        const census = compileBoundedLookupCensus();
        expect(census.challengeCount).toBe(
            census.basePrime ** 2 * (census.basePrime - 1),
        );
        expect(census.validAcceptances).toBe(census.challengeCount);
        expect(census.invalidAcceptances).toBe(3);
        expect(census.roots).toEqual(['1,0,1', '1,0,3', '1,0,9']);
        // An occurrence count equal to the characteristic is a real failure,
        // even though every challenge is outside the base field.
        expect(census.characteristicWrapAcceptances).toBe(
            census.challengeCount,
        );
    });

    it('certifies the base field and the degree-three extension separately', () => {
        const field = compileSmallLimbProofFieldCensus();
        expect(field.modulus).toBe((1n << 128n) - 133n * (1n << 64n) + 1n);
        expect(field.modulusBitLength).toBe(128n);
        expect(field.packedFieldElementByteLength).toBe(16n);
        expect(field.packedExtensionElementByteLength).toBe(48n);
        expect(field.oddFactor % 2n).toBe(1n);
        expect(field.oddFactor).toBeLessThan(field.wordRadix);
        expect(field.transformOrder).toBe(1n << 20n);
    });
});
