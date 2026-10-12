import { describe, expect, it } from 'vitest';

import {
    compileCommonAgreementDegreeCensus,
    degreeShiftBoundaryCounterexample,
    separateProximityDegreeCounterexample,
} from '#tests/common-agreement-degree-model.js';

describe('common agreement for degree-shifted oracles', () => {
    it('exhibits separately close words with an invalid declared degree', () => {
        const model = separateProximityDegreeCounterexample();
        expect(
            model.domain.filter(
                (_point, index) => model.factorizationValues[index] === 0n,
            ),
        ).toEqual(model.commonRoots);
        expect(model.firstAgreement).toHaveLength(11);
        expect(model.secondAgreement).toHaveLength(11);
        expect(model.commonAgreement).toHaveLength(6);
        // A [16,4] Reed-Solomon code has distance 13, so these radius-five
        // decodings are unique. The first decoded polynomial is X^3, while
        // multiplication by X^3 was supposed to certify degree at most zero.
        expect(2 * (16 - model.firstAgreement.length)).toBeLessThan(13);
        expect(new Set(model.raw).size).toBeGreaterThan(1);
    });

    it('requires enough shared points for every degree and relation identity', () => {
        const census = compileCommonAgreementDegreeCensus();
        expect(census.minimumAgreementPoints).toBe(197632);
        expect(census.minimumDeclaredDegree).toBe(65534);
        expect(census.maximumShiftIdentityDegree).toBe(196608);
        expect(census.maximumRelationIdentityDegree).toBe(133888);
        expect(census.minimumAgreementPoints).toBeGreaterThan(
            census.maximumShiftIdentityDegree,
        );
        expect(census.minimumAgreementPoints).toBeGreaterThan(
            census.maximumRelationIdentityDegree,
        );
        expect(census.maskDimension).toBe(1409);
    });

    it('requires strictly more common roots than the tighter shift-degree bound', () => {
        const model = degreeShiftBoundaryCounterexample();
        expect(model.original.length - 1).toBe(model.maximumDegree);
        expect(model.original[model.original.length - 1]).toBe(1n);
        expect(model.original.length - 1).toBeGreaterThan(model.declaredDegree);
        expect(model.shifted.length - 1).toBeLessThanOrEqual(
            model.maximumDegree,
        );
        expect(model.agreement).toEqual(
            Array.from(
                { length: 24 },
                (_, index) => 28n ** BigInt(index) % 97n,
            ),
        );
        expect(28n ** 32n % 97n).toBe(1n);
        expect(28n ** 16n % 97n).toBe(96n);
        expect(model.agreement.length).toBe(model.maximumShiftIdentityDegree);
        expect(2 * (32 - model.agreement.length)).toBeLessThan(
            32 - (model.maximumDegree + 1) + 1,
        );
    });
});
