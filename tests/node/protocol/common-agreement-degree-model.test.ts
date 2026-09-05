import { describe, expect, it } from 'vitest';

import {
    compileCommonAgreementDegreeCensus,
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
        expect(census.minimumAgreementPoints).toBe(331776);
        expect(census.maximumShiftIdentityDegree).toBe(262142);
        expect(census.maximumRelationIdentityDegree).toBe(132800);
        expect(census.minimumAgreementPoints).toBeGreaterThan(
            census.maximumShiftIdentityDegree,
        );
        expect(census.minimumAgreementPoints).toBeGreaterThan(
            census.maximumRelationIdentityDegree,
        );
        expect(census.maskDimension).toBe(865);
    });
});
