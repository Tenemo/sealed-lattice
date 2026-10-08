import { describe, expect, it } from 'vitest';

import { compileBoundedLookupCensus } from '#tests/bounded-lookup-model.js';

describe('bounded lookup', () => {
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
});
