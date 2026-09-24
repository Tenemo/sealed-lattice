import { describe, expect, it } from 'vitest';

import { keyedXofViews } from '#tests/keyed-xof-model.js';
import { unrevealedPointQueryBound } from '#tests/unrevealed-point-query-model.js';

describe('Keyed XOF coupling', () => {
    it('matches both complete worlds with interleaved prefix and extended-output queries', () => {
        const value = keyedXofViews();
        for (const [world, samples] of [
            ['keyed', value.keyedSamples],
            ['random', value.randomSamples],
            ['onePointOracle', value.simulatedSamples],
            ['zeroPointOracle', value.simulatedSamples],
        ] as const)
            expect(
                value.views.reduce((total, view) => total + view[world], 0n),
            ).toBe(samples);
        expect(
            value.views.some((view) => view.keyed === 0n && view.random > 0n),
        ).toBe(true);
        for (const view of value.views) {
            expect(view.keyed * value.simulatedSamples).toBe(
                view.onePointOracle * value.keyedSamples,
            );
            expect(view.random * value.simulatedSamples).toBe(
                view.zeroPointOracle * value.randomSamples,
            );
            const [table, oracle, first, extended, next, response, repeated] =
                JSON.parse(view.view) as number[];
            expect(first).toBe(oracle & 1);
            expect(extended).toBe((table >> (2 * first)) & 3);
            expect(next).toBe((extended >> 1) ^ first);
            expect(response).toBe((oracle >> next) & 1);
            expect(repeated).toBe(first);
        }
    });
    it('does not claim that the hidden-key bound survives explicit key disclosure', () => {
        const value = keyedXofViews();
        expect(value.disclosedKeyedMatches).toBe(value.disclosedKeyedSamples);
        expect(value.disclosedRandomMatches * 2n).toBe(
            value.disclosedRandomSamples,
        );
        // Once the key is supplied, one public query compares the keyed reply
        // with its actual XOF input and has advantage 1/2 for this output bit,
        // independently of the size of the otherwise uniform key space.
        const hidden = unrevealedPointQueryBound(2n, 4096n).bound;
        expect(hidden.numerator * 2n).toBeLessThan(hidden.denominator);
        const large = unrevealedPointQueryBound(2n * (1n << 80n), 1n << 256n);
        expect(large.bound).toEqual({ numerator: 5n, denominator: 1n << 93n });
    });
});
