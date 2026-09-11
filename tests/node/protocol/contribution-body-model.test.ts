import { describe, expect, it } from 'vitest';

import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';

describe('complete contribution body encoding', () => {
    it('omits only fixed common polynomials and previously verified recipient keys', () => {
        const value = compileContributionBodyCensus();
        const excluded = new Set([
            42,
            73,
            ...Array.from({ length: 6 }, (_, gadget) => [
                7 * gadget,
                7 * gadget + 3,
                7 * gadget + 5,
            ]).flat(),
            ...Array.from({ length: 10 }, (_, recipient) => 43 + 3 * recipient),
        ]);
        expect(
            value.polynomials.map((polynomial) => polynomial.expandedIndex),
        ).toEqual(
            Array.from({ length: 75 }, (_, index) => index).filter(
                (index) => !excluded.has(index),
            ),
        );
        expect(value.polynomialPayloadBytes).toBe(198_991_872n);
        expect(value.maximumBodyBytes).toBeLessThan(256n * 1024n ** 2n);
        expect(value.maximumHashInputBytes).toBeLessThan(1n << 32n);
        expect(value.hashPrefixBytes).toBeLessThan(4096n);
    });
});
