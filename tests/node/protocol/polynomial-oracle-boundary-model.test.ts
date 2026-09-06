import { describe, expect, it } from 'vitest';

import {
    createFalseBinaryRelationTable,
    enumerateRandomizedEncodingViews,
} from '#tests/polynomial-oracle-boundary-model.js';

describe('polynomial oracle boundaries', () => {
    it('hides each constant with one mask at one distinct query', () => {
        const reference = enumerateRandomizedEncodingViews(0, 1, [2]);
        for (const constant of [1, 2, 8, 16]) {
            expect(enumerateRandomizedEncodingViews(constant, 1, [2])).toEqual(
                reference,
            );
        }
        expect(enumerateRandomizedEncodingViews(0, 1, [2, 2])).toEqual(
            enumerateRandomizedEncodingViews(1, 1, [2, 2]),
        );
    });

    it('exposes disjoint witness distributions after a second distinct query', () => {
        const zero = enumerateRandomizedEncodingViews(0, 1, [2, 3]);
        const one = enumerateRandomizedEncodingViews(1, 1, [2, 3]);
        expect(zero.size).toBe(17);
        expect(one.size).toBe(17);
        expect([...zero.keys()].filter((view) => one.has(view))).toEqual([]);
    });

    it('needs enough independent masks for the complete joint query view', () => {
        for (const points of [
            [2, 3],
            [2, 3, 5],
        ]) {
            const zero = enumerateRandomizedEncodingViews(
                0,
                points.length,
                points,
            );
            expect(zero.size).toBe(17 ** points.length);
            expect(new Set(zero.values())).toEqual(new Set([1]));
            for (const constant of [1, 8, 16]) {
                expect(
                    enumerateRandomizedEncodingViews(
                        constant,
                        points.length,
                        points,
                    ),
                ).toEqual(zero);
            }
        }
        const zero = enumerateRandomizedEncodingViews(0, 2, [2, 3, 5]);
        const one = enumerateRandomizedEncodingViews(1, 2, [2, 3, 5]);
        expect([...zero.keys()].filter((view) => one.has(view))).toEqual([]);
        expect(() => enumerateRandomizedEncodingViews(1, 1, [1])).toThrow(
            RangeError,
        );
    });

    it('passes every pointwise check of a false relation without a degree constraint', () => {
        const { prime, witnessValue, claimedQuotientMaximumDegree, entries } =
            createFalseBinaryRelationTable();
        expect((witnessValue * (witnessValue - 1)) % prime).toBe(2);
        for (const { point, quotient } of entries) {
            expect(
                ((((point ** 4 - 1) * quotient) % prime) + prime) % prime,
            ).toBe(2);
        }
        // Any claimed quotient has deg((X^4-1)q-2)<=8. Its value at 1 is
        // -2, so it is nonzero and cannot vanish at these 93 distinct points.
        expect(new Set(entries.map(({ point }) => point)).size).toBe(93);
        expect(entries.length).toBeGreaterThan(
            claimedQuotientMaximumDegree + 4,
        );
    });
});
