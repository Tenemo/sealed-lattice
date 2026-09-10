import { describe, expect, it } from 'vitest';

import {
    hashGraphCollisionBound,
    hashGraphViews,
} from '#tests/hash-graph-model.js';

describe('Acyclic hash graph argument', () => {
    it('matches the complete evaluated, programmed and search distributions', () => {
        const value = hashGraphViews();
        expect(value.views.reduce((sum, view) => sum + view.real, 0n)).toBe(
            1024n,
        );
        expect(
            value.views.reduce((sum, view) => sum + view.programmed, 0n),
        ).toBe(4096n);
        for (const view of value.views) {
            expect(view.programmed).toBe(4n * view.real);
            expect(view.search).toBe(view.programmed);
        }
        expect(value.collisions).toBeGreaterThan(0);
        expect(value.cyclesFail).toBeGreaterThan(0);
        expect(value.reusedRowsFail).toBeGreaterThan(0);
    });
    it('uses the total oracle count without a graph-node multiplier', () => {
        expect(hashGraphCollisionBound(0n, 256n)).toEqual({
            numerator: 1n,
            denominator: 32n,
        });
        expect(hashGraphCollisionBound(1n, 256n)).toEqual({
            numerator: 9n,
            denominator: 32n,
        });
        expect(hashGraphCollisionBound(100n, 256n)).toEqual({
            numerator: 1n,
            denominator: 1n,
        });
        expect(() => hashGraphCollisionBound(-1n, 256n)).toThrow(RangeError);
        expect(() => hashGraphCollisionBound(1n, 0n)).toThrow(RangeError);
    });
});
