import { describe, expect, it } from 'vitest';

import {
    labelledKeyedXofBound,
    labelledKeyedXofViews,
} from '#tests/labelled-keyed-xof-model.js';

describe('Labelled keyed XOF families', () => {
    it('matches joint function views for several hidden keys and secret roles', () => {
        const value = labelledKeyedXofViews();
        expect(value.views.reduce((total, view) => total + view.real, 0n)).toBe(
            4096n,
        );
        expect(
            value.views.reduce((total, view) => total + view.random, 0n),
        ).toBe(4096n);
        expect(value.views.reduce((total, view) => total + view.one, 0n)).toBe(
            131072n,
        );
        expect(value.views.reduce((total, view) => total + view.zero, 0n)).toBe(
            131072n,
        );
        for (const view of value.views) {
            expect(view.one * value.originalSamples).toBe(
                view.real * value.simulatedSamples,
            );
            expect(view.zero * value.originalSamples).toBe(
                view.random * value.simulatedSamples,
            );
            const [
                table,
                keyed,
                first,
                before,
                created,
                second,
                later,
                repeated,
            ] = JSON.parse(view.view) as [
                number,
                number[],
                number,
                number,
                boolean,
                number,
                number,
                number,
            ];
            expect(first).toBe(keyed[0]);
            expect(before).toBe((table >> (2 * (2 + first))) & 1);
            expect(created).toBe(before === 1);
            expect(second).toBe(created ? keyed[2 * first + 1] : -1);
            expect(later).toBe(
                (table >>
                    (2 * (2 * first + (created ? 1 : 0)) +
                        (second < 0 ? first : second))) &
                    1,
            );
            expect(repeated).toBe(first);
        }
        expect(
            value.views.some((view) => view.real === 0n && view.random > 0n),
        ).toBe(true);
        expect(value.collisions).toBe(4);
    });
    it('charges public-label collisions separately from public-query work', () => {
        const value = labelledKeyedXofBound(1n, 2n, 4096n, 1024n);
        expect(value.labelCollision).toEqual({
            numerator: 1n,
            denominator: 1024n,
        });
        expect(value.hiddenPoint.bound).toEqual({
            numerator: 5n,
            denominator: 512n,
        });
        expect(value.bound).toEqual({ numerator: 11n, denominator: 1024n });
        expect(labelledKeyedXofBound(1n, 10n, 4096n, 1024n).bound).toEqual({
            numerator: 55n,
            denominator: 1024n,
        });
        expect(labelledKeyedXofBound(8n, 0n, 4096n, 1024n).bound).toEqual({
            numerator: 0n,
            denominator: 1n,
        });
        expect(labelledKeyedXofBound(1n, 2n, 4096n, 1n).bound).toEqual({
            numerator: 1n,
            denominator: 1n,
        });
        expect(() => labelledKeyedXofBound(1n, -1n, 4096n, 1024n)).toThrow(
            RangeError,
        );
        expect(() => labelledKeyedXofBound(1n, 2n, 0n, 1024n)).toThrow(
            RangeError,
        );
    });
});
