import { describe, expect, it } from 'vitest';

import {
    stagedPreimageBound,
    stagedPreimageStateControl,
    stagedPreimageViews,
} from '#tests/staged-preimage-model.js';

describe('Staged preimage openings', () => {
    it('retains adaptive quantum state and charges the unopened final-point guess', () => {
        for (const inputs of [16, 64] as const) {
            const value = stagedPreimageStateControl(inputs);
            expect(value.samples).toBe(8 * inputs ** 2);
            expect(value.denominator).toBe((2 * inputs) ** 3);
            expect(
                BigInt(value.difference) * BigInt(inputs),
            ).toBeLessThanOrEqual(
                16n * BigInt(value.samples) * BigInt(value.denominator),
            );
            expect(value.realSuccess).toBeLessThanOrEqual(
                2 * value.stagedSuccess + 2 * value.difference,
            );
            expect(value.stagedSuccess).toBeLessThanOrEqual(
                value.baseSuccess + value.guessSuccess,
            );
            expect(BigInt(value.guessSuccess) * BigInt(inputs)).toBe(
                BigInt(value.eligible),
            );
            expect(value.positiveGaps).toBeGreaterThan(0);
            expect(value.negativeGaps).toBeGreaterThan(0);
        }
    });
    it('matches the original image law and every staged/search view', () => {
        const value = stagedPreimageViews();
        expect(
            value.imageViews.reduce((sum, view) => sum + view.real, 0n),
        ).toBe(1024n);
        expect(
            value.imageViews.reduce((sum, view) => sum + view.programmed, 0n),
        ).toBe(4096n);
        expect(
            value.stageViews.reduce((sum, view) => sum + view.staged, 0n),
        ).toBe(16384n);
        expect(
            value.stageViews.reduce((sum, view) => sum + view.search, 0n),
        ).toBe(16384n);
        for (const view of value.imageViews)
            expect(view.programmed).toBe(4n * view.real);
        for (const view of value.stageViews)
            expect(view.staged).toBe(view.search);
        for (const control of value.controls) {
            expect(control.samples).toBe(4096);
            expect(control.guess * 2).toBe(control.eligible);
            expect(control.success).toBeLessThanOrEqual(
                control.baseMatch + control.guess,
            );
        }
        expect(value.controls[2].eligible).toBe(0);
        expect(value.controls[2].success).toBe(0);
        expect(value.controls.some((control) => control.guessOnly > 0)).toBe(
            true,
        );
    });
    it('excludes correlated preimages from the independence argument', () => {
        const value = stagedPreimageViews();
        // With equal preimages, opening one reveals the other. The reachable
        // view therefore fixes that remaining input instead of leaving it
        // uniform. The independent-case group checks are inside the model.
        expect(value.correlatedGroups).toBeGreaterThan(0);
        expect(value.correlatedSingletons).toBe(value.correlatedGroups);
    });
    it('separates search, state error and final-point guessing at exact sizes', () => {
        const value = stagedPreimageBound(1n, 4096n, 4096n);
        expect(value.search).toEqual({ numerator: 9n, denominator: 256n });
        expect(value.stateError).toEqual({ numerator: 1n, denominator: 512n });
        expect(value.finalPointGuess).toEqual({
            numerator: 1n,
            denominator: 2048n,
        });
        expect(value.bound).toEqual({ numerator: 77n, denominator: 2048n });
        expect(stagedPreimageBound(1n, 4096n, 1024n).bound).toEqual({
            numerator: 293n,
            denominator: 2048n,
        });
        expect(stagedPreimageBound(0n, 4096n, 4096n).bound).toEqual({
            numerator: 9n,
            denominator: 2048n,
        });
        expect(stagedPreimageBound(8n, 1n, 256n).bound).toEqual({
            numerator: 1n,
            denominator: 1n,
        });
        const queries = 1n << 80n,
            large = stagedPreimageBound(queries, 1n << 256n, 1n << 256n);
        expect(large.bound).toEqual({
            numerator: 36n * queries ** 2n + 32n * queries + 9n,
            denominator: 1n << 255n,
        });
        expect(() => stagedPreimageBound(-1n, 16n, 16n)).toThrow(RangeError);
        expect(() => stagedPreimageBound(0n, 0n, 16n)).toThrow(RangeError);
    });
});
