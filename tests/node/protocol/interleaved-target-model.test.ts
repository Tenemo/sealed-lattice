import { describe, expect, it } from 'vitest';

import {
    interleavedCoverageBound,
    interleavedTargetQueryBound,
    interleavedTargetViews,
    stagedRowStateControl,
} from '#tests/interleaved-target-model.js';
import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

describe('Interleaved target queries', () => {
    it('bounds every small target union including repeated and collocated digests', () => {
        const outputs = Array.from({ length: 18 }, (_, index) => ({
            instance: Math.floor(index / 9),
            leaves: [Math.floor(index / 3) % 3, index % 3],
        }));
        const check = (targets: typeof outputs) => {
            const covered = outputs.filter((candidate) =>
                candidate.leaves.every((leaf, tree) =>
                    targets.some(
                        (target) =>
                            target.instance === candidate.instance &&
                            target.leaves[tree] === leaf,
                    ),
                ),
            ).length;
            const bound = interleavedCoverageBound(
                BigInt(targets.length),
                2n,
                3n,
                2n,
            );
            expect(BigInt(covered) * bound.denominator).toBeLessThanOrEqual(
                18n * bound.numerator,
            );
            return covered;
        };
        expect(check([])).toBe(0);
        expect(check([outputs[0]])).toBe(1);
        expect(check([outputs[0], outputs[4]])).toBe(4);
        expect(check([outputs[0], outputs[9]])).toBe(2);
        expect(check([outputs[0], outputs[4], outputs[8]])).toBe(9);
        for (const first of outputs)
            for (const second of outputs)
                for (const third of outputs) check([first, second, third]);
    });
    it('keeps altered quantum states and uses one common final success predicate', () => {
        for (const keys of [16, 64] as const) {
            const value = stagedRowStateControl(keys);
            expect(value.samples).toBe(4 * keys * (keys - 1));
            expect(value.changeableQueries).toBe(2);
            expect(value.knownRowReads).toBe(1);
            expect(value.positiveGaps).toBeGreaterThan(0);
            expect(value.negativeGaps).toBeGreaterThan(0);
            const denominator =
                BigInt(value.samples) * BigInt(value.denominator);
            expect(BigInt(value.difference) * BigInt(keys)).toBeLessThanOrEqual(
                32n * denominator,
            );
            expect(value.realSuccess).toBeLessThanOrEqual(
                2 * value.stagedSuccess + 2 * value.difference,
            );
            expect(value.realSuccess).not.toBe(value.stagedSuccess);
        }
    });
    it('matches complete deferred and search views including early stopping', () => {
        const value = interleavedTargetViews();
        expect(
            value.views.reduce((total, view) => total + view.staged, 0n),
        ).toBe(512n);
        expect(
            value.views.reduce((total, view) => total + view.deferred, 0n),
        ).toBe(2048n);
        expect(
            value.views.reduce((total, view) => total + view.search, 0n),
        ).toBe(2048n);
        expect(value.successes).toBe(1088);
        expect(value.early).toBe(1024);
        // A known target can satisfy coverage without solving the search
        // predicate. The actual success definition excludes that same pair.
        expect(value.forcedWithoutSearch).toBe(768);
        for (const view of value.views) {
            expect(view.deferred * value.stagedSamples).toBe(
                view.staged * value.deferredSamples,
            );
            expect(view.search).toBe(view.deferred);
        }
    });
    it('charges key repetition, state error and the staged search separately', () => {
        expect(
            interleavedTargetQueryBound(1n, 1n, 4096n, 16n, 16n, 2n).bound,
        ).toEqual({ numerator: 19n, denominator: 512n });
        const value = interleavedTargetQueryBound(1n, 2n, 4096n, 16n, 16n, 2n);
        expect(value.coverage).toEqual({ numerator: 1n, denominator: 1024n });
        expect(value.repeatedKey).toEqual({
            numerator: 1n,
            denominator: 4096n,
        });
        expect(value.stateError).toEqual({ numerator: 1n, denominator: 256n });
        expect(value.search).toEqual({ numerator: 9n, denominator: 64n });
        expect(value.bound).toEqual({ numerator: 593n, denominator: 4096n });
        expect(
            interleavedTargetQueryBound(8n, 0n, 16n, 2n, 4n, 2n).bound,
        ).toEqual({ numerator: 0n, denominator: 1n });
        expect(
            interleavedTargetQueryBound(8n, 3n, 2n, 2n, 4n, 2n).bound,
        ).toEqual({ numerator: 1n, denominator: 1n });
        const parameters = compileStatelessSignatureWork();
        const current = interleavedTargetQueryBound(
            1n << 80n,
            6n,
            1n << (8n * parameters.nodeBytes),
            1n << parameters.totalHeight,
            parameters.forestLeaves,
            parameters.forestTrees,
        );
        expect(current.bound.numerator * (1n << 90n)).toBeLessThan(
            current.bound.denominator,
        );
        expect(current.bound.numerator * (1n << 91n)).toBeGreaterThan(
            current.bound.denominator,
        );
        expect(() =>
            interleavedTargetQueryBound(-1n, 1n, 16n, 2n, 4n, 2n),
        ).toThrow(RangeError);
        expect(() => interleavedCoverageBound(1n, 2n, 4n, 0n)).toThrow(
            RangeError,
        );
    });
});
