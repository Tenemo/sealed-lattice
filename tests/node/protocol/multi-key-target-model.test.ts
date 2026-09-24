import { describe, expect, it } from 'vitest';

import {
    coverageThinningControl,
    multiKeyTargetBound,
    multiKeyTargetStateControl,
    multiKeyTargetViews,
    randomizerInputCoupling,
} from '#tests/multi-key-target-model.js';
import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

describe('Multi-key message targets', () => {
    it('retains queries across namespaces and equal cross-key randomizers', () => {
        for (const randomizers of [16, 64] as const) {
            const value = multiKeyTargetStateControl(randomizers);
            expect(value.samples).toBe(4 * randomizers ** 2);
            expect(value.equalRandomizerCases).toBe(4 * randomizers);
            expect(
                BigInt(value.distance) * BigInt(randomizers),
            ).toBeLessThanOrEqual(
                16n * BigInt(value.samples) * BigInt(value.denominator),
            );
            expect(value.realSuccess).toBeLessThanOrEqual(
                2 * value.stagedSuccess + 2 * value.distance,
            );
            expect(value.crossKeyOnly).toBeGreaterThan(0);
        }
    });
    it('matches full adaptive credential-choice and staged-search views', () => {
        const value = multiKeyTargetViews();
        expect(
            value.views.reduce((total, view) => total + view.staged, 0n),
        ).toBe(16384n);
        expect(
            value.views.reduce((total, view) => total + view.deferred, 0n),
        ).toBe(65536n);
        expect(
            value.views.reduce((total, view) => total + view.search, 0n),
        ).toBe(65536n);
        for (const view of value.views) {
            expect(view.deferred * value.originalSamples).toBe(
                view.staged * value.simulatedSamples,
            );
            expect(view.search).toBe(view.deferred);
        }
        expect(value.early).toBeGreaterThan(0);
        expect(value.equalSalts).toBe(32768);
        expect(value.successes).toBeGreaterThan(0);
        expect(value.crossKeyOnly).toBeGreaterThan(0);
    });
    it('uses a first-bad input coupling instead of conditioning on no repetition', () => {
        const value = randomizerInputCoupling();
        expect(value.realBad).toBe(16);
        expect(value.freshBad).toBe(4);
        expect(value.views.reduce((total, view) => total + view.real, 0n)).toBe(
            48n,
        );
        expect(
            value.views.reduce((total, view) => total + view.fresh, 0n),
        ).toBe(12n);
        for (const view of value.views)
            expect(view.real * value.freshSamples).toBe(
                view.fresh * value.realSamples,
            );
        expect(value.allFirst).toEqual([8, 8]);
        expect(value.goodFirst).toEqual([4, 8]);
        expect(value.crossKeyCoinMatches).toBe(4);
    });
    it('thins different coverage densities without creating a false search solution', () => {
        for (const value of coverageThinningControl()) {
            expect(value.counts).toEqual([6, 6, 6, 6]);
            expect(value.falseSearchSolutions).toBe(0);
        }
    });
    it('keeps per-key query terms separate from population repetition terms', () => {
        const input = {
            publicQueries: 1n,
            credentials: 2n,
            requestsPerCredential: 2n,
            randomizerDomain: 4096n,
            coinDomain: 4096n,
            instances: 16n,
            leavesPerTree: 16n,
            trees: 2n,
        };
        const value = multiKeyTargetBound(input);
        expect(value.coinInputRepetition).toEqual({
            numerator: 1n,
            denominator: 2048n,
        });
        expect(value.randomizerRepetition).toEqual({
            numerator: 1n,
            denominator: 2048n,
        });
        expect(value.stateError).toEqual({ numerator: 1n, denominator: 256n });
        expect(value.search).toEqual({ numerator: 9n, denominator: 64n });
        expect(value.coreBound).toEqual({
            numerator: 297n,
            denominator: 2048n,
        });
        expect(value.hedgedBound).toEqual({
            numerator: 149n,
            denominator: 1024n,
        });
        const ten = multiKeyTargetBound({ ...input, credentials: 10n });
        expect(ten.stateError).toEqual(value.stateError);
        expect(ten.search).toEqual(value.search);
        expect(ten.hedgedBound).toEqual({
            numerator: 153n,
            denominator: 1024n,
        });
        expect(
            multiKeyTargetBound({ ...input, credentials: 0n }).hedgedBound,
        ).toEqual({ numerator: 0n, denominator: 1n });
        expect(
            multiKeyTargetBound({ ...input, randomizerDomain: 1n }).hedgedBound,
        ).toEqual({ numerator: 1n, denominator: 1n });
        const parameters = compileStatelessSignatureWork(),
            domain = 1n << (8n * parameters.nodeBytes);
        const large = multiKeyTargetBound({
            publicQueries: 1n << 80n,
            credentials: 1n << 80n,
            requestsPerCredential: 10n,
            randomizerDomain: domain,
            coinDomain: domain,
            instances: 1n << parameters.totalHeight,
            leavesPerTree: parameters.forestLeaves,
            trees: parameters.forestTrees,
        });
        expect(large.hedgedBound.numerator * (1n << 89n)).toBeLessThan(
            large.hedgedBound.denominator,
        );
        expect(large.hedgedBound.numerator * (1n << 90n)).toBeGreaterThan(
            large.hedgedBound.denominator,
        );
        expect(() =>
            multiKeyTargetBound({ ...input, credentials: -1n }),
        ).toThrow(RangeError);
        expect(() => multiKeyTargetBound({ ...input, coinDomain: 0n })).toThrow(
            RangeError,
        );
    });
});
