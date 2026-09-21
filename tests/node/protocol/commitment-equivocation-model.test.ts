import { describe, expect, it } from 'vitest';

import {
    compareCommitmentEquivocationHybrids,
    compareDuplicateCommitmentInputs,
    compileCommitmentEquivocationBound,
} from '#tests/commitment-equivocation-model.js';

describe('whole-message commitment equivocation model', () => {
    it('preserves the full joint state when a previously announced value is opened', () => {
        for (const [messages, salts] of [
            [2, 2],
            [3, 2],
            [2, 4],
        ] as const) {
            const value = compareCommitmentEquivocationHybrids(
                messages,
                salts,
                'complete-slice',
            );
            expect(value.realTrace).toBe(value.commonDenominator);
            expect(value.simulatedTrace).toBe(value.commonDenominator);
            expect(value.differingEntries).toBe(0);
            expect(value.firstDifference).toBeUndefined();
        }
    });

    it('detects incomplete masking and the wrong post-opening oracle', () => {
        for (const variant of [
            'first-message-only',
            'retain-shadow',
        ] as const) {
            const value = compareCommitmentEquivocationHybrids(3, 2, variant);
            expect(value.realTrace).toBe(value.commonDenominator);
            expect(value.simulatedTrace).toBe(value.commonDenominator);
            expect(value.differingEntries).toBeGreaterThan(0);
            expect(value.absoluteEntryDifference).toBeGreaterThan(0);
            expect(value.firstDifference).toBeDefined();
        }
    });

    it('programs only the committed prefix while preserving the full oracle output', () => {
        const valid = compareCommitmentEquivocationHybrids(
            2,
            2,
            'complete-slice',
            2,
            1,
        );
        expect(valid.realTrace).toBe(valid.commonDenominator);
        expect(valid.simulatedTrace).toBe(valid.commonDenominator);
        expect(valid.differingEntries).toBe(0);
        const changedSuffix = compareCommitmentEquivocationHybrids(
            2,
            2,
            'replace-full-output',
            2,
            1,
        );
        expect(changedSuffix.differingEntries).toBeGreaterThan(0);
    });

    it('charges a separate honest-sender hybrid without a per-message-bit factor', () => {
        for (let participants = 3; participants <= 20; participants++) {
            const value = compileCommitmentEquivocationBound(participants);
            expect(value.numerator << 170n).toBeLessThanOrEqual(
                value.denominator,
            );
            expect(
                value.numerator << (value.failureExponent + 1n),
            ).toBeGreaterThan(value.denominator);
            expect(value.maximumControlledOracleCalls).toBe(
                BigInt(participants + 1) * (1n << 80n),
            );
        }
        expect(() => compileCommitmentEquivocationBound(2)).toThrow();
        expect(() => compileCommitmentEquivocationBound(21)).toThrow();
        expect(() =>
            compareCommitmentEquivocationHybrids(3, 4, 'complete-slice'),
        ).toThrow();
    });

    it('charges potential credential scopes even when the final roster is smaller', () => {
        const rosterOnly = compileCommitmentEquivocationBound(10);
        const potentialPool = compileCommitmentEquivocationBound(10, 30n);
        expect(potentialPool.credentialScopeCount).toBe(30n);
        expect(potentialPool.numerator).toBe(3n * rosterOnly.numerator);
        expect(potentialPool.maximumControlledOracleCalls).toBe(
            31n * (1n << 80n),
        );
        expect(potentialPool.failureExponent).toBeLessThan(
            rosterOnly.failureExponent,
        );
        expect(compileCommitmentEquivocationBound(10, 10n)).toEqual(rosterOnly);
        // Two union events per unordered pair: equal original seeds, or
        // equal public rho prefixes at distinct key-expansion inputs.
        const pairs = Array.from({ length: 30 }, (_, first) =>
            Array.from({ length: first }, (_entry, second) => [first, second]),
        ).flat();
        expect(potentialPool.credentialCollisionNumerator).toBe(
            2n * BigInt(pairs.length),
        );
        expect(potentialPool.credentialCollisionDenominator).toBe(1n << 256n);
        expect(() => compileCommitmentEquivocationBound(10, 9n)).toThrow(
            'scope',
        );
    });

    it('exposes duplicate-input inconsistency and removes it with distinct sender scopes', () => {
        const repeated = compareDuplicateCommitmentInputs(false);
        expect(repeated.realEvents).toBe(0);
        expect(repeated.simulatedEvents * 8).toBe(repeated.simulatedCases * 3);
        const separated = compareDuplicateCommitmentInputs(true);
        expect(separated.realEvents).toBe(0);
        expect(separated.simulatedEvents).toBe(0);
    });
});
