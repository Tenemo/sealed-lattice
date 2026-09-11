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

    it('exposes duplicate-input inconsistency and removes it with distinct sender scopes', () => {
        const repeated = compareDuplicateCommitmentInputs(false);
        expect(repeated.realEvents).toBe(0);
        expect(repeated.simulatedEvents * 8).toBe(repeated.simulatedCases * 3);
        const separated = compareDuplicateCommitmentInputs(true);
        expect(separated.realEvents).toBe(0);
        expect(separated.simulatedEvents).toBe(0);
    });
});
