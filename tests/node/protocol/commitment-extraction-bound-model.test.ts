import { describe, expect, it } from 'vitest';

import { compileCommitmentExtractionBound } from '#tests/commitment-extraction-bound-model.js';

describe('early full-body commitment extraction bounds', () => {
    it('dominates both exact DFMS error terms without floating-point logarithms', () => {
        // Sum through 3! and bound the tail geometrically by (1/4!)/(1-1/5).
        expect(96 + 96 + 48 + 16 + 5).toBe(3 * 87);
        expect(40n * 87n ** 2n).toBeLessThan(296n * 32n ** 2n);
        expect(12n ** 2n).toBeGreaterThan(8n ** 2n * 2n);
        for (
            let participantCount = 4;
            participantCount <= 20;
            participantCount += 1
        ) {
            const bound = compileCommitmentExtractionBound(participantCount);
            const exponent = bound.combinedFailureExponent;
            expect(exponent).toBeDefined();
            if (exponent === undefined)
                throw new Error(
                    'A nonempty extraction experiment needs an exponent.',
                );
            expect(
                bound.combinedFailureNumerator << exponent,
            ).toBeLessThanOrEqual(bound.denominator);
            expect(
                bound.combinedFailureNumerator << (exponent + 1n),
            ).toBeGreaterThan(bound.denominator);
            expect(exponent).toBeGreaterThanOrEqual(163n);
            expect(bound.extractedCommitmentCount).toBe(
                BigInt(participantCount) *
                    BigInt(Math.floor((participantCount - 1) / 3)),
            );
        }
    });

    it('does not charge a collision event when there is no corrupt commitment', () => {
        const bound = compileCommitmentExtractionBound(3);
        expect(bound.extractedCommitmentCount).toBe(0n);
        expect(bound.combinedFailureNumerator).toBe(0n);
        expect(bound.combinedFailureExponent).toBeUndefined();
    });
});
