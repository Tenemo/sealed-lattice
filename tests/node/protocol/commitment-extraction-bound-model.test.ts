import { describe, expect, it } from 'vitest';

import { compileCommitmentExtractionBound } from '#tests/commitment-extraction-bound-model.js';
import { prefixOracleQueriesPerAccess } from '#tests/compressed-oracle-model.js';

describe('early full-body commitment extraction bounds', () => {
    it('charges the full-value oracle calls used by a SHAKE prefix query', () => {
        const logicalQueries = 1n << 80n,
            fullQueries = prefixOracleQueriesPerAccess * logicalQueries;
        const prefix = compileCommitmentExtractionBound(10),
            stream = compileCommitmentExtractionBound(10, fullQueries);
        expect(stream.quantumQueryCount).toBe(1n << 81n);
        expect(stream.simulatorQuadraticQueryCoefficient).toBe(1n << 162n);
        expect(stream.combinedFailureNumerator).toBeGreaterThan(
            prefix.combinedFailureNumerator,
        );
        expect(stream.combinedFailureExponent).toBeGreaterThanOrEqual(80n);
        expect(() => compileCommitmentExtractionBound(10, -1n)).toThrow();
    });
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
            expect(bound.simulatorRelationEvaluationCoefficient).toBe(
                BigInt(participantCount) *
                    BigInt(Math.floor((participantCount - 1) / 3)) *
                    (1n << 80n),
            );
            expect(bound.simulatorQuadraticQueryCoefficient).toBe(1n << 160n);
        }
    });

    it('does not charge a collision event when there is no corrupt commitment', () => {
        const bound = compileCommitmentExtractionBound(3);
        expect(bound.extractedCommitmentCount).toBe(0n);
        expect(bound.combinedFailureNumerator).toBe(0n);
        expect(bound.combinedFailureExponent).toBeUndefined();
    });
});
