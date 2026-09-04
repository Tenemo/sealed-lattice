import { describe, expect, it } from 'vitest';

import {
    compilePackedRankingEvaluationGraph,
    evaluatePolynomialRanking,
    evaluateReferenceRanking,
    verifyExactRankingModel,
} from '#tests/exact-ranking-model.js';

describe('exact ranking model', () => {
    it('exhausts the bounded comparison and rank domains independently', () => {
        expect(verifyExactRankingModel()).toEqual({
            comparisonPolynomialDegree: 360,
            comparisonPolynomialNonzeroCoefficientCount: 361,
            exhaustiveComparisonPointCount: 361,
            equalityDomainCount: 19,
            testedParticipantOptionProfileCount: 342,
            testedMatrixCount: 4_788,
            testedTopCountExecutionCount: 52_668,
        });
    });

    it('handles the required terminal edge cases', () => {
        const allOneBallots = Array.from(
            { length: 10 },
            () =>
                ({
                    kind: 'accepted',
                    scores: Array.from({ length: 10 }, () => 1),
                }) as const,
        );
        expect(evaluatePolynomialRanking(allOneBallots, 10, 10)).toEqual({
            kind: 'result',
            orderedOptionPositions: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        expect(
            evaluatePolynomialRanking(
                Array.from(
                    { length: 10 },
                    () => ({ kind: 'not-accepted' }) as const,
                ),
                10,
                1,
            ),
        ).toEqual({ kind: 'no-result', orderedOptionPositions: [] });
        expect(evaluatePolynomialRanking(allOneBallots, 10, 1)).toEqual(
            evaluateReferenceRanking(allOneBallots, 10, 1),
        );
    });

    it('derives the packed candidate graph from actual dependencies', () => {
        expect(compilePackedRankingEvaluationGraph(10, 10, 10)).toEqual({
            materializedCiphertextNodeCount: 7_230,
            scheduledPeakLiveCiphertextCount: 65,
            scheduledPeakCiphertextByteLength: 351_804_593,
            ciphertextInputCount: 10,
            ciphertextAdditionCount: 3_269,
            plaintextAdditionCount: 145,
            ciphertextMultiplicationCount: 467,
            plaintextMultiplicationCount: 3_272,
            relinearizationCount: 467,
            rotationCount: 67,
            multiplicativeDepth: 14,
        });
        expect(compilePackedRankingEvaluationGraph(20, 20, 20)).toMatchObject({
            scheduledPeakLiveCiphertextCount: 65,
            scheduledPeakCiphertextByteLength: 385_883_313,
            ciphertextMultiplicationCount: 987,
            relinearizationCount: 987,
            rotationCount: 157,
            multiplicativeDepth: 15,
        });
    });
});
