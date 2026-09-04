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
            packedLayoutCount: 209,
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
            materializedCiphertextNodeCount: 855,
            orderedPairDifferenceLaneCount: 90,
            packedBallotLaneCount: 320,
            scheduledPeakLiveCiphertextCount: 63,
            scheduledPeakCiphertextByteLength: 341_318_607,
            ciphertextInputCount: 10,
            ciphertextAdditionCount: 379,
            plaintextAdditionCount: 16,
            ciphertextMultiplicationCount: 59,
            plaintextMultiplicationCount: 374,
            relinearizationKeyRingLimbReadCount: 15_276,
            relinearizationCount: 59,
            rotationCount: 17,
            rotationKeyRingLimbReadCount: 425,
            scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength: 341_318_607,
            multiplicativeDepth: 14,
        });
        expect(compilePackedRankingEvaluationGraph(20, 20, 20)).toMatchObject({
            orderedPairDifferenceLaneCount: 380,
            packedBallotLaneCount: 1_280,
            scheduledPeakLiveCiphertextCount: 63,
            scheduledPeakCiphertextByteLength: 374_348_751,
            ciphertextMultiplicationCount: 69,
            relinearizationKeyRingLimbReadCount: 18_762,
            relinearizationCount: 69,
            rotationCount: 37,
            rotationKeyRingLimbReadCount: 1_332,
            scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength: 374_348_751,
            multiplicativeDepth: 15,
        });
    });
});
