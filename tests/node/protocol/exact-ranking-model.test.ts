import { describe, expect, it } from 'vitest';

import {
    compilePackedRankingEvaluationGraph,
    evaluatePolynomialRanking,
    evaluateReferenceRanking,
    verifyExactRankingModel,
    type BallotInventoryEntry,
} from '#tests/exact-ranking-model.js';

// Product goals, maintained independently of the model: a poll has 3 to 20
// participants and 2 to 20 options, a valid ballot scores every option from 1
// to 10, and the result lists from one to all option identifiers.
const maximumParticipantCount = 20;
const minimumScore = 1;
const maximumScore = 10;
const inclusiveRange = (first: number, last: number): number[] =>
    Array.from({ length: last - first + 1 }, (_unused, index) => first + index);
const supportedParticipantCounts = inclusiveRange(3, maximumParticipantCount);
const supportedOptionCounts = inclusiveRange(2, 20);
const sum = (values: readonly number[]): number =>
    values.reduce((total, value) => total + value, 0);

describe('exact ranking model', () => {
    it('exhausts the bounded comparison and rank domains independently', () => {
        const expectedProfiles = supportedParticipantCounts.flatMap(
            (participantCount) =>
                supportedOptionCounts.map((optionCount) => ({
                    participantCount,
                    optionCount,
                })),
        );
        // Two option totals over at most 20 accepted ballots differ by at most
        // 20 * (10 - 1) either way, and the comparison covers every difference.
        const comparisonPointCount =
            2 * maximumParticipantCount * (maximumScore - minimumScore) + 1;
        // Each profile checks six fixed and eight pseudorandom matrices, each
        // at every result length from one to its option count.
        const matricesPerProfile = 6 + 8;
        expect(verifyExactRankingModel()).toEqual({
            comparisonPolynomialDegree: comparisonPointCount - 1,
            // Observed rather than derived: no interpolated coefficient is zero.
            comparisonPolynomialNonzeroCoefficientCount: 361,
            exhaustiveComparisonPointCount: comparisonPointCount,
            equalityDomainCount: supportedOptionCounts.length,
            // One packed layout per option count and result length.
            packedLayoutCount: sum(supportedOptionCounts),
            testedParticipantOptionProfiles: expectedProfiles,
            testedParticipantOptionProfileCount: expectedProfiles.length,
            testedMatrixCount: matricesPerProfile * expectedProfiles.length,
            testedTopCountExecutionCount:
                matricesPerProfile *
                sum(expectedProfiles.map(({ optionCount }) => optionCount)),
        });
    });

    it('ranks a hand-computed inventory by descending total with lower positions first on ties', () => {
        // Totals of the three accepted ballots by option position:
        // 1 + 3 + 5 = 9, 4 + 5 + 5 = 14, 6 + 5 + 5 = 16, 10 + 1 + 3 = 14 and
        // 2 + 4 + 3 = 9.
        const inventory: readonly BallotInventoryEntry[] = [
            { kind: 'accepted', scores: [1, 4, 6, 10, 2] },
            { kind: 'not-accepted' },
            { kind: 'accepted', scores: [3, 5, 5, 1, 4] },
            { kind: 'accepted', scores: [5, 5, 5, 3, 3] },
        ];
        // Position 2 leads. Position 3 holds the only 10 but ties position 1
        // on total, as position 4 ties position 0. Each tie lists the lower
        // position first, including across the cut after two identifiers.
        const completeOrder = [2, 1, 3, 0, 4];
        for (let topCount = 1; topCount <= 5; topCount += 1) {
            const expected = {
                kind: 'result',
                orderedOptionPositions: completeOrder.slice(0, topCount),
            };
            expect(evaluateReferenceRanking(inventory, 5, topCount)).toEqual(
                expected,
            );
            expect(evaluatePolynomialRanking(inventory, 5, topCount)).toEqual(
                expected,
            );
        }
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
