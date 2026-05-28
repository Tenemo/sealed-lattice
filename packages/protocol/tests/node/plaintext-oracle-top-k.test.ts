import { describe, expect, it } from 'vitest';

import {
    decodeSparseTopKTarget,
    derivePlaintextTopKOracle,
} from '../../src/plaintext-oracle/index';

import {
    assertValidPollSpec,
    topKVectors,
} from './plaintext-oracle-test-vectors';

describe('plaintext tally and top-k oracle', () => {
    it('matches deterministic top-k vectors including skipped-score normalization', () => {
        const pollSpec = assertValidPollSpec(topKVectors.pollSpecInput);
        const oracle = derivePlaintextTopKOracle({
            ballots: topKVectors.ballots,
            maximumRosterSize: topKVectors.maximumRosterSize,
            pollSpec: pollSpec.normalized,
        });

        expect(oracle.tally.optionTallies).toEqual(
            topKVectors.expected.optionTallies,
        );
        expect(oracle.tally.tallyFieldElements).toEqual(
            topKVectors.expected.tallyFieldElements,
        );
        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.expected.rankingOptionOrdinals,
        );
        expect(
            decodeSparseTopKTarget({
                expectedLayoutHash: oracle.sparseTarget.layoutHash,
                target: oracle.sparseTarget,
            }).selectedOptionOrdinals,
        ).toEqual(topKVectors.expected.selectedOptionOrdinals);
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.expected.targetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.expected.targetOrderSlots,
        );
        expect(oracle.tally.tallyHash).toBe(topKVectors.expected.tallyHash);
        expect(oracle.oracleHash).toBe(topKVectors.expected.oracleHash);
    });

    it('uses lower option index as the full-ranking tie breaker', () => {
        const pollSpec = assertValidPollSpec(
            topKVectors.fullTieCase.pollSpecInput,
        );
        const oracle = derivePlaintextTopKOracle({
            ballots: topKVectors.fullTieCase.ballots,
            maximumRosterSize: 20,
            pollSpec: pollSpec.normalized,
        });

        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.fullTieCase.expectedRankingOptionOrdinals,
        );
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.fullTieCase.expectedTargetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.fullTieCase.expectedTargetOrderSlots,
        );
        expect(oracle.oracleHash).toBe(
            topKVectors.fullTieCase.expectedOracleHash,
        );
    });

    it('covers K_top = 1 with a single clear winner', () => {
        const pollSpec = assertValidPollSpec(
            topKVectors.topOneClearWinnerCase.pollSpecInput,
        );
        const oracle = derivePlaintextTopKOracle({
            ballots: topKVectors.topOneClearWinnerCase.ballots,
            maximumRosterSize: 20,
            pollSpec: pollSpec.normalized,
        });
        const decoding = decodeSparseTopKTarget({
            expectedLayoutHash: oracle.sparseTarget.layoutHash,
            target: oracle.sparseTarget,
        });

        expect(oracle.tally.optionTallies).toEqual(
            topKVectors.topOneClearWinnerCase.expectedOptionTallies,
        );
        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.topOneClearWinnerCase.expectedRankingOptionOrdinals,
        );
        expect(decoding.ok).toBe(true);
        expect(decoding.selectedOptionOrdinals).toEqual(
            topKVectors.topOneClearWinnerCase.expectedSelectedOptionOrdinals,
        );
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.topOneClearWinnerCase.expectedTargetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.topOneClearWinnerCase.expectedTargetOrderSlots,
        );
        expect(oracle.tally.tallyHash).toBe(
            topKVectors.topOneClearWinnerCase.expectedTallyHash,
        );
        expect(oracle.oracleHash).toBe(
            topKVectors.topOneClearWinnerCase.expectedOracleHash,
        );
    });

    it('supports every K_top for a 20-option poll', () => {
        const options = Array.from(
            { length: 20 },
            (_unused, optionIndex) => `Option ${String(optionIndex + 1)}`,
        );
        const ballots = [
            {
                scores: options.map(
                    (_option, optionIndex) => 10 - (optionIndex % 10),
                ),
            },
            {
                scores: options.map(
                    (_option, optionIndex) => (optionIndex % 5) + 1,
                ),
            },
            {
                scores: options.map(
                    (_option, optionIndex) => (optionIndex % 4) + 3,
                ),
            },
        ];

        for (
            let topOptionCount = 1;
            topOptionCount <= options.length;
            topOptionCount += 1
        ) {
            const pollSpec = assertValidPollSpec({
                pollId: `all-k-${String(topOptionCount)}`,
                question: 'Question',
                options,
                topOptionCount,
            });
            const oracle = derivePlaintextTopKOracle({
                ballots,
                maximumRosterSize: 20,
                pollSpec: pollSpec.normalized,
            });
            const decoding = decodeSparseTopKTarget({
                expectedLayoutHash: oracle.sparseTarget.layoutHash,
                target: oracle.sparseTarget,
            });
            const expectedSelectedOrdinals = oracle.ranking
                .slice(0, topOptionCount)
                .map((entry) => entry.optionOrdinal);

            expect(decoding.ok, `K_top=${String(topOptionCount)}`).toBe(true);
            expect(decoding.selectedOptionOrdinals).toEqual(
                expectedSelectedOrdinals,
            );
            expect(
                oracle.sparseTarget.targetIdSlots.filter(
                    (optionOrdinal) => optionOrdinal !== 0,
                ),
            ).toHaveLength(topOptionCount);
            expect(
                oracle.sparseTarget.targetOrderSlots
                    .filter((orderPosition) => orderPosition !== 0)
                    .sort((left, right) => left - right),
            ).toEqual(
                Array.from(
                    { length: topOptionCount },
                    (_unused, orderIndex) => orderIndex + 1,
                ),
            );
        }
    });

    it('covers the maximum n=50, m=20 no-wrap tally and full ranking', () => {
        const pollSpec = assertValidPollSpec(
            topKVectors.maximumNoWrapCase.pollSpecInput,
        );
        const ballots = Array.from(
            { length: topKVectors.maximumNoWrapCase.ballotCount },
            () => ({
                scores: Array.from(
                    { length: pollSpec.normalized.options.length },
                    () => topKVectors.maximumNoWrapCase.score,
                ),
            }),
        );
        const oracle = derivePlaintextTopKOracle({
            ballots,
            maximumRosterSize: topKVectors.maximumNoWrapCase.ballotCount,
            pollSpec: pollSpec.normalized,
        });

        expect(Math.max(...oracle.tally.optionTallies)).toBe(
            topKVectors.maximumNoWrapCase.expectedMaximumTally,
        );
        expect(oracle.tally.optionTallies).toEqual(
            Array.from(
                { length: pollSpec.normalized.options.length },
                () => topKVectors.maximumNoWrapCase.expectedMaximumTally,
            ),
        );
        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual(
            topKVectors.maximumNoWrapCase.expectedRankingOptionOrdinals,
        );
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.maximumNoWrapCase.expectedTargetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.maximumNoWrapCase.expectedTargetOrderSlots,
        );
        expect(oracle.tally.tallyHash).toBe(
            topKVectors.maximumNoWrapCase.expectedTallyHash,
        );
        expect(oracle.oracleHash).toBe(
            topKVectors.maximumNoWrapCase.expectedOracleHash,
        );
    });

    it('encodes unset options exactly as score one without a skip bucket', () => {
        const pollSpec = assertValidPollSpec(topKVectors.pollSpecInput);
        const oracle = derivePlaintextTopKOracle({
            ballots: [{ scores: [10] }],
            pollSpec: pollSpec.normalized,
        });

        expect(oracle.tally.normalizedBallots[0]?.scores).toEqual([
            10, 1, 1, 1,
        ]);
        expect(oracle.tally.optionTallies).toEqual([10, 1, 1, 1]);
    });

    it('rejects malformed score vectors and no-wrap violations', () => {
        const pollSpec = assertValidPollSpec(topKVectors.pollSpecInput);

        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [0, 1, 1, 1] }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('1..10');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [1, 1, 1, 11] }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('1..10');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [null, 1, 1, 1] as never }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('1..10');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: [{ scores: [1, 1, 1, 1, 1] }],
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('more entries than poll options');
        expect(() =>
            derivePlaintextTopKOracle({
                ballots: Array.from({ length: 21 }, () => ({
                    scores: [10, 10, 10, 10],
                })),
                maximumRosterSize: 20,
                pollSpec: pollSpec.normalized,
            }),
        ).toThrow('cannot exceed maximum roster');
    });
});
