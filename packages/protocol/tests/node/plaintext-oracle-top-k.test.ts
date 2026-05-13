import { describe, expect, it } from 'vitest';

import {
    decodeSparseTopKTarget,
    derivePlaintextTopKOracle,
} from '../../src/index';

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
                expectedLayoutDigest: oracle.sparseTarget.layoutDigest,
                target: oracle.sparseTarget,
            }).selectedOptionOrdinals,
        ).toEqual(topKVectors.expected.selectedOptionOrdinals);
        expect(oracle.sparseTarget.targetIdSlots).toEqual(
            topKVectors.expected.targetIdSlots,
        );
        expect(oracle.sparseTarget.targetOrderSlots).toEqual(
            topKVectors.expected.targetOrderSlots,
        );
        expect(oracle.tally.tallyDigest).toBe(topKVectors.expected.tallyDigest);
        expect(oracle.oracleDigest).toBe(topKVectors.expected.oracleDigest);
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
        expect(oracle.oracleDigest).toBe(
            topKVectors.fullTieCase.expectedOracleDigest,
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
            expectedLayoutDigest: oracle.sparseTarget.layoutDigest,
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
        expect(oracle.tally.tallyDigest).toBe(
            topKVectors.topOneClearWinnerCase.expectedTallyDigest,
        );
        expect(oracle.oracleDigest).toBe(
            topKVectors.topOneClearWinnerCase.expectedOracleDigest,
        );
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
        expect(oracle.tally.tallyDigest).toBe(
            topKVectors.maximumNoWrapCase.expectedTallyDigest,
        );
        expect(oracle.oracleDigest).toBe(
            topKVectors.maximumNoWrapCase.expectedOracleDigest,
        );
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
