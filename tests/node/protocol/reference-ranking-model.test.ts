import { describe, expect, it } from 'vitest';

import {
    evaluateReferenceRanking,
    type BallotInventoryEntry,
} from '#tests/reference-ranking-model.js';

const accepted = (scores: readonly number[]): BallotInventoryEntry => ({
    kind: 'accepted',
    scores,
});
const notAccepted: BallotInventoryEntry = { kind: 'not-accepted' };

describe('reference ranking model', () => {
    it('ranks a hand-computed inventory by descending total with lower positions first on ties', () => {
        // Totals of the three accepted ballots by option position:
        // 1 + 3 + 5 = 9, 4 + 5 + 5 = 14, 6 + 5 + 5 = 16, 10 + 1 + 3 = 14 and
        // 2 + 4 + 3 = 9.
        const inventory = [
            accepted([1, 4, 6, 10, 2]),
            notAccepted,
            accepted([3, 5, 5, 1, 4]),
            accepted([5, 5, 5, 3, 3]),
        ];
        // Position 2 leads. Position 3 holds the only 10 but ties position 1
        // on total, as position 4 ties position 0. Each tie lists the lower
        // position first, including across the cut after two identifiers.
        const completeOrder = [2, 1, 3, 0, 4];
        for (let topCount = 1; topCount <= 5; topCount += 1)
            expect(evaluateReferenceRanking(inventory, 5, topCount)).toEqual({
                kind: 'result',
                orderedOptionPositions: completeOrder.slice(0, topCount),
            });
    });

    it('orders equal totals by position and returns no result without an accepted ballot', () => {
        const allOnes = Array.from({ length: 10 }, () =>
            accepted(Array.from({ length: 10 }, () => 1)),
        );
        expect(evaluateReferenceRanking(allOnes, 10, 10)).toEqual({
            kind: 'result',
            orderedOptionPositions: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        expect(
            evaluateReferenceRanking(
                [notAccepted, notAccepted, notAccepted],
                2,
                1,
            ),
        ).toEqual({ kind: 'no-result', orderedOptionPositions: [] });
        // One accepted ballot at the smallest and largest supported sizes.
        expect(
            evaluateReferenceRanking(
                [accepted([1, 10]), notAccepted, notAccepted],
                2,
                2,
            ),
        ).toEqual({ kind: 'result', orderedOptionPositions: [1, 0] });
        const largest = Array.from({ length: 20 }, (_unused, position) =>
            position === 19
                ? accepted(
                      Array.from(
                          { length: 20 },
                          (_option, option) => 1 + (option % 10),
                      ),
                  )
                : notAccepted,
        );
        expect(evaluateReferenceRanking(largest, 20, 3)).toEqual({
            kind: 'result',
            orderedOptionPositions: [9, 19, 8],
        });
    });

    it('refuses inventories outside the supported profiles', () => {
        const ballots = (count: number, scores: readonly number[]) =>
            Array.from({ length: count }, () => accepted(scores));
        for (const [inventory, optionCount, topCount] of [
            [ballots(2, [1, 1]), 2, 1],
            [ballots(21, [1, 1]), 2, 1],
            [ballots(3, [1]), 1, 1],
            [
                ballots(
                    3,
                    Array.from({ length: 21 }, () => 1),
                ),
                21,
                1,
            ],
            [ballots(3, [1, 1]), 2, 0],
            [ballots(3, [1, 1]), 2, 3],
            [ballots(3, [1, 1]), 2, 1.5],
            [ballots(3, [0, 1]), 2, 1],
            [ballots(3, [1, 11]), 2, 1],
            [ballots(3, [1, 1.5]), 2, 1],
            [ballots(3, [1, 1, 1]), 2, 1],
        ] as const)
            expect(() =>
                evaluateReferenceRanking(inventory, optionCount, topCount),
            ).toThrow(RangeError);
    });
});
