// The ordered result of a closed ballot inventory, computed in the clear:
// option totals over the accepted ballots, sorted by descending total with
// the lower option position first on ties, cut to the requested length.
// Without an accepted ballot there is no result.
const maximumParticipantCount = 20;
const maximumOptionCount = 20;
const minimumScore = 1;
const maximumScore = 10;

export type BallotInventoryEntry =
    | Readonly<{ kind: 'accepted'; scores: readonly number[] }>
    | Readonly<{ kind: 'not-accepted' }>;
export type RankingResult = Readonly<{
    kind: 'no-result' | 'result';
    orderedOptionPositions: readonly number[];
}>;

const requireProfile = (
    inventory: readonly BallotInventoryEntry[],
    optionCount: number,
    topCount: number,
): void => {
    if (inventory.length < 3 || inventory.length > maximumParticipantCount) {
        throw new RangeError(
            'The ballot count is outside the supported range.',
        );
    }
    if (
        !Number.isSafeInteger(optionCount) ||
        optionCount < 2 ||
        optionCount > maximumOptionCount
    ) {
        throw new RangeError(
            'The option count is outside the supported range.',
        );
    }
    if (
        !Number.isSafeInteger(topCount) ||
        topCount < 1 ||
        topCount > optionCount
    ) {
        throw new RangeError('The result length is outside the option range.');
    }
    for (const entry of inventory) {
        if (entry.kind === 'not-accepted') continue;
        if (
            entry.scores.length !== optionCount ||
            entry.scores.some(
                (score) =>
                    !Number.isSafeInteger(score) ||
                    score < minimumScore ||
                    score > maximumScore,
            )
        ) {
            throw new RangeError(
                'An accepted ballot is not a complete score vector.',
            );
        }
    }
};

export const evaluateReferenceRanking = (
    inventory: readonly BallotInventoryEntry[],
    optionCount: number,
    topCount: number,
): RankingResult => {
    requireProfile(inventory, optionCount, topCount);
    const accepted = inventory.flatMap((entry) =>
        entry.kind === 'accepted' ? [entry.scores] : [],
    );
    if (accepted.length === 0) {
        return { kind: 'no-result', orderedOptionPositions: [] };
    }
    const totals = Array.from({ length: optionCount }, (_unused, option) =>
        accepted.reduce((total, scores) => total + scores[option], 0),
    );
    return {
        kind: 'result',
        orderedOptionPositions: Array.from(
            { length: optionCount },
            (_unused, option) => option,
        )
            .sort((left, right) => totals[right] - totals[left] || left - right)
            .slice(0, topCount),
    };
};
