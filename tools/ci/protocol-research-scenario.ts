import { evaluateReferenceRanking } from '#tests/reference-ranking-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

// Release subsets and departure sets the ceremony checks after share
// generation: every set when there are at most this many, otherwise this
// many.
const checkedSetLimit = 256;
const maximumScore = 10;

const binomial = (count: number, size: number): number => {
    let value = 1;
    for (let index = 0; index < size; index++)
        value = (value * (count - index)) / (index + 1);
    return value;
};
const range = (start: number, end: number): number[] =>
    Array.from(
        { length: Math.max(0, end - start) },
        (_unused, index) => start + index,
    );

// The native ceremony's fixture scores for a position and option.
export const researchBallotScore = (position: number, option: number) =>
    1 +
    ((position * position + 5 * position + 3 * option + 7 * position * option) %
        maximumScore);

// The native ceremony's roles, derived here from the threshold model rather
// than from the ceremony. Positions one to f are corrupt: the last corrupt
// position equivocates, the one before it submits an invalid proof and the
// one before that a wrong-position envelope. The first f + 2 honest
// positions cast accepted ballots. With f positive and a spare honest
// position, the last position's ballot is omitted. Every corrupt position
// withholds its target signature.
export const deriveResearchScenario = (
    participantCount: number,
    optionCount: number,
    setupDeparture = false,
    selectionFork = false,
) => {
    const thresholds = compileThresholdCompletionProfile(participantCount);
    const corrupt = thresholds.maximumCorruptParticipantCount;
    if (
        (setupDeparture && selectionFork) ||
        ((setupDeparture || selectionFork) &&
            (participantCount !== 4 || optionCount !== 2))
    )
        throw new Error(
            'The fixed setup cases require four participants and two options.',
        );
    const honest = selectionFork
        ? [1, 2, 3]
        : setupDeparture
          ? [0, 1, 3]
          : [0, ...range(corrupt + 1, participantCount)];
    const voters = selectionFork
        ? [0, 1, 2, 3]
        : setupDeparture
          ? [0, 2, 3]
          : honest.slice(0, thresholds.minimumTurnout);
    const role = (rank: number) =>
        !setupDeparture && !selectionFork && corrupt - rank > 0
            ? [corrupt - rank]
            : [];
    const departed = setupDeparture ? [1] : [];
    const omitted =
        !setupDeparture &&
        !selectionFork &&
        corrupt > 0 &&
        honest.length > thresholds.minimumTurnout
            ? [participantCount - 1]
            : [];
    const ranking = evaluateReferenceRanking(
        range(0, participantCount).map((position) =>
            voters.includes(position)
                ? {
                      kind: 'accepted' as const,
                      scores: range(0, optionCount).map((option) =>
                          researchBallotScore(position, option),
                      ),
                  }
                : { kind: 'not-accepted' as const },
        ),
        optionCount,
        optionCount,
    );
    let departureTotal = 0;
    for (let size = 0; size <= corrupt; size++)
        departureTotal += binomial(participantCount, size);
    return {
        participantCount,
        optionCount,
        corrupt: selectionFork
            ? [0]
            : setupDeparture
              ? [2]
              : range(1, corrupt + 1),
        honest,
        accepted: voters,
        omitted,
        invalid: [...role(2), ...role(1)],
        conflicting: role(0),
        signers: setupDeparture || selectionFork ? voters : honest,
        responseFiles: range(0, participantCount)
            .filter((position) => !departed.includes(position))
            .map((position) => 'response-' + position + '.bin'),
        ...(setupDeparture || selectionFork
            ? { departed, selectedAuthors: [0, 2] }
            : {}),
        identifiers: ranking.orderedOptionPositions.map(
            (option) => `option-${option}`,
        ),
        releaseThreshold: thresholds.resultReleaseThreshold,
        certificateThreshold: thresholds.inventoryCertificateThreshold,
        releaseSubsets: Math.min(
            binomial(
                participantCount - Number(setupDeparture),
                thresholds.resultReleaseThreshold,
            ),
            checkedSetLimit,
        ),
        departureSets: setupDeparture
            ? 1
            : Math.min(departureTotal, checkedSetLimit),
    };
};
