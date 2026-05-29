import { oneHotScore } from './relation-fixtures-and-summaries.mjs';

import type { BallotPrivacyRelationCompilerInput } from '#packages/protocol/src/ballot-privacy/relation-compiler.js';

export const mutatedMiniRelationInputs = (
    baseInput: BallotPrivacyRelationCompilerInput,
): readonly {
    readonly caseName: string;
    readonly description: string;
    readonly mutation: string;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}[] => [
    {
        caseName: 'score-zero-rejects',
        description: 'Score zero fails the frozen score-domain relation.',
        mutation: 'score-0',
        relationInput: {
            ...baseInput,
            normalizedScores: [0, 3],
            scoreOneHotWitnesses: [oneHotScore(1), oneHotScore(3)],
        },
    },
    {
        caseName: 'score-eleven-rejects',
        description: 'Score eleven fails the frozen score-domain relation.',
        mutation: 'score-11',
        relationInput: {
            ...baseInput,
            normalizedScores: [11, 3],
            scoreOneHotWitnesses: [oneHotScore(10), oneHotScore(3)],
        },
    },
    {
        caseName: 'malformed-one-hot-rejects',
        description: 'Two active bucket entries fail one-hot membership.',
        mutation: 'two-active-buckets',
        relationInput: {
            ...baseInput,
            scoreOneHotWitnesses: [
                [0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
                oneHotScore(3),
            ],
        },
    },
    {
        caseName: 'signed-cancellation-one-hot-rejects',
        description:
            'Signed cancellation fails boolean one-hot membership even when a linear reconstruction can be made to look small.',
        mutation: 'signed-cancellation',
        relationInput: {
            ...baseInput,
            scoreOneHotWitnesses: [
                [0, 0, -1, 0, 2, 0, 0, 0, 0, 0],
                oneHotScore(3),
            ],
        },
    },
    {
        caseName: 'wrong-quotient-rejects',
        description: 'A mutated receiver share fails the quotient equation.',
        mutation: 'wrong-quotient',
        relationInput: {
            ...baseInput,
            receivers: baseInput.receivers.map((receiver) =>
                receiver.receiverRosterPosition === 2
                    ? {
                          ...receiver,
                          receiverShareVector: receiver.receiverShareVector.map(
                              (shareRepresentative, coordinateIndex) =>
                                  coordinateIndex === 0
                                      ? shareRepresentative + 1
                                      : shareRepresentative,
                          ),
                      }
                    : receiver,
            ),
        },
    },
    {
        caseName: 'wrong-degree-rejects',
        description:
            'A coefficient row with degree equal to the threshold fails.',
        mutation: 'wrong-degree',
        relationInput: {
            ...baseInput,
            encodedCoordinateShamirCoefficients: [
                [65_536, 1],
                ...baseInput.encodedCoordinateShamirCoefficients.slice(1),
            ],
        },
    },
    {
        caseName: 'omitted-receiver-rejects',
        description: 'Omitting one receiver fails coverage.',
        mutation: 'omitted-receiver',
        relationInput: {
            ...baseInput,
            receivers: baseInput.receivers.slice(0, 2),
        },
    },
    {
        caseName: 'duplicate-receiver-rejects',
        description:
            'Duplicating a receiver roster position fails receiver coverage.',
        mutation: 'duplicate-receiver',
        relationInput: {
            ...baseInput,
            receivers: [
                baseInput.receivers[0],
                {
                    ...baseInput.receivers[1],
                    receiverRosterPosition: 1,
                },
                baseInput.receivers[2],
            ],
        },
    },
    {
        caseName: 'nonzero-padding-rejects',
        description: 'Nonzero share-vector padding fails closed.',
        mutation: 'nonzero-padding',
        relationInput: {
            ...baseInput,
            receivers: baseInput.receivers.map((receiver) =>
                receiver.receiverRosterPosition === 3
                    ? {
                          ...receiver,
                          receiverShareVector: [
                              ...receiver.receiverShareVector,
                              1,
                          ],
                      }
                    : receiver,
            ),
        },
    },
];
