import { describe, expect, it } from 'vitest';

import {
    compileBallotPrivacyRelation,
    type BallotPrivacyRelationCompilerInput,
} from '#packages/protocol/src/ballot-privacy/index';

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const encodedShareVector = (input: {
    readonly firstOptionScoreShare: number;
    readonly secondOptionScoreShare: number;
}): readonly number[] => [
    input.firstOptionScoreShare,
    ...oneHotScore(7),
    input.secondOptionScoreShare,
    ...oneHotScore(3),
];

const encodedCoordinateShamirCoefficients =
    (): readonly (readonly number[])[] => [
        [65_536],
        ...Array.from({ length: 10 }, () => [0] as const),
        [9],
        ...Array.from({ length: 10 }, () => [0] as const),
    ];

const validRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    optionCount: 2,
    rosterSize: 3,
    pvssThreshold: 2,
    normalizedScores: [7, 3],
    scoreOneHotWitnesses: [oneHotScore(7), oneHotScore(3)],
    encodedCoordinateShamirCoefficients: encodedCoordinateShamirCoefficients(),
    receivers: [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 6,
                secondOptionScoreShare: 12,
            }),
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 5,
                secondOptionScoreShare: 21,
            }),
        },
        {
            receiverIdentity: 'receiver-3',
            receiverRosterPosition: 3,
            receiverShareVector: encodedShareVector({
                firstOptionScoreShare: 4,
                secondOptionScoreShare: 30,
            }),
        },
    ],
});

const expectRelationRefusal = (
    input: BallotPrivacyRelationCompilerInput,
    expectedMessage: string,
): void => {
    const result = compileBallotPrivacyRelation(input);

    expect(result.ok).toBe(false);
    if (result.ok) {
        throw new Error('Expected relation compiler input to be refused.');
    }
    expect(result.unresolvedReason).toBe('BallotPrivacyRelationInvalid');
    expect(
        result.refusedObjects.some((refusal) =>
            refusal.message.includes(expectedMessage),
        ),
    ).toBe(true);
};

describe('ballot privacy relation compiler', () => {
    it('compiles encoded score membership and Shamir quotient constraints', () => {
        const result = compileBallotPrivacyRelation(validRelationInput());

        expect(result).toMatchObject({
            ok: true,
            relationLabel: 'BallotPrivacyPvssRelation',
            optionCount: 2,
            rosterSize: 3,
            pvssThreshold: 2,
            shareVectorWidth: 22,
            encodedCoordinateCount: 22,
            maximumAbsoluteShamirQuotient: 3,
        });
        if (!result.ok) {
            throw new Error('Expected valid relation input to compile.');
        }
        expect(result.scoreMembershipConstraints).toEqual([
            {
                optionIndex: 0,
                oneHotSum: 1,
                reconstructedScore: 7,
            },
            {
                optionIndex: 1,
                oneHotSum: 1,
                reconstructedScore: 3,
            },
        ]);
        expect(result.shamirQuotientConstraints).toHaveLength(3 * 22);
        expect(result.shamirQuotientConstraints).toEqual(
            expect.arrayContaining([
                {
                    coordinateRole: 'ScalarScore',
                    encodedCoordinateIndex: 0,
                    evaluatedInteger: 65_543,
                    optionIndex: 0,
                    quotient: 1,
                    receiverRosterPosition: 1,
                    scoreBucketValue: undefined,
                    shareRepresentative: 6,
                },
                {
                    coordinateRole: 'ScoreBucket',
                    encodedCoordinateIndex: 7,
                    evaluatedInteger: 1,
                    optionIndex: 0,
                    quotient: 0,
                    receiverRosterPosition: 1,
                    scoreBucketValue: 7,
                    shareRepresentative: 1,
                },
                {
                    coordinateRole: 'ScalarScore',
                    encodedCoordinateIndex: 11,
                    evaluatedInteger: 30,
                    optionIndex: 1,
                    quotient: 0,
                    receiverRosterPosition: 3,
                    scoreBucketValue: undefined,
                    shareRepresentative: 30,
                },
                {
                    coordinateRole: 'ScoreBucket',
                    encodedCoordinateIndex: 14,
                    evaluatedInteger: 1,
                    optionIndex: 1,
                    quotient: 0,
                    receiverRosterPosition: 3,
                    scoreBucketValue: 3,
                    shareRepresentative: 1,
                },
            ]),
        );
    });

    it('rejects scores outside the frozen score domain', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                normalizedScores: [0, 3],
                scoreOneHotWitnesses: [oneHotScore(1), oneHotScore(3)],
            },
            'score is outside the frozen score domain',
        );
        expectRelationRefusal(
            {
                ...validRelationInput(),
                normalizedScores: [11, 3],
                scoreOneHotWitnesses: [oneHotScore(10), oneHotScore(3)],
            },
            'score is outside the frozen score domain',
        );
    });

    it('rejects malformed one-hot witnesses', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                scoreOneHotWitnesses: [
                    [0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
                    oneHotScore(3),
                ],
            },
            'score one-hot witness is not a valid score encoding',
        );
        expectRelationRefusal(
            {
                ...validRelationInput(),
                scoreOneHotWitnesses: [
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    oneHotScore(3),
                ],
            },
            'score one-hot witness is not a valid score encoding',
        );
        expectRelationRefusal(
            {
                ...validRelationInput(),
                scoreOneHotWitnesses: [[0, 0, 0], oneHotScore(3)],
            },
            'ten-entry one-hot score witness',
        );
    });

    it('rejects signed-cancellation-style one-hot witnesses even when linear equations match', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                scoreOneHotWitnesses: [
                    [0, 0, -1, 0, 2, 0, 0, 0, 0, 0],
                    oneHotScore(3),
                ],
            },
            'score one-hot witness is not a valid score encoding',
        );
    });

    it('rejects wrong polynomial degree and quotient constraints across encoded coordinates', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                encodedCoordinateShamirCoefficients: [
                    [65_536, 1],
                    ...encodedCoordinateShamirCoefficients().slice(1),
                ],
            },
            'degree less than the PVSS threshold',
        );

        const wrongScalarShareInput = validRelationInput();
        expectRelationRefusal(
            {
                ...wrongScalarShareInput,
                receivers: wrongScalarShareInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 2
                        ? {
                              ...receiver,
                              receiverShareVector: encodedShareVector({
                                  firstOptionScoreShare: 6,
                                  secondOptionScoreShare: 21,
                              }),
                          }
                        : receiver,
                ),
            },
            'Shamir quotient constraint is not exact',
        );

        const wrongBucketShareInput = validRelationInput();
        expectRelationRefusal(
            {
                ...wrongBucketShareInput,
                receivers: wrongBucketShareInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 1
                        ? {
                              ...receiver,
                              receiverShareVector:
                                  receiver.receiverShareVector.map(
                                      (shareRepresentative, coordinateIndex) =>
                                          coordinateIndex === 7
                                              ? 0
                                              : shareRepresentative,
                                  ),
                          }
                        : receiver,
                ),
            },
            'Shamir quotient constraint is not exact',
        );
    });

    it('rejects omitted or duplicated receivers', () => {
        const duplicateReceiverInput = validRelationInput();
        expectRelationRefusal(
            {
                ...duplicateReceiverInput,
                receivers: [
                    duplicateReceiverInput.receivers[0],
                    {
                        ...duplicateReceiverInput.receivers[1],
                        receiverRosterPosition: 1,
                    },
                    duplicateReceiverInput.receivers[2],
                ],
            },
            'receiver roster positions must be unique',
        );

        const omittedReceiverInput = validRelationInput();
        expectRelationRefusal(
            {
                ...omittedReceiverInput,
                receivers: omittedReceiverInput.receivers.slice(0, 2),
            },
            'one receiver entry for every roster position',
        );
    });

    it('rejects stale scalar-only layouts and nonzero padding', () => {
        const scalarOnlyInput = validRelationInput();
        expectRelationRefusal(
            {
                ...scalarOnlyInput,
                receivers: scalarOnlyInput.receivers.map((receiver) => ({
                    ...receiver,
                    receiverShareVector: receiver.receiverShareVector.slice(
                        0,
                        2,
                    ),
                })),
            },
            'receiver share vectors must use the encoded width',
        );

        const nonzeroPaddingInput = validRelationInput();
        expectRelationRefusal(
            {
                ...nonzeroPaddingInput,
                receivers: nonzeroPaddingInput.receivers.map((receiver) =>
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
            'share-vector padding must be zero',
        );
    });
});
