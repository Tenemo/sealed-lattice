import { describe, expect, it } from 'vitest';

import {
    compileBallotPrivacyRelation,
    type BallotPrivacyRelationCompilerInput,
} from '../../src/ballot-privacy/index';

const zeroPadding = Array.from({ length: 18 }, () => 0);

const oneHotScore = (score: number): readonly number[] =>
    Array.from({ length: 10 }, (_unusedValue, scoreIndex) =>
        scoreIndex + 1 === score ? 1 : 0,
    );

const validRelationInput = (): BallotPrivacyRelationCompilerInput => ({
    optionCount: 2,
    rosterSize: 3,
    pvssThreshold: 2,
    normalizedScores: [7, 3],
    scoreMembershipWitnesses: [oneHotScore(7), oneHotScore(3)],
    shamirCoefficients: [[65_536], [9]],
    receivers: [
        {
            receiverIdentity: 'receiver-1',
            receiverRosterPosition: 1,
            receiverShareVector: [6, 12, ...zeroPadding],
        },
        {
            receiverIdentity: 'receiver-2',
            receiverRosterPosition: 2,
            receiverShareVector: [5, 21, ...zeroPadding],
        },
        {
            receiverIdentity: 'receiver-3',
            receiverRosterPosition: 3,
            receiverShareVector: [4, 30, ...zeroPadding],
        },
    ],
});

const expectRelationRefusal = (
    input: BallotPrivacyRelationCompilerInput,
    expectedMessage: string,
): void => {
    const result = compileBallotPrivacyRelation(input);

    expect(result.ok).toBe(false);
    if (!result.ok) {
        expect(result.unresolvedReason).toBe('BallotPrivacyRelationInvalid');
        expect(
            result.refusedObjects.some((refusal) =>
                refusal.message.includes(expectedMessage),
            ),
        ).toBe(true);
    }
};

describe('ballot privacy relation compiler', () => {
    it('compiles score membership and Shamir quotient constraints', () => {
        const result = compileBallotPrivacyRelation(validRelationInput());

        expect(result).toMatchObject({
            ok: true,
            relationLabel: 'BallotPrivacyPvssRelation',
            optionCount: 2,
            rosterSize: 3,
            pvssThreshold: 2,
            maximumAbsoluteShamirQuotient: 3,
        });
        if (result.ok) {
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
            expect(result.shamirQuotientConstraints).toEqual([
                {
                    optionIndex: 0,
                    receiverRosterPosition: 1,
                    evaluatedInteger: 65_543,
                    shareRepresentative: 6,
                    quotient: 1,
                },
                {
                    optionIndex: 1,
                    receiverRosterPosition: 1,
                    evaluatedInteger: 12,
                    shareRepresentative: 12,
                    quotient: 0,
                },
                {
                    optionIndex: 0,
                    receiverRosterPosition: 2,
                    evaluatedInteger: 131_079,
                    shareRepresentative: 5,
                    quotient: 2,
                },
                {
                    optionIndex: 1,
                    receiverRosterPosition: 2,
                    evaluatedInteger: 21,
                    shareRepresentative: 21,
                    quotient: 0,
                },
                {
                    optionIndex: 0,
                    receiverRosterPosition: 3,
                    evaluatedInteger: 196_615,
                    shareRepresentative: 4,
                    quotient: 3,
                },
                {
                    optionIndex: 1,
                    receiverRosterPosition: 3,
                    evaluatedInteger: 30,
                    shareRepresentative: 30,
                    quotient: 0,
                },
            ]);
        }
    });

    it('rejects scores outside the frozen score domain', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                normalizedScores: [0, 3],
                scoreMembershipWitnesses: [oneHotScore(1), oneHotScore(3)],
            },
            'score is outside the frozen score domain',
        );
        expectRelationRefusal(
            {
                ...validRelationInput(),
                normalizedScores: [11, 3],
                scoreMembershipWitnesses: [oneHotScore(10), oneHotScore(3)],
            },
            'score is outside the frozen score domain',
        );
    });

    it('rejects malformed one-hot witnesses including signed cancellation', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                scoreMembershipWitnesses: [
                    oneHotScore(7),
                    [-1, 2, 0, 0, 0, 0, 0, 0, 0, 0],
                ],
            },
            'score-membership witness is not one-hot',
        );
        expectRelationRefusal(
            {
                ...validRelationInput(),
                scoreMembershipWitnesses: [
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    oneHotScore(3),
                ],
            },
            'score-membership witness is not one-hot',
        );
    });

    it('rejects wrong polynomial degree, constant term, and quotient constraints', () => {
        expectRelationRefusal(
            {
                ...validRelationInput(),
                shamirCoefficients: [[65_536, 1], [9]],
            },
            'degree less than the PVSS threshold',
        );
        expectRelationRefusal(
            {
                ...validRelationInput(),
                normalizedScores: [8, 3],
                scoreMembershipWitnesses: [oneHotScore(8), oneHotScore(3)],
            },
            'Shamir quotient constraint is not exact',
        );

        const wrongShareInput = validRelationInput();
        expectRelationRefusal(
            {
                ...wrongShareInput,
                receivers: wrongShareInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 2
                        ? {
                              ...receiver,
                              receiverShareVector: [6, 21, ...zeroPadding],
                          }
                        : receiver,
                ),
            },
            'Shamir quotient constraint is not exact',
        );
    });

    it('rejects malformed receiver coverage and share-vector layout', () => {
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

        const nonzeroPaddingInput = validRelationInput();
        expectRelationRefusal(
            {
                ...nonzeroPaddingInput,
                receivers: nonzeroPaddingInput.receivers.map((receiver) =>
                    receiver.receiverRosterPosition === 3
                        ? {
                              ...receiver,
                              receiverShareVector: [
                                  4,
                                  30,
                                  1,
                                  ...zeroPadding.slice(1),
                              ],
                          }
                        : receiver,
                ),
            },
            'share-vector padding must be zero',
        );
    });
});
