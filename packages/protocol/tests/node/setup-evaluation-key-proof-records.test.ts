import { describe, expect, it } from 'vitest';

import { deriveCollectiveBgvSetupContextHash } from '#packages/protocol/src/setup/common-fields';
import {
    createGaloisKeyShareBatches,
    createRelinearizationKeyShareRounds,
    type EvaluationKeyProofCommonInput,
    type GaloisKeyShareBatchContribution,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
} from '#packages/protocol/src/setup/evaluation-key-proof-records';
import type { EvaluatorKeySchedule } from '#packages/protocol/src/setup/evaluator-key-schedule';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const participantCount = 3;
const fixtureHash = makeSetupFixtureHash('setup-evaluation-key-proof-records');
const setupContext = makeSetupContext(fixtureHash, participantCount);
const relinearizationLevels = [1, 2] as const;
const requiredGaloisKeySchedule = [
    { rotation: 3, level: 2 },
    { rotation: 7, level: 1 },
] as const;

const evaluatorKeySchedule = (): EvaluatorKeySchedule => ({
    objectType: 'EvaluatorKeySchedule',
    setupContextHash: deriveCollectiveBgvSetupContextHash(setupContext),
    publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
    publicKeyShareSetRoot: fixtureHash('public-key-share-set'),
    relinearizationLevelSchedule: relinearizationLevels.map((level) => ({
        level,
    })),
    requiredGaloisKeySchedule,
});

const commonInput = (): EvaluationKeyProofCommonInput => ({
    setupContext,
    qSharePrimes: [101, 103, 107],
    evaluatorKeySchedule: evaluatorKeySchedule(),
    trusteeReferences: [2, 0, 1].map((trusteeRosterPosition) => ({
        trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
        trusteeRosterPosition,
    })),
});

const roundRoot = (
    round: 'round-one' | 'round-two',
    level: number,
    trusteeRosterPosition: number,
) => fixtureHash(`${round}-${String(level)}-${String(trusteeRosterPosition)}`);

const roundContributions = <
    Contribution extends
        | RelinearizationRoundOneContribution
        | RelinearizationRoundTwoContribution,
>(
    round: 'round-one' | 'round-two',
): Contribution[] =>
    relinearizationLevels
        .flatMap((level) =>
            [0, 1, 2].map((trusteeRosterPosition) => ({
                trusteeRosterPosition,
                level,
                keySwitchComponentMaterialRoot: roundRoot(
                    round,
                    level,
                    trusteeRosterPosition,
                ),
            })),
        )
        .reverse() as Contribution[];

const galoisBatchContributions = (): GaloisKeyShareBatchContribution[] =>
    [2, 0, 1].map((trusteeRosterPosition) => ({
        trusteeRosterPosition,
        galoisKeyShares: requiredGaloisKeySchedule.map(
            ({ rotation, level }) => ({
                rotation,
                level,
                keySwitchComponentMaterialRoot: fixtureHash(
                    `galois-${String(trusteeRosterPosition)}-${String(rotation)}-${String(level)}`,
                ),
            }),
        ),
    }));

describe('createRelinearizationKeyShareRounds', () => {
    it('orders every scheduled root by level and roster position', () => {
        const result = createRelinearizationKeyShareRounds({
            ...commonInput(),
            roundOneContributions:
                roundContributions<RelinearizationRoundOneContribution>(
                    'round-one',
                ),
            roundTwoContributions:
                roundContributions<RelinearizationRoundTwoContribution>(
                    'round-two',
                ),
        });

        expect(result).toEqual({
            objectType: 'RelinearizationKeyShareRounds',
            roundOneKeySwitchComponentMaterialRoots:
                relinearizationLevels.flatMap((level) =>
                    [0, 1, 2].map((trusteeRosterPosition) =>
                        roundRoot('round-one', level, trusteeRosterPosition),
                    ),
                ),
            roundTwoKeySwitchComponentMaterialRoots:
                relinearizationLevels.flatMap((level) =>
                    [0, 1, 2].map((trusteeRosterPosition) =>
                        roundRoot('round-two', level, trusteeRosterPosition),
                    ),
                ),
        });
    });

    it('rejects missing, duplicate, extraneous, malformed, and wrong-context contributions', () => {
        const roundOne =
            roundContributions<RelinearizationRoundOneContribution>(
                'round-one',
            );
        const roundTwo =
            roundContributions<RelinearizationRoundTwoContribution>(
                'round-two',
            );
        const invoke = (
            overrides: Partial<
                Parameters<typeof createRelinearizationKeyShareRounds>[0]
            >,
        ) =>
            createRelinearizationKeyShareRounds({
                ...commonInput(),
                roundOneContributions: roundOne,
                roundTwoContributions: roundTwo,
                ...overrides,
            });

        expect(() =>
            invoke({ roundOneContributions: roundOne.slice(1) }),
        ).toThrow('missing a scheduled trustee and level');
        expect(() =>
            invoke({ roundOneContributions: [...roundOne, roundOne[0]] }),
        ).toThrow('must not repeat a trustee and level');
        expect(() =>
            invoke({
                roundOneContributions: [
                    ...roundOne,
                    {
                        ...roundOne[0],
                        level: 9,
                    },
                ],
            }),
        ).toThrow('must match the scheduled trustees and levels exactly');
        expect(() =>
            invoke({
                roundOneContributions: [
                    { ...roundOne[0], keySwitchComponentMaterialRoot: 'bad' },
                    ...roundOne.slice(1),
                ],
            }),
        ).toThrow('must be a protocol hash');
        expect(() =>
            invoke({
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'different-epoch',
                },
            }),
        ).toThrow('must match the authoritative setup context');
    });
});

describe('createGaloisKeyShareBatches', () => {
    it('orders trustee batches while preserving the frozen key schedule', () => {
        const result = createGaloisKeyShareBatches({
            ...commonInput(),
            batchContributions: galoisBatchContributions(),
        });

        expect(result).toEqual(
            [0, 1, 2].map((trusteeRosterPosition) => ({
                objectType: 'GaloisKeyShareBatch',
                keySwitchComponentMaterialRoots: requiredGaloisKeySchedule.map(
                    ({ rotation, level }) =>
                        fixtureHash(
                            `galois-${String(trusteeRosterPosition)}-${String(rotation)}-${String(level)}`,
                        ),
                ),
            })),
        );
    });

    it('rejects missing, duplicate, extraneous, reordered, and malformed batches', () => {
        const batches = galoisBatchContributions();
        const invoke = (
            batchContributions: readonly GaloisKeyShareBatchContribution[],
        ) =>
            createGaloisKeyShareBatches({
                ...commonInput(),
                batchContributions,
            });

        expect(() => invoke(batches.slice(1))).toThrow(
            'one batch per participant',
        );
        expect(() => invoke([...batches, batches[0]])).toThrow(
            'must not repeat a trustee roster position',
        );
        expect(() =>
            invoke([
                ...batches,
                {
                    ...batches[0],
                    trusteeRosterPosition: 9,
                },
            ]),
        ).toThrow('one batch per participant');
        expect(() =>
            invoke([
                {
                    ...batches[0],
                    galoisKeyShares: [...batches[0].galoisKeyShares].reverse(),
                },
                ...batches.slice(1),
            ]),
        ).toThrow('must follow the frozen Galois key schedule');
        expect(() =>
            invoke([
                {
                    ...batches[0],
                    galoisKeyShares: [
                        {
                            ...batches[0].galoisKeyShares[0],
                            keySwitchComponentMaterialRoot: 'bad',
                        },
                        ...batches[0].galoisKeyShares.slice(1),
                    ],
                },
                ...batches.slice(1),
            ]),
        ).toThrow('must be a protocol hash');
    });
});
