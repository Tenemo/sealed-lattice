import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertSetupContextHashMatches,
    requireFoundationRosterParameters,
} from '../common-fields.js';

import {
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyTrusteeReference,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareBatchesInput,
    type RelinearizationKeyShareRounds,
    type RelinearizationKeyShareRoundsInput,
} from './constants-and-types.js';

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

const sortedTrusteeReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        'setupContext' | 'trusteeReferences'
    >,
): EvaluationKeyTrusteeReference[] => {
    const references = [...input.trusteeReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.setupContext.participantCount) {
        throw new Error(
            'trusteeReferences must contain one trustee per participant.',
        );
    }
    references.forEach((reference, expectedRosterPosition) => {
        assertNonEmptyString(reference.trusteeIdentity, 'trusteeIdentity');
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            'trusteeRosterPosition',
        );
        if (reference.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'trusteeReferences roster positions must be contiguous from zero.',
            );
        }
    });

    return references;
};

const validateCommonInput = (
    input: EvaluationKeyProofCommonInput,
): EvaluationKeyTrusteeReference[] => {
    requireFoundationRosterParameters(
        input.setupContext.participantCount,
        'setupContext.participantCount',
    );
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertSetupContextHashMatches(
        input.setupContext,
        input.evaluatorKeySchedule,
        'evaluatorKeySchedule',
    );
    for (const [fieldName, hashValue] of [
        [
            'publicKeyShareSetRoot',
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        [
            'publicMatrixSeedHash',
            input.evaluatorKeySchedule.publicMatrixSeedHash,
        ],
    ] as const) {
        assertProtocolHash(hashValue, fieldName);
    }

    return sortedTrusteeReferences(input);
};

const contributionMap = <
    Contribution extends {
        readonly trusteeRosterPosition: number;
        readonly level: number;
    },
>(
    contributions: readonly Contribution[],
    fieldName: string,
): ReadonlyMap<string, Contribution> => {
    const byKey = new Map<string, Contribution>();
    contributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            `${fieldName}.trusteeRosterPosition`,
        );
        assertNonNegativeSafeInteger(contribution.level, `${fieldName}.level`);
        const key = contributionKey(
            contribution.level,
            contribution.trusteeRosterPosition,
        );
        if (byKey.has(key)) {
            throw new Error(
                `${fieldName} must not repeat a trustee and level.`,
            );
        }
        byKey.set(key, contribution);
    });

    return byKey;
};

const scheduledRelinearizationMaterialRoots = (
    contributions: ReadonlyMap<
        string,
        Readonly<{ readonly keySwitchComponentMaterialRoot: ProtocolHash }>
    >,
    fieldName: 'roundOneContributions' | 'roundTwoContributions',
    trusteeReferences: readonly EvaluationKeyTrusteeReference[],
    levels: readonly number[],
): ProtocolHash[] => {
    const materialRoots: ProtocolHash[] = [];
    levels.forEach((level) => {
        trusteeReferences.forEach((trusteeReference) => {
            const contribution = contributions.get(
                contributionKey(level, trusteeReference.trusteeRosterPosition),
            );
            if (contribution === undefined) {
                throw new Error(
                    `${fieldName} is missing a scheduled trustee and level.`,
                );
            }
            assertProtocolHash(
                contribution.keySwitchComponentMaterialRoot,
                `${fieldName}.keySwitchComponentMaterialRoot`,
            );
            materialRoots.push(contribution.keySwitchComponentMaterialRoot);
        });
    });

    return materialRoots;
};

export const createRelinearizationKeyShareRounds = (
    input: RelinearizationKeyShareRoundsInput,
): RelinearizationKeyShareRounds => {
    const trusteeReferences = validateCommonInput(input);
    const roundOneContributions = contributionMap(
        input.roundOneContributions,
        'roundOneContributions',
    );
    const roundTwoContributions = contributionMap(
        input.roundTwoContributions,
        'roundTwoContributions',
    );
    const levels = input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
        (entry) => entry.level,
    );
    const roundOneKeySwitchComponentMaterialRoots =
        scheduledRelinearizationMaterialRoots(
            roundOneContributions,
            'roundOneContributions',
            trusteeReferences,
            levels,
        );
    const roundTwoKeySwitchComponentMaterialRoots =
        scheduledRelinearizationMaterialRoots(
            roundTwoContributions,
            'roundTwoContributions',
            trusteeReferences,
            levels,
        );
    const expectedContributionCount = levels.length * trusteeReferences.length;
    if (
        roundOneContributions.size !== expectedContributionCount ||
        roundTwoContributions.size !== expectedContributionCount
    ) {
        throw new Error(
            'relinearization contributions must match the scheduled trustees and levels exactly.',
        );
    }

    return {
        objectType: 'RelinearizationKeyShareRounds',
        roundOneKeySwitchComponentMaterialRoots,
        roundTwoKeySwitchComponentMaterialRoots,
    } satisfies RelinearizationKeyShareRounds;
};

export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => {
    const trusteeReferences = validateCommonInput(input);
    const contributionsByRosterPosition = new Map<
        number,
        GaloisKeyShareBatchContribution
    >();
    input.batchContributions.forEach((contribution) => {
        assertNonNegativeSafeInteger(
            contribution.trusteeRosterPosition,
            'batchContributions.trusteeRosterPosition',
        );
        if (
            contributionsByRosterPosition.has(
                contribution.trusteeRosterPosition,
            )
        ) {
            throw new Error(
                'batchContributions must not repeat a trustee roster position.',
            );
        }
        contributionsByRosterPosition.set(
            contribution.trusteeRosterPosition,
            contribution,
        );
    });
    if (contributionsByRosterPosition.size !== trusteeReferences.length) {
        throw new Error(
            'batchContributions must contain one batch per participant.',
        );
    }

    return trusteeReferences.map((trusteeReference) => {
        const contribution = contributionsByRosterPosition.get(
            trusteeReference.trusteeRosterPosition,
        );
        if (contribution === undefined) {
            throw new Error(
                'batchContributions must contain one batch per participant.',
            );
        }
        if (
            contribution.galoisKeyShares.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                'galoisKeyShares must contain one share per required Galois key.',
            );
        }
        const keySwitchComponentMaterialRoots =
            contribution.galoisKeyShares.map((shareContribution, index) => {
                const expectedScheduleEntry =
                    input.evaluatorKeySchedule.requiredGaloisKeySchedule[index];
                if (
                    shareContribution.rotation !==
                        expectedScheduleEntry.rotation ||
                    shareContribution.level !== expectedScheduleEntry.level
                ) {
                    throw new Error(
                        'galoisKeyShares must follow the frozen Galois key schedule.',
                    );
                }
                assertProtocolHash(
                    shareContribution.keySwitchComponentMaterialRoot,
                    'galoisKeyShares.keySwitchComponentMaterialRoot',
                );

                return shareContribution.keySwitchComponentMaterialRoot;
            });
        return {
            objectType: 'GaloisKeyShareBatch',
            keySwitchComponentMaterialRoots,
        } satisfies GaloisKeyShareBatch;
    });
};
