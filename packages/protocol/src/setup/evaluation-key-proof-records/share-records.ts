import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertSetupContextHashMatches,
    deriveCollectiveBgvSetupContextHash,
} from '../common-fields.js';
import { type EvaluatorKeySchedule } from '../evaluator-key-schedule.js';

import {
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyTrusteeReference,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareBatchesInput,
    type GaloisKeyShareMaterialRecord,
    type RelinearizationKeyShareRoundOneRecord,
    type RelinearizationKeyShareRoundTwoRecord,
    type RelinearizationKeyShareRounds,
    type RelinearizationKeyShareRoundsInput,
    evaluationKeyShareComponentMaterialEncoding,
} from './constants-and-types.js';
import {
    assertLowercaseHex,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
} from './encoding.js';

const assertShareMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    fieldName: string,
): void => {
    assertNonEmptyString(
        shareMaterial.keySwitchDomain,
        `${fieldName}.keySwitchDomain`,
    );
    assertNonEmptyString(
        shareMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertLowercaseHex(
        shareMaterial.keySwitchSeedHex,
        `${fieldName}.keySwitchSeedHex`,
    );
    assertPositiveSafeInteger(
        shareMaterial.ringDegree,
        `${fieldName}.ringDegree`,
    );
    assertProtocolHash(
        shareMaterial.keySwitchComponentVectorRoot,
        `${fieldName}.keySwitchComponentVectorRoot`,
    );
    if (
        shareMaterial.keySwitchMaterialEncoding ===
        evaluationKeyShareComponentMaterialEncoding
    ) {
        assertProtocolHash(
            shareMaterial.keySwitchComponentMaterialRoot,
            `${fieldName}.keySwitchComponentMaterialRoot`,
        );
    } else {
        throw new TypeError(
            `${fieldName}.keySwitchMaterialEncoding must be binary-chunked-key-switch-component-vectors.`,
        );
    }
};

const shareMaterialRecordFields = (
    shareMaterial: EvaluationKeyShareMaterial,
): Readonly<{
    readonly keySwitchComponentVectorRoot: ProtocolHash;
    readonly keySwitchComponentMaterialRoot: ProtocolHash;
}> => ({
    keySwitchComponentVectorRoot: shareMaterial.keySwitchComponentVectorRoot,
    keySwitchComponentMaterialRoot:
        shareMaterial.keySwitchComponentMaterialRoot,
});

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

export const relinearizationKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        publicMatrixSeedHash: evaluatorKeySchedule.publicMatrixSeedHash,
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        round,
        level,
    });

export const galoisKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        publicMatrixSeedHash: evaluatorKeySchedule.publicMatrixSeedHash,
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        rotation,
        level,
    });

const assertRelinearizationKeySwitchSampleBinding = (
    shareMaterial: EvaluationKeyShareMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
    fieldName: string,
): void => {
    if (shareMaterial.keySwitchDomain !== 'relinearization') {
        throw new Error(
            `${fieldName}.keySwitchDomain must be relinearization.`,
        );
    }
    const expectedSeed = relinearizationKeySwitchSeed(
        evaluatorKeySchedule,
        round,
        level,
    );
    if (shareMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled relinearization level and round.`,
        );
    }
};

const assertGaloisKeySwitchSampleBinding = (
    shareMaterial: EvaluationKeyShareMaterial,
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
    fieldName: string,
): void => {
    const expectedDomain = `galois-${String(rotation)}`;
    if (shareMaterial.keySwitchDomain !== expectedDomain) {
        throw new Error(
            `${fieldName}.keySwitchDomain must match the scheduled Galois rotation.`,
        );
    }
    const expectedSeed = galoisKeySwitchSeed(
        evaluatorKeySchedule,
        rotation,
        level,
    );
    if (shareMaterial.keySwitchSeedHex !== expectedSeed) {
        throw new Error(
            `${fieldName}.keySwitchSeedHex must be shared by scheduled Galois rotation and level.`,
        );
    }
};

const sortedTrusteeReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        'participantCount' | 'trusteeReferences'
    >,
): EvaluationKeyTrusteeReference[] => {
    const references = [...input.trusteeReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.participantCount) {
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

export const validateCommonInput = (
    input: EvaluationKeyProofCommonInput,
): EvaluationKeyTrusteeReference[] => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
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
            'evaluatorKeyScheduleRoot',
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        ],
        [
            'publicKeyShareSetRoot',
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        [
            'publicMatrixSeedHash',
            input.evaluatorKeySchedule.publicMatrixSeedHash,
        ],
        [
            'publicKeyShareSuccinctProofSetRoot',
            input.publicKeyShareSuccinctProofSetRoot,
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
    const roundOneRecords: RelinearizationKeyShareRoundOneRecord[] = [];
    levels.forEach((level) => {
        trusteeReferences.forEach((trusteeReference) => {
            const key = contributionKey(
                level,
                trusteeReference.trusteeRosterPosition,
            );
            const contribution = roundOneContributions.get(key);
            if (contribution === undefined) {
                throw new Error(
                    'roundOneContributions is missing a scheduled trustee and level.',
                );
            }
            assertShareMaterial(
                contribution.shareMaterial,
                'roundOneContributions.shareMaterial',
            );
            assertRelinearizationKeySwitchSampleBinding(
                contribution.shareMaterial,
                input.evaluatorKeySchedule,
                'round-one',
                level,
                'roundOneContributions.shareMaterial',
            );
            roundOneRecords.push({
                objectType: 'RelinearizationKeyShareRoundOne',
                trusteeIdentity: trusteeReference.trusteeIdentity,
                trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
                level,
                ...shareMaterialRecordFields(contribution.shareMaterial),
            });
        });
    });

    const roundTwoRecords: RelinearizationKeyShareRoundTwoRecord[] = [];
    levels.forEach((level) => {
        trusteeReferences.forEach((trusteeReference) => {
            const key = contributionKey(
                level,
                trusteeReference.trusteeRosterPosition,
            );
            const contribution = roundTwoContributions.get(key);
            if (contribution === undefined) {
                throw new Error(
                    'roundTwoContributions is missing a scheduled trustee and level.',
                );
            }
            assertShareMaterial(
                contribution.shareMaterial,
                'roundTwoContributions.shareMaterial',
            );
            assertRelinearizationKeySwitchSampleBinding(
                contribution.shareMaterial,
                input.evaluatorKeySchedule,
                'round-two',
                level,
                'roundTwoContributions.shareMaterial',
            );
            roundTwoRecords.push({
                objectType: 'RelinearizationKeyShareRoundTwo',
                trusteeIdentity: trusteeReference.trusteeIdentity,
                trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
                level,
                ...shareMaterialRecordFields(contribution.shareMaterial),
            });
        });
    });

    return {
        objectType: 'RelinearizationKeyShareRounds',
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofSetRoot,
        roundOneRecords,
        roundTwoRecords,
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
        const galoisKeyShareMaterialRecords = contribution.galoisKeyShares.map(
            (shareContribution, index): GaloisKeyShareMaterialRecord => {
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
                assertShareMaterial(
                    shareContribution.shareMaterial,
                    'galoisKeyShares.shareMaterial',
                );
                assertGaloisKeySwitchSampleBinding(
                    shareContribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    shareContribution.rotation,
                    shareContribution.level,
                    'galoisKeyShares.shareMaterial',
                );

                return {
                    objectType: 'GaloisKeyShareMaterial',
                    rotation: shareContribution.rotation,
                    level: shareContribution.level,
                    ...shareMaterialRecordFields(
                        shareContribution.shareMaterial,
                    ),
                };
            },
        );
        return {
            objectType: 'GaloisKeyShareBatch',
            trusteeIdentity: trusteeReference.trusteeIdentity,
            trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
            galoisKeyShareMaterialRecords,
        } satisfies GaloisKeyShareBatch;
    });
};

export { assertSetupContextHashMatches, deriveCollectiveBgvSetupContextHash };
