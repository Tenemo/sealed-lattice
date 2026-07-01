import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { assertContextMatches, contextFields } from '../common-fields.js';
import { type EvaluatorKeySchedule } from '../evaluator-key-schedule.js';

import {
    type EvaluationKeyProofCommonInput,
    type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    type EvaluationKeyShareMaterial,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareBatchesInput,
    type GaloisKeyShareMaterialRecord,
    type JsonRecord,
    type RelinearizationKeyShareRoundOneRecord,
    type RelinearizationKeyShareRoundTwoRecord,
    type RelinearizationKeyShareRounds,
    type RelinearizationKeyShareRoundsInput,
    type SameSecretProofReference,
    evaluationKeyShareComponentMaterialEncoding,
} from './constants-and-types.js';
import {
    assertLowercaseHex,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertJsonRecord,
} from './encoding.js';

const assertEmbeddedComponentMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    fieldName: string,
): EvaluationKeyShareMaterial &
    EvaluationKeyShareEmbeddedKeySwitchComponentMaterial => {
    if (
        shareMaterial.keySwitchMaterialEncoding !==
        'embedded-full-key-switch-component-vectors'
    ) {
        throw new Error(
            `${fieldName}.keySwitchMaterialEncoding must embed full key-switch component vectors.`,
        );
    }
    if (shareMaterial.keySwitchComponentVectors.length === 0) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectors must be non-empty.`,
        );
    }

    return shareMaterial;
};

const assertShareMaterial = (
    shareMaterial: EvaluationKeyShareMaterial,
    expectedComponentVectorRoot: ProtocolHash,
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
        shareMaterial.keySwitchComponentVectorRoot !==
        expectedComponentVectorRoot
    ) {
        throw new Error(
            `${fieldName}.keySwitchComponentVectorRoot must match the share root.`,
        );
    }
    if (
        shareMaterial.keySwitchMaterialEncoding ===
        'embedded-full-key-switch-component-vectors'
    ) {
        if (shareMaterial.keySwitchComponentVectors.length === 0) {
            throw new Error(
                `${fieldName}.keySwitchComponentVectors must be non-empty.`,
            );
        }
        shareMaterial.keySwitchComponentVectors.forEach(
            (componentVector, vectorIndex) => {
                assertJsonRecord(
                    componentVector,
                    `${fieldName}.keySwitchComponentVectors.${String(vectorIndex)}`,
                );
            },
        );
    } else if (
        shareMaterial.keySwitchMaterialEncoding ===
        evaluationKeyShareComponentMaterialEncoding
    ) {
        for (const [hashFieldName, hashValue] of [
            [
                'keySwitchComponentMaterialRoot',
                shareMaterial.keySwitchComponentMaterialRoot,
            ],
            [
                'keySwitchComponentFullObjectHash',
                shareMaterial.keySwitchComponentFullObjectHash,
            ],
            [
                'keySwitchComponentChunkRoot',
                shareMaterial.keySwitchComponentChunkRoot,
            ],
        ] as const) {
            assertProtocolHash(hashValue, `${fieldName}.${hashFieldName}`);
        }
        assertPositiveSafeInteger(
            shareMaterial.keySwitchComponentChunkSizeBytes,
            `${fieldName}.keySwitchComponentChunkSizeBytes`,
        );
        assertPositiveSafeInteger(
            shareMaterial.keySwitchComponentChunkCount,
            `${fieldName}.keySwitchComponentChunkCount`,
        );
        assertPositiveSafeInteger(
            shareMaterial.keySwitchComponentTotalByteLength,
            `${fieldName}.keySwitchComponentTotalByteLength`,
        );
        if (
            shareMaterial.keySwitchComponentChunkHashes.length !==
            shareMaterial.keySwitchComponentChunkCount
        ) {
            throw new Error(
                `${fieldName}.keySwitchComponentChunkHashes must match keySwitchComponentChunkCount.`,
            );
        }
        shareMaterial.keySwitchComponentChunkHashes.forEach(
            (chunkHash, chunkIndex) => {
                assertProtocolHash(
                    chunkHash,
                    `${fieldName}.keySwitchComponentChunkHashes.${String(chunkIndex)}`,
                );
            },
        );
    } else {
        throw new TypeError(
            `${fieldName}.keySwitchMaterialEncoding must be embedded-full-key-switch-component-vectors or binary-chunked-key-switch-component-vectors.`,
        );
    }
};

const shareMaterialRecordFields = (
    shareMaterial: EvaluationKeyShareMaterial,
): JsonRecord => ({
    keySwitchDomain: shareMaterial.keySwitchDomain,
    keySwitchSeedHex: shareMaterial.keySwitchSeedHex,
    ringDegree: shareMaterial.ringDegree,
    keySwitchComponentVectorRoot: shareMaterial.keySwitchComponentVectorRoot,
    ...(shareMaterial.keySwitchMaterialEncoding ===
    'embedded-full-key-switch-component-vectors'
        ? {
              keySwitchMaterialEncoding:
                  shareMaterial.keySwitchMaterialEncoding,
              keySwitchComponentVectors:
                  shareMaterial.keySwitchComponentVectors,
          }
        : {
              keySwitchMaterialEncoding:
                  shareMaterial.keySwitchMaterialEncoding,
              keySwitchComponentMaterialRoot:
                  shareMaterial.keySwitchComponentMaterialRoot,
              keySwitchComponentChunkSizeBytes:
                  shareMaterial.keySwitchComponentChunkSizeBytes,
              keySwitchComponentChunkCount:
                  shareMaterial.keySwitchComponentChunkCount,
              keySwitchComponentTotalByteLength:
                  shareMaterial.keySwitchComponentTotalByteLength,
              keySwitchComponentFullObjectHash:
                  shareMaterial.keySwitchComponentFullObjectHash,
              keySwitchComponentChunkRoot:
                  shareMaterial.keySwitchComponentChunkRoot,
              keySwitchComponentChunkHashes:
                  shareMaterial.keySwitchComponentChunkHashes,
          }),
});

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

const relinearizationKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        proofFamily: 'relinearization-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: evaluatorKeySchedule.relinearizationCrpRoot,
        round,
        level,
    });

const galoisKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
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

const sortedSameSecretProofReferences = (
    input: Pick<
        EvaluationKeyProofCommonInput,
        'participantCount' | 'sameSecretProofReferences'
    >,
): SameSecretProofReference[] => {
    const references = [...input.sameSecretProofReferences].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (references.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofReferences must contain one proof per participant.',
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
                'sameSecretProofReferences roster positions must be contiguous from zero.',
            );
        }
        for (const [fieldName, hashValue] of [
            ['sameSecretStatementRoot', reference.sameSecretStatementRoot],
            [
                'trusteeSecretCommitmentRoot',
                reference.trusteeSecretCommitmentRoot,
            ],
            ['sameSecretProofRoot', reference.sameSecretProofRoot],
        ] as const) {
            assertProtocolHash(hashValue, fieldName);
        }
    });

    return references;
};

export const validateCommonInput = (
    input: EvaluationKeyProofCommonInput,
): SameSecretProofReference[] => {
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
    assertContextMatches(
        input.setupContext,
        input.evaluatorKeySchedule,
        'evaluatorKeySchedule',
    );
    if (
        input.evaluatorKeySchedule.participantCount !==
            input.participantCount ||
        input.evaluatorKeySchedule.rnsLimbCount !== input.qSharePrimes.length
    ) {
        throw new Error(
            'evaluatorKeySchedule must match participant and RNS limb counts.',
        );
    }
    for (const [fieldName, hashValue] of [
        [
            'evaluatorKeyScheduleRoot',
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        ],
        [
            'sameSecretConsistencyRoot',
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        ],
        ['sameSecretProofSetRoot', input.sameSecretProofSetRoot],
        [
            'sameSecretProofFamilyBindingRoot',
            input.sameSecretProofFamilyBindingRoot,
        ],
        [
            'publicKeyShareSetRoot',
            input.evaluatorKeySchedule.publicKeyShareSetRoot,
        ],
        [
            'publicKeyShareSuccinctProofSetRoot',
            input.publicKeyShareSuccinctProofSetRoot,
        ],
        [
            'relinearizationCrpRoot',
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        ],
        ['galoisKeyCrpRoot', input.evaluatorKeySchedule.galoisKeyCrpRoot],
        [
            'requiredGaloisSetHash',
            input.evaluatorKeySchedule.requiredGaloisSetHash,
        ],
    ] as const) {
        assertProtocolHash(hashValue, fieldName);
    }

    return sortedSameSecretProofReferences(input);
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
    const sameSecretProofReferences = validateCommonInput(input);
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
    const roundOneShareRoots = new Map<string, ProtocolHash>();
    const roundOneRecordRoots = new Map<string, ProtocolHash>();
    const roundOneAggregateRootByLevel = new Map<number, ProtocolHash>();
    const roundOneAggregateRoots = levels.map((level) => {
        const roundOneRecordRootsForLevel = sameSecretProofReferences.map(
            (proofReference) => {
                const key = contributionKey(
                    level,
                    proofReference.trusteeRosterPosition,
                );
                const contribution = roundOneContributions.get(key);
                if (contribution === undefined) {
                    throw new Error(
                        'roundOneContributions is missing a scheduled trustee and level.',
                    );
                }
                assertProtocolHash(
                    contribution.roundOneShareRoot,
                    'roundOneShareRoot',
                );
                assertShareMaterial(
                    contribution.shareMaterial,
                    contribution.roundOneShareRoot,
                    'roundOneContributions.shareMaterial',
                );
                assertRelinearizationKeySwitchSampleBinding(
                    contribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    'round-one',
                    level,
                    'roundOneContributions.shareMaterial',
                );
                const recordWithoutRoot = {
                    objectType: 'RelinearizationKeyShareRoundOne',
                    objectVersion: 1,
                    proofFamily: 'relinearization-key-share',
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareSuccinctProofSetRoot:
                        input.publicKeyShareSuccinctProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot: contribution.roundOneShareRoot,
                    ...shareMaterialRecordFields(contribution.shareMaterial),
                } as JsonRecord;
                const roundOneRecordRoot =
                    deriveCanonicalObjectHash(recordWithoutRoot);
                roundOneShareRoots.set(key, contribution.roundOneShareRoot);
                roundOneRecordRoots.set(key, roundOneRecordRoot);
                roundOneRecords.push({
                    ...recordWithoutRoot,
                    roundOneRecordRoot,
                } as RelinearizationKeyShareRoundOneRecord);

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundOneRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = deriveCanonicalObjectHash({
            objectType: 'RelinearizationRoundOneAggregate',
            objectVersion: 1,
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            level,
            roundOneRecordRoots: roundOneRecordRootsForLevel,
        });
        roundOneAggregateRootByLevel.set(level, roundOneAggregateRoot);

        return {
            level,
            roundOneAggregateRoot,
        };
    });

    const roundTwoRecords: RelinearizationKeyShareRoundTwoRecord[] = [];
    const roundTwoAggregateRoots = levels.map((level) => {
        const roundTwoRecordRootsForLevel = sameSecretProofReferences.map(
            (proofReference) => {
                const key = contributionKey(
                    level,
                    proofReference.trusteeRosterPosition,
                );
                const contribution = roundTwoContributions.get(key);
                const roundOneShareRoot = roundOneShareRoots.get(key);
                const roundOneRecordRoot = roundOneRecordRoots.get(key);
                const roundOneAggregateRoot =
                    roundOneAggregateRootByLevel.get(level);
                if (
                    contribution === undefined ||
                    roundOneShareRoot === undefined ||
                    roundOneRecordRoot === undefined ||
                    roundOneAggregateRoot === undefined
                ) {
                    throw new Error(
                        'roundTwoContributions is missing a scheduled trustee and level.',
                    );
                }
                assertProtocolHash(
                    contribution.roundTwoShareRoot,
                    'roundTwoShareRoot',
                );
                assertShareMaterial(
                    contribution.shareMaterial,
                    contribution.roundTwoShareRoot,
                    'roundTwoContributions.shareMaterial',
                );
                assertRelinearizationKeySwitchSampleBinding(
                    contribution.shareMaterial,
                    input.evaluatorKeySchedule,
                    'round-two',
                    level,
                    'roundTwoContributions.shareMaterial',
                );
                const recordWithoutRoot = {
                    objectType: 'RelinearizationKeyShareRoundTwo',
                    objectVersion: 1,
                    proofFamily: 'relinearization-key-share',
                    ...contextFields(input.setupContext),
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    level,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretConsistencyRoot:
                        input.evaluatorKeySchedule.sameSecretConsistencyRoot,
                    sameSecretProofSetRoot: input.sameSecretProofSetRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareSuccinctProofSetRoot:
                        input.publicKeyShareSuccinctProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot,
                    roundOneRecordRoot,
                    roundOneAggregateRoot,
                    roundTwoShareRoot: contribution.roundTwoShareRoot,
                    ...shareMaterialRecordFields(contribution.shareMaterial),
                } as JsonRecord;
                const roundTwoRecordRoot =
                    deriveCanonicalObjectHash(recordWithoutRoot);
                roundTwoRecords.push({
                    ...recordWithoutRoot,
                    roundTwoRecordRoot,
                } as RelinearizationKeyShareRoundTwoRecord);

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundTwoRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = roundOneAggregateRootByLevel.get(level);
        if (roundOneAggregateRoot === undefined) {
            throw new Error(
                'roundTwoContributions is missing a scheduled round-one aggregate root.',
            );
        }
        const roundTwoAggregateRoot = deriveCanonicalObjectHash({
            objectType: 'RelinearizationRoundTwoAggregate',
            objectVersion: 1,
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            level,
            roundOneAggregateRoot,
            roundTwoRecordRoots: roundTwoRecordRootsForLevel,
        });

        return {
            level,
            roundTwoAggregateRoot,
        };
    });

    const roundsWithoutRoot = {
        objectType: 'RelinearizationKeyShareRounds',
        objectVersion: 1,
        proofFamily: 'relinearization-key-share',
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        sameSecretConsistencyRoot:
            input.evaluatorKeySchedule.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofSetRoot,
        relinearizationCrpRoot:
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        relinearizationLevelSchedule:
            input.evaluatorKeySchedule.relinearizationLevelSchedule,
        roundOneAggregateRoots,
        roundOneRecords,
        roundTwoAggregateRoots,
        roundTwoRecords,
    } as const satisfies Omit<
        RelinearizationKeyShareRounds,
        'relinearizationKeyShareRoundsRoot'
    >;

    return {
        ...roundsWithoutRoot,
        relinearizationKeyShareRoundsRoot:
            deriveCanonicalObjectHash(roundsWithoutRoot),
    } satisfies RelinearizationKeyShareRounds;
};

export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => {
    const sameSecretProofReferences = validateCommonInput(input);
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

    return sameSecretProofReferences.map((proofReference) => {
        const contribution = contributionsByRosterPosition.get(
            proofReference.trusteeRosterPosition,
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
            (shareContribution, index) => {
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
                    shareContribution.galoisKeyShareRoot,
                    'galoisKeyShareRoot',
                );
                assertShareMaterial(
                    shareContribution.shareMaterial,
                    shareContribution.galoisKeyShareRoot,
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
                    objectVersion: 1,
                    proofFamily: 'galois-key-share',
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    rotation: shareContribution.rotation,
                    level: shareContribution.level,
                    galoisKeyShareRoot: shareContribution.galoisKeyShareRoot,
                    ...shareMaterialRecordFields(
                        shareContribution.shareMaterial,
                    ),
                } as GaloisKeyShareMaterialRecord;
            },
        );
        const batchWithoutRoot = {
            objectType: 'GaloisKeyShareBatch',
            objectVersion: 1,
            proofFamily: 'galois-key-share',
            ...contextFields(input.setupContext),
            trusteeIdentity: proofReference.trusteeIdentity,
            trusteeRosterPosition: proofReference.trusteeRosterPosition,
            evaluatorKeyScheduleRoot:
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
            sameSecretConsistencyRoot:
                input.evaluatorKeySchedule.sameSecretConsistencyRoot,
            sameSecretProofSetRoot: input.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                input.sameSecretProofFamilyBindingRoot,
            publicKeyShareSuccinctProofSetRoot:
                input.publicKeyShareSuccinctProofSetRoot,
            sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                proofReference.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: proofReference.sameSecretProofRoot,
            galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
            requiredGaloisSetHash:
                input.evaluatorKeySchedule.requiredGaloisSetHash,
            requiredGaloisKeySchedule:
                input.evaluatorKeySchedule.requiredGaloisKeySchedule,
            galoisKeyShareMaterialRecords,
        } as const satisfies Omit<
            GaloisKeyShareBatch,
            'galoisKeyShareBatchRoot'
        >;

        return {
            ...batchWithoutRoot,
            galoisKeyShareBatchRoot:
                deriveCanonicalObjectHash(batchWithoutRoot),
        } satisfies GaloisKeyShareBatch;
    });
};

export { assertContextMatches, assertEmbeddedComponentMaterial, contextFields };
