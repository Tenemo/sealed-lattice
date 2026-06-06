import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type EvaluatorKeySchedule,
    type RelinearizationLevelScheduleEntry,
    type RequiredGaloisKeyScheduleEntry,
} from './evaluator-key-schedule.js';
import { setupProofProfileId } from './same-secret-consistency-records.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const relinearizationProofVerificationStatus =
    'lnp-relinearization-proof-records-bound-review-gated';
export const relinearizationProofModelStatus =
    'round-one and round-two proof records are root-bound to the frozen evaluator schedule, accepted same-secret proof roots, same-secret proof-family root, public-key LNP proof-set root, relinearization CRP root, decomposition level, round-one aggregate root, and round-two share roots; algebraic LNP verifier and full tbox quadratic/range closure remain required before evaluation-key acceptance';
export const galoisProofVerificationStatus =
    'lnp-galois-proof-records-bound-review-gated';
export const galoisProofModelStatus =
    'Galois proof batches are root-bound to the frozen evaluator schedule, RequiredGaloisSetHash, accepted same-secret proof roots, same-secret proof-family root, public-key LNP proof-set root, Galois CRP root, exact automorphism/level schedule, and per-trustee batch roots; algebraic LNP verifier and full tbox closure remain required before evaluation-key acceptance';

export type SameSecretProofReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
}>;

export type RelinearizationRoundOneContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundOneShareRoot: ProtocolHash;
    readonly roundOneProofRoot: ProtocolHash;
}>;

export type RelinearizationRoundTwoContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundTwoShareRoot: ProtocolHash;
    readonly roundTwoProofRoot: ProtocolHash;
}>;

export type RelinearizationKeyShareRoundOneRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundOne';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof relinearizationProofVerificationStatus;
        readonly proofModelStatus: typeof relinearizationProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneProofRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
    }
>;

export type RelinearizationKeyShareRoundTwoRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRoundTwo';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof relinearizationProofVerificationStatus;
        readonly proofModelStatus: typeof relinearizationProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly level: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly roundOneShareRoot: ProtocolHash;
        readonly roundOneRecordRoot: ProtocolHash;
        readonly roundOneAggregateRoot: ProtocolHash;
        readonly roundTwoShareRoot: ProtocolHash;
        readonly roundTwoProofRoot: ProtocolHash;
        readonly roundTwoRecordRoot: ProtocolHash;
    }
>;

export type RelinearizationKeyShareRounds = Readonly<
    JsonRecord & {
        readonly objectType: 'RelinearizationKeyShareRounds';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'relinearization-key-share';
        readonly proofVerificationStatus: typeof relinearizationProofVerificationStatus;
        readonly proofModelStatus: typeof relinearizationProofModelStatus;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly roundOneAggregateRoots: readonly {
            readonly level: number;
            readonly roundOneAggregateRoot: ProtocolHash;
        }[];
        readonly roundOneRecords: readonly RelinearizationKeyShareRoundOneRecord[];
        readonly roundTwoAggregateRoots: readonly {
            readonly level: number;
            readonly roundTwoAggregateRoot: ProtocolHash;
        }[];
        readonly roundTwoRecords: readonly RelinearizationKeyShareRoundTwoRecord[];
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
    }
>;

export type GaloisKeyShareRootReference = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly galoisKeyShareRoot: ProtocolHash;
}>;

export type GaloisKeyShareBatchContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareRoots: readonly GaloisKeyShareRootReference[];
    readonly galoisKeyBatchProofRoot: ProtocolHash;
}>;

export type GaloisKeyShareBatch = Readonly<
    JsonRecord & {
        readonly objectType: 'GaloisKeyShareBatch';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: 'galois-key-share';
        readonly proofVerificationStatus: typeof galoisProofVerificationStatus;
        readonly proofModelStatus: typeof galoisProofModelStatus;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly galoisKeyShareRoots: readonly GaloisKeyShareRootReference[];
        readonly galoisKeyBatchProofRoot: ProtocolHash;
        readonly galoisKeyShareBatchRoot: ProtocolHash;
    }
>;

export type EvaluationKeyProofCommonInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly sameSecretProofSetRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly publicKeyShareLnpProofSetRoot: ProtocolHash;
    readonly sameSecretProofReferences: readonly SameSecretProofReference[];
}>;

export type RelinearizationKeyShareRoundsInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly roundOneContributions: readonly RelinearizationRoundOneContribution[];
        readonly roundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    }>;

export type GaloisKeyShareBatchesInput = EvaluationKeyProofCommonInput &
    Readonly<{
        readonly batchContributions: readonly GaloisKeyShareBatchContribution[];
    }>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const contributionKey = (
    level: number,
    trusteeRosterPosition: number,
): string => `${String(level)}:${String(trusteeRosterPosition)}`;

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

const validateCommonInput = (
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
        ['publicKeyShareLnpProofSetRoot', input.publicKeyShareLnpProofSetRoot],
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
                assertProtocolHash(
                    contribution.roundOneProofRoot,
                    'roundOneProofRoot',
                );
                const recordWithoutRoot = {
                    objectType: 'RelinearizationKeyShareRoundOne',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'relinearization-key-share',
                    proofVerificationStatus:
                        relinearizationProofVerificationStatus,
                    proofModelStatus: relinearizationProofModelStatus,
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
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
                    sameSecretStatementRoot:
                        proofReference.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        proofReference.trusteeSecretCommitmentRoot,
                    sameSecretProofRoot: proofReference.sameSecretProofRoot,
                    relinearizationCrpRoot:
                        input.evaluatorKeySchedule.relinearizationCrpRoot,
                    roundOneShareRoot: contribution.roundOneShareRoot,
                    roundOneProofRoot: contribution.roundOneProofRoot,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundOneRecord,
                    'roundOneRecordRoot'
                >;
                const roundOneRecordRoot = deriveProtocolHash(
                    'RelinearizationRoundOneRecordRoot',
                    recordWithoutRoot,
                );
                roundOneShareRoots.set(key, contribution.roundOneShareRoot);
                roundOneRecordRoots.set(key, roundOneRecordRoot);
                roundOneRecords.push({
                    ...recordWithoutRoot,
                    roundOneRecordRoot,
                });

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundOneRecordRoot,
                };
            },
        );
        const roundOneAggregateRoot = deriveProtocolHash(
            'RelinearizationRoundOneAggregateRoot',
            {
                objectType: 'RelinearizationRoundOneAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneRecordRoots: roundOneRecordRootsForLevel,
            },
        );
        roundOneAggregateRootByLevel.set(level, roundOneAggregateRoot);

        return { level, roundOneAggregateRoot };
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
                assertProtocolHash(
                    contribution.roundTwoProofRoot,
                    'roundTwoProofRoot',
                );
                const recordWithoutRoot = {
                    objectType: 'RelinearizationKeyShareRoundTwo',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: 'relinearization-key-share',
                    proofVerificationStatus:
                        relinearizationProofVerificationStatus,
                    proofModelStatus: relinearizationProofModelStatus,
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
                    publicKeyShareLnpProofSetRoot:
                        input.publicKeyShareLnpProofSetRoot,
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
                    roundTwoProofRoot: contribution.roundTwoProofRoot,
                } as const satisfies Omit<
                    RelinearizationKeyShareRoundTwoRecord,
                    'roundTwoRecordRoot'
                >;
                const roundTwoRecordRoot = deriveProtocolHash(
                    'RelinearizationRoundTwoRecordRoot',
                    recordWithoutRoot,
                );
                roundTwoRecords.push({
                    ...recordWithoutRoot,
                    roundTwoRecordRoot,
                });

                return {
                    trusteeIdentity: proofReference.trusteeIdentity,
                    trusteeRosterPosition: proofReference.trusteeRosterPosition,
                    roundTwoRecordRoot,
                };
            },
        );
        const roundTwoAggregateRoot = deriveProtocolHash(
            'RelinearizationRoundTwoAggregateRoot',
            {
                objectType: 'RelinearizationRoundTwoAggregate',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                level,
                roundOneAggregateRoot: roundOneAggregateRootByLevel.get(level),
                roundTwoRecordRoots: roundTwoRecordRootsForLevel,
            },
        );

        return { level, roundTwoAggregateRoot };
    });

    const roundsWithoutRoot = {
        objectType: 'RelinearizationKeyShareRounds',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'relinearization-key-share',
        proofVerificationStatus: relinearizationProofVerificationStatus,
        proofModelStatus: relinearizationProofModelStatus,
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
        publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
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
        relinearizationKeyShareRoundsRoot: deriveProtocolHash(
            'RelinearizationKeyShareRoundsRoot',
            roundsWithoutRoot,
        ),
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
        assertProtocolHash(
            contribution.galoisKeyBatchProofRoot,
            'galoisKeyBatchProofRoot',
        );
        if (
            contribution.galoisKeyShareRoots.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                'galoisKeyShareRoots must contain one root per required Galois key.',
            );
        }
        contribution.galoisKeyShareRoots.forEach((rootReference, index) => {
            const expectedScheduleEntry =
                input.evaluatorKeySchedule.requiredGaloisKeySchedule[index];
            if (
                rootReference.rotation !== expectedScheduleEntry.rotation ||
                rootReference.level !== expectedScheduleEntry.level
            ) {
                throw new Error(
                    'galoisKeyShareRoots must follow the frozen Galois key schedule.',
                );
            }
            assertProtocolHash(
                rootReference.galoisKeyShareRoot,
                'galoisKeyShareRoot',
            );
        });
        const batchWithoutRoot = {
            objectType: 'GaloisKeyShareBatch',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: 'galois-key-share',
            proofVerificationStatus: galoisProofVerificationStatus,
            proofModelStatus: galoisProofModelStatus,
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
            publicKeyShareLnpProofSetRoot: input.publicKeyShareLnpProofSetRoot,
            sameSecretStatementRoot: proofReference.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                proofReference.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: proofReference.sameSecretProofRoot,
            galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
            requiredGaloisSetHash:
                input.evaluatorKeySchedule.requiredGaloisSetHash,
            requiredGaloisKeySchedule:
                input.evaluatorKeySchedule.requiredGaloisKeySchedule,
            galoisKeyShareRoots: contribution.galoisKeyShareRoots,
            galoisKeyBatchProofRoot: contribution.galoisKeyBatchProofRoot,
        } as const satisfies Omit<
            GaloisKeyShareBatch,
            'galoisKeyShareBatchRoot'
        >;

        return {
            ...batchWithoutRoot,
            galoisKeyShareBatchRoot: deriveProtocolHash(
                'GaloisKeyShareBatchRoot',
                batchWithoutRoot,
            ),
        } satisfies GaloisKeyShareBatch;
    });
};
