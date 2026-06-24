import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    PublicKeyShareProofSet,
    PublicKeyShareSet,
} from './public-key-share-records.js';
import {
    setupProofProfileId,
    type SameSecretConsistencyStatementSet,
} from './same-secret-consistency-records.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const evaluatorKeyGenericSwitchPolicy =
    'refused-unless-explicitly-required';

export type RelinearizationLevelScheduleEntry = Readonly<{
    readonly level: number;
    readonly proofFamily: 'relinearization-key-share';
    readonly keyShareRounds: readonly ['round-one', 'round-two'];
}>;

export type RequiredGaloisKeyScheduleEntry = Readonly<{
    readonly rotation: number;
    readonly level: number;
    readonly purpose: string;
    readonly proofFamily: 'galois-key-share';
}>;

export type RequiredGaloisSet = Readonly<
    JsonRecord & {
        readonly objectType: 'RequiredGaloisSet';
        readonly objectVersion: 1;
        readonly evaluatorProfile: 'direct-encrypted-ballot-evaluator-replay';
        readonly packingProfile: 'direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing';
        readonly rnsLimbCount: number;
        readonly entries: readonly RequiredGaloisKeyScheduleEntry[];
    }
>;

export type EvaluatorKeySchedule = Readonly<
    JsonRecord & {
        readonly objectType: 'EvaluatorKeySchedule';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly publicKeyShareProofSetRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly genericKeySwitchPolicy: typeof evaluatorKeyGenericSwitchPolicy;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
    }
>;

export type EvaluatorKeyScheduleInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly relinearizationCrpRoot: ProtocolHash;
    readonly galoisKeyCrpRoot: ProtocolHash;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
};

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

const validateRequiredGaloisSchedule = (
    entries: readonly RequiredGaloisKeyScheduleEntry[],
): RequiredGaloisKeyScheduleEntry[] => {
    const sortedEntries = [...entries].sort((left, right) => {
        const rotationDifference = left.rotation - right.rotation;

        return rotationDifference === 0
            ? left.level - right.level
            : rotationDifference;
    });
    const seenKeys = new Set<string>();
    sortedEntries.forEach((entry) => {
        assertPositiveSafeInteger(entry.rotation, 'rotation');
        assertNonNegativeSafeInteger(entry.level, 'level');
        assertNonEmptyString(entry.purpose, 'purpose');
        if (entry.proofFamily !== 'galois-key-share') {
            throw new Error(
                'requiredGaloisKeySchedule proofFamily must be galois-key-share.',
            );
        }
        const key = `${String(entry.rotation)}:${String(entry.level)}`;
        if (seenKeys.has(key)) {
            throw new Error(
                'requiredGaloisKeySchedule must not repeat a rotation and level.',
            );
        }
        seenKeys.add(key);
    });

    return sortedEntries;
};

export const createRequiredGaloisSet = (
    rnsLimbCount: number,
    entries: readonly RequiredGaloisKeyScheduleEntry[],
): RequiredGaloisSet => {
    assertPositiveSafeInteger(rnsLimbCount, 'rnsLimbCount');

    return {
        objectType: 'RequiredGaloisSet',
        objectVersion: 1,
        evaluatorProfile: 'direct-encrypted-ballot-evaluator-replay',
        packingProfile:
            'direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing',
        rnsLimbCount,
        entries: validateRequiredGaloisSchedule(entries),
    };
};

// The selected evaluator working level: every evaluation key is generated at
// this level and lower-level uses reuse the same key through CRT-idempotent
// truncation, so the frozen schedule carries one relinearization entry per
// round and no per-level entries. Mirrors the kernel evaluator constant.
export const selectedEvaluatorWorkingLevel = 15;

export const createRelinearizationLevelSchedule = (
    rnsLimbCount: number,
): RelinearizationLevelScheduleEntry[] => {
    assertPositiveSafeInteger(rnsLimbCount, 'rnsLimbCount');
    if (selectedEvaluatorWorkingLevel >= rnsLimbCount) {
        throw new Error(
            'selected evaluator working level must stay inside the Q_share basis.',
        );
    }

    return [
        {
            level: selectedEvaluatorWorkingLevel,
            proofFamily: 'relinearization-key-share',
            keyShareRounds: ['round-one', 'round-two'],
        },
    ];
};

export const createEvaluatorKeySchedule = (
    input: EvaluatorKeyScheduleInput,
): EvaluatorKeySchedule => {
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
    for (const [fieldName, hashValue] of [
        ['publicMatrixSeedHash', input.publicMatrixSeedHash],
        ['relinearizationCrpRoot', input.relinearizationCrpRoot],
        ['galoisKeyCrpRoot', input.galoisKeyCrpRoot],
    ] as const) {
        assertProtocolHash(hashValue, fieldName);
    }
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    if (
        input.publicKeyShares.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'public-key share records must bind the accepted same-secret and share-set roots.',
        );
    }

    const rnsLimbCount = input.qSharePrimes.length;
    const requiredGaloisSet = createRequiredGaloisSet(
        rnsLimbCount,
        input.requiredGaloisKeySchedule,
    );
    const requiredGaloisSetHash = deriveProtocolHash(
        'RequiredGaloisSetHash',
        requiredGaloisSet,
    );
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        relinearizationCrpRoot: input.relinearizationCrpRoot,
        galoisKeyCrpRoot: input.galoisKeyCrpRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        relinearizationLevelSchedule:
            createRelinearizationLevelSchedule(rnsLimbCount),
        requiredGaloisKeySchedule: requiredGaloisSet.entries,
        requiredGaloisSetHash,
        genericKeySwitchPolicy: evaluatorKeyGenericSwitchPolicy,
    } as const satisfies Omit<EvaluatorKeySchedule, 'evaluatorKeyScheduleRoot'>;

    return {
        ...scheduleWithoutRoot,
        evaluatorKeyScheduleRoot: deriveProtocolHash(
            'EvaluatorKeyScheduleRoot',
            scheduleWithoutRoot,
        ),
    } satisfies EvaluatorKeySchedule;
};
