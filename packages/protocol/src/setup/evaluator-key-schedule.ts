import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertContextMatches,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    contextFields,
    type JsonRecord,
} from './common-fields.js';
import type { PublicKeyShareSet } from './public-key-share-records.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

export type RelinearizationLevelScheduleEntry = Readonly<{
    readonly level: number;
}>;

export type RequiredGaloisKeyScheduleEntry = Readonly<{
    readonly rotation: number;
    readonly level: number;
}>;

type RequiredGaloisSet = Readonly<
    JsonRecord & {
        readonly objectType: 'RequiredGaloisSet';
        readonly rnsLimbCount: number;
        readonly entries: readonly RequiredGaloisKeyScheduleEntry[];
    }
>;

export type EvaluatorKeySchedule = Readonly<
    JsonRecord & {
        readonly objectType: 'EvaluatorKeySchedule';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly relinearizationCrpRoot: ProtocolHash;
        readonly galoisKeyCrpRoot: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly requiredGaloisSetHash: ProtocolHash;
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
    }
>;

type EvaluatorKeyScheduleInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly relinearizationCrpRoot: ProtocolHash;
    readonly galoisKeyCrpRoot: ProtocolHash;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
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

const createRequiredGaloisSet = (
    rnsLimbCount: number,
    entries: readonly RequiredGaloisKeyScheduleEntry[],
): RequiredGaloisSet => {
    assertPositiveSafeInteger(rnsLimbCount, 'rnsLimbCount');

    return {
        objectType: 'RequiredGaloisSet',
        rnsLimbCount,
        entries: validateRequiredGaloisSchedule(entries),
    };
};

// The selected evaluator working level: every evaluation key is generated at
// this level and lower-level uses reuse the same key through CRT-idempotent
// truncation, so the frozen schedule carries one relinearization entry per
// round and no per-level entries. This must match the kernel evaluator constant.
const selectedEvaluatorWorkingLevel = 16;

const createRelinearizationLevelSchedule = (
    rnsLimbCount: number,
): RelinearizationLevelScheduleEntry[] => {
    assertPositiveSafeInteger(rnsLimbCount, 'rnsLimbCount');
    if (selectedEvaluatorWorkingLevel >= rnsLimbCount) {
        throw new Error(
            'selected evaluator working level must stay inside the Q_share basis.',
        );
    }

    return [{ level: selectedEvaluatorWorkingLevel }];
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
        input.publicKeyShares,
        'publicKeyShares',
    );
    const rnsLimbCount = input.qSharePrimes.length;
    const requiredGaloisSet = createRequiredGaloisSet(
        rnsLimbCount,
        input.requiredGaloisKeySchedule,
    );
    const requiredGaloisSetHash = deriveCanonicalObjectHash(requiredGaloisSet);
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        ...contextFields(input.setupContext),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        relinearizationCrpRoot: input.relinearizationCrpRoot,
        galoisKeyCrpRoot: input.galoisKeyCrpRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        relinearizationLevelSchedule:
            createRelinearizationLevelSchedule(rnsLimbCount),
        requiredGaloisKeySchedule: requiredGaloisSet.entries,
        requiredGaloisSetHash,
    } as const satisfies Omit<EvaluatorKeySchedule, 'evaluatorKeyScheduleRoot'>;

    return {
        ...scheduleWithoutRoot,
        evaluatorKeyScheduleRoot:
            deriveCanonicalObjectHash(scheduleWithoutRoot),
    } satisfies EvaluatorKeySchedule;
};
