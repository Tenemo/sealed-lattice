import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    deriveCollectiveBgvSetupContextHash,
    type JsonRecord,
} from './common-fields.js';
import { publicKeyShareRecordsByRosterPosition } from './public-key-share-records/share-statement-records.js';
import type { PublicKeyShareSet } from './public-key-share-records.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

export type RelinearizationLevelScheduleEntry = Readonly<{
    readonly level: number;
}>;

export type RequiredGaloisKeyScheduleEntry = Readonly<{
    readonly rotation: number;
    readonly level: number;
}>;

export type EvaluatorKeySchedule = Readonly<
    JsonRecord & {
        readonly objectType: 'EvaluatorKeySchedule';
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicKeyShareSetRoot: ProtocolHash;
        readonly relinearizationLevelSchedule: readonly RelinearizationLevelScheduleEntry[];
        readonly requiredGaloisKeySchedule: readonly RequiredGaloisKeyScheduleEntry[];
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
    }
>;

type EvaluatorKeyScheduleInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly publicMatrixSeedHash: ProtocolHash;
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
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    publicKeyShareRecordsByRosterPosition(input);
    const rnsLimbCount = input.qSharePrimes.length;
    const requiredGaloisKeySchedule = validateRequiredGaloisSchedule(
        input.requiredGaloisKeySchedule,
    );
    const scheduleWithoutRoot = {
        objectType: 'EvaluatorKeySchedule',
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        relinearizationLevelSchedule:
            createRelinearizationLevelSchedule(rnsLimbCount),
        requiredGaloisKeySchedule,
    } as const satisfies Omit<EvaluatorKeySchedule, 'evaluatorKeyScheduleRoot'>;

    return {
        ...scheduleWithoutRoot,
        evaluatorKeyScheduleRoot:
            deriveCanonicalObjectHash(scheduleWithoutRoot),
    } satisfies EvaluatorKeySchedule;
};
