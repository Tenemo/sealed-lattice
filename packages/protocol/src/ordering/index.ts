import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    RefusalRecord,
    ValidatedFirstValidObject,
} from '@sealed-lattice/types';

import {
    createRefusal,
    isNonNegativeInteger,
    uniqueStrings,
} from '../common/verification-helpers.js';

const defaultMaxPerIdentity = 1;

const compareCandidates = (
    left: ValidatedFirstValidObject,
    right: ValidatedFirstValidObject,
): number =>
    left.boardSequence - right.boardSequence ||
    left.boardPosition - right.boardPosition ||
    left.actionSequence - right.actionSequence ||
    left.objectDigest.localeCompare(right.objectDigest);

const candidateConflictKey = (candidate: ValidatedFirstValidObject): string =>
    [
        candidate.signerIdentity,
        candidate.objectType,
        candidate.contextDigest,
    ].join('\u0000');

const isNonEmptyString = (value: unknown): value is string =>
    typeof value === 'string' && value.length > 0;

const validateFirstValidObjectShape = (
    candidate: ValidatedFirstValidObject,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const objectDigest = isNonEmptyString(candidate.objectDigest)
        ? candidate.objectDigest
        : undefined;
    const objectType = isNonEmptyString(candidate.objectType)
        ? candidate.objectType
        : undefined;

    if (
        !isNonEmptyString(candidate.objectDigest) ||
        !isNonEmptyString(candidate.objectType) ||
        !isNonEmptyString(candidate.signerIdentity) ||
        !isNonEmptyString(candidate.contextDigest)
    ) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid object string fields must be non-empty canonical strings.',
                objectDigest,
                objectType,
            ),
        );
    }
    if (
        !isNonNegativeInteger(candidate.boardSequence) ||
        !isNonNegativeInteger(candidate.boardPosition) ||
        !isNonNegativeInteger(candidate.recoveryEpoch) ||
        !isNonNegativeInteger(candidate.deviceEpoch) ||
        !isNonNegativeInteger(candidate.actionSequence)
    ) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid object sequence and epoch fields must be non-negative safe integers.',
                objectDigest,
                objectType,
            ),
        );
    }
    if (typeof candidate.isByteIdenticalRetransmission !== 'boolean') {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid object retransmission flag must be boolean.',
                objectDigest,
                objectType,
            ),
        );
    }

    return refusedObjects;
};

const isCurrentRecoveryEpoch = (
    input: FirstValidOrderingInput,
    candidate: ValidatedFirstValidObject,
): boolean => {
    const recoveryEntry =
        input.currentRecoveryEpochMap[candidate.signerIdentity];

    if (recoveryEntry === undefined) {
        return false;
    }
    if (
        candidate.recoveryEpoch === recoveryEntry.currentRecoveryEpoch &&
        candidate.deviceEpoch === recoveryEntry.currentDeviceEpoch
    ) {
        return true;
    }

    return (
        recoveryEntry.oldActionCutoffBoardSequence !== undefined &&
        candidate.boardSequence < recoveryEntry.oldActionCutoffBoardSequence &&
        candidate.recoveryEpoch < recoveryEntry.currentRecoveryEpoch &&
        candidate.deviceEpoch < recoveryEntry.currentDeviceEpoch
    );
};

const deriveFirstValidOrderDigest = (
    input: Pick<
        FirstValidOrderingInput,
        'requiredContextDigest' | 'selectionPolicyDigest'
    >,
    orderedCandidates: readonly ValidatedFirstValidObject[],
): string =>
    deriveProtocolDigest('FirstValidOrderDigest', {
        orderedObjectDigests: orderedCandidates.map(
            (candidate) => candidate.objectDigest,
        ),
        requiredContextDigest: input.requiredContextDigest,
        selectionPolicyDigest: input.selectionPolicyDigest,
    });

const deriveValidatedFirstValidOrderUnchecked = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const deduplicatedCandidates: ValidatedFirstValidObject[] = [];
    const seenObjectDigests = new Set<string>();
    const seenConflictKeys = new Map<string, ValidatedFirstValidObject>();

    if (input.selectionPolicyDigest !== input.expectedSelectionPolicyDigest) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid ordering requires the manifest-bound selection policy digest.',
                input.selectionPolicyDigest,
            ),
        );
    }

    for (const candidate of input.objects) {
        const candidateShapeRefusals = validateFirstValidObjectShape(candidate);
        if (candidateShapeRefusals.length > 0) {
            refusedObjects.push(...candidateShapeRefusals);
            continue;
        }

        const recoveryEntry =
            input.currentRecoveryEpochMap[candidate.signerIdentity];

        if (candidate.contextDigest !== input.requiredContextDigest) {
            refusedObjects.push(
                createRefusal(
                    'FirstValidContextMismatch',
                    'First-valid object context digest does not match the required context.',
                    candidate.objectDigest,
                    candidate.objectType,
                ),
            );
            continue;
        }
        if (recoveryEntry === undefined) {
            refusedObjects.push(
                createRefusal(
                    'UnknownRecoveryEpoch',
                    'First-valid object signer has no current recovery-epoch state.',
                    candidate.objectDigest,
                    candidate.objectType,
                ),
            );
            continue;
        }
        if (!isCurrentRecoveryEpoch(input, candidate)) {
            refusedObjects.push(
                createRefusal(
                    'StaleRecoveryEpoch',
                    'First-valid object uses a stale recovery or device epoch.',
                    candidate.objectDigest,
                    candidate.objectType,
                ),
            );
            continue;
        }

        const conflictKey = candidateConflictKey(candidate);
        const earlierCandidate = seenConflictKeys.get(conflictKey);
        if (
            earlierCandidate !== undefined &&
            earlierCandidate.objectDigest !== candidate.objectDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'ConflictingFirstValidObject',
                    'Same identity posted non-identical first-valid objects for the same context.',
                    candidate.objectDigest,
                    candidate.objectType,
                ),
            );
            continue;
        }
        seenConflictKeys.set(conflictKey, candidate);

        if (seenObjectDigests.has(candidate.objectDigest)) {
            if (!candidate.isByteIdenticalRetransmission) {
                refusedObjects.push(
                    createRefusal(
                        'DuplicateFirstValidObject',
                        'Duplicate first-valid object was not marked as byte-identical retransmission.',
                        candidate.objectDigest,
                        candidate.objectType,
                    ),
                );
            }
            continue;
        }

        seenObjectDigests.add(candidate.objectDigest);
        deduplicatedCandidates.push(candidate);
    }

    const maxPerIdentity = input.maxPerIdentity ?? defaultMaxPerIdentity;
    if (!Number.isInteger(maxPerIdentity) || maxPerIdentity < 1) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid ordering requires a positive maxPerIdentity value.',
                input.selectionPolicyDigest,
            ),
        );
    }
    const countByIdentity = new Map<string, number>();
    const orderedCandidates = deduplicatedCandidates
        .sort(compareCandidates)
        .filter((candidate) => {
            const currentCount =
                countByIdentity.get(candidate.signerIdentity) ?? 0;
            if (currentCount >= maxPerIdentity) {
                return false;
            }

            countByIdentity.set(candidate.signerIdentity, currentCount + 1);
            return true;
        });
    const firstValidOrderDigest = deriveFirstValidOrderDigest(
        input,
        orderedCandidates,
    );

    return {
        ok: refusedObjects.length === 0,
        statusLabels: [],
        acceptedDigests: uniqueStrings([
            firstValidOrderDigest,
            ...orderedCandidates.map((candidate) => candidate.objectDigest),
        ]),
        refusedObjects,
        firstValidOrderDigest:
            refusedObjects.length === 0 ? firstValidOrderDigest : undefined,
        orderedObjects: orderedCandidates,
    };
};

export const deriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => {
    try {
        return deriveValidatedFirstValidOrderUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'FirstValidPolicyMismatch',
                    'First-valid ordering input could not be canonicalized or validated.',
                ),
            ],
            orderedObjects: [],
        };
    }
};

export const verifyFirstValidPolicy = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => deriveValidatedFirstValidOrder(input);
