import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    RefusalRecord,
    ValidatedFirstValidObject,
} from '@sealed-lattice/types';

import {
    compareCanonicalStrings,
    createRefusal,
    isNonNegativeInteger,
    uniqueStrings,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

const defaultMaxPerIdentity = 1;

const compareCandidates = (
    left: ValidatedFirstValidObject,
    right: ValidatedFirstValidObject,
): number =>
    left.boardSequence - right.boardSequence ||
    left.boardPosition - right.boardPosition ||
    left.actionSequence - right.actionSequence ||
    compareCanonicalStrings(left.objectHash, right.objectHash);

const candidateConflictKey = (candidate: ValidatedFirstValidObject): string =>
    [
        candidate.signerIdentity,
        candidate.objectType,
        candidate.contextHash,
    ].join('\u0000');

const isNonEmptyString = (value: unknown): value is string =>
    typeof value === 'string' && value.length > 0;

const validateFirstValidObjectShape = (
    candidate: ValidatedFirstValidObject,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const objectHash = isNonEmptyString(candidate.objectHash)
        ? candidate.objectHash
        : undefined;
    const objectType = isNonEmptyString(candidate.objectType)
        ? candidate.objectType
        : undefined;

    if (
        !isNonEmptyString(candidate.objectHash) ||
        !isNonEmptyString(candidate.objectType) ||
        !isNonEmptyString(candidate.signerIdentity) ||
        !isNonEmptyString(candidate.contextHash)
    ) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid object string fields must be non-empty canonical strings.',
                objectHash,
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
                objectHash,
                objectType,
            ),
        );
    }
    if (typeof candidate.isByteIdenticalRetransmission !== 'boolean') {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid object retransmission flag must be boolean.',
                objectHash,
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

const deriveFirstValidOrderHash = (
    input: Pick<
        FirstValidOrderingInput,
        'requiredContextHash' | 'selectionPolicyHash'
    >,
    orderedCandidates: readonly ValidatedFirstValidObject[],
): string =>
    deriveProtocolHash('FirstValidOrderHash', {
        orderedObjectHashes: orderedCandidates.map(
            (candidate) => candidate.objectHash,
        ),
        purpose: 'first-valid-order-v1',
        requiredContextHash: input.requiredContextHash,
        selectionPolicyHash: input.selectionPolicyHash,
    });

const deriveValidatedFirstValidOrderUnchecked = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const deduplicatedCandidates: ValidatedFirstValidObject[] = [];
    const seenObjectHashes = new Set<string>();
    const seenConflictKeys = new Map<string, ValidatedFirstValidObject>();

    if (input.selectionPolicyHash !== input.expectedSelectionPolicyHash) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid ordering requires the manifest-bound selection policy hash.',
                input.selectionPolicyHash,
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

        if (candidate.contextHash !== input.requiredContextHash) {
            refusedObjects.push(
                createRefusal(
                    'FirstValidContextMismatch',
                    'First-valid object context hash does not match the required context.',
                    candidate.objectHash,
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
                    candidate.objectHash,
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
                    candidate.objectHash,
                    candidate.objectType,
                ),
            );
            continue;
        }

        const conflictKey = candidateConflictKey(candidate);
        const earlierCandidate = seenConflictKeys.get(conflictKey);
        if (
            earlierCandidate !== undefined &&
            earlierCandidate.objectHash !== candidate.objectHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'ConflictingFirstValidObject',
                    'Same identity posted non-identical first-valid objects for the same context.',
                    candidate.objectHash,
                    candidate.objectType,
                ),
            );
            continue;
        }
        seenConflictKeys.set(conflictKey, candidate);

        if (seenObjectHashes.has(candidate.objectHash)) {
            if (!candidate.isByteIdenticalRetransmission) {
                refusedObjects.push(
                    createRefusal(
                        'DuplicateFirstValidObject',
                        'Duplicate first-valid object was not marked as byte-identical retransmission.',
                        candidate.objectHash,
                        candidate.objectType,
                    ),
                );
            }
            continue;
        }

        seenObjectHashes.add(candidate.objectHash);
        deduplicatedCandidates.push(candidate);
    }

    const maxPerIdentity = input.maxPerIdentity ?? defaultMaxPerIdentity;
    if (!Number.isInteger(maxPerIdentity) || maxPerIdentity < 1) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'First-valid ordering requires a positive maxPerIdentity value.',
                input.selectionPolicyHash,
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
    const firstValidOrderHash = deriveFirstValidOrderHash(
        input,
        orderedCandidates,
    );

    return {
        ok: refusedObjects.length === 0,
        statusLabels: [],
        acceptedHashes: uniqueStrings([
            firstValidOrderHash,
            ...orderedCandidates.map((candidate) => candidate.objectHash),
        ]),
        refusedObjects,
        firstValidOrderHash:
            refusedObjects.length === 0 ? firstValidOrderHash : undefined,
        orderedObjects: orderedCandidates,
    };
};

export const deriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => {
    try {
        return deriveValidatedFirstValidOrderUnchecked(input);
    } catch (error) {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'FirstValidPolicyMismatch',
                    verificationExceptionMessage(
                        'First-valid ordering input could not be canonicalized or validated.',
                        error,
                    ),
                ),
            ],
            orderedObjects: [],
        };
    }
};

export const verifyFirstValidPolicy = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => deriveValidatedFirstValidOrder(input);
