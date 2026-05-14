import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    FirstComeOrderingInput,
    FirstComeOrderingVerification,
    RefusalRecord,
    ValidatedFirstComeCandidate,
} from '@sealed-lattice/types';

import {
    createRefusal,
    isNonNegativeInteger,
    uniqueStrings,
} from '../common/verification-helpers.js';

const defaultMaxPerIdentity = 1;

const compareCandidates = (
    left: ValidatedFirstComeCandidate,
    right: ValidatedFirstComeCandidate,
): number =>
    left.boardSequence - right.boardSequence ||
    left.boardPosition - right.boardPosition ||
    left.actionSequence - right.actionSequence ||
    left.objectDigest.localeCompare(right.objectDigest);

const candidateConflictKey = (candidate: ValidatedFirstComeCandidate): string =>
    [
        candidate.signerIdentity,
        candidate.objectType,
        candidate.contextDigest,
    ].join('\u0000');

const isNonEmptyString = (value: unknown): value is string =>
    typeof value === 'string' && value.length > 0;

const validateFirstComeCandidateShape = (
    candidate: ValidatedFirstComeCandidate,
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
                'FirstComePolicyMismatch',
                'First-come candidate string fields must be non-empty canonical strings.',
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
                'FirstComePolicyMismatch',
                'First-come candidate sequence and epoch fields must be non-negative safe integers.',
                objectDigest,
                objectType,
            ),
        );
    }
    if (typeof candidate.isByteIdenticalRetransmission !== 'boolean') {
        refusedObjects.push(
            createRefusal(
                'FirstComePolicyMismatch',
                'First-come candidate retransmission flag must be boolean.',
                objectDigest,
                objectType,
            ),
        );
    }

    return refusedObjects;
};

const isCurrentRecoveryEpoch = (
    input: FirstComeOrderingInput,
    candidate: ValidatedFirstComeCandidate,
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

const deriveFirstComeOrderDigest = (
    input: Pick<
        FirstComeOrderingInput,
        'requiredContextDigest' | 'selectionPolicyDigest'
    >,
    orderedCandidates: readonly ValidatedFirstComeCandidate[],
): string =>
    deriveProtocolDigest('FirstComeOrderDigest', {
        orderedObjectDigests: orderedCandidates.map(
            (candidate) => candidate.objectDigest,
        ),
        requiredContextDigest: input.requiredContextDigest,
        selectionPolicyDigest: input.selectionPolicyDigest,
    });

const deriveValidatedFirstComeOrderUnchecked = (
    input: FirstComeOrderingInput,
): FirstComeOrderingVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const deduplicatedCandidates: ValidatedFirstComeCandidate[] = [];
    const seenObjectDigests = new Set<string>();
    const seenConflictKeys = new Map<string, ValidatedFirstComeCandidate>();

    if (input.selectionPolicyDigest !== input.expectedSelectionPolicyDigest) {
        refusedObjects.push(
            createRefusal(
                'FirstComePolicyMismatch',
                'First-come ordering requires the manifest-bound selection policy digest.',
                input.selectionPolicyDigest,
            ),
        );
    }

    for (const candidate of input.candidates) {
        const candidateShapeRefusals =
            validateFirstComeCandidateShape(candidate);
        if (candidateShapeRefusals.length > 0) {
            refusedObjects.push(...candidateShapeRefusals);
            continue;
        }

        const recoveryEntry =
            input.currentRecoveryEpochMap[candidate.signerIdentity];

        if (candidate.contextDigest !== input.requiredContextDigest) {
            refusedObjects.push(
                createRefusal(
                    'FirstComeContextMismatch',
                    'First-come candidate context digest does not match the required context.',
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
                    'First-come candidate signer has no current recovery-epoch state.',
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
                    'First-come candidate uses a stale recovery or device epoch.',
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
                    'ConflictingFirstComeCandidate',
                    'Same identity posted non-identical first-come candidates for the same context.',
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
                        'DuplicateFirstComeCandidate',
                        'Duplicate first-come candidate was not marked as byte-identical retransmission.',
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
                'FirstComePolicyMismatch',
                'First-come ordering requires a positive maxPerIdentity value.',
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
    const firstComeOrderDigest = deriveFirstComeOrderDigest(
        input,
        orderedCandidates,
    );

    return {
        ok: refusedObjects.length === 0,
        statusLabels: [],
        acceptedDigests: uniqueStrings([
            firstComeOrderDigest,
            ...orderedCandidates.map((candidate) => candidate.objectDigest),
        ]),
        refusedObjects,
        firstComeOrderDigest:
            refusedObjects.length === 0 ? firstComeOrderDigest : undefined,
        orderedCandidates,
    };
};

export const deriveValidatedFirstComeOrder = (
    input: FirstComeOrderingInput,
): FirstComeOrderingVerification => {
    try {
        return deriveValidatedFirstComeOrderUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'FirstComePolicyMismatch',
                    'First-come ordering input could not be canonicalized or validated.',
                ),
            ],
            orderedCandidates: [],
        };
    }
};

export const verifyFirstComePolicy = (
    input: FirstComeOrderingInput,
): FirstComeOrderingVerification => deriveValidatedFirstComeOrder(input);
