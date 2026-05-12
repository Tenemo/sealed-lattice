import type {
    FirstComeOrderingInput,
    FirstComeOrderingVerification,
    RefusalRecord,
    ValidatedFirstComeCandidate,
} from '@sealed-lattice/types';

import { deriveProtocolDigest } from '../common/digests.js';
import {
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';

const defaultMaxPerIdentity = 1;

const compareCandidates = (
    left: ValidatedFirstComeCandidate,
    right: ValidatedFirstComeCandidate,
): number =>
    left.boardSeq - right.boardSeq ||
    left.boardPosition - right.boardPosition ||
    left.actionSequence - right.actionSequence ||
    left.objectDigest.localeCompare(right.objectDigest);

const candidateConflictKey = (candidate: ValidatedFirstComeCandidate): string =>
    [
        candidate.signerIdentity,
        candidate.objectType,
        candidate.contextDigest,
    ].join('\u0000');

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
        recoveryEntry.oldActionCutoffBoardSeq !== undefined &&
        candidate.boardSeq < recoveryEntry.oldActionCutoffBoardSeq &&
        candidate.recoveryEpoch < recoveryEntry.currentRecoveryEpoch &&
        candidate.deviceEpoch < recoveryEntry.currentDeviceEpoch
    );
};

export const deriveFirstComeOrderDigest = (
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
