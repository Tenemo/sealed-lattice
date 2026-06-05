import {
    deriveProtocolHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    ProtocolHash,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    collectBoardEvidence,
    verifyBoardInclusionProof,
} from '../board/shell-evidence.js';
import {
    createRefusal,
    defaultSignedRootContextHash,
    isNonNegativeInteger,
    signedObjectRootByteLength,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

export const deriveActionContextHash = (
    actionContext: Omit<
        ActionCurrentForRecoveryEpochInput['actionContext'],
        'actionContextHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ActionContextHash', {
        acceptedRecoveryEpochUpdateHash:
            actionContext.acceptedRecoveryEpochUpdateHash,
        actionSequence: actionContext.actionSequence,
        boardHeadHash: actionContext.boardHeadHash,
        boardSequence: actionContext.boardSequence,
        ceremonyId: actionContext.ceremonyId,
        contextHash: actionContext.contextHash,
        deviceEpoch: actionContext.deviceEpoch,
        electionManifestHash: actionContext.electionManifestHash,
        recoveryEpoch: actionContext.recoveryEpoch,
        recoveryPolicyHash: actionContext.recoveryPolicyHash,
        rosterExternalAcceptanceHash:
            actionContext.rosterExternalAcceptanceHash,
        signerIdentity: actionContext.signerIdentity,
    });

export const deriveRecoveryEpochUpdateHash = (
    update: Omit<RecoveryEpochUpdate, 'recoveryEpochUpdateHash' | 'signature'>,
): ProtocolHash =>
    deriveProtocolHash('RecoveryEpochUpdateHash', {
        boardHeadHash: update.boardHeadHash,
        ceremonyId: update.ceremonyId,
        newDeviceEpoch: update.newDeviceEpoch,
        newRecoveryEpoch: update.newRecoveryEpoch,
        newSigningPublicKeyHash: update.newSigningPublicKeyHash,
        newTrusteeSetupCommitment: update.newTrusteeSetupCommitment,
        objectType: update.objectType,
        objectVersion: update.objectVersion,
        oldActionCutoffBoardSequence: update.oldActionCutoffBoardSequence,
        previousDeviceEpoch: update.previousDeviceEpoch,
        previousRecoveryEpoch: update.previousRecoveryEpoch,
        recoveryPolicyHash: update.recoveryPolicyHash,
        recoveryRootPublicKeyHash: update.recoveryRootPublicKeyHash,
        restoredEncryptedBallotStateCommitment:
            update.restoredEncryptedBallotStateCommitment,
        signerIdentity: update.signerIdentity,
    });

const isActionCurrentForRecoveryEpochUnchecked = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult => {
    const expectedActionContextHash = deriveActionContextHash({
        actionSequence: input.actionContext.actionSequence,
        boardHeadHash: input.actionContext.boardHeadHash,
        boardSequence: input.actionContext.boardSequence,
        ceremonyId: input.actionContext.ceremonyId,
        contextHash: input.actionContext.contextHash,
        deviceEpoch: input.actionContext.deviceEpoch,
        electionManifestHash: input.actionContext.electionManifestHash,
        recoveryEpoch: input.actionContext.recoveryEpoch,
        recoveryPolicyHash: input.actionContext.recoveryPolicyHash,
        rosterExternalAcceptanceHash:
            input.actionContext.rosterExternalAcceptanceHash,
        acceptedRecoveryEpochUpdateHash:
            input.actionContext.acceptedRecoveryEpochUpdateHash,
        signerIdentity: input.actionContext.signerIdentity,
    });
    const refusedObjects: RefusalRecord[] = [];

    if (input.actionContext.actionContextHash !== expectedActionContextHash) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Action context hash does not match its canonical payload.',
                input.actionContext.actionContextHash,
                'ActionContext',
            ),
        );
    }
    if (
        input.actionContext.signerIdentity !==
        input.recoveryEpochState.signerIdentity
    ) {
        refusedObjects.push(
            createRefusal(
                'StaleRecoveryEpoch',
                'Action context signer does not match the supplied recovery epoch state.',
                input.actionContext.actionContextHash,
                'ActionContext',
            ),
        );
    }
    if (
        !isNonNegativeInteger(input.actionContext.boardSequence) ||
        !isNonNegativeInteger(input.actionContext.recoveryEpoch) ||
        !isNonNegativeInteger(input.actionContext.deviceEpoch) ||
        !isNonNegativeInteger(input.actionContext.actionSequence)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Action context sequence and epoch fields must be non-negative integers.',
                input.actionContext.actionContextHash,
                'ActionContext',
            ),
        );
    }
    if (
        input.expectedRosterExternalAcceptanceHash !== undefined &&
        input.actionContext.rosterExternalAcceptanceHash !==
            input.expectedRosterExternalAcceptanceHash
    ) {
        refusedObjects.push(
            createRefusal(
                'RosterExternalAcceptanceInvalid',
                'Action context must bind the expected local roster external acceptance hash.',
                input.actionContext.actionContextHash,
                'ActionContext',
            ),
        );
    }
    if (
        input.actionContext.recoveryEpoch ===
            input.recoveryEpochState.currentRecoveryEpoch &&
        input.actionContext.deviceEpoch ===
            input.recoveryEpochState.currentDeviceEpoch
    ) {
        return {
            ok: refusedObjects.length === 0,
            statusLabels: [],
            acceptedHashes: [input.actionContext.actionContextHash],
            refusedObjects,
        };
    }
    if (
        input.recoveryEpochState.oldActionCutoffBoardSequence !== undefined &&
        input.actionContext.boardSequence <
            input.recoveryEpochState.oldActionCutoffBoardSequence &&
        input.actionContext.recoveryEpoch <
            input.recoveryEpochState.currentRecoveryEpoch &&
        input.actionContext.deviceEpoch <
            input.recoveryEpochState.currentDeviceEpoch
    ) {
        return {
            ok: refusedObjects.length === 0,
            statusLabels: [],
            acceptedHashes: [input.actionContext.actionContextHash],
            refusedObjects,
        };
    }

    refusedObjects.push(
        createRefusal(
            'StaleRecoveryEpoch',
            'Action context is not current for the supplied recovery epoch.',
            input.actionContext.actionContextHash,
            'ActionContext',
        ),
    );

    return {
        ok: false,
        statusLabels: [],
        acceptedHashes: [],
        refusedObjects,
    };
};

export const isActionCurrentForRecoveryEpoch = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult => {
    try {
        return isActionCurrentForRecoveryEpochUnchecked(input);
    } catch (error) {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'InvalidSignedRoot',
                    verificationExceptionMessage(
                        'Action recovery context could not be canonicalized or validated.',
                        error,
                    ),
                    undefined,
                    'ActionContext',
                ),
            ],
        };
    }
};

const verifyRecoveryEpochUpdateUnchecked = (
    input: RecoveryEpochVerificationInput,
): RecoveryEpochVerification => {
    const { update, currentEntry } = input;
    const boardEvidence = collectBoardEvidence(input.boardEvidence);
    const { boardResult, headsByHash } = boardEvidence;
    const updateInclusionHead = headsByHash.get(
        input.updateInclusionProof.boardHeadHash,
    );
    const refusedObjects: RefusalRecord[] = [...boardResult.refusedObjects];
    const expectedHash = deriveRecoveryEpochUpdateHash({
        boardHeadHash: update.boardHeadHash,
        ceremonyId: update.ceremonyId,
        newDeviceEpoch: update.newDeviceEpoch,
        newRecoveryEpoch: update.newRecoveryEpoch,
        newSigningPublicKeyHash: update.newSigningPublicKeyHash,
        newTrusteeSetupCommitment: update.newTrusteeSetupCommitment,
        objectType: update.objectType,
        objectVersion: update.objectVersion,
        oldActionCutoffBoardSequence: update.oldActionCutoffBoardSequence,
        previousDeviceEpoch: update.previousDeviceEpoch,
        previousRecoveryEpoch: update.previousRecoveryEpoch,
        recoveryPolicyHash: update.recoveryPolicyHash,
        recoveryRootPublicKeyHash: update.recoveryRootPublicKeyHash,
        restoredEncryptedBallotStateCommitment:
            update.restoredEncryptedBallotStateCommitment,
        signerIdentity: update.signerIdentity,
    });

    if (update.recoveryEpochUpdateHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update hash does not match its canonical payload.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.objectType !== 'RecoveryEpochUpdate' ||
        update.objectVersion !== 1 ||
        !isNonNegativeInteger(update.previousRecoveryEpoch) ||
        !isNonNegativeInteger(update.newRecoveryEpoch) ||
        !isNonNegativeInteger(update.previousDeviceEpoch) ||
        !isNonNegativeInteger(update.newDeviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update object shape is not canonical.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (update.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Recovery epoch update ceremony does not match the supplied board evidence.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.signerIdentity !== currentEntry.signerIdentity ||
        update.previousRecoveryEpoch !== currentEntry.currentRecoveryEpoch ||
        update.previousDeviceEpoch !== currentEntry.currentDeviceEpoch
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateStale',
                'Recovery epoch update does not extend the current recovery state.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (update.recoveryPolicyHash !== input.expectedRecoveryPolicyHash) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update does not bind the expected recovery policy hash.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.recoveryRootPublicKeyHash !==
        input.expectedRecoveryRootPublicKeyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Recovery epoch update must be signed by the expected recovery root.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    // Strict single-step advancement: both the recovery epoch and the device
    // epoch must increase by exactly one. This forbids skipping or replaying
    // epochs (an update must extend the immediately prior state, not jump).
    if (
        update.newRecoveryEpoch !== update.previousRecoveryEpoch + 1 ||
        update.newDeviceEpoch !== update.previousDeviceEpoch + 1 ||
        !isNonNegativeInteger(update.oldActionCutoffBoardSequence)
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update must advance recovery and device epochs by one.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.newSigningPublicKeyHash.length === 0 ||
        update.restoredEncryptedBallotStateCommitment.length === 0 ||
        update.newTrusteeSetupCommitment.length === 0 ||
        update.recoveryPolicyHash.length === 0
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update must bind new signing, encrypted-ballot state, trustee setup, and recovery-policy commitments.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        input.updateInclusionProof.includedObjectType !==
            'RecoveryEpochUpdate' ||
        input.updateInclusionProof.includedObjectHash !==
            update.recoveryEpochUpdateHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Recovery epoch update inclusion proof does not bind the update.',
                input.updateInclusionProof.inclusionProofHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    // The update must be included at exactly the cutoff boundary it declares:
    // the inclusion proof's board sequence equals the declared
    // oldActionCutoffBoardSequence, and the inclusion head extends the update's
    // own boardHeadHash (its previousHeadHash points back at it).
    if (
        input.updateInclusionProof.boardSequence !==
            update.oldActionCutoffBoardSequence ||
        updateInclusionHead?.previousHeadHash !== update.boardHeadHash
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update inclusion must extend the signed recovery context head at the old-action cutoff.',
                update.recoveryEpochUpdateHash,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (!headsByHash.has(update.boardHeadHash)) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Recovery epoch update binds an unknown signed board head.',
                update.boardHeadHash,
                'BoardHead',
            ),
        );
    }
    refusedObjects.push(
        ...verifyBoardInclusionProof(boardEvidence, input.updateInclusionProof),
    );
    for (const conflictingUpdate of input.conflictingUpdates ?? []) {
        if (
            conflictingUpdate.signerIdentity === update.signerIdentity &&
            conflictingUpdate.previousRecoveryEpoch ===
                update.previousRecoveryEpoch &&
            conflictingUpdate.previousDeviceEpoch ===
                update.previousDeviceEpoch &&
            conflictingUpdate.recoveryEpochUpdateHash !==
                update.recoveryEpochUpdateHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'RecoveryUpdateConflict',
                    'Supplied evidence contains conflicting recovery updates for the same prior epoch.',
                    conflictingUpdate.recoveryEpochUpdateHash,
                    'RecoveryEpochUpdate',
                ),
            );
        }
    }

    const signatureResult = verifySignedObjectSignature(update.signature, {
        objectType: 'RecoveryEpochUpdate',
        objectVersion: 1,
        signerRole: 'RecoveryRoot',
        signerIdentity: update.signerIdentity,
        ceremonyId: update.ceremonyId,
        manifestHash: null,
        objectRoot: update.recoveryEpochUpdateHash,
        boardHeadHash: update.boardHeadHash,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: update.previousRecoveryEpoch,
        deviceEpoch: update.previousDeviceEpoch,
        contextHash: defaultSignedRootContextHash,
        publicKeyHash: input.expectedRecoveryRootPublicKeyHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return {
        ok: refusedObjects.length === 0,
        statusLabels: boardResult.statusLabels,
        acceptedHashes:
            refusedObjects.length === 0
                ? [
                      ...boardResult.acceptedHashes,
                      update.recoveryEpochUpdateHash,
                      input.updateInclusionProof.inclusionProofHash,
                  ]
                : [],
        refusedObjects,
        forkEvidence: boardResult.forkEvidence,
        updatedEntry:
            refusedObjects.length === 0
                ? {
                      signerIdentity: update.signerIdentity,
                      currentRecoveryEpoch: update.newRecoveryEpoch,
                      currentDeviceEpoch: update.newDeviceEpoch,
                      oldActionCutoffBoardSequence:
                          update.oldActionCutoffBoardSequence,
                  }
                : undefined,
    };
};

export const verifyRecoveryEpochUpdate = (
    input: RecoveryEpochVerificationInput,
): RecoveryEpochVerification => {
    try {
        return verifyRecoveryEpochUpdateUnchecked(input);
    } catch (error) {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'RecoveryUpdateInvalid',
                    verificationExceptionMessage(
                        'Recovery epoch update evidence could not be canonicalized or validated.',
                        error,
                    ),
                    undefined,
                    'RecoveryEpochUpdate',
                ),
            ],
        };
    }
};
