import {
    deriveProtocolDigest,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import type {
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    ProtocolDigest,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import {
    buildBoardHeadMap,
    createRefusal,
    defaultSignedRootContextDigest,
    isNonNegativeInteger,
    signedObjectRootByteLength,
} from '../common/verification-helpers.js';

export const deriveActionContextDigest = (
    actionContext: Omit<
        ActionCurrentForRecoveryEpochInput['actionContext'],
        'actionContextDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ActionContextDigest', {
        acceptedRecoveryEpochUpdateDigest:
            actionContext.acceptedRecoveryEpochUpdateDigest,
        actionSequence: actionContext.actionSequence,
        boardHeadDigest: actionContext.boardHeadDigest,
        boardSequence: actionContext.boardSequence,
        ceremonyId: actionContext.ceremonyId,
        contextDigest: actionContext.contextDigest,
        deviceEpoch: actionContext.deviceEpoch,
        electionManifestDigest: actionContext.electionManifestDigest,
        recoveryEpoch: actionContext.recoveryEpoch,
        recoveryPolicyDigest: actionContext.recoveryPolicyDigest,
        rosterExternalAcceptanceDigest:
            actionContext.rosterExternalAcceptanceDigest,
        signerIdentity: actionContext.signerIdentity,
    });

export const deriveRecoveryEpochUpdateDigest = (
    update: Omit<
        RecoveryEpochUpdate,
        'recoveryEpochUpdateDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('RecoveryEpochUpdateDigest', {
        boardHeadDigest: update.boardHeadDigest,
        ceremonyId: update.ceremonyId,
        newDeviceEpoch: update.newDeviceEpoch,
        newRecoveryEpoch: update.newRecoveryEpoch,
        newSigningPublicKeyDigest: update.newSigningPublicKeyDigest,
        newTrusteeSetupCommitment: update.newTrusteeSetupCommitment,
        objectType: update.objectType,
        objectVersion: update.objectVersion,
        oldActionCutoffBoardSequence: update.oldActionCutoffBoardSequence,
        previousDeviceEpoch: update.previousDeviceEpoch,
        previousRecoveryEpoch: update.previousRecoveryEpoch,
        recoveryPolicyDigest: update.recoveryPolicyDigest,
        recoveryRootPublicKeyDigest: update.recoveryRootPublicKeyDigest,
        restoredFrozenReceiverStateCommitment:
            update.restoredFrozenReceiverStateCommitment,
        signerIdentity: update.signerIdentity,
    });

const isActionCurrentForRecoveryEpochUnchecked = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult => {
    const expectedActionContextDigest = deriveActionContextDigest({
        actionSequence: input.actionContext.actionSequence,
        boardHeadDigest: input.actionContext.boardHeadDigest,
        boardSequence: input.actionContext.boardSequence,
        ceremonyId: input.actionContext.ceremonyId,
        contextDigest: input.actionContext.contextDigest,
        deviceEpoch: input.actionContext.deviceEpoch,
        electionManifestDigest: input.actionContext.electionManifestDigest,
        recoveryEpoch: input.actionContext.recoveryEpoch,
        recoveryPolicyDigest: input.actionContext.recoveryPolicyDigest,
        rosterExternalAcceptanceDigest:
            input.actionContext.rosterExternalAcceptanceDigest,
        acceptedRecoveryEpochUpdateDigest:
            input.actionContext.acceptedRecoveryEpochUpdateDigest,
        signerIdentity: input.actionContext.signerIdentity,
    });
    const refusedObjects: RefusalRecord[] = [];

    if (
        input.actionContext.actionContextDigest !== expectedActionContextDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Action context digest does not match its canonical payload.',
                input.actionContext.actionContextDigest,
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
                input.actionContext.actionContextDigest,
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
                input.actionContext.actionContextDigest,
                'ActionContext',
            ),
        );
    }
    if (
        input.expectedRosterExternalAcceptanceDigest !== undefined &&
        input.actionContext.rosterExternalAcceptanceDigest !==
            input.expectedRosterExternalAcceptanceDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'RosterExternalAcceptanceInvalid',
                'Action context must bind the expected local roster external acceptance digest.',
                input.actionContext.actionContextDigest,
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
            acceptedDigests: [input.actionContext.actionContextDigest],
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
            acceptedDigests: [input.actionContext.actionContextDigest],
            refusedObjects,
        };
    }

    refusedObjects.push(
        createRefusal(
            'StaleRecoveryEpoch',
            'Action context is not current for the supplied recovery epoch.',
            input.actionContext.actionContextDigest,
            'ActionContext',
        ),
    );

    return {
        ok: false,
        statusLabels: [],
        acceptedDigests: [],
        refusedObjects,
    };
};

export const isActionCurrentForRecoveryEpoch = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult => {
    try {
        return isActionCurrentForRecoveryEpochUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'InvalidSignedRoot',
                    'Action recovery context could not be canonicalized or validated.',
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
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );
    const updateInclusionHead = headsByDigest.get(
        input.updateInclusionProof.boardHeadDigest,
    );
    const refusedObjects: RefusalRecord[] = [...boardResult.refusedObjects];
    const expectedDigest = deriveRecoveryEpochUpdateDigest({
        boardHeadDigest: update.boardHeadDigest,
        ceremonyId: update.ceremonyId,
        newDeviceEpoch: update.newDeviceEpoch,
        newRecoveryEpoch: update.newRecoveryEpoch,
        newSigningPublicKeyDigest: update.newSigningPublicKeyDigest,
        newTrusteeSetupCommitment: update.newTrusteeSetupCommitment,
        objectType: update.objectType,
        objectVersion: update.objectVersion,
        oldActionCutoffBoardSequence: update.oldActionCutoffBoardSequence,
        previousDeviceEpoch: update.previousDeviceEpoch,
        previousRecoveryEpoch: update.previousRecoveryEpoch,
        recoveryPolicyDigest: update.recoveryPolicyDigest,
        recoveryRootPublicKeyDigest: update.recoveryRootPublicKeyDigest,
        restoredFrozenReceiverStateCommitment:
            update.restoredFrozenReceiverStateCommitment,
        signerIdentity: update.signerIdentity,
    });

    if (update.recoveryEpochUpdateDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update digest does not match its canonical payload.',
                update.recoveryEpochUpdateDigest,
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
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (update.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Recovery epoch update ceremony does not match the supplied board evidence.',
                update.recoveryEpochUpdateDigest,
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
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (update.recoveryPolicyDigest !== input.expectedRecoveryPolicyDigest) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update does not bind the expected recovery policy digest.',
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.recoveryRootPublicKeyDigest !==
        input.expectedRecoveryRootPublicKeyDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Recovery epoch update must be signed by the expected recovery root.',
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.newRecoveryEpoch !== update.previousRecoveryEpoch + 1 ||
        update.newDeviceEpoch !== update.previousDeviceEpoch + 1 ||
        !isNonNegativeInteger(update.oldActionCutoffBoardSequence)
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update must advance recovery and device epochs by one.',
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        update.newSigningPublicKeyDigest.length === 0 ||
        update.restoredFrozenReceiverStateCommitment.length === 0 ||
        update.newTrusteeSetupCommitment.length === 0 ||
        update.recoveryPolicyDigest.length === 0
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update must bind new signing, receiver-state, trustee-setup, and recovery-policy commitments.',
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        input.updateInclusionProof.includedObjectType !==
            'RecoveryEpochUpdate' ||
        input.updateInclusionProof.includedObjectDigest !==
            update.recoveryEpochUpdateDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Recovery epoch update inclusion proof does not bind the update.',
                input.updateInclusionProof.inclusionProofDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (
        input.updateInclusionProof.boardSequence !==
            update.oldActionCutoffBoardSequence ||
        updateInclusionHead?.previousHeadDigest !== update.boardHeadDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'RecoveryUpdateInvalid',
                'Recovery epoch update inclusion must extend the signed recovery context head at the old-action cutoff.',
                update.recoveryEpochUpdateDigest,
                'RecoveryEpochUpdate',
            ),
        );
    }
    if (!headsByDigest.has(update.boardHeadDigest)) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Recovery epoch update binds an unknown signed board head.',
                update.boardHeadDigest,
                'BoardHead',
            ),
        );
    }
    refusedObjects.push(
        ...verifyInclusionProof(input.updateInclusionProof, headsByDigest),
    );
    for (const conflictingUpdate of input.conflictingUpdates ?? []) {
        if (
            conflictingUpdate.signerIdentity === update.signerIdentity &&
            conflictingUpdate.previousRecoveryEpoch ===
                update.previousRecoveryEpoch &&
            conflictingUpdate.previousDeviceEpoch ===
                update.previousDeviceEpoch &&
            conflictingUpdate.recoveryEpochUpdateDigest !==
                update.recoveryEpochUpdateDigest
        ) {
            refusedObjects.push(
                createRefusal(
                    'RecoveryUpdateConflict',
                    'Supplied evidence contains conflicting recovery updates for the same prior epoch.',
                    conflictingUpdate.recoveryEpochUpdateDigest,
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
        manifestDigest: null,
        objectRoot: update.recoveryEpochUpdateDigest,
        boardHeadDigest: update.boardHeadDigest,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: update.previousRecoveryEpoch,
        deviceEpoch: update.previousDeviceEpoch,
        contextDigest: defaultSignedRootContextDigest,
        publicKeyDigest: input.expectedRecoveryRootPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return {
        ok: refusedObjects.length === 0,
        statusLabels: boardResult.statusLabels,
        acceptedDigests:
            refusedObjects.length === 0
                ? [
                      ...boardResult.acceptedDigests,
                      update.recoveryEpochUpdateDigest,
                      input.updateInclusionProof.inclusionProofDigest,
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
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'RecoveryUpdateInvalid',
                    'Recovery epoch update evidence could not be canonicalized or validated.',
                    undefined,
                    'RecoveryEpochUpdate',
                ),
            ],
        };
    }
};
