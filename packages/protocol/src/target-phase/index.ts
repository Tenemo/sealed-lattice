import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    LocalReplayRecord,
    LocalReplayRecordVerification,
    LocalReplayRecordVerificationInput,
    ProtocolDigest,
    RefusalRecord,
    TargetAcceptedRecord,
    TargetAcceptedRecordVerification,
    TargetAcceptedRecordVerificationInput,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TopKDecryptionShareShell,
    TopKDecryptionShareShellVerification,
    TopKDecryptionShareShellVerificationInput,
} from '@sealed-lattice/types';

import { collectSignedBoardInclusionEvidence } from '../board/shell-evidence.js';
import {
    createRefusal,
    isNonNegativeInteger,
} from '../common/verification-helpers.js';

const targetFinalityIsAccepted = (
    record: TargetFinalityRecord,
    verification: TargetFinalityVerification,
): boolean =>
    verification.ok &&
    verification.targetFinalityRecordDigest ===
        record.targetFinalityRecordDigest &&
    verification.targetProposalDigest === record.targetProposalDigest;

export const deriveLocalReplayRecordDigest = (
    record: Omit<LocalReplayRecord, 'localReplayRecordDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('LocalReplayRecordDigest', {
        ceremonyId: record.ceremonyId,
        deviceEpoch: record.deviceEpoch,
        electionManifestDigest: record.electionManifestDigest,
        evaluationProofRecordDigest: record.evaluationProofRecordDigest,
        mobileReplayCertDigest: record.mobileReplayCertDigest,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        participantIdentity: record.participantIdentity,
        recoveryEpoch: record.recoveryEpoch,
        replayContextDigest: record.replayContextDigest,
        targetFinalityRecordDigest: record.targetFinalityRecordDigest,
        targetProposalDigest: record.targetProposalDigest,
    });

export const deriveTargetAcceptedRecordDigest = (
    record: Omit<
        TargetAcceptedRecord,
        'targetAcceptedRecordDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('TargetAcceptedRecordDigest', {
        boardPosition: record.boardPosition,
        boardSequence: record.boardSequence,
        acceptanceMode: record.acceptanceMode,
        bgvAsyncThresholdCPADProfileDigest:
            record.bgvAsyncThresholdCPADProfileDigest,
        ceremonyId: record.ceremonyId,
        cpadProfileDigest: record.cpadProfileDigest,
        cpadProfileId: record.cpadProfileId,
        cTargetDigest: record.cTargetDigest,
        electionManifestDigest: record.electionManifestDigest,
        evaluationProofProfileDigest: record.evaluationProofProfileDigest,
        evaluationProofRecordDigest: record.evaluationProofRecordDigest,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        organizerIdentity: record.organizerIdentity,
        qTargetDigest: record.qTargetDigest,
        targetContextDigest: record.targetContextDigest,
        targetFinalityCheckpointDigest: record.targetFinalityCheckpointDigest,
        targetFinalityRecordDigest: record.targetFinalityRecordDigest,
        targetLayoutDigest: record.targetLayoutDigest,
        targetPhase: record.targetPhase,
        targetPreimageDigest: record.targetPreimageDigest,
        targetProposalDigest: record.targetProposalDigest,
        thresholdDecryptionProfileDigest:
            record.thresholdDecryptionProfileDigest,
        thresholdDecryptionProfileId: record.thresholdDecryptionProfileId,
        topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
    });

export const deriveTopKDecryptionShareDigest = (
    share: Omit<
        TopKDecryptionShareShell,
        'topKDecryptionShareDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('TopKDecryptionShareDigest', {
        bgvAsyncThresholdCPADProfileDigest:
            share.bgvAsyncThresholdCPADProfileDigest,
        boardPosition: share.boardPosition,
        boardSequence: share.boardSequence,
        ceremonyId: share.ceremonyId,
        cpadProfileDigest: share.cpadProfileDigest,
        cTargetDigest: share.cTargetDigest,
        deviceEpoch: share.deviceEpoch,
        electionManifestDigest: share.electionManifestDigest,
        evaluationProofRecordDigest: share.evaluationProofRecordDigest,
        objectType: share.objectType,
        objectVersion: share.objectVersion,
        qTargetDigest: share.qTargetDigest,
        recoveryEpoch: share.recoveryEpoch,
        shareRoot: share.shareRoot,
        targetAcceptedRecordDigest: share.targetAcceptedRecordDigest,
        targetContextDigest: share.targetContextDigest,
        targetDecryptionCiphertextDigest:
            share.targetDecryptionCiphertextDigest,
        targetDecryptionPreparationRecordDigest:
            share.targetDecryptionPreparationRecordDigest,
        targetFinalityCheckpointDigest: share.targetFinalityCheckpointDigest,
        targetFinalityRecordDigest: share.targetFinalityRecordDigest,
        targetPreimageDigest: share.targetPreimageDigest,
        targetProposalDigest: share.targetProposalDigest,
        thresholdShareVerificationKeyDigest:
            share.thresholdShareVerificationKeyDigest,
        thresholdShareVerificationKeyRoot:
            share.thresholdShareVerificationKeyRoot,
        thresholdDecryptionProfileDigest:
            share.thresholdDecryptionProfileDigest,
        topKEvaluationRecordDigest: share.topKEvaluationRecordDigest,
        trusteeThresholdVerificationKeyDigest:
            share.trusteeThresholdVerificationKeyDigest,
        trusteeIdentity: share.trusteeIdentity,
    });

const verifyLocalReplayRecordShape = (
    input: LocalReplayRecordVerificationInput,
): readonly RefusalRecord[] => {
    const { evaluationProofRecord, record, targetFinalityRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveLocalReplayRecordDigest({
        ceremonyId: record.ceremonyId,
        deviceEpoch: record.deviceEpoch,
        electionManifestDigest: record.electionManifestDigest,
        evaluationProofRecordDigest: record.evaluationProofRecordDigest,
        mobileReplayCertDigest: record.mobileReplayCertDigest,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        participantIdentity: record.participantIdentity,
        recoveryEpoch: record.recoveryEpoch,
        replayContextDigest: record.replayContextDigest,
        targetFinalityRecordDigest: record.targetFinalityRecordDigest,
        targetProposalDigest: record.targetProposalDigest,
    });

    if (record.localReplayRecordDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record digest does not match its canonical payload.',
                record.localReplayRecordDigest,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        record.objectType !== 'LocalReplayRecord' ||
        record.objectVersion !== 1 ||
        !isNonNegativeInteger(record.recoveryEpoch) ||
        !isNonNegativeInteger(record.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record object shape is not canonical.',
                record.localReplayRecordDigest,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        !targetFinalityIsAccepted(
            targetFinalityRecord,
            input.targetFinalityVerification,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetPhaseAuthorizationFailure',
                'Local replay record requires an accepted target-finality record.',
                record.localReplayRecordDigest,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        record.targetProposalDigest !==
            targetFinalityRecord.targetProposalDigest ||
        record.targetFinalityRecordDigest !==
            targetFinalityRecord.targetFinalityRecordDigest ||
        record.evaluationProofRecordDigest !==
            evaluationProofRecord.evaluationProofRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record must bind the exact accepted target and evaluation proof.',
                record.localReplayRecordDigest,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        input.recordInclusionProof.includedObjectType !== 'LocalReplayRecord' ||
        input.recordInclusionProof.includedObjectDigest !==
            record.localReplayRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Local replay record inclusion proof does not bind the record.',
                input.recordInclusionProof.inclusionProofDigest,
                'LocalReplayRecord',
            ),
        );
    }

    return refusedObjects;
};

export const verifyLocalReplayRecordShell = (
    input: LocalReplayRecordVerificationInput,
): LocalReplayRecordVerification => {
    try {
        const { acceptedDigests, boardResult, refusedObjects } =
            collectSignedBoardInclusionEvidence({
                boardEvidence: input.boardEvidence,
                inclusionProof: input.recordInclusionProof,
                objectRefusals: verifyLocalReplayRecordShape(input),
                signature: input.record.signature,
                signatureExpectation: {
                    objectType: 'LocalReplayRecord',
                    objectVersion: 1,
                    signerRole: 'Participant',
                    signerIdentity: input.record.participantIdentity,
                    ceremonyId: input.record.ceremonyId,
                    publicKeyDigest: input.expectedSignerPublicKeyDigest,
                    manifestDigest: input.record.electionManifestDigest,
                    objectRoot: input.record.localReplayRecordDigest,
                    boardHeadDigest: input.recordInclusionProof.boardHeadDigest,
                    contextDigest: input.record.replayContextDigest,
                },
                acceptedObjectDigest: input.record.localReplayRecordDigest,
            });

        return {
            ok: refusedObjects.length === 0,
            statusLabels: boardResult.statusLabels,
            acceptedDigests,
            refusedObjects,
            forkEvidence: boardResult.forkEvidence,
            localReplayRecordDigest:
                refusedObjects.length === 0
                    ? input.record.localReplayRecordDigest
                    : undefined,
            targetFinalityRecordDigest:
                refusedObjects.length === 0
                    ? input.record.targetFinalityRecordDigest
                    : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'LocalReplayRecordInvalid',
                    'Local replay record evidence could not be canonicalized or validated.',
                    undefined,
                    'LocalReplayRecord',
                ),
            ],
        };
    }
};

const verifyTargetAcceptedRecordShape = (
    input: TargetAcceptedRecordVerificationInput,
): readonly RefusalRecord[] => {
    const {
        evaluationProofRecord,
        targetAcceptedRecord,
        targetFinalityRecord,
    } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTargetAcceptedRecordDigest({
        boardPosition: targetAcceptedRecord.boardPosition,
        boardSequence: targetAcceptedRecord.boardSequence,
        acceptanceMode: targetAcceptedRecord.acceptanceMode,
        bgvAsyncThresholdCPADProfileDigest:
            targetAcceptedRecord.bgvAsyncThresholdCPADProfileDigest,
        ceremonyId: targetAcceptedRecord.ceremonyId,
        cpadProfileDigest: targetAcceptedRecord.cpadProfileDigest,
        cpadProfileId: targetAcceptedRecord.cpadProfileId,
        cTargetDigest: targetAcceptedRecord.cTargetDigest,
        electionManifestDigest: targetAcceptedRecord.electionManifestDigest,
        evaluationProofProfileDigest:
            targetAcceptedRecord.evaluationProofProfileDigest,
        evaluationProofRecordDigest:
            targetAcceptedRecord.evaluationProofRecordDigest,
        objectType: targetAcceptedRecord.objectType,
        objectVersion: targetAcceptedRecord.objectVersion,
        organizerIdentity: targetAcceptedRecord.organizerIdentity,
        qTargetDigest: targetAcceptedRecord.qTargetDigest,
        targetContextDigest: targetAcceptedRecord.targetContextDigest,
        targetFinalityCheckpointDigest:
            targetAcceptedRecord.targetFinalityCheckpointDigest,
        targetFinalityRecordDigest:
            targetAcceptedRecord.targetFinalityRecordDigest,
        targetLayoutDigest: targetAcceptedRecord.targetLayoutDigest,
        targetPhase: targetAcceptedRecord.targetPhase,
        targetPreimageDigest: targetAcceptedRecord.targetPreimageDigest,
        targetProposalDigest: targetAcceptedRecord.targetProposalDigest,
        thresholdDecryptionProfileDigest:
            targetAcceptedRecord.thresholdDecryptionProfileDigest,
        thresholdDecryptionProfileId:
            targetAcceptedRecord.thresholdDecryptionProfileId,
        topKEvaluationRecordDigest:
            targetAcceptedRecord.topKEvaluationRecordDigest,
    });

    if (targetAcceptedRecord.targetAcceptedRecordDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record digest does not match its canonical payload.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        targetAcceptedRecord.objectType !== 'TargetAcceptedRecord' ||
        targetAcceptedRecord.objectVersion !== 1 ||
        targetAcceptedRecord.acceptanceMode !== 'evaluation-proof' ||
        !isNonNegativeInteger(targetAcceptedRecord.boardSequence) ||
        !isNonNegativeInteger(targetAcceptedRecord.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record object shape is not canonical.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        !targetFinalityIsAccepted(
            targetFinalityRecord,
            input.targetFinalityVerification,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetPhaseAuthorizationFailure',
                'Target acceptance requires an accepted target-finality record.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        targetAcceptedRecord.targetProposalDigest !==
            targetFinalityRecord.targetProposalDigest ||
        targetAcceptedRecord.targetFinalityRecordDigest !==
            targetFinalityRecord.targetFinalityRecordDigest ||
        targetAcceptedRecord.targetFinalityCheckpointDigest !==
            targetFinalityRecord.targetFinalityCheckpoint
                .targetFinalityCheckpointDigest ||
        targetAcceptedRecord.evaluationProofRecordDigest !==
            evaluationProofRecord.evaluationProofRecordDigest ||
        targetAcceptedRecord.evaluationProofProfileDigest !==
            evaluationProofRecord.evaluationProofProfileDigest ||
        targetAcceptedRecord.topKEvaluationRecordDigest !==
            evaluationProofRecord.topKEvaluationRecordDigest ||
        targetAcceptedRecord.cTargetDigest !==
            evaluationProofRecord.cTargetDigest ||
        targetAcceptedRecord.targetLayoutDigest !==
            evaluationProofRecord.targetLayoutDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record must bind exact finality and mandatory evaluation proof evidence.',
                targetAcceptedRecord.targetAcceptedRecordDigest,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        input.targetAcceptedRecordInclusionProof.includedObjectType !==
            'TargetAcceptedRecord' ||
        input.targetAcceptedRecordInclusionProof.includedObjectDigest !==
            targetAcceptedRecord.targetAcceptedRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Target-accepted record inclusion proof does not bind the record.',
                input.targetAcceptedRecordInclusionProof.inclusionProofDigest,
                'TargetAcceptedRecord',
            ),
        );
    }

    return refusedObjects;
};

export const verifyTargetAcceptedRecordShell = (
    input: TargetAcceptedRecordVerificationInput,
): TargetAcceptedRecordVerification => {
    try {
        const { acceptedDigests, boardResult, refusedObjects } =
            collectSignedBoardInclusionEvidence({
                boardEvidence: input.boardEvidence,
                inclusionProof: input.targetAcceptedRecordInclusionProof,
                objectRefusals: verifyTargetAcceptedRecordShape(input),
                signature: input.targetAcceptedRecord.signature,
                signatureExpectation: {
                    objectType: 'TargetAcceptedRecord',
                    objectVersion: 1,
                    signerRole: 'Organizer',
                    signerIdentity:
                        input.targetAcceptedRecord.organizerIdentity,
                    ceremonyId: input.targetAcceptedRecord.ceremonyId,
                    publicKeyDigest: input.expectedOrganizerPublicKeyDigest,
                    manifestDigest:
                        input.targetAcceptedRecord.electionManifestDigest,
                    objectRoot:
                        input.targetAcceptedRecord.targetAcceptedRecordDigest,
                    boardHeadDigest:
                        input.targetAcceptedRecordInclusionProof
                            .boardHeadDigest,
                },
                acceptedObjectDigest:
                    input.targetAcceptedRecord.targetAcceptedRecordDigest,
            });

        return {
            ok: refusedObjects.length === 0,
            statusLabels: boardResult.statusLabels,
            acceptedDigests,
            refusedObjects,
            forkEvidence: boardResult.forkEvidence,
            targetAcceptedRecordDigest:
                refusedObjects.length === 0
                    ? input.targetAcceptedRecord.targetAcceptedRecordDigest
                    : undefined,
            targetFinalityRecordDigest:
                refusedObjects.length === 0
                    ? input.targetAcceptedRecord.targetFinalityRecordDigest
                    : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'TargetAcceptedRecordInvalid',
                    'Target-accepted record evidence could not be canonicalized or validated.',
                    undefined,
                    'TargetAcceptedRecord',
                ),
            ],
        };
    }
};

const verifyTopKDecryptionShareShape = (
    input: TopKDecryptionShareShellVerificationInput,
): readonly RefusalRecord[] => {
    const { decryptionShare, targetAcceptedRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTopKDecryptionShareDigest({
        bgvAsyncThresholdCPADProfileDigest:
            decryptionShare.bgvAsyncThresholdCPADProfileDigest,
        boardPosition: decryptionShare.boardPosition,
        boardSequence: decryptionShare.boardSequence,
        ceremonyId: decryptionShare.ceremonyId,
        cpadProfileDigest: decryptionShare.cpadProfileDigest,
        cTargetDigest: decryptionShare.cTargetDigest,
        deviceEpoch: decryptionShare.deviceEpoch,
        electionManifestDigest: decryptionShare.electionManifestDigest,
        evaluationProofRecordDigest:
            decryptionShare.evaluationProofRecordDigest,
        objectType: decryptionShare.objectType,
        objectVersion: decryptionShare.objectVersion,
        qTargetDigest: decryptionShare.qTargetDigest,
        recoveryEpoch: decryptionShare.recoveryEpoch,
        shareRoot: decryptionShare.shareRoot,
        targetAcceptedRecordDigest: decryptionShare.targetAcceptedRecordDigest,
        targetContextDigest: decryptionShare.targetContextDigest,
        targetDecryptionCiphertextDigest:
            decryptionShare.targetDecryptionCiphertextDigest,
        targetDecryptionPreparationRecordDigest:
            decryptionShare.targetDecryptionPreparationRecordDigest,
        targetFinalityCheckpointDigest:
            decryptionShare.targetFinalityCheckpointDigest,
        targetFinalityRecordDigest: decryptionShare.targetFinalityRecordDigest,
        targetPreimageDigest: decryptionShare.targetPreimageDigest,
        targetProposalDigest: decryptionShare.targetProposalDigest,
        thresholdShareVerificationKeyDigest:
            decryptionShare.thresholdShareVerificationKeyDigest,
        thresholdShareVerificationKeyRoot:
            decryptionShare.thresholdShareVerificationKeyRoot,
        thresholdDecryptionProfileDigest:
            decryptionShare.thresholdDecryptionProfileDigest,
        topKEvaluationRecordDigest: decryptionShare.topKEvaluationRecordDigest,
        trusteeThresholdVerificationKeyDigest:
            decryptionShare.trusteeThresholdVerificationKeyDigest,
        trusteeIdentity: decryptionShare.trusteeIdentity,
    });

    if (decryptionShare.topKDecryptionShareDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell digest does not match its canonical payload.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        decryptionShare.targetAcceptedRecordDigest !==
            targetAcceptedRecord.targetAcceptedRecordDigest ||
        decryptionShare.targetProposalDigest !==
            targetAcceptedRecord.targetProposalDigest ||
        decryptionShare.targetPreimageDigest !==
            targetAcceptedRecord.targetPreimageDigest ||
        decryptionShare.targetFinalityRecordDigest !==
            targetAcceptedRecord.targetFinalityRecordDigest ||
        decryptionShare.targetFinalityCheckpointDigest !==
            targetAcceptedRecord.targetFinalityCheckpointDigest ||
        decryptionShare.evaluationProofRecordDigest !==
            targetAcceptedRecord.evaluationProofRecordDigest ||
        decryptionShare.cTargetDigest !== targetAcceptedRecord.cTargetDigest ||
        decryptionShare.cpadProfileDigest !==
            targetAcceptedRecord.cpadProfileDigest ||
        decryptionShare.qTargetDigest !== targetAcceptedRecord.qTargetDigest ||
        decryptionShare.targetContextDigest !==
            targetAcceptedRecord.targetContextDigest ||
        decryptionShare.thresholdDecryptionProfileDigest !==
            targetAcceptedRecord.thresholdDecryptionProfileDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell must bind the accepted target and profile digests.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        !input.targetAcceptedRecordVerification.ok ||
        input.targetAcceptedRecordVerification.targetAcceptedRecordDigest !==
            targetAcceptedRecord.targetAcceptedRecordDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetPhaseAuthorizationFailure',
                'Decryption-share shell requires an accepted target record.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        input.decryptionShareInclusionProof.includedObjectType !==
            'TopKDecryptionShare' ||
        input.decryptionShareInclusionProof.includedObjectDigest !==
            decryptionShare.topKDecryptionShareDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Decryption-share shell inclusion proof does not bind the share.',
                input.decryptionShareInclusionProof.inclusionProofDigest,
                'TopKDecryptionShare',
            ),
        );
    }

    return refusedObjects;
};

export const verifyTopKDecryptionShareShell = (
    input: TopKDecryptionShareShellVerificationInput,
): TopKDecryptionShareShellVerification => {
    try {
        const { acceptedDigests, boardResult, refusedObjects } =
            collectSignedBoardInclusionEvidence({
                boardEvidence: input.boardEvidence,
                inclusionProof: input.decryptionShareInclusionProof,
                objectRefusals: verifyTopKDecryptionShareShape(input),
                signature: input.decryptionShare.signature,
                signatureExpectation: {
                    objectType: 'TopKDecryptionShare',
                    objectVersion: 1,
                    signerRole: 'Trustee',
                    signerIdentity: input.decryptionShare.trusteeIdentity,
                    ceremonyId: input.decryptionShare.ceremonyId,
                    publicKeyDigest: input.expectedTrusteePublicKeyDigest,
                    manifestDigest:
                        input.decryptionShare.electionManifestDigest,
                    objectRoot: input.decryptionShare.topKDecryptionShareDigest,
                    boardHeadDigest:
                        input.decryptionShareInclusionProof.boardHeadDigest,
                },
                acceptedObjectDigest:
                    input.decryptionShare.topKDecryptionShareDigest,
            });

        return {
            ok: refusedObjects.length === 0,
            statusLabels: boardResult.statusLabels,
            acceptedDigests,
            refusedObjects,
            forkEvidence: boardResult.forkEvidence,
            topKDecryptionShareDigest:
                refusedObjects.length === 0
                    ? input.decryptionShare.topKDecryptionShareDigest
                    : undefined,
            targetAcceptedRecordDigest:
                refusedObjects.length === 0
                    ? input.decryptionShare.targetAcceptedRecordDigest
                    : undefined,
            targetFinalityRecordDigest:
                refusedObjects.length === 0
                    ? input.decryptionShare.targetFinalityRecordDigest
                    : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'DecryptionShareInvalid',
                    'Decryption-share shell evidence could not be canonicalized or validated.',
                    undefined,
                    'TopKDecryptionShare',
                ),
            ],
        };
    }
};
