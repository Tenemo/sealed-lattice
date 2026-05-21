import type {
    LocalReplayRecordVerification,
    LocalReplayRecordVerificationInput,
    RefusalRecord,
    TargetAcceptedRecordVerification,
    TargetAcceptedRecordVerificationInput,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TopKDecryptionShareShellVerification,
    TopKDecryptionShareShellVerificationInput,
} from '@sealed-lattice/types';

import {
    buildSignedBoardShellVerificationBase,
    collectSignedBoardInclusionEvidence,
} from '../board/shell-evidence.js';
import {
    createRefusal,
    isNonNegativeInteger,
    signedObjectRootByteLength,
} from '../common/verification-helpers.js';

import {
    deriveLocalReplayRecordDigest,
    deriveTargetAcceptedRecordDigest,
    deriveTopKDecryptionShareDigest,
} from './digests.js';
export {
    deriveLocalReplayRecordDigest,
    deriveTargetAcceptedRecordDigest,
    deriveTopKDecryptionShareDigest,
} from './digests.js';

const targetFinalityIsAccepted = (
    record: TargetFinalityRecord,
    verification: TargetFinalityVerification,
): boolean =>
    verification.ok &&
    verification.targetFinalityRecordDigest ===
        record.targetFinalityRecordDigest &&
    verification.targetProposalDigest === record.targetProposalDigest;

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
        record.ceremonyId !== targetFinalityRecord.ceremonyId ||
        record.ceremonyId !== evaluationProofRecord.ceremonyId ||
        record.electionManifestDigest !==
            targetFinalityRecord.targetFinalityCheckpoint
                .electionManifestDigest ||
        record.electionManifestDigest !==
            evaluationProofRecord.electionManifestDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record ceremony and manifest must match the accepted target evidence.',
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
                'TargetAcceptanceAuthorizationFailure',
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
        const evidence = collectSignedBoardInclusionEvidence({
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
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: input.record.recoveryEpoch,
                deviceEpoch: input.record.deviceEpoch,
            },
            acceptedObjectDigest: input.record.localReplayRecordDigest,
        });
        const verificationBase =
            buildSignedBoardShellVerificationBase(evidence);

        return {
            ...verificationBase,
            localReplayRecordDigest: verificationBase.ok
                ? input.record.localReplayRecordDigest
                : undefined,
            targetFinalityRecordDigest: verificationBase.ok
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
        targetCiphertextDigest: targetAcceptedRecord.targetCiphertextDigest,
        electionManifestDigest: targetAcceptedRecord.electionManifestDigest,
        evaluationProofProfileDigest:
            targetAcceptedRecord.evaluationProofProfileDigest,
        evaluationProofRecordDigest:
            targetAcceptedRecord.evaluationProofRecordDigest,
        objectType: targetAcceptedRecord.objectType,
        objectVersion: targetAcceptedRecord.objectVersion,
        organizerIdentity: targetAcceptedRecord.organizerIdentity,
        targetBasisDigest: targetAcceptedRecord.targetBasisDigest,
        targetContextDigest: targetAcceptedRecord.targetContextDigest,
        targetFinalityCheckpointDigest:
            targetAcceptedRecord.targetFinalityCheckpointDigest,
        targetFinalityRecordDigest:
            targetAcceptedRecord.targetFinalityRecordDigest,
        targetLayoutDigest: targetAcceptedRecord.targetLayoutDigest,
        targetFinalityScope: targetAcceptedRecord.targetFinalityScope,
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
        targetAcceptedRecord.ceremonyId !== targetFinalityRecord.ceremonyId ||
        targetAcceptedRecord.ceremonyId !== evaluationProofRecord.ceremonyId ||
        targetAcceptedRecord.electionManifestDigest !==
            targetFinalityRecord.targetFinalityCheckpoint
                .electionManifestDigest ||
        targetAcceptedRecord.electionManifestDigest !==
            evaluationProofRecord.electionManifestDigest ||
        targetAcceptedRecord.targetFinalityScope !==
            targetFinalityRecord.targetFinalityScope
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record ceremony, manifest, and scope must match the accepted target evidence.',
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
                'TargetAcceptanceAuthorizationFailure',
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
        targetAcceptedRecord.targetCiphertextDigest !==
            evaluationProofRecord.targetCiphertextDigest ||
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
    if (
        input.targetAcceptedRecordInclusionProof.boardSequence !==
            targetAcceptedRecord.boardSequence ||
        input.targetAcceptedRecordInclusionProof.boardPosition !==
            targetAcceptedRecord.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Target-accepted record board position must match its inclusion proof.',
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
        const evidence = collectSignedBoardInclusionEvidence({
            boardEvidence: input.boardEvidence,
            inclusionProof: input.targetAcceptedRecordInclusionProof,
            objectRefusals: verifyTargetAcceptedRecordShape(input),
            signature: input.targetAcceptedRecord.signature,
            signatureExpectation: {
                objectType: 'TargetAcceptedRecord',
                objectVersion: 1,
                signerRole: 'Organizer',
                signerIdentity: input.targetAcceptedRecord.organizerIdentity,
                ceremonyId: input.targetAcceptedRecord.ceremonyId,
                publicKeyDigest: input.expectedOrganizerPublicKeyDigest,
                manifestDigest:
                    input.targetAcceptedRecord.electionManifestDigest,
                objectRoot:
                    input.targetAcceptedRecord.targetAcceptedRecordDigest,
                boardHeadDigest:
                    input.targetAcceptedRecordInclusionProof.boardHeadDigest,
                contextDigest: input.targetAcceptedRecord.targetContextDigest,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: 0,
                deviceEpoch: 0,
            },
            acceptedObjectDigest:
                input.targetAcceptedRecord.targetAcceptedRecordDigest,
        });
        const verificationBase =
            buildSignedBoardShellVerificationBase(evidence);

        return {
            ...verificationBase,
            targetAcceptedRecordDigest: verificationBase.ok
                ? input.targetAcceptedRecord.targetAcceptedRecordDigest
                : undefined,
            targetFinalityRecordDigest: verificationBase.ok
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
        targetCiphertextDigest: decryptionShare.targetCiphertextDigest,
        deviceEpoch: decryptionShare.deviceEpoch,
        electionManifestDigest: decryptionShare.electionManifestDigest,
        evaluationProofRecordDigest:
            decryptionShare.evaluationProofRecordDigest,
        objectType: decryptionShare.objectType,
        objectVersion: decryptionShare.objectVersion,
        targetBasisDigest: decryptionShare.targetBasisDigest,
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
        decryptionShare.objectType !== 'TopKDecryptionShare' ||
        decryptionShare.objectVersion !== 1 ||
        !isNonNegativeInteger(decryptionShare.boardSequence) ||
        !isNonNegativeInteger(decryptionShare.boardPosition) ||
        !isNonNegativeInteger(decryptionShare.recoveryEpoch) ||
        !isNonNegativeInteger(decryptionShare.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell object shape is not canonical.',
                decryptionShare.topKDecryptionShareDigest,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        decryptionShare.ceremonyId !== targetAcceptedRecord.ceremonyId ||
        decryptionShare.electionManifestDigest !==
            targetAcceptedRecord.electionManifestDigest ||
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
        decryptionShare.topKEvaluationRecordDigest !==
            targetAcceptedRecord.topKEvaluationRecordDigest ||
        decryptionShare.targetCiphertextDigest !==
            targetAcceptedRecord.targetCiphertextDigest ||
        decryptionShare.cpadProfileDigest !==
            targetAcceptedRecord.cpadProfileDigest ||
        decryptionShare.targetBasisDigest !==
            targetAcceptedRecord.targetBasisDigest ||
        decryptionShare.targetContextDigest !==
            targetAcceptedRecord.targetContextDigest ||
        decryptionShare.bgvAsyncThresholdCPADProfileDigest !==
            targetAcceptedRecord.bgvAsyncThresholdCPADProfileDigest ||
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
                'TargetAcceptanceAuthorizationFailure',
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
    if (
        input.decryptionShareInclusionProof.boardSequence !==
            decryptionShare.boardSequence ||
        input.decryptionShareInclusionProof.boardPosition !==
            decryptionShare.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Decryption-share shell board position must match its inclusion proof.',
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
        const evidence = collectSignedBoardInclusionEvidence({
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
                manifestDigest: input.decryptionShare.electionManifestDigest,
                objectRoot: input.decryptionShare.topKDecryptionShareDigest,
                boardHeadDigest:
                    input.decryptionShareInclusionProof.boardHeadDigest,
                contextDigest: input.decryptionShare.targetContextDigest,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: input.decryptionShare.recoveryEpoch,
                deviceEpoch: input.decryptionShare.deviceEpoch,
            },
            acceptedObjectDigest:
                input.decryptionShare.topKDecryptionShareDigest,
        });
        const verificationBase =
            buildSignedBoardShellVerificationBase(evidence);

        return {
            ...verificationBase,
            topKDecryptionShareDigest: verificationBase.ok
                ? input.decryptionShare.topKDecryptionShareDigest
                : undefined,
            targetAcceptedRecordDigest: verificationBase.ok
                ? input.decryptionShare.targetAcceptedRecordDigest
                : undefined,
            targetFinalityRecordDigest: verificationBase.ok
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
