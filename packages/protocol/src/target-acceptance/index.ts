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
    deriveLocalReplayRecordHash,
    deriveTargetAcceptedRecordHash,
    deriveTopKDecryptionShareHash,
} from './hashes.js';
export {
    deriveLocalReplayRecordHash,
    deriveTargetAcceptedRecordHash,
    deriveTopKDecryptionShareHash,
} from './hashes.js';

const targetFinalityIsAccepted = (
    record: TargetFinalityRecord,
    verification: TargetFinalityVerification,
): boolean =>
    verification.ok &&
    verification.targetFinalityRecordHash === record.targetFinalityRecordHash &&
    verification.targetProposalHash === record.targetProposalHash;

const verifyLocalReplayRecordShape = (
    input: LocalReplayRecordVerificationInput,
): readonly RefusalRecord[] => {
    const { evaluationProofRecord, record, targetFinalityRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveLocalReplayRecordHash({
        ceremonyId: record.ceremonyId,
        deviceEpoch: record.deviceEpoch,
        electionManifestHash: record.electionManifestHash,
        evaluationProofRecordHash: record.evaluationProofRecordHash,
        localReplayDiagnosticHash: record.localReplayDiagnosticHash,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        participantIdentity: record.participantIdentity,
        recoveryEpoch: record.recoveryEpoch,
        replayContextHash: record.replayContextHash,
        targetFinalityRecordHash: record.targetFinalityRecordHash,
        targetProposalHash: record.targetProposalHash,
    });

    if (record.localReplayRecordHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record hash does not match its canonical payload.',
                record.localReplayRecordHash,
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
                record.localReplayRecordHash,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        record.ceremonyId !== targetFinalityRecord.ceremonyId ||
        record.ceremonyId !== evaluationProofRecord.ceremonyId ||
        record.electionManifestHash !==
            targetFinalityRecord.targetFinalityCheckpoint
                .electionManifestHash ||
        record.electionManifestHash !==
            evaluationProofRecord.electionManifestHash
    ) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record ceremony and manifest must match the accepted target evidence.',
                record.localReplayRecordHash,
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
                record.localReplayRecordHash,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        record.targetProposalHash !== targetFinalityRecord.targetProposalHash ||
        record.targetFinalityRecordHash !==
            targetFinalityRecord.targetFinalityRecordHash ||
        record.evaluationProofRecordHash !==
            evaluationProofRecord.evaluationProofRecordHash
    ) {
        refusedObjects.push(
            createRefusal(
                'LocalReplayRecordInvalid',
                'Local replay record must bind the exact accepted target and evaluation proof.',
                record.localReplayRecordHash,
                'LocalReplayRecord',
            ),
        );
    }
    if (
        input.recordInclusionProof.includedObjectType !== 'LocalReplayRecord' ||
        input.recordInclusionProof.includedObjectHash !==
            record.localReplayRecordHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Local replay record inclusion proof does not bind the record.',
                input.recordInclusionProof.inclusionProofHash,
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
                publicKeyHash: input.expectedSignerPublicKeyHash,
                manifestHash: input.record.electionManifestHash,
                objectRoot: input.record.localReplayRecordHash,
                boardHeadHash: input.recordInclusionProof.boardHeadHash,
                contextHash: input.record.replayContextHash,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: input.record.recoveryEpoch,
                deviceEpoch: input.record.deviceEpoch,
            },
            acceptedObjectHash: input.record.localReplayRecordHash,
        });
        const verificationBase =
            buildSignedBoardShellVerificationBase(evidence);

        return {
            ...verificationBase,
            localReplayRecordHash: verificationBase.ok
                ? input.record.localReplayRecordHash
                : undefined,
            targetFinalityRecordHash: verificationBase.ok
                ? input.record.targetFinalityRecordHash
                : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
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
    const expectedHash = deriveTargetAcceptedRecordHash({
        boardPosition: targetAcceptedRecord.boardPosition,
        boardSequence: targetAcceptedRecord.boardSequence,
        acceptanceMode: targetAcceptedRecord.acceptanceMode,
        kllpsTargetDecryptionProfileHash:
            targetAcceptedRecord.kllpsTargetDecryptionProfileHash,
        ceremonyId: targetAcceptedRecord.ceremonyId,
        cpadProfileHash: targetAcceptedRecord.cpadProfileHash,
        cpadProfileId: targetAcceptedRecord.cpadProfileId,
        targetCiphertextHash: targetAcceptedRecord.targetCiphertextHash,
        electionManifestHash: targetAcceptedRecord.electionManifestHash,
        evaluationProofProfileHash:
            targetAcceptedRecord.evaluationProofProfileHash,
        evaluationProofRecordHash:
            targetAcceptedRecord.evaluationProofRecordHash,
        objectType: targetAcceptedRecord.objectType,
        objectVersion: targetAcceptedRecord.objectVersion,
        organizerIdentity: targetAcceptedRecord.organizerIdentity,
        targetBasisHash: targetAcceptedRecord.targetBasisHash,
        targetContextHash: targetAcceptedRecord.targetContextHash,
        targetFinalityCheckpointHash:
            targetAcceptedRecord.targetFinalityCheckpointHash,
        targetFinalityRecordHash: targetAcceptedRecord.targetFinalityRecordHash,
        targetLayoutHash: targetAcceptedRecord.targetLayoutHash,
        targetFinalityScope: targetAcceptedRecord.targetFinalityScope,
        targetPreimageHash: targetAcceptedRecord.targetPreimageHash,
        targetProposalHash: targetAcceptedRecord.targetProposalHash,
        thresholdDecryptionProfileHash:
            targetAcceptedRecord.thresholdDecryptionProfileHash,
        thresholdDecryptionProfileId:
            targetAcceptedRecord.thresholdDecryptionProfileId,
        topKEvaluationRecordHash: targetAcceptedRecord.topKEvaluationRecordHash,
    });

    if (targetAcceptedRecord.targetAcceptedRecordHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record hash does not match its canonical payload.',
                targetAcceptedRecord.targetAcceptedRecordHash,
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
                targetAcceptedRecord.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        targetAcceptedRecord.ceremonyId !== targetFinalityRecord.ceremonyId ||
        targetAcceptedRecord.ceremonyId !== evaluationProofRecord.ceremonyId ||
        targetAcceptedRecord.electionManifestHash !==
            targetFinalityRecord.targetFinalityCheckpoint
                .electionManifestHash ||
        targetAcceptedRecord.electionManifestHash !==
            evaluationProofRecord.electionManifestHash ||
        targetAcceptedRecord.targetFinalityScope !==
            targetFinalityRecord.targetFinalityScope
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record ceremony, manifest, and scope must match the accepted target evidence.',
                targetAcceptedRecord.targetAcceptedRecordHash,
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
                targetAcceptedRecord.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        targetAcceptedRecord.targetProposalHash !==
            targetFinalityRecord.targetProposalHash ||
        targetAcceptedRecord.targetFinalityRecordHash !==
            targetFinalityRecord.targetFinalityRecordHash ||
        targetAcceptedRecord.targetFinalityCheckpointHash !==
            targetFinalityRecord.targetFinalityCheckpoint
                .targetFinalityCheckpointHash ||
        targetAcceptedRecord.evaluationProofRecordHash !==
            evaluationProofRecord.evaluationProofRecordHash ||
        targetAcceptedRecord.evaluationProofProfileHash !==
            evaluationProofRecord.evaluationProofProfileHash ||
        targetAcceptedRecord.topKEvaluationRecordHash !==
            evaluationProofRecord.topKEvaluationRecordHash ||
        targetAcceptedRecord.targetCiphertextHash !==
            evaluationProofRecord.targetCiphertextHash ||
        targetAcceptedRecord.targetLayoutHash !==
            evaluationProofRecord.targetLayoutHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target-accepted record must bind exact finality and mandatory evaluation proof evidence.',
                targetAcceptedRecord.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        input.targetAcceptedRecordInclusionProof.includedObjectType !==
            'TargetAcceptedRecord' ||
        input.targetAcceptedRecordInclusionProof.includedObjectHash !==
            targetAcceptedRecord.targetAcceptedRecordHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Target-accepted record inclusion proof does not bind the record.',
                input.targetAcceptedRecordInclusionProof.inclusionProofHash,
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
                input.targetAcceptedRecordInclusionProof.inclusionProofHash,
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
                publicKeyHash: input.expectedOrganizerPublicKeyHash,
                manifestHash: input.targetAcceptedRecord.electionManifestHash,
                objectRoot: input.targetAcceptedRecord.targetAcceptedRecordHash,
                boardHeadHash:
                    input.targetAcceptedRecordInclusionProof.boardHeadHash,
                contextHash: input.targetAcceptedRecord.targetContextHash,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: 0,
                deviceEpoch: 0,
            },
            acceptedObjectHash:
                input.targetAcceptedRecord.targetAcceptedRecordHash,
        });
        const verificationBase =
            buildSignedBoardShellVerificationBase(evidence);

        return {
            ...verificationBase,
            targetAcceptedRecordHash: verificationBase.ok
                ? input.targetAcceptedRecord.targetAcceptedRecordHash
                : undefined,
            targetFinalityRecordHash: verificationBase.ok
                ? input.targetAcceptedRecord.targetFinalityRecordHash
                : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
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
    const expectedHash = deriveTopKDecryptionShareHash({
        kllpsTargetDecryptionProfileHash:
            decryptionShare.kllpsTargetDecryptionProfileHash,
        boardPosition: decryptionShare.boardPosition,
        boardSequence: decryptionShare.boardSequence,
        ceremonyId: decryptionShare.ceremonyId,
        cpadProfileHash: decryptionShare.cpadProfileHash,
        targetCiphertextHash: decryptionShare.targetCiphertextHash,
        deviceEpoch: decryptionShare.deviceEpoch,
        electionManifestHash: decryptionShare.electionManifestHash,
        evaluationProofRecordHash: decryptionShare.evaluationProofRecordHash,
        objectType: decryptionShare.objectType,
        objectVersion: decryptionShare.objectVersion,
        targetBasisHash: decryptionShare.targetBasisHash,
        recoveryEpoch: decryptionShare.recoveryEpoch,
        shareRoot: decryptionShare.shareRoot,
        targetAcceptedRecordHash: decryptionShare.targetAcceptedRecordHash,
        targetContextHash: decryptionShare.targetContextHash,
        targetDecryptionCiphertextHash:
            decryptionShare.targetDecryptionCiphertextHash,
        targetDecryptionPreparationRecordHash:
            decryptionShare.targetDecryptionPreparationRecordHash,
        targetFinalityCheckpointHash:
            decryptionShare.targetFinalityCheckpointHash,
        targetFinalityRecordHash: decryptionShare.targetFinalityRecordHash,
        targetPreimageHash: decryptionShare.targetPreimageHash,
        targetProposalHash: decryptionShare.targetProposalHash,
        thresholdShareVerificationKeyHash:
            decryptionShare.thresholdShareVerificationKeyHash,
        thresholdShareVerificationKeyRoot:
            decryptionShare.thresholdShareVerificationKeyRoot,
        thresholdDecryptionProfileHash:
            decryptionShare.thresholdDecryptionProfileHash,
        topKEvaluationRecordHash: decryptionShare.topKEvaluationRecordHash,
        trusteeThresholdVerificationKeyHash:
            decryptionShare.trusteeThresholdVerificationKeyHash,
        trusteeIdentity: decryptionShare.trusteeIdentity,
    });

    if (decryptionShare.topKDecryptionShareHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell hash does not match its canonical payload.',
                decryptionShare.topKDecryptionShareHash,
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
                decryptionShare.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        decryptionShare.ceremonyId !== targetAcceptedRecord.ceremonyId ||
        decryptionShare.electionManifestHash !==
            targetAcceptedRecord.electionManifestHash ||
        decryptionShare.targetAcceptedRecordHash !==
            targetAcceptedRecord.targetAcceptedRecordHash ||
        decryptionShare.targetProposalHash !==
            targetAcceptedRecord.targetProposalHash ||
        decryptionShare.targetPreimageHash !==
            targetAcceptedRecord.targetPreimageHash ||
        decryptionShare.targetFinalityRecordHash !==
            targetAcceptedRecord.targetFinalityRecordHash ||
        decryptionShare.targetFinalityCheckpointHash !==
            targetAcceptedRecord.targetFinalityCheckpointHash ||
        decryptionShare.evaluationProofRecordHash !==
            targetAcceptedRecord.evaluationProofRecordHash ||
        decryptionShare.topKEvaluationRecordHash !==
            targetAcceptedRecord.topKEvaluationRecordHash ||
        decryptionShare.targetCiphertextHash !==
            targetAcceptedRecord.targetCiphertextHash ||
        decryptionShare.cpadProfileHash !==
            targetAcceptedRecord.cpadProfileHash ||
        decryptionShare.targetBasisHash !==
            targetAcceptedRecord.targetBasisHash ||
        decryptionShare.targetContextHash !==
            targetAcceptedRecord.targetContextHash ||
        decryptionShare.kllpsTargetDecryptionProfileHash !==
            targetAcceptedRecord.kllpsTargetDecryptionProfileHash ||
        decryptionShare.thresholdDecryptionProfileHash !==
            targetAcceptedRecord.thresholdDecryptionProfileHash
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption-share shell must bind the accepted target and profile Hashes.',
                decryptionShare.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        !input.targetAcceptedRecordVerification.ok ||
        input.targetAcceptedRecordVerification.targetAcceptedRecordHash !==
            targetAcceptedRecord.targetAcceptedRecordHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptanceAuthorizationFailure',
                'Decryption-share shell requires an accepted target record.',
                decryptionShare.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        input.decryptionShareInclusionProof.includedObjectType !==
            'TopKDecryptionShare' ||
        input.decryptionShareInclusionProof.includedObjectHash !==
            decryptionShare.topKDecryptionShareHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Decryption-share shell inclusion proof does not bind the share.',
                input.decryptionShareInclusionProof.inclusionProofHash,
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
                input.decryptionShareInclusionProof.inclusionProofHash,
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
                publicKeyHash: input.expectedTrusteePublicKeyHash,
                manifestHash: input.decryptionShare.electionManifestHash,
                objectRoot: input.decryptionShare.topKDecryptionShareHash,
                boardHeadHash:
                    input.decryptionShareInclusionProof.boardHeadHash,
                contextHash: input.decryptionShare.targetContextHash,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: input.decryptionShare.recoveryEpoch,
                deviceEpoch: input.decryptionShare.deviceEpoch,
            },
            acceptedObjectHash: input.decryptionShare.topKDecryptionShareHash,
        });
        const verificationBase =
            buildSignedBoardShellVerificationBase(evidence);

        return {
            ...verificationBase,
            topKDecryptionShareHash: verificationBase.ok
                ? input.decryptionShare.topKDecryptionShareHash
                : undefined,
            targetAcceptedRecordHash: verificationBase.ok
                ? input.decryptionShare.targetAcceptedRecordHash
                : undefined,
            targetFinalityRecordHash: verificationBase.ok
                ? input.decryptionShare.targetFinalityRecordHash
                : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
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
