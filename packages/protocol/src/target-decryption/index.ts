import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import {
    targetDecryptionProfileId,
    type ProtocolVerificationStatusLabel,
    type RefusalRecord,
    type TargetAcceptedRecordVerification,
    type TargetAcceptedRecordVerificationInput,
    type TopKDecryptionShareShellVerification,
    type TopKDecryptionShareShellVerificationInput,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import {
    buildBoardHeadMap,
    createRefusal,
    defaultSignedRootContextHash,
    isProtocolHashString,
    signedObjectRootByteLength,
    uniqueStrings,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

import {
    deriveTargetAcceptedRecordHash,
    deriveTopKDecryptionShareHash,
} from './hashes.js';
export {
    deriveTargetAcceptedRecordHash,
    deriveTopKDecryptionShareHash,
} from './hashes.js';

const successfulStatusLabels: readonly ProtocolVerificationStatusLabel[] = [];

const verifyTargetAcceptedRecordUnchecked = (
    input: TargetAcceptedRecordVerificationInput,
): TargetAcceptedRecordVerification => {
    const { targetAcceptedRecord: record } = input;
    const refusedObjects: RefusalRecord[] = [];
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByHash = buildBoardHeadMap(input.boardEvidence.signedBoardHeads);
    const checkpoint = input.targetFinalityRecord.targetFinalityCheckpoint;
    const expectedRecordHash = deriveTargetAcceptedRecordHash({
        acceptanceMode: record.acceptanceMode,
        boardPosition: record.boardPosition,
        boardSequence: record.boardSequence,
        ceremonyId: record.ceremonyId,
        electionManifestHash: record.electionManifestHash,
        evaluatorReplayProfileHash: record.evaluatorReplayProfileHash,
        evaluatorReplayRecordHash: record.evaluatorReplayRecordHash,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        organizerIdentity: record.organizerIdentity,
        targetBasisHash: record.targetBasisHash,
        targetCiphertextHash: record.targetCiphertextHash,
        targetContextHash: record.targetContextHash,
        targetDecryptionProfileHash: record.targetDecryptionProfileHash,
        targetDecryptionProfileId: record.targetDecryptionProfileId,
        targetFinalityCheckpointHash: record.targetFinalityCheckpointHash,
        targetFinalityRecordHash: record.targetFinalityRecordHash,
        targetFinalityScope: record.targetFinalityScope,
        targetLayoutHash: record.targetLayoutHash,
        targetPreimageHash: record.targetPreimageHash,
        targetProposalHash: record.targetProposalHash,
    });

    refusedObjects.push(...boardResult.refusedObjects);
    refusedObjects.push(
        ...verifyInclusionProof(
            input.targetAcceptedRecordInclusionProof,
            headsByHash,
        ),
    );

    if (record.targetAcceptedRecordHash !== expectedRecordHash) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target accepted record hash does not match its canonical payload.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        record.objectType !== 'TargetAcceptedRecord' ||
        record.objectVersion !== 1 ||
        record.acceptanceMode !== 'evaluator-replay'
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target accepted record object shape is not canonical.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        input.targetAcceptedRecordInclusionProof.includedObjectType !==
            'TargetAcceptedRecord' ||
        input.targetAcceptedRecordInclusionProof.includedObjectHash !==
            record.targetAcceptedRecordHash ||
        input.targetAcceptedRecordInclusionProof.boardSequence !==
            record.boardSequence ||
        input.targetAcceptedRecordInclusionProof.boardPosition !==
            record.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target accepted record inclusion proof must include the exact accepted-target record at its declared board position.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (record.ceremonyId !== input.boardEvidence.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Target accepted record ceremony does not match the board evidence.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        input.targetFinalityVerification.ok !== true ||
        input.targetFinalityVerification.targetFinalityRecordHash !==
            input.targetFinalityRecord.targetFinalityRecordHash ||
        !input.targetFinalityVerification.acceptedHashes.includes(
            input.targetFinalityRecord.targetFinalityRecordHash,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Target acceptance requires verified target-finality evidence for the same record.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        record.targetFinalityRecordHash !==
            input.targetFinalityRecord.targetFinalityRecordHash ||
        record.targetFinalityCheckpointHash !==
            checkpoint.targetFinalityCheckpointHash ||
        record.targetProposalHash !==
            input.targetFinalityRecord.targetProposalHash ||
        record.targetFinalityScope !==
            input.targetFinalityRecord.targetFinalityScope
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target accepted record must bind the exact finalized target proposal and checkpoint.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        record.electionManifestHash !== checkpoint.electionManifestHash ||
        record.evaluatorReplayRecordHash !==
            checkpoint.evaluatorReplayRecordHash ||
        record.evaluatorReplayProfileHash !==
            checkpoint.evaluatorReplayProfileHash ||
        record.targetCiphertextHash !== checkpoint.targetCiphertextHash ||
        record.targetLayoutHash !== checkpoint.targetLayoutHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptanceAuthorizationFailure',
                'Target accepted record must bind the same evaluator replay, target ciphertext, and layout finalized by witnesses.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        input.evaluatorReplayRecord.evaluatorReplayRecordHash !==
            record.evaluatorReplayRecordHash ||
        input.evaluatorReplayRecord.targetProposalHash !==
            record.targetProposalHash ||
        input.evaluatorReplayRecord.targetFinalityRecordHash !==
            record.targetFinalityRecordHash ||
        input.evaluatorReplayRecord.targetCiphertextHash !==
            record.targetCiphertextHash ||
        input.evaluatorReplayRecord.targetLayoutHash !==
            record.targetLayoutHash ||
        input.evaluatorReplayRecord.evaluatorReplayProfileHash !==
            record.evaluatorReplayProfileHash
    ) {
        refusedObjects.push(
            createRefusal(
                'EvaluatorReplayInvalid',
                'Target accepted record must match the evaluator replay record for the accepted target ciphertext.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }
    if (
        record.targetDecryptionProfileId !== targetDecryptionProfileId ||
        !isProtocolHashString(record.targetDecryptionProfileHash) ||
        !isProtocolHashString(record.targetBasisHash) ||
        !isProtocolHashString(record.targetContextHash) ||
        !isProtocolHashString(record.targetPreimageHash)
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Target accepted record must bind the supported target decryption profile and canonical target hashes.',
                record.targetAcceptedRecordHash,
                'TargetAcceptedRecord',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(record.signature, {
        boardHeadHash: input.targetAcceptedRecordInclusionProof.boardHeadHash,
        byteLength: signedObjectRootByteLength,
        ceremonyId: record.ceremonyId,
        contextHash: defaultSignedRootContextHash,
        deviceEpoch: 0,
        manifestHash: record.electionManifestHash,
        objectRoot: record.targetAcceptedRecordHash,
        objectType: 'TargetAcceptedRecord',
        objectVersion: 1,
        publicKeyHash: input.expectedOrganizerPublicKeyHash,
        recoveryEpoch: 0,
        signerIdentity: record.organizerIdentity,
        signerRole: 'Organizer',
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    const accepted = refusedObjects.length === 0;

    return {
        ok: accepted,
        statusLabels: successfulStatusLabels,
        acceptedHashes: accepted
            ? uniqueStrings([
                  ...boardResult.acceptedHashes,
                  input.targetAcceptedRecordInclusionProof.inclusionProofHash,
                  input.targetFinalityRecord.targetFinalityRecordHash,
                  record.targetAcceptedRecordHash,
              ])
            : [],
        refusedObjects,
        targetAcceptedRecordHash: accepted
            ? record.targetAcceptedRecordHash
            : undefined,
        targetFinalityRecordHash: accepted
            ? input.targetFinalityRecord.targetFinalityRecordHash
            : undefined,
    };
};

export const verifyTargetAcceptedRecord = (
    input: TargetAcceptedRecordVerificationInput,
): TargetAcceptedRecordVerification => {
    try {
        return verifyTargetAcceptedRecordUnchecked(input);
    } catch (error) {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'TargetAcceptedRecordInvalid',
                    verificationExceptionMessage(
                        'Target accepted record could not be canonicalized or validated.',
                        error,
                    ),
                    undefined,
                    'TargetAcceptedRecord',
                ),
            ],
        };
    }
};

const verifyTopKDecryptionShareShellUnchecked = (
    input: TopKDecryptionShareShellVerificationInput,
): TopKDecryptionShareShellVerification => {
    const { decryptionShare: share, targetAcceptedRecord } = input;
    const refusedObjects: RefusalRecord[] = [];
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByHash = buildBoardHeadMap(input.boardEvidence.signedBoardHeads);
    const expectedShareHash = deriveTopKDecryptionShareHash({
        boardPosition: share.boardPosition,
        boardSequence: share.boardSequence,
        ceremonyId: share.ceremonyId,
        deviceEpoch: share.deviceEpoch,
        electionManifestHash: share.electionManifestHash,
        evaluatorReplayRecordHash: share.evaluatorReplayRecordHash,
        objectType: share.objectType,
        objectVersion: share.objectVersion,
        recoveryEpoch: share.recoveryEpoch,
        shareRoot: share.shareRoot,
        targetAcceptedRecordHash: share.targetAcceptedRecordHash,
        targetBasisHash: share.targetBasisHash,
        targetCiphertextHash: share.targetCiphertextHash,
        targetContextHash: share.targetContextHash,
        targetDecryptionCiphertextHash: share.targetDecryptionCiphertextHash,
        targetDecryptionPreparationRecordHash:
            share.targetDecryptionPreparationRecordHash,
        targetDecryptionProfileHash: share.targetDecryptionProfileHash,
        targetFinalityCheckpointHash: share.targetFinalityCheckpointHash,
        targetFinalityRecordHash: share.targetFinalityRecordHash,
        targetPreimageHash: share.targetPreimageHash,
        targetProposalHash: share.targetProposalHash,
        thresholdShareVerificationKeyHash:
            share.thresholdShareVerificationKeyHash,
        thresholdShareVerificationKeyRoot:
            share.thresholdShareVerificationKeyRoot,
        trusteeIdentity: share.trusteeIdentity,
        trusteeThresholdVerificationKeyHash:
            share.trusteeThresholdVerificationKeyHash,
    });

    refusedObjects.push(...boardResult.refusedObjects);
    refusedObjects.push(
        ...verifyInclusionProof(
            input.decryptionShareInclusionProof,
            headsByHash,
        ),
    );

    if (share.topKDecryptionShareHash !== expectedShareHash) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption share hash does not match its canonical payload.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        share.objectType !== 'TopKDecryptionShare' ||
        share.objectVersion !== 1
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption share object shape is not canonical.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        input.decryptionShareInclusionProof.includedObjectType !==
            'TopKDecryptionShare' ||
        input.decryptionShareInclusionProof.includedObjectHash !==
            share.topKDecryptionShareHash ||
        input.decryptionShareInclusionProof.boardSequence !==
            share.boardSequence ||
        input.decryptionShareInclusionProof.boardPosition !==
            share.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption share inclusion proof must include the exact share at its declared board position.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        input.targetAcceptedRecordVerification.ok !== true ||
        input.targetAcceptedRecordVerification.targetAcceptedRecordHash !==
            targetAcceptedRecord.targetAcceptedRecordHash ||
        !input.targetAcceptedRecordVerification.acceptedHashes.includes(
            targetAcceptedRecord.targetAcceptedRecordHash,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetAcceptedRecordInvalid',
                'Decryption shares require verified accepted-target evidence.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        share.ceremonyId !== targetAcceptedRecord.ceremonyId ||
        share.electionManifestHash !==
            targetAcceptedRecord.electionManifestHash ||
        share.targetAcceptedRecordHash !==
            targetAcceptedRecord.targetAcceptedRecordHash ||
        share.targetProposalHash !== targetAcceptedRecord.targetProposalHash ||
        share.targetPreimageHash !== targetAcceptedRecord.targetPreimageHash ||
        share.targetFinalityRecordHash !==
            targetAcceptedRecord.targetFinalityRecordHash ||
        share.targetFinalityCheckpointHash !==
            targetAcceptedRecord.targetFinalityCheckpointHash ||
        share.evaluatorReplayRecordHash !==
            targetAcceptedRecord.evaluatorReplayRecordHash ||
        share.targetContextHash !== targetAcceptedRecord.targetContextHash ||
        share.targetCiphertextHash !==
            targetAcceptedRecord.targetCiphertextHash ||
        share.targetDecryptionProfileHash !==
            targetAcceptedRecord.targetDecryptionProfileHash ||
        share.targetBasisHash !== targetAcceptedRecord.targetBasisHash
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption share must bind the exact accepted target record and target ciphertext.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        share.targetDecryptionCiphertextHash !==
        targetAcceptedRecord.targetCiphertextHash
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Only the accepted target ciphertext may receive target-bound decryption shares.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }
    if (
        !isProtocolHashString(share.shareRoot) ||
        !isProtocolHashString(share.thresholdShareVerificationKeyRoot) ||
        !isProtocolHashString(share.thresholdShareVerificationKeyHash) ||
        !isProtocolHashString(share.trusteeThresholdVerificationKeyHash) ||
        !isProtocolHashString(share.targetDecryptionPreparationRecordHash)
    ) {
        refusedObjects.push(
            createRefusal(
                'DecryptionShareInvalid',
                'Decryption share must bind canonical share, preparation, and verification-key hashes.',
                share.topKDecryptionShareHash,
                'TopKDecryptionShare',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(share.signature, {
        boardHeadHash: input.decryptionShareInclusionProof.boardHeadHash,
        byteLength: signedObjectRootByteLength,
        ceremonyId: share.ceremonyId,
        contextHash: defaultSignedRootContextHash,
        deviceEpoch: share.deviceEpoch,
        manifestHash: share.electionManifestHash,
        objectRoot: share.topKDecryptionShareHash,
        objectType: 'TopKDecryptionShare',
        objectVersion: 1,
        publicKeyHash: input.expectedTrusteePublicKeyHash,
        recoveryEpoch: share.recoveryEpoch,
        signerIdentity: share.trusteeIdentity,
        signerRole: 'Trustee',
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    const accepted = refusedObjects.length === 0;

    return {
        ok: accepted,
        statusLabels: successfulStatusLabels,
        acceptedHashes: accepted
            ? uniqueStrings([
                  ...boardResult.acceptedHashes,
                  targetAcceptedRecord.targetAcceptedRecordHash,
                  input.decryptionShareInclusionProof.inclusionProofHash,
                  share.topKDecryptionShareHash,
              ])
            : [],
        refusedObjects,
        topKDecryptionShareHash: accepted
            ? share.topKDecryptionShareHash
            : undefined,
        targetAcceptedRecordHash: accepted
            ? targetAcceptedRecord.targetAcceptedRecordHash
            : undefined,
        targetFinalityRecordHash: accepted
            ? targetAcceptedRecord.targetFinalityRecordHash
            : undefined,
    };
};

export const verifyTopKDecryptionShareShell = (
    input: TopKDecryptionShareShellVerificationInput,
): TopKDecryptionShareShellVerification => {
    try {
        return verifyTopKDecryptionShareShellUnchecked(input);
    } catch (error) {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'DecryptionShareInvalid',
                    verificationExceptionMessage(
                        'Decryption share could not be canonicalized or validated.',
                        error,
                    ),
                    undefined,
                    'TopKDecryptionShare',
                ),
            ],
        };
    }
};
