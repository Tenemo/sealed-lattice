import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    ProtocolHash,
    TargetAcceptedRecord,
    TopKDecryptionShareShell,
} from '@sealed-lattice/types';

export const deriveTargetAcceptedRecordHash = (
    record: Omit<
        TargetAcceptedRecord,
        'targetAcceptedRecordHash' | 'signature'
    >,
): ProtocolHash =>
    deriveProtocolHash('TargetAcceptedRecordHash', {
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

export const deriveTopKDecryptionShareHash = (
    share: Omit<
        TopKDecryptionShareShell,
        'topKDecryptionShareHash' | 'signature'
    >,
): ProtocolHash =>
    deriveProtocolHash('TopKDecryptionShareHash', {
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
