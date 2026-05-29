import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    LocalReplayRecord,
    ProtocolHash,
    TargetAcceptedRecord,
    TopKDecryptionShareShell,
} from '@sealed-lattice/types';

export const deriveLocalReplayRecordHash = (
    record: Omit<LocalReplayRecord, 'localReplayRecordHash' | 'signature'>,
): ProtocolHash =>
    deriveProtocolHash('LocalReplayRecordHash', {
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

export const deriveTargetAcceptedRecordHash = (
    record: Omit<
        TargetAcceptedRecord,
        'targetAcceptedRecordHash' | 'signature'
    >,
): ProtocolHash =>
    deriveProtocolHash('TargetAcceptedRecordHash', {
        boardPosition: record.boardPosition,
        boardSequence: record.boardSequence,
        acceptanceMode: record.acceptanceMode,
        kllpsTargetDecryptionProfileHash:
            record.kllpsTargetDecryptionProfileHash,
        ceremonyId: record.ceremonyId,
        cpadProfileHash: record.cpadProfileHash,
        cpadProfileId: record.cpadProfileId,
        targetCiphertextHash: record.targetCiphertextHash,
        electionManifestHash: record.electionManifestHash,
        evaluationProofProfileHash: record.evaluationProofProfileHash,
        evaluationProofRecordHash: record.evaluationProofRecordHash,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        organizerIdentity: record.organizerIdentity,
        targetBasisHash: record.targetBasisHash,
        targetContextHash: record.targetContextHash,
        targetFinalityCheckpointHash: record.targetFinalityCheckpointHash,
        targetFinalityRecordHash: record.targetFinalityRecordHash,
        targetLayoutHash: record.targetLayoutHash,
        targetFinalityScope: record.targetFinalityScope,
        targetPreimageHash: record.targetPreimageHash,
        targetProposalHash: record.targetProposalHash,
        thresholdDecryptionProfileHash: record.thresholdDecryptionProfileHash,
        thresholdDecryptionProfileId: record.thresholdDecryptionProfileId,
        topKEvaluationRecordHash: record.topKEvaluationRecordHash,
    });

export const deriveTopKDecryptionShareHash = (
    share: Omit<
        TopKDecryptionShareShell,
        'topKDecryptionShareHash' | 'signature'
    >,
): ProtocolHash =>
    deriveProtocolHash('TopKDecryptionShareHash', {
        kllpsTargetDecryptionProfileHash:
            share.kllpsTargetDecryptionProfileHash,
        boardPosition: share.boardPosition,
        boardSequence: share.boardSequence,
        ceremonyId: share.ceremonyId,
        cpadProfileHash: share.cpadProfileHash,
        targetCiphertextHash: share.targetCiphertextHash,
        deviceEpoch: share.deviceEpoch,
        electionManifestHash: share.electionManifestHash,
        evaluationProofRecordHash: share.evaluationProofRecordHash,
        objectType: share.objectType,
        objectVersion: share.objectVersion,
        targetBasisHash: share.targetBasisHash,
        recoveryEpoch: share.recoveryEpoch,
        shareRoot: share.shareRoot,
        targetAcceptedRecordHash: share.targetAcceptedRecordHash,
        targetContextHash: share.targetContextHash,
        targetDecryptionCiphertextHash: share.targetDecryptionCiphertextHash,
        targetDecryptionPreparationRecordHash:
            share.targetDecryptionPreparationRecordHash,
        targetFinalityCheckpointHash: share.targetFinalityCheckpointHash,
        targetFinalityRecordHash: share.targetFinalityRecordHash,
        targetPreimageHash: share.targetPreimageHash,
        targetProposalHash: share.targetProposalHash,
        thresholdShareVerificationKeyHash:
            share.thresholdShareVerificationKeyHash,
        thresholdShareVerificationKeyRoot:
            share.thresholdShareVerificationKeyRoot,
        thresholdDecryptionProfileHash: share.thresholdDecryptionProfileHash,
        topKEvaluationRecordHash: share.topKEvaluationRecordHash,
        trusteeThresholdVerificationKeyHash:
            share.trusteeThresholdVerificationKeyHash,
        trusteeIdentity: share.trusteeIdentity,
    });
