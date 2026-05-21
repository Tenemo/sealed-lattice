import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    LocalReplayRecord,
    ProtocolDigest,
    TargetAcceptedRecord,
    TopKDecryptionShareShell,
} from '@sealed-lattice/types';

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
        targetCiphertextDigest: record.targetCiphertextDigest,
        electionManifestDigest: record.electionManifestDigest,
        evaluationProofProfileDigest: record.evaluationProofProfileDigest,
        evaluationProofRecordDigest: record.evaluationProofRecordDigest,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        organizerIdentity: record.organizerIdentity,
        targetBasisDigest: record.targetBasisDigest,
        targetContextDigest: record.targetContextDigest,
        targetFinalityCheckpointDigest: record.targetFinalityCheckpointDigest,
        targetFinalityRecordDigest: record.targetFinalityRecordDigest,
        targetLayoutDigest: record.targetLayoutDigest,
        targetFinalityScope: record.targetFinalityScope,
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
        targetCiphertextDigest: share.targetCiphertextDigest,
        deviceEpoch: share.deviceEpoch,
        electionManifestDigest: share.electionManifestDigest,
        evaluationProofRecordDigest: share.evaluationProofRecordDigest,
        objectType: share.objectType,
        objectVersion: share.objectVersion,
        targetBasisDigest: share.targetBasisDigest,
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
