import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ConflictingHeadEvidence,
    ProtocolDigest,
    TargetFinalityCheckpoint,
    TargetFinalityPolicy,
    TargetFinalityRecord,
    TargetProposal,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

import { compareCanonicalStrings } from '../common/verification-helpers.js';

export const deriveWitnessCheckpointDigest = (
    checkpoint: Omit<WitnessCheckpoint, 'checkpointDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessCheckpointDigest', {
        ceremonyId: checkpoint.ceremonyId,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityCheckpointDigest:
            checkpoint.targetFinalityCheckpointDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetFinalityScope: checkpoint.targetFinalityScope,
        targetProposalDigest: checkpoint.targetProposalDigest,
        witnessIdentity: checkpoint.witnessIdentity,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });

export const deriveTargetProposalDigest = (
    proposal: Omit<TargetProposal, 'targetProposalDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetProposalDigest', {
        targetCiphertextDigest: proposal.targetCiphertextDigest,
        topKCiphertextDigest: proposal.topKCiphertextDigest,
        ceremonyId: proposal.ceremonyId,
        electionManifestDigest: proposal.electionManifestDigest,
        thresholdProfileDigest: proposal.thresholdProfileDigest,
        evaluationContextDigest: proposal.evaluationContextDigest,
        evaluationProofProfileDigest: proposal.evaluationProofProfileDigest,
        publicSlotMaskDigest: proposal.publicSlotMaskDigest,
        targetFinalityPolicyDigest: proposal.targetFinalityPolicyDigest,
        targetLayoutDigest: proposal.targetLayoutDigest,
        topKEvaluationRecordDigest: proposal.topKEvaluationRecordDigest,
    });

export const deriveTargetFinalityCheckpointDigest = (
    checkpoint: Omit<
        TargetFinalityCheckpoint,
        'targetFinalityCheckpointDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityCheckpointDigest', {
        boardPolicyDigest: checkpoint.boardPolicyDigest,
        targetCiphertextDigest: checkpoint.targetCiphertextDigest,
        topKCiphertextDigest: checkpoint.topKCiphertextDigest,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestDigest: checkpoint.electionManifestDigest,
        thresholdProfileDigest: checkpoint.thresholdProfileDigest,
        evaluationContextDigest: checkpoint.evaluationContextDigest,
        evaluationProofProfileDigest: checkpoint.evaluationProofProfileDigest,
        finalizedBoardHeadDigest: checkpoint.finalizedBoardHeadDigest,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        publicSlotMaskDigest: checkpoint.publicSlotMaskDigest,
        targetFinalityPolicyDigest: checkpoint.targetFinalityPolicyDigest,
        targetLayoutDigest: checkpoint.targetLayoutDigest,
        targetProposalDigest: checkpoint.targetProposalDigest,
        topKEvaluationRecordDigest: checkpoint.topKEvaluationRecordDigest,
        witnessPolicyDigest: checkpoint.witnessPolicyDigest,
    });

export const deriveWitnessPolicyDigest = (
    policy: Omit<WitnessPolicy, 'witnessPolicyDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessPolicyDigest', {
        totalWitnesses: policy.totalWitnesses,
        witnessIdentities: [...policy.witnessIdentities].sort(
            compareCanonicalStrings,
        ),
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityPolicyDigest = (
    policy: Omit<TargetFinalityPolicy, 'targetFinalityPolicyDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityPolicyDigest', {
        targetFinalityScope: policy.targetFinalityScope,
        totalWitnesses: policy.totalWitnesses,
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityRecordDigest = (
    record: Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('TargetFinalityRecordDigest', {
        ceremonyId: record.ceremonyId,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityCheckpointDigest:
            record.targetFinalityCheckpoint.targetFinalityCheckpointDigest,
        targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
        targetFinalityScope: record.targetFinalityScope,
        targetProposalDigest: record.targetProposalDigest,
        witnessCheckpoints: record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointDigest,
        ),
        witnessPolicyDigest: record.witnessPolicyDigest,
    });

export const deriveWitnessEquivocationEvidenceDigest = (
    evidence: Omit<ConflictingHeadEvidence, 'evidenceDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('WitnessEquivocationEvidenceDigest', {
        boardPolicyDigest: evidence.boardPolicyDigest,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadDigest: evidence.leftBoardHeadDigest,
        rightBoardHeadDigest: evidence.rightBoardHeadDigest,
        targetFinalityScope: evidence.targetFinalityScope ?? null,
    });
