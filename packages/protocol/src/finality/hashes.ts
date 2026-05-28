import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    ConflictingHeadEvidence,
    ProtocolHash,
    TargetFinalityCheckpoint,
    TargetFinalityPolicy,
    TargetFinalityRecord,
    TargetProposal,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

import { compareCanonicalStrings } from '../common/verification-helpers.js';

export const deriveWitnessCheckpointHash = (
    checkpoint: Omit<WitnessCheckpoint, 'checkpointHash' | 'signature'>,
): ProtocolHash =>
    deriveProtocolHash('WitnessCheckpointHash', {
        ceremonyId: checkpoint.ceremonyId,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        targetFinalityCheckpointHash: checkpoint.targetFinalityCheckpointHash,
        targetFinalityPolicyHash: checkpoint.targetFinalityPolicyHash,
        targetFinalityScope: checkpoint.targetFinalityScope,
        targetProposalHash: checkpoint.targetProposalHash,
        witnessIdentity: checkpoint.witnessIdentity,
        witnessPolicyHash: checkpoint.witnessPolicyHash,
    });

export const deriveTargetProposalHash = (
    proposal: Omit<TargetProposal, 'targetProposalHash'>,
): ProtocolHash =>
    deriveProtocolHash('TargetProposalHash', {
        targetCiphertextHash: proposal.targetCiphertextHash,
        topKCiphertextHash: proposal.topKCiphertextHash,
        ceremonyId: proposal.ceremonyId,
        electionManifestHash: proposal.electionManifestHash,
        thresholdProfileHash: proposal.thresholdProfileHash,
        evaluationContextHash: proposal.evaluationContextHash,
        evaluationProofProfileHash: proposal.evaluationProofProfileHash,
        publicSlotMaskHash: proposal.publicSlotMaskHash,
        targetFinalityPolicyHash: proposal.targetFinalityPolicyHash,
        targetLayoutHash: proposal.targetLayoutHash,
        topKEvaluationRecordHash: proposal.topKEvaluationRecordHash,
    });

export const deriveTargetFinalityCheckpointHash = (
    checkpoint: Omit<TargetFinalityCheckpoint, 'targetFinalityCheckpointHash'>,
): ProtocolHash =>
    deriveProtocolHash('TargetFinalityCheckpointHash', {
        boardPolicyHash: checkpoint.boardPolicyHash,
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        topKCiphertextHash: checkpoint.topKCiphertextHash,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        thresholdProfileHash: checkpoint.thresholdProfileHash,
        evaluationContextHash: checkpoint.evaluationContextHash,
        evaluationProofProfileHash: checkpoint.evaluationProofProfileHash,
        finalizedBoardHeadHash: checkpoint.finalizedBoardHeadHash,
        objectType: checkpoint.objectType,
        objectVersion: checkpoint.objectVersion,
        publicSlotMaskHash: checkpoint.publicSlotMaskHash,
        targetFinalityPolicyHash: checkpoint.targetFinalityPolicyHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        targetProposalHash: checkpoint.targetProposalHash,
        topKEvaluationRecordHash: checkpoint.topKEvaluationRecordHash,
        witnessPolicyHash: checkpoint.witnessPolicyHash,
    });

export const deriveWitnessPolicyHash = (
    policy: Omit<WitnessPolicy, 'witnessPolicyHash'>,
): ProtocolHash =>
    deriveProtocolHash('WitnessPolicyHash', {
        totalWitnesses: policy.totalWitnesses,
        witnessIdentities: [...policy.witnessIdentities].sort(
            compareCanonicalStrings,
        ),
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityPolicyHash = (
    policy: Omit<TargetFinalityPolicy, 'targetFinalityPolicyHash'>,
): ProtocolHash =>
    deriveProtocolHash('TargetFinalityPolicyHash', {
        targetFinalityScope: policy.targetFinalityScope,
        totalWitnesses: policy.totalWitnesses,
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityRecordHash = (
    record: Omit<TargetFinalityRecord, 'targetFinalityRecordHash'>,
): ProtocolHash =>
    deriveProtocolHash('TargetFinalityRecordHash', {
        ceremonyId: record.ceremonyId,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
        objectVersion: record.objectVersion,
        targetFinalityCheckpointHash:
            record.targetFinalityCheckpoint.targetFinalityCheckpointHash,
        targetFinalityPolicyHash: record.targetFinalityPolicyHash,
        targetFinalityScope: record.targetFinalityScope,
        targetProposalHash: record.targetProposalHash,
        witnessCheckpoints: record.witnessCheckpoints.map(
            (checkpoint) => checkpoint.checkpointHash,
        ),
        witnessPolicyHash: record.witnessPolicyHash,
    });

export const deriveWitnessEquivocationEvidenceHash = (
    evidence: Omit<ConflictingHeadEvidence, 'evidenceHash'>,
): ProtocolHash =>
    deriveProtocolHash('WitnessEquivocationEvidenceHash', {
        boardPolicyHash: evidence.boardPolicyHash,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadHash: evidence.leftBoardHeadHash,
        rightBoardHeadHash: evidence.rightBoardHeadHash,
        targetFinalityScope: evidence.targetFinalityScope ?? null,
    });
