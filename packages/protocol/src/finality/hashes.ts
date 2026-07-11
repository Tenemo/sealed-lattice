import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
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
    deriveCanonicalObjectHash({
        ceremonyId: checkpoint.ceremonyId,
        objectType: checkpoint.objectType,
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
    deriveCanonicalObjectHash({
        objectType: 'TargetProposal',
        ceremonyId: proposal.ceremonyId,
        electionManifestHash: proposal.electionManifestHash,
        encryptedBallotAggregateHash: proposal.encryptedBallotAggregateHash,
        evaluatorReplayContextHash: proposal.evaluatorReplayContextHash,
        bgvParametersHash: proposal.bgvParametersHash,
        evaluatorReplayRecordHash: proposal.evaluatorReplayRecordHash,
        targetCiphertextHash: proposal.targetCiphertextHash,
        targetFinalityPolicyHash: proposal.targetFinalityPolicyHash,
        targetLayoutHash: proposal.targetLayoutHash,
        thresholdParametersHash: proposal.thresholdParametersHash,
        tiePolicyHash: proposal.tiePolicyHash,
        topOptionCount: proposal.topOptionCount,
    });

export const deriveTargetFinalityCheckpointHash = (
    checkpoint: Omit<TargetFinalityCheckpoint, 'targetFinalityCheckpointHash'>,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        boardPolicyHash: checkpoint.boardPolicyHash,
        ceremonyId: checkpoint.ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        encryptedBallotAggregateHash: checkpoint.encryptedBallotAggregateHash,
        evaluatorReplayContextHash: checkpoint.evaluatorReplayContextHash,
        bgvParametersHash: checkpoint.bgvParametersHash,
        evaluatorReplayRecordHash: checkpoint.evaluatorReplayRecordHash,
        finalizedBoardHeadHash: checkpoint.finalizedBoardHeadHash,
        objectType: checkpoint.objectType,
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        targetFinalityPolicyHash: checkpoint.targetFinalityPolicyHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        targetProposalHash: checkpoint.targetProposalHash,
        thresholdParametersHash: checkpoint.thresholdParametersHash,
        tiePolicyHash: checkpoint.tiePolicyHash,
        topOptionCount: checkpoint.topOptionCount,
        witnessPolicyHash: checkpoint.witnessPolicyHash,
    });

export const deriveWitnessPolicyHash = (
    policy: Omit<WitnessPolicy, 'witnessPolicyHash'>,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'WitnessPolicy',
        totalWitnesses: policy.totalWitnesses,
        witnessIdentities: [...policy.witnessIdentities].sort(
            compareCanonicalStrings,
        ),
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityPolicyHash = (
    policy: Omit<TargetFinalityPolicy, 'targetFinalityPolicyHash'>,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'TargetFinalityPolicy',
        targetFinalityScope: policy.targetFinalityScope,
        totalWitnesses: policy.totalWitnesses,
        witnessQuorum: policy.witnessQuorum,
    });

export const deriveTargetFinalityRecordHash = (
    record: Omit<TargetFinalityRecord, 'targetFinalityRecordHash'>,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        ceremonyId: record.ceremonyId,
        inclusionProof: record.inclusionProof,
        objectType: record.objectType,
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
    deriveCanonicalObjectHash({
        objectType: 'WitnessEquivocationEvidence',
        boardPolicyHash: evidence.boardPolicyHash,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadHash: evidence.leftBoardHeadHash,
        rightBoardHeadHash: evidence.rightBoardHeadHash,
        targetFinalityScope: evidence.targetFinalityScope ?? null,
    });
