import {
    cpadProfileId,
    targetBoundShareSelectionProfileId,
    type CapabilityContext,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveThresholdProfile,
    evaluateActionCapability,
} from '../../src/index';

const targetBoundShareSelectionProfile = {
    profileId: targetBoundShareSelectionProfileId,
    certificateDigest: 'target-bound-certificate-digest',
    cpadProfileId,
    targetBasisDigest: 'target-basis-digest',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
    selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
} as const;

const thresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const certifiedThresholdProfile = deriveThresholdProfile({
    rosterSize: 20,
    targetBoundShareSelectionProfile,
});

const createContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext => ({
    lifecycleState: 'DraftPoll',
    thresholdProfile,
    pollSpecValid: true,
    browserSupported: true,
    localRosterExternallyAccepted: true,
    rosterExternalAcceptanceDigest: 'accepted-roster-digest',
    actionContextRosterExternalAcceptanceDigest: 'accepted-roster-digest',
    ...overrides,
});

const targetAcceptedContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext =>
    createContext({
        lifecycleState: 'TargetAccepted',
        thresholdProfile: certifiedThresholdProfile,
        targetFinalityAccepted: true,
        targetAccepted: true,
        evaluationProofVerified: true,
        oneShotDecryptionProofCertificatePresent: true,
        thresholdDecryptionCertificatePresent: true,
        ...overrides,
    });

describe('election foundation capability evaluator', () => {
    it('requires local roster acceptance for claim-bearing actions', () => {
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({
                    lifecycleState: 'EvaluationProofOpen',
                    localRosterExternallyAccepted: false,
                    targetFinalityAccepted: true,
                    evaluationProofCertificatePresent: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'LocalRosterNotAccepted' });
    });

    it('requires claim-bearing action contexts to bind the local roster acceptance digest', () => {
        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'VotingOpen',
                    rosterExternalAcceptanceDigest: undefined,
                    actionContextRosterExternalAcceptanceDigest: undefined,
                }),
            ),
        ).toMatchObject({
            reason: 'RosterExternalAcceptanceDigestMissing',
        });

        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'VotingOpen',
                    rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                    actionContextRosterExternalAcceptanceDigest: undefined,
                }),
            ),
        ).toMatchObject({
            reason: 'RosterExternalAcceptanceDigestMissing',
        });

        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'VotingOpen',
                    rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                    actionContextRosterExternalAcceptanceDigest:
                        'different-roster-digest',
                }),
            ),
        ).toMatchObject({
            reason: 'RosterExternalAcceptanceDigestMismatch',
        });

        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'VotingOpen',
                    rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                    actionContextRosterExternalAcceptanceDigest:
                        'accepted-roster-digest',
                }),
            ),
        ).toEqual({ allowed: true, action: 'SubmitVote' });
    });

    it('refuses aggregate contribution before setup and turnout thresholds', () => {
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({ lifecycleState: 'VotingOpen' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'VotingClosed',
                    setupCompleteCount: 19,
                    turnoutCount: thresholdProfile.releaseQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'SetupIncomplete' });
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'VotingClosed',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum - 1,
                }),
            ),
        ).toMatchObject({ reason: 'TurnoutBelowReleaseFloor' });
    });

    it('allows aggregate contribution once structural and bridge gates pass', () => {
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'AwaitingAggregateContributors',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum,
                    bridgeMobileCertificatePresent: true,
                    bridgeProverCertificatePresent: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'DeriveAggregateContribution',
        });
    });

    it('keeps reserved safe API actions fail-closed until their implementations exist', () => {
        expect(
            evaluateActionCapability('VerifyTranscript', createContext()),
        ).toMatchObject({ reason: 'OperationUnavailable' });
        expect(
            evaluateActionCapability(
                'CreateBridgeProof',
                createContext({
                    bridgeMobileCertificatePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingBridgeMobileCertificate' });
        expect(
            evaluateActionCapability(
                'VerifyBridgeProof',
                createContext({
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'OperationUnavailable' });
        expect(
            evaluateActionCapability(
                'VerifyOneShotSharePolicy',
                createContext({
                    lifecycleState: 'FirstThresholdSharesReached',
                    thresholdProfile: certifiedThresholdProfile,
                    oneShotDecryptionProofCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'OperationUnavailable' });
    });

    it('verifies the mandatory evaluation proof only after target finality', () => {
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({ lifecycleState: 'TopKEvaluated' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({ lifecycleState: 'EvaluationProofOpen' }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({
                    lifecycleState: 'EvaluationProofOpen',
                    targetFinalityAccepted: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'MissingEvaluationProofCertificate' });
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({
                    lifecycleState: 'EvaluationProofOpen',
                    targetFinalityAccepted: true,
                    evaluationProofCertificatePresent: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'VerifyEvaluationProof' });
    });

    it('accepts a target only after finality and verified evaluation proof', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofOpen',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofVerified',
                    evaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofVerified',
                    targetFinalityAccepted: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluationProofMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofVerified',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('keeps opt-in local replay behind accepted target evidence', () => {
        expect(
            evaluateActionCapability(
                'CreateLocalReplayRecord',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    evaluationProofVerified: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetNotAccepted' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluation',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    targetAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluationProofMissing' });
        expect(
            evaluateActionCapability(
                'CreateLocalReplayRecord',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    targetAccepted: true,
                    evaluationProofVerified: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'CreateLocalReplayRecord' });
    });

    it('refuses decryption-share capability before accepted target evidence is complete', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({ lifecycleState: 'EvaluationProofVerified' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({ lifecycleState: 'TargetAccepted' }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    targetFinalityAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetNotAccepted' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluationProofMissing' });
    });

    it('requires the certified BGV async CPAD threshold profile before decryption', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    evaluationProofVerified: true,
                }),
            ),
        ).toMatchObject({ reason: 'ThresholdDecryptionProfileNotCertified' });
    });

    it.each([
        ['Ambiguous', 'AmbiguousRecoveryState'],
        ['MissingRecoveryMaterial', 'AmbiguousRecoveryState'],
        ['StaleEpoch', 'StaleRecoveryEpoch'],
        ['ClonedDeviceSuspected', 'ClonedDeviceState'],
    ] as const)(
        'refuses decryption-share capability for %s recovery state',
        (recoveryState, reason) => {
            expect(
                evaluateActionCapability(
                    'CreateTargetBoundDecryptionShare',
                    targetAcceptedContext({ recoveryState }),
                ),
            ).toMatchObject({ reason });
        },
    );

    it('allows target-bound decryption shares while awaiting first threshold shares', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                targetAcceptedContext({
                    lifecycleState: 'AwaitingFirstDecryptionShares',
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'CreateTargetBoundDecryptionShare',
        });
    });

    it('requires decryption and CPAD certificates for the target decryption path', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                targetAcceptedContext({
                    oneShotDecryptionProofCertificatePresent: false,
                }),
            ),
        ).toMatchObject({
            reason: 'MissingOneShotDecryptionProofCertificate',
        });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                targetAcceptedContext({
                    thresholdDecryptionCertificatePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingThresholdDecryptionCertificate' });
        expect(
            evaluateActionCapability(
                'VerifyCPADProfile',
                createContext({
                    lifecycleState: 'FirstThresholdSharesReached',
                    thresholdProfile,
                    cpadCertificatePresent: true,
                    decryptionShareCount: thresholdProfile.decryptionThreshold,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({
            reason: 'ThresholdDecryptionProfileNotCertified',
        });
        expect(
            evaluateActionCapability(
                'VerifyCPADProfile',
                createContext({
                    lifecycleState: 'FirstThresholdSharesReached',
                    thresholdProfile: certifiedThresholdProfile,
                    cpadCertificatePresent: false,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'MissingCPADCertificate' });
    });

    it('allows CPAD verification and recombination only after mandatory profile checks pass', () => {
        expect(
            evaluateActionCapability(
                'VerifyCPADProfile',
                createContext({
                    lifecycleState: 'FirstThresholdSharesReached',
                    thresholdProfile: certifiedThresholdProfile,
                    cpadCertificatePresent: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'VerifyCPADProfile' });
        expect(
            evaluateActionCapability(
                'VerifyCPADProfile',
                createContext({
                    lifecycleState: 'FirstThresholdSharesReached',
                    thresholdProfile: certifiedThresholdProfile,
                    cpadCertificatePresent: true,
                    decryptionShareCount:
                        (certifiedThresholdProfile.decryptionShareQuorum ?? 0) -
                        1,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'FirstThresholdSharesNotReached' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'FirstThresholdSharesReached',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    evaluationProofVerified: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    cpadProfileVerified: false,
                }),
            ),
        ).toMatchObject({ reason: 'CPADProfileNotVerified' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'CPADProfileVerified',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    evaluationProofVerified: true,
                    cpadProfileVerified: true,
                    decryptionShareCount:
                        (certifiedThresholdProfile.decryptionShareQuorum ?? 0) -
                        1,
                    oneShotDecryptionProofCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'FirstThresholdSharesNotReached' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'CPADProfileVerified',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    evaluationProofVerified: true,
                    cpadProfileVerified: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    oneShotDecryptionProofCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'RecombineAcceptedTarget' });
    });

    it('allows acknowledged unsafe small-roster profiles through claim-bearing environment gates', () => {
        const unsafeThresholdProfile = deriveThresholdProfile({
            rosterSize: 19,
            unsafeMicroRosterAcknowledged: true,
        });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofVerified',
                    thresholdProfile: unsafeThresholdProfile,
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('refuses claim-bearing capabilities when mobile environment gates fail', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofVerified',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                    mobileProfileSupported: false,
                }),
            ),
        ).toMatchObject({ reason: 'UnsupportedMobileProfile' });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationProofVerified',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                    storageQuotaSufficient: false,
                }),
            ),
        ).toMatchObject({ reason: 'InsufficientStorageQuota' });
    });

    it('leaves verified top-k decoding unavailable in election foundation', () => {
        expect(
            evaluateActionCapability(
                'DecodeVerifiedTopK',
                createContext({
                    lifecycleState: 'FullyVerifiedResult',
                    thresholdProfile: certifiedThresholdProfile,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'OperationUnavailable' });
    });

    it('refuses unknown runtime actions with a structured decision', () => {
        expect(
            evaluateActionCapability(
                'NotAProtocolAction' as never,
                createContext(),
            ),
        ).toEqual({
            allowed: false,
            action: 'NotAProtocolAction',
            reason: 'ForbiddenOperation',
        });
    });
});
