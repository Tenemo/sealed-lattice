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

const dynamicRosterProfileCertificateDigest = 'a'.repeat(128);
const thresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const certifiedThresholdProfile = deriveThresholdProfile({
    rosterSize: 20,
    targetBoundShareSelectionProfile,
});

const createContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext => ({
    lifecycleState: 'draft',
    thresholdProfile,
    pollSpecValid: true,
    localRosterAccepted: true,
    rosterExternalAcceptanceDigest: 'accepted-roster-digest',
    actionContextRosterExternalAcceptanceDigest: 'accepted-roster-digest',
    ...overrides,
});

const targetAcceptedContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext =>
    createContext({
        lifecycleState: 'targetAccepted',
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
                    lifecycleState: 'evaluationProofPending',
                    localRosterAccepted: false,
                    targetFinalityAccepted: true,
                    evaluationProofCertificatePresent: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'LocalRosterNotAccepted' });
    });

    it('requires claim-bearing action contexts to bind the local roster acceptance digest', () => {
        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'votingOpen',
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
                    lifecycleState: 'votingOpen',
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
                    lifecycleState: 'votingOpen',
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
                    lifecycleState: 'votingOpen',
                    rosterExternalAcceptanceDigest: 'accepted-roster-digest',
                    actionContextRosterExternalAcceptanceDigest:
                        'accepted-roster-digest',
                }),
            ),
        ).toEqual({ allowed: true, action: 'SubmitVote' });
    });

    it('opens voting only after the frozen roster profile and trustee material are complete', () => {
        expect(
            evaluateActionCapability(
                'OpenVoting',
                createContext({
                    lifecycleState: 'rosterFrozen',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'ClaimClosureMissing' });

        expect(
            evaluateActionCapability(
                'OpenVoting',
                createContext({
                    ballotProofProfileFrozen: true,
                    kllpsCpadProfileReferencePresent: true,
                    finalRosterDigest: 'final-roster-digest',
                    frozenRosterProfileDigest: 'threshold-profile-digest',
                    lifecycleState: 'rosterFrozen',
                    receiverKeyCoverageComplete: true,
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    shareLayoutFrozen: true,
                    targetOutputLayoutFrozen: true,
                    trusteeSetupComplete: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'OpenVoting' });
    });

    it('refuses aggregate contribution before setup and turnout thresholds', () => {
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({ lifecycleState: 'votingOpen' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount: 19,
                    turnoutCount: thresholdProfile.releaseQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'setupIncomplete' });
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum - 1,
                }),
            ),
        ).toMatchObject({ reason: 'turnoutFloorNotReached' });
    });

    it('allows aggregate contribution once structural and bridge gates pass', () => {
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'aggregatePending',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum,
                    bridgeBenchmarkReportPresent: true,
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
                'VerifyBridgeProof',
                createContext({
                    bridgeBenchmarkReportPresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingBridgeBenchmarkReport' });
        expect(
            evaluateActionCapability(
                'VerifyBridgeProof',
                createContext({
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'OperationUnavailable' });
        expect(
            evaluateActionCapability(
                'VerifyOneShotSharePolicy',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
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
                createContext({ lifecycleState: 'topKEvaluated' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({ lifecycleState: 'evaluationProofPending' }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({
                    lifecycleState: 'evaluationProofPending',
                    targetFinalityAccepted: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'MissingEvaluationProofCertificate' });
        expect(
            evaluateActionCapability(
                'VerifyEvaluationProof',
                createContext({
                    lifecycleState: 'evaluationProofPending',
                    targetFinalityAccepted: true,
                    evaluationProofCertificatePresent: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'VerifyEvaluationProof' });
    });

    it('accepts a target only after finality and verified evaluation proof', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluationProofPending',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluationProofVerified',
                    evaluationProofVerified: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluationProofVerified',
                    targetFinalityAccepted: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluationProofMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluationProofVerified',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('keeps opt-in local replay behind accepted target evidence', () => {
        expect(
            evaluateActionCapability(
                'CreateLocalReplayDiagnostic',
                createContext({
                    lifecycleState: 'targetAccepted',
                    evaluationProofVerified: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetNotAccepted' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluation',
                createContext({
                    lifecycleState: 'targetAccepted',
                    targetAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluationProofMissing' });
        expect(
            evaluateActionCapability(
                'CreateLocalReplayDiagnostic',
                createContext({
                    lifecycleState: 'targetAccepted',
                    targetAccepted: true,
                    evaluationProofVerified: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'CreateLocalReplayDiagnostic' });
    });

    it('refuses decryption-share capability before accepted target evidence is complete', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({ lifecycleState: 'evaluationProofVerified' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({ lifecycleState: 'targetAccepted' }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'targetAccepted',
                    targetFinalityAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetNotAccepted' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'targetAccepted',
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
                    lifecycleState: 'targetAccepted',
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
                    lifecycleState: 'decryptionPending',
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
                'VerifyKllpsTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile,
                    kllpsCpadCertificatePresent: true,
                    decryptionShareCount: thresholdProfile.decryptionThreshold,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({
            reason: 'ThresholdDecryptionProfileNotCertified',
        });
        expect(
            evaluateActionCapability(
                'VerifyKllpsTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    kllpsCpadCertificatePresent: false,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'MissingKllpsCpadCertificate' });
    });

    it('allows CPAD verification and recombination only after mandatory profile checks pass', () => {
        expect(
            evaluateActionCapability(
                'VerifyKllpsTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    kllpsCpadCertificatePresent: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    thresholdDecryptionCertificatePresent: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'VerifyKllpsTargetDecryptionProfile',
        });
        expect(
            evaluateActionCapability(
                'VerifyKllpsTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    kllpsCpadCertificatePresent: true,
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
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    evaluationProofVerified: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    cpadProfileVerified: false,
                }),
            ),
        ).toMatchObject({ reason: 'KllpsCpadProfileNotVerified' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'cpadProfileVerified',
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
                    lifecycleState: 'cpadProfileVerified',
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

    it.each([3, 4, 5, 6, 7, 8, 9])(
        'refuses roster size %d casual micro-rosters but allows certified dynamic rosters through claim-bearing gates',
        (rosterSize) => {
            const casualThresholdProfile = deriveThresholdProfile({
                casualMicroRosterAcknowledged: true,
                rosterSize,
            });
            const dynamicThresholdProfile = deriveThresholdProfile({
                dynamicRosterProfileCertificateDigest,
                rosterSize: 16,
            });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'evaluationProofVerified',
                        thresholdProfile: casualThresholdProfile,
                        targetFinalityAccepted: true,
                        evaluationProofVerified: true,
                        bridgeBenchmarkReportPresent: true,
                    }),
                ),
            ).toMatchObject({ reason: 'ProfileNotClaimBearing' });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'evaluationProofVerified',
                        thresholdProfile: dynamicThresholdProfile,
                        targetFinalityAccepted: true,
                        evaluationProofVerified: true,
                        bridgeBenchmarkReportPresent: true,
                    }),
                ),
            ).toEqual({ allowed: true, action: 'AcceptTarget' });
        },
    );

    it('keeps measured runtime profiles as evidence, not browser-storage protocol gates', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluationProofVerified',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeBenchmarkReportPresent: true,
                    runtimeProfileSupported: false,
                }),
            ),
        ).toMatchObject({ reason: 'OutsideMeasuredRuntimeProfile' });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluationProofVerified',
                    targetFinalityAccepted: true,
                    evaluationProofVerified: true,
                    bridgeBenchmarkReportPresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('leaves verified top-k decoding unavailable in election foundation', () => {
        expect(
            evaluateActionCapability(
                'DecodeVerifiedTopK',
                createContext({
                    lifecycleState: 'fullyVerified',
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
