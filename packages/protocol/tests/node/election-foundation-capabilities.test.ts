import type { CapabilityContext } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveThresholdProfile,
    evaluateActionCapability,
} from '../../src/index';

const appendixCShareSelectionProfile = {
    profileId: 'appendix-c-certified-first-valid-v1',
    certificateDigest: 'appendix-c-certificate-digest',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
    selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
} as const;

const thresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const certifiedThresholdProfile = deriveThresholdProfile({
    rosterSize: 20,
    appendixCShareSelectionProfile,
});

const createContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext => ({
    lifecycleState: 'DraftPoll',
    thresholdProfile,
    pollSpecValid: true,
    browserSupported: true,
    ...overrides,
});

describe('election foundation capability evaluator', () => {
    it('refuses aggregate contribution before voting is closed', () => {
        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({ lifecycleState: 'VotingOpen' }),
            ),
        ).toEqual({
            allowed: false,
            action: 'DeriveAggregateContribution',
            reason: 'InvalidLifecycleState',
        });
    });

    it('refuses aggregate contribution before setup and turnout thresholds', () => {
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

    it('allows aggregate contribution once structural gates pass', () => {
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

    it('refuses replay and attestation without target finality', () => {
        expect(
            evaluateActionCapability(
                'ReplayEvaluation',
                createContext({ lifecycleState: 'TopKEvaluated' }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'AttestReplay',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    localReplaySucceeded: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
    });

    it('refuses replay attestation without local replay success', () => {
        expect(
            evaluateActionCapability(
                'AttestReplay',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    targetFinalityAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'LocalReplayNotVerified' });
    });

    it('refuses create poll when the poll spec is invalid', () => {
        expect(
            evaluateActionCapability(
                'CreatePoll',
                createContext({ pollSpecValid: false }),
            ),
        ).toMatchObject({ reason: 'PollSpecInvalid' });
    });

    it('enforces target acceptance attestation threshold or optional proof', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    targetFinalityAccepted: true,
                    replayAttestationCount:
                        thresholdProfile.evaluationReplayQuorum - 1,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluationReplayThresholdNotReached' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    targetFinalityAccepted: true,
                    replayAttestationCount:
                        thresholdProfile.evaluationReplayQuorum,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'OptionalEvaluationProofVerified',
                    targetFinalityAccepted: true,
                    optionalEvaluationProofVerified: true,
                    bridgeMobileCertificatePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('refuses decryption-share capability before target acceptance or finality', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({ lifecycleState: 'EvaluationReplayAttested' }),
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
                    createContext({
                        lifecycleState: 'TargetAccepted',
                        thresholdProfile: certifiedThresholdProfile,
                        targetFinalityAccepted: true,
                        targetAccepted: true,
                        recoveryState,
                        oneShotDecryptionProofCertificatePresent: true,
                    }),
                ),
            ).toMatchObject({ reason });
        },
    );

    it('requires accepted target evidence before recombination', () => {
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'AwaitingFirstDecryptionShares',
                    thresholdProfile: certifiedThresholdProfile,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'TargetNotAccepted' });
    });

    it('requires target finality before recombination', () => {
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'AwaitingFirstDecryptionShares',
                    thresholdProfile: certifiedThresholdProfile,
                    targetAccepted: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
    });

    it('requires an Appendix-C-certified share-selection profile before decryption and recombination', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'ShareSelectionProfileNotCertified' });

        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'AwaitingFirstDecryptionShares',
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    decryptionShareCount: 9,
                }),
            ),
        ).toMatchObject({ reason: 'ShareSelectionProfileNotCertified' });
    });

    it('refuses recombination until the first threshold shares are reached', () => {
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'AwaitingFirstDecryptionShares',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    decryptionShareCount:
                        (certifiedThresholdProfile.decryptionShareQuorum ?? 0) -
                        1,
                }),
            ),
        ).toMatchObject({ reason: 'FirstThresholdSharesNotReached' });
    });

    it('keeps non-claim-bearing profiles out of claim-bearing capabilities', () => {
        const unsafeThresholdProfile = deriveThresholdProfile({
            rosterSize: 19,
            unsafeMicroRosterAcknowledged: true,
        });
        const certificateGatedThresholdProfile = deriveThresholdProfile({
            rosterSize: 21,
        });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    thresholdProfile: unsafeThresholdProfile,
                    targetFinalityAccepted: true,
                    replayAttestationCount:
                        unsafeThresholdProfile.evaluationReplayQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'ProfileNotClaimBearing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    thresholdProfile: certificateGatedThresholdProfile,
                    targetFinalityAccepted: true,
                    replayAttestationCount:
                        certificateGatedThresholdProfile.evaluationReplayQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'ProfileNotClaimBearing' });
    });

    it('refuses claim-bearing capabilities when mobile environment gates fail', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    targetFinalityAccepted: true,
                    replayAttestationCount:
                        thresholdProfile.evaluationReplayQuorum,
                    mobileProfileSupported: false,
                }),
            ),
        ).toMatchObject({ reason: 'UnsupportedMobileProfile' });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'EvaluationReplayOpen',
                    targetFinalityAccepted: true,
                    replayAttestationCount:
                        thresholdProfile.evaluationReplayQuorum,
                    storageQuotaSufficient: false,
                }),
            ),
        ).toMatchObject({ reason: 'InsufficientStorageQuota' });
    });

    it('refuses bridge and one-shot decryption paths when required mobile certificates are missing', () => {
        expect(
            evaluateActionCapability(
                'ReplayEvaluation',
                createContext({
                    lifecycleState: 'TopKEvaluated',
                    targetFinalityAccepted: true,
                    bridgeMobileCertificatePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingBridgeMobileCertificate' });

        expect(
            evaluateActionCapability(
                'DeriveAggregateContribution',
                createContext({
                    lifecycleState: 'VotingClosed',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum,
                    bridgeMobileCertificatePresent: true,
                    bridgeProverCertificatePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingBridgeProverCertificate' });

        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'TargetAccepted',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    oneShotDecryptionProofCertificatePresent: false,
                }),
            ),
        ).toMatchObject({
            reason: 'MissingOneShotDecryptionProofCertificate',
        });
    });

    it('leaves verified top-k decoding unavailable in election foundation', () => {
        expect(
            evaluateActionCapability(
                'DecodeVerifiedTopK',
                createContext({
                    lifecycleState: 'FullyVerifiedResult',
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'OperationUnavailable' });
    });
});
