import type { CapabilityContext } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    dynamicRosterProfileCertificateHash,
    targetBoundShareSelectionProfile,
} from './election-foundation-fixture-constants.js';

import {
    deriveThresholdProfile,
    evaluateActionCapability,
} from '#packages/protocol/src/index';

const thresholdProfile = deriveThresholdProfile({ rosterSize: 10 });
const certifiedThresholdProfile = deriveThresholdProfile({
    rosterSize: 10,
    targetBoundShareSelectionProfile,
});

const createContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext => ({
    lifecycleState: 'draft',
    thresholdProfile,
    pollSpecValid: true,
    localRosterAccepted: true,
    rosterExternalAcceptanceHash: 'accepted-roster-hash',
    actionContextRosterExternalAcceptanceHash: 'accepted-roster-hash',
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
        targetDecryptionCertificatePresent: true,
        ...overrides,
    });

describe('election foundation capability evaluator', () => {
    it('requires local roster acceptance for claim-bearing direct actions', () => {
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    localRosterAccepted: false,
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum,
                    directProofTransportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'LocalRosterNotAccepted' });
    });

    it('requires claim-bearing action contexts to bind the local roster acceptance hash', () => {
        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'votingOpen',
                    rosterExternalAcceptanceHash: undefined,
                    actionContextRosterExternalAcceptanceHash: undefined,
                }),
            ),
        ).toMatchObject({
            reason: 'RosterExternalAcceptanceHashMissing',
        });

        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'votingOpen',
                    rosterExternalAcceptanceHash: 'accepted-roster-hash',
                    actionContextRosterExternalAcceptanceHash: undefined,
                }),
            ),
        ).toMatchObject({
            reason: 'RosterExternalAcceptanceHashMissing',
        });

        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'votingOpen',
                    rosterExternalAcceptanceHash: 'accepted-roster-hash',
                    actionContextRosterExternalAcceptanceHash:
                        'different-roster-hash',
                }),
            ),
        ).toMatchObject({
            reason: 'RosterExternalAcceptanceHashMismatch',
        });

        expect(
            evaluateActionCapability(
                'SubmitVote',
                createContext({
                    lifecycleState: 'votingOpen',
                    rosterExternalAcceptanceHash: 'accepted-roster-hash',
                    actionContextRosterExternalAcceptanceHash:
                        'accepted-roster-hash',
                }),
            ),
        ).toEqual({ allowed: true, action: 'SubmitVote' });
    });

    it('opens voting only after the frozen roster profile and direct setup material are complete', () => {
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
                    finalRosterHash: 'final-roster-hash',
                    frozenRosterProfileHash: 'threshold-profile-hash',
                    lifecycleState: 'rosterFrozen',
                    encryptedBallotLayoutFrozen: true,
                    ballotValidityProofProfileFrozen: true,
                    evaluatorReplayProfileFrozen: true,
                    targetOutputLayoutFrozen: true,
                    targetDecryptionProfileReferencePresent: true,
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    trusteeSetupComplete: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'OpenVoting' });
    });

    it('verifies encrypted ballot proofs only after setup, turnout, and proof transport gates pass', () => {
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({ lifecycleState: 'votingOpen' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount:
                        thresholdProfile.setupCompletionQuorum - 1,
                    turnoutCount: thresholdProfile.releaseQuorum,
                    directProofTransportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'setupIncomplete' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum - 1,
                    directProofTransportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'turnoutFloorNotReached' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'MissingDirectProofTransport' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                    turnoutCount: thresholdProfile.releaseQuorum,
                    directProofTransportPresent: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'VerifyEncryptedBallotProofs',
        });
    });

    it('allows public encrypted ballot aggregation only after ballot proofs verify', () => {
        expect(
            evaluateActionCapability(
                'AggregateEncryptedBallots',
                createContext({ lifecycleState: 'votingClosed' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'AggregateEncryptedBallots',
                createContext({
                    lifecycleState: 'ballotProofsVerified',
                    ballotProofsVerified: false,
                }),
            ),
        ).toMatchObject({ reason: 'BallotProofsMissing' });
        expect(
            evaluateActionCapability(
                'AggregateEncryptedBallots',
                createContext({
                    lifecycleState: 'ballotProofsVerified',
                    ballotProofsVerified: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'AggregateEncryptedBallots',
        });
    });

    it('replays the evaluator only after the aggregate and mobile replay evidence are present', () => {
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({ lifecycleState: 'ballotProofsVerified' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({
                    lifecycleState: 'encryptedBallotAggregateComputed',
                    encryptedBallotAggregateComputed: false,
                    mobileReplayEvidencePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'EncryptedBallotAggregateMissing' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({
                    lifecycleState: 'encryptedBallotAggregateComputed',
                    encryptedBallotAggregateComputed: true,
                    mobileReplayEvidencePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingMobileReplayEvidence' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({
                    lifecycleState: 'encryptedBallotAggregateComputed',
                    encryptedBallotAggregateComputed: true,
                    mobileReplayEvidencePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'ReplayEvaluator' });
    });

    it('accepts a target only after evaluator replay and finality evidence', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'encryptedBallotAggregateComputed',
                }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluatorReplayed',
                    evaluatorReplaySucceeded: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    targetFinalityAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluatorReplayMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    targetFinalityAccepted: true,
                    evaluatorReplaySucceeded: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('refuses target-bound decryption shares before accepted target evidence is complete', () => {
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({ lifecycleState: 'evaluatorReplayed' }),
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
        ).toMatchObject({ reason: 'TargetDecryptionProfileNotCertified' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                targetAcceptedContext({
                    targetDecryptionCertificatePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingTargetDecryptionCertificate' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                targetAcceptedContext(),
            ),
        ).toEqual({
            allowed: true,
            action: 'CreateTargetBoundDecryptionShare',
        });
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

    it('verifies the target decryption profile only after enough certified shares and certificate evidence', () => {
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile,
                    decryptionShareCount: thresholdProfile.decryptionThreshold,
                    targetDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({
            reason: 'TargetDecryptionProfileNotCertified',
        });
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    decryptionShareCount:
                        (certifiedThresholdProfile.decryptionShareQuorum ?? 0) -
                        1,
                    targetDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'FirstThresholdSharesNotReached' });
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'MissingTargetDecryptionCertificate' });
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionProfile',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                    targetDecryptionCertificatePresent: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'VerifyTargetDecryptionProfile',
        });
    });

    it('allows recombination only after target decryption profile and closure evidence', () => {
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'TargetDecryptionProfileNotCertified' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    targetDecryptionProfileVerified: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'ClaimClosureMissing' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdProfile: certifiedThresholdProfile,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    targetDecryptionProfileVerified: true,
                    targetDecryptionClosureApplied: true,
                    decryptionShareCount:
                        certifiedThresholdProfile.decryptionShareQuorum ?? 0,
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
                dynamicRosterProfileCertificateHash,
                rosterSize: 16,
                targetBoundShareSelectionProfile,
            });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'targetFinalityReached',
                        thresholdProfile: casualThresholdProfile,
                        targetFinalityAccepted: true,
                        evaluatorReplaySucceeded: true,
                    }),
                ),
            ).toMatchObject({ reason: 'ProfileNotClaimBearing' });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'targetFinalityReached',
                        thresholdProfile: dynamicThresholdProfile,
                        targetFinalityAccepted: true,
                        evaluatorReplaySucceeded: true,
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
                    lifecycleState: 'targetFinalityReached',
                    targetFinalityAccepted: true,
                    evaluatorReplaySucceeded: true,
                    runtimeProfileSupported: false,
                }),
            ),
        ).toMatchObject({ reason: 'OutsideMeasuredRuntimeProfile' });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    targetFinalityAccepted: true,
                    evaluatorReplaySucceeded: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('keeps reserved safe API actions fail-closed until their implementations exist', () => {
        expect(
            evaluateActionCapability('VerifyTranscript', createContext()),
        ).toMatchObject({ reason: 'OperationUnavailable' });
        expect(
            evaluateActionCapability(
                'CreateRecoveryEpochUpdate',
                createContext(),
            ),
        ).toMatchObject({ reason: 'OperationUnavailable' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedEnvelope',
                createContext(),
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
