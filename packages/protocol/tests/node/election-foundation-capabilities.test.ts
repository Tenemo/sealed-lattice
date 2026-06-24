import type { CapabilityContext } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    dynamicRosterParametersCertificateHash,
    targetBoundShareSelectionParameters,
} from './election-foundation-fixture-constants.js';

import {
    deriveThresholdParameters,
    evaluateActionCapability,
} from '#packages/protocol/src/index';

const thresholdParameters = deriveThresholdParameters({ rosterSize: 10 });
const certifiedThresholdParameters = deriveThresholdParameters({
    rosterSize: 10,
    targetBoundShareSelectionParameters,
});

const createContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext => ({
    lifecycleState: 'draft',
    thresholdParameters,
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
        thresholdParameters: certifiedThresholdParameters,
        targetFinalityAccepted: true,
        targetAccepted: true,
        targetDecryptionCertificatePresent: true,
        ...overrides,
    });

describe('election foundation capability evaluator', () => {
    it('requires local roster acceptance for roster-bound direct actions', () => {
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    localRosterAccepted: false,
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                    turnoutCount: thresholdParameters.releaseQuorum,
                    directProofTransportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'LocalRosterNotAccepted' });
    });

    it('requires roster-bound action contexts to bind the local roster acceptance hash', () => {
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

    it('opens voting only after the frozen roster parameters and direct setup material are complete', () => {
        expect(
            evaluateActionCapability(
                'OpenVoting',
                createContext({
                    lifecycleState: 'rosterFrozen',
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'FrozenStateIncomplete' });

        expect(
            evaluateActionCapability(
                'OpenVoting',
                createContext({
                    finalRosterHash: 'final-roster-hash',
                    frozenRosterParametersHash: 'threshold-parameters-hash',
                    lifecycleState: 'rosterFrozen',
                    encryptedBallotLayoutFrozen: true,
                    ballotValidityProofParametersFrozen: true,
                    evaluatorReplayParametersFrozen: true,
                    targetOutputLayoutFrozen: true,
                    targetDecryptionParametersReferencePresent: true,
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
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
                        thresholdParameters.setupCompletionQuorum - 1,
                    turnoutCount: thresholdParameters.releaseQuorum,
                    directProofTransportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'setupIncomplete' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                    turnoutCount: thresholdParameters.releaseQuorum - 1,
                    directProofTransportPresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'turnoutFloorNotReached' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                    turnoutCount: thresholdParameters.releaseQuorum,
                }),
            ),
        ).toMatchObject({ reason: 'MissingDirectProofTransport' });
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                    turnoutCount: thresholdParameters.releaseQuorum,
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
        ).toMatchObject({ reason: 'TargetDecryptionParametersNotCertified' });
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

    it('verifies the target decryption parameters only after enough certified shares and certificate evidence', () => {
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionParameters',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters,
                    decryptionShareCount:
                        thresholdParameters.decryptionThreshold,
                    targetDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({
            reason: 'TargetDecryptionParametersNotCertified',
        });
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionParameters',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    decryptionShareCount:
                        (certifiedThresholdParameters.decryptionShareQuorum ??
                            0) - 1,
                    targetDecryptionCertificatePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'FirstThresholdSharesNotReached' });
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionParameters',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    decryptionShareCount:
                        certifiedThresholdParameters.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'MissingTargetDecryptionCertificate' });
        expect(
            evaluateActionCapability(
                'VerifyTargetDecryptionParameters',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    decryptionShareCount:
                        certifiedThresholdParameters.decryptionShareQuorum ?? 0,
                    targetDecryptionCertificatePresent: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'VerifyTargetDecryptionParameters',
        });
    });

    it('allows recombination only after target decryption parameters and closure evidence', () => {
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    decryptionShareCount:
                        certifiedThresholdParameters.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'TargetDecryptionParametersNotCertified' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    targetDecryptionParametersVerified: true,
                    decryptionShareCount:
                        certifiedThresholdParameters.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toMatchObject({ reason: 'TargetDecryptionClosureMissing' });
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    targetFinalityAccepted: true,
                    targetAccepted: true,
                    targetDecryptionParametersVerified: true,
                    targetDecryptionClosureApplied: true,
                    decryptionShareCount:
                        certifiedThresholdParameters.decryptionShareQuorum ?? 0,
                }),
            ),
        ).toEqual({ allowed: true, action: 'RecombineAcceptedTarget' });
    });

    it.each([3, 4, 5, 6, 7, 8, 9])(
        'no longer gates target acceptance on roster certification: casual micro-roster size %d and certified dynamic rosters both pass',
        (rosterSize) => {
            const casualThresholdParameters = deriveThresholdParameters({
                casualMicroRosterAcknowledged: true,
                rosterSize,
            });
            const dynamicThresholdParameters = deriveThresholdParameters({
                dynamicRosterParametersCertificateHash,
                rosterSize: 16,
                targetBoundShareSelectionParameters,
            });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'targetFinalityReached',
                        thresholdParameters: casualThresholdParameters,
                        targetFinalityAccepted: true,
                        evaluatorReplaySucceeded: true,
                    }),
                ),
            ).toEqual({ allowed: true, action: 'AcceptTarget' });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'targetFinalityReached',
                        thresholdParameters: dynamicThresholdParameters,
                        targetFinalityAccepted: true,
                        evaluatorReplaySucceeded: true,
                    }),
                ),
            ).toEqual({ allowed: true, action: 'AcceptTarget' });
        },
    );

    it('keeps measured runtime parameters as evidence, not browser-storage protocol gates', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    targetFinalityAccepted: true,
                    evaluatorReplaySucceeded: true,
                    runtimeParametersSupported: false,
                }),
            ),
        ).toMatchObject({ reason: 'OutsideMeasuredRuntimeParameters' });

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
