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
    isPollSpecValid: true,
    isLocalRosterAccepted: true,
    rosterExternalAcceptanceHash: 'accepted-roster-hash',
    actionContextRosterExternalAcceptanceHash: 'accepted-roster-hash',
    ...overrides,
});

const targetAcceptedContext = (
    overrides: Partial<CapabilityContext> = {},
): CapabilityContext =>
    createContext({
        lifecycleState: 'isTargetAccepted',
        thresholdParameters: certifiedThresholdParameters,
        isTargetFinalityAccepted: true,
        isTargetAccepted: true,
        isTargetDecryptionCertificatePresent: true,
        ...overrides,
    });

describe('election foundation capability evaluator', () => {
    it('requires local roster acceptance for roster-bound direct actions', () => {
        expect(
            evaluateActionCapability(
                'VerifyEncryptedBallotProofs',
                createContext({
                    lifecycleState: 'votingClosed',
                    isLocalRosterAccepted: false,
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                    turnoutCount: thresholdParameters.releaseQuorum,
                    isDirectProofTransportPresent: true,
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
                    isEncryptedBallotLayoutFrozen: true,
                    isBallotValidityProofParametersFrozen: true,
                    isEvaluatorReplayParametersFrozen: true,
                    isTargetOutputLayoutFrozen: true,
                    isTargetDecryptionParametersReferencePresent: true,
                    setupCompleteCount:
                        thresholdParameters.setupCompletionQuorum,
                    isTrusteeSetupComplete: true,
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
                    isDirectProofTransportPresent: true,
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
                    isDirectProofTransportPresent: true,
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
                    isDirectProofTransportPresent: true,
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
                    lifecycleState: 'isBallotProofsVerified',
                    isBallotProofsVerified: false,
                }),
            ),
        ).toMatchObject({ reason: 'BallotProofsMissing' });
        expect(
            evaluateActionCapability(
                'AggregateEncryptedBallots',
                createContext({
                    lifecycleState: 'isBallotProofsVerified',
                    isBallotProofsVerified: true,
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
                createContext({ lifecycleState: 'isBallotProofsVerified' }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({
                    lifecycleState: 'isEncryptedBallotAggregateComputed',
                    isEncryptedBallotAggregateComputed: false,
                    isMobileReplayEvidencePresent: true,
                }),
            ),
        ).toMatchObject({ reason: 'EncryptedBallotAggregateMissing' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({
                    lifecycleState: 'isEncryptedBallotAggregateComputed',
                    isEncryptedBallotAggregateComputed: true,
                    isMobileReplayEvidencePresent: false,
                }),
            ),
        ).toMatchObject({ reason: 'MissingMobileReplayEvidence' });
        expect(
            evaluateActionCapability(
                'ReplayEvaluator',
                createContext({
                    lifecycleState: 'isEncryptedBallotAggregateComputed',
                    isEncryptedBallotAggregateComputed: true,
                    isMobileReplayEvidencePresent: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'ReplayEvaluator' });
    });

    it('accepts a target only after evaluator replay and finality evidence', () => {
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'isEncryptedBallotAggregateComputed',
                }),
            ),
        ).toMatchObject({ reason: 'InvalidLifecycleState' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'evaluatorReplayed',
                    isEvaluatorReplaySucceeded: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    isTargetFinalityAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'EvaluatorReplayMissing' });
        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    isTargetFinalityAccepted: true,
                    isEvaluatorReplaySucceeded: true,
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
                createContext({ lifecycleState: 'isTargetAccepted' }),
            ),
        ).toMatchObject({ reason: 'TargetFinalityCheckpointMissing' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'isTargetAccepted',
                    isTargetFinalityAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetNotAccepted' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                createContext({
                    lifecycleState: 'isTargetAccepted',
                    isTargetFinalityAccepted: true,
                    isTargetAccepted: true,
                }),
            ),
        ).toMatchObject({ reason: 'TargetDecryptionParametersNotCertified' });
        expect(
            evaluateActionCapability(
                'CreateTargetBoundDecryptionShare',
                targetAcceptedContext({
                    isTargetDecryptionCertificatePresent: false,
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
                    isTargetDecryptionCertificatePresent: true,
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
                    isTargetDecryptionCertificatePresent: true,
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
                    isTargetDecryptionCertificatePresent: true,
                }),
            ),
        ).toEqual({
            allowed: true,
            action: 'VerifyTargetDecryptionParameters',
        });
    });

    it('allows recombination only after target decryption parameters and the share quorum', () => {
        expect(
            evaluateActionCapability(
                'RecombineAcceptedTarget',
                createContext({
                    lifecycleState: 'decryptionSharesReady',
                    thresholdParameters: certifiedThresholdParameters,
                    isTargetFinalityAccepted: true,
                    isTargetAccepted: true,
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
                    isTargetFinalityAccepted: true,
                    isTargetAccepted: true,
                    isTargetDecryptionParametersVerified: true,
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
                isCasualMicroRosterAcknowledged: true,
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
                        isTargetFinalityAccepted: true,
                        isEvaluatorReplaySucceeded: true,
                    }),
                ),
            ).toEqual({ allowed: true, action: 'AcceptTarget' });

            expect(
                evaluateActionCapability(
                    'AcceptTarget',
                    createContext({
                        lifecycleState: 'targetFinalityReached',
                        thresholdParameters: dynamicThresholdParameters,
                        isTargetFinalityAccepted: true,
                        isEvaluatorReplaySucceeded: true,
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
                    isTargetFinalityAccepted: true,
                    isEvaluatorReplaySucceeded: true,
                    isRuntimeParametersSupported: false,
                }),
            ),
        ).toMatchObject({ reason: 'OutsideMeasuredRuntimeParameters' });

        expect(
            evaluateActionCapability(
                'AcceptTarget',
                createContext({
                    lifecycleState: 'targetFinalityReached',
                    isTargetFinalityAccepted: true,
                    isEvaluatorReplaySucceeded: true,
                }),
            ),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });

    it('keeps reserved safe API actions fail-closed until their implementations exist', () => {
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
