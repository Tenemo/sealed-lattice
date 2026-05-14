import type {
    CapabilityContext,
    CapabilityDecision,
    LifecycleState,
    ProtocolAction,
    RefusalReason,
    RecoveryState,
} from '@sealed-lattice/types';

import { isValidLifecycleTransition } from './lifecycle.js';
import { allowAction, refuseAction } from './refusal.js';

const claimBearingActions = new Set<ProtocolAction>([
    'DeriveAggregateContribution',
    'ReplayEvaluation',
    'AttestReplay',
    'AcceptTarget',
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'RecombineAcceptedTarget',
    'DecodeVerifiedTopK',
]);

const bridgeMobileCertificateActions = new Set<ProtocolAction>([
    'DeriveAggregateContribution',
    'ReplayEvaluation',
    'AttestReplay',
    'AcceptTarget',
]);

const oneShotDecryptionProofCertificateActions = new Set<ProtocolAction>([
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'RecombineAcceptedTarget',
    'DecodeVerifiedTopK',
]);

const countAtLeast = (actual: number | undefined, required: number): boolean =>
    actual !== undefined && actual >= required;

const getCertifiedDecryptionShareQuorum = (
    context: CapabilityContext,
): number | undefined =>
    context.thresholdProfile.decryptionShareQuorum ?? undefined;

const isRecoveryRefused = (
    recoveryState: RecoveryState | undefined,
): RefusalReason | undefined => {
    if (
        recoveryState === 'Ambiguous' ||
        recoveryState === 'MissingRecoveryMaterial'
    ) {
        return 'AmbiguousRecoveryState';
    }
    if (recoveryState === 'StaleEpoch') {
        return 'StaleRecoveryEpoch';
    }
    if (recoveryState === 'ClonedDeviceSuspected') {
        return 'ClonedDeviceState';
    }

    return undefined;
};

const lifecycleAllows = (
    context: CapabilityContext,
    to: LifecycleState,
): boolean =>
    isValidLifecycleTransition({
        from: context.lifecycleState,
        to,
    });

const evaluateLifecycleAction = (
    action: ProtocolAction,
    context: CapabilityContext,
    to: LifecycleState,
): CapabilityDecision =>
    lifecycleAllows(context, to)
        ? allowAction(action)
        : refuseAction(action, 'InvalidLifecycleState');

const evaluateAggregateContribution = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'VotingClosed' &&
        context.lifecycleState !== 'AwaitingAggregateContributors'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (
        !countAtLeast(
            context.setupCompleteCount,
            context.thresholdProfile.setupCompletionQuorum,
        )
    ) {
        return refuseAction(action, 'SetupIncomplete');
    }
    if (
        !countAtLeast(
            context.turnoutCount,
            context.thresholdProfile.releaseQuorum,
        )
    ) {
        return refuseAction(action, 'TurnoutBelowReleaseFloor');
    }
    if (context.bridgeMobileCertificatePresent !== true) {
        return refuseAction(action, 'MissingBridgeMobileCertificate');
    }
    if (context.bridgeProverCertificatePresent !== true) {
        return refuseAction(action, 'MissingBridgeProverCertificate');
    }

    return allowAction(action);
};

const evaluateReplay = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'TopKEvaluated' &&
        context.lifecycleState !== 'EvaluationReplayOpen'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.bridgeMobileCertificatePresent !== true) {
        return refuseAction(action, 'MissingBridgeMobileCertificate');
    }

    return allowAction(action);
};

const evaluateReplayAttestation = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'EvaluationReplayOpen') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.localReplaySucceeded !== true) {
        return refuseAction(action, 'LocalReplayNotVerified');
    }
    if (context.bridgeMobileCertificatePresent !== true) {
        return refuseAction(action, 'MissingBridgeMobileCertificate');
    }

    return allowAction(action);
};

const evaluateTargetAcceptance = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'EvaluationReplayOpen' &&
        context.lifecycleState !== 'EvaluationReplayAttested' &&
        context.lifecycleState !== 'OptionalEvaluationProofVerified'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (
        context.optionalEvaluationProofVerified !== true &&
        !countAtLeast(
            context.replayAttestationCount,
            context.thresholdProfile.evaluationReplayQuorum,
        )
    ) {
        return refuseAction(action, 'EvaluationReplayThresholdNotReached');
    }
    if (context.bridgeMobileCertificatePresent !== true) {
        return refuseAction(action, 'MissingBridgeMobileCertificate');
    }

    return allowAction(action);
};

const evaluateDecryptionShare = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'TargetAccepted') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.targetAccepted !== true) {
        return refuseAction(action, 'TargetNotAccepted');
    }
    if (getCertifiedDecryptionShareQuorum(context) === undefined) {
        return refuseAction(action, 'ShareSelectionProfileNotCertified');
    }

    const recoveryRefusal = isRecoveryRefused(context.recoveryState);
    if (recoveryRefusal !== undefined) {
        return refuseAction(action, recoveryRefusal);
    }
    if (context.oneShotDecryptionProofCertificatePresent !== true) {
        return refuseAction(action, 'MissingOneShotDecryptionProofCertificate');
    }

    return allowAction(action);
};

const evaluateRecombination = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'AwaitingFirstDecryptionShares' &&
        context.lifecycleState !== 'ResultComputedAuditable' &&
        context.lifecycleState !== 'FullyVerifiedResult'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetAccepted !== true) {
        return refuseAction(action, 'TargetNotAccepted');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    const certifiedDecryptionShareQuorum =
        getCertifiedDecryptionShareQuorum(context);
    if (certifiedDecryptionShareQuorum === undefined) {
        return refuseAction(action, 'ShareSelectionProfileNotCertified');
    }
    if (
        !countAtLeast(
            context.decryptionShareCount,
            certifiedDecryptionShareQuorum,
        )
    ) {
        return refuseAction(action, 'FirstThresholdSharesNotReached');
    }
    if (context.oneShotDecryptionProofCertificatePresent !== true) {
        return refuseAction(action, 'MissingOneShotDecryptionProofCertificate');
    }

    return allowAction(action);
};

const evaluateClaimBearingEnvironment = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision | undefined => {
    if (!claimBearingActions.has(action)) {
        return undefined;
    }
    if (context.mobileProfileSupported === false) {
        return refuseAction(action, 'UnsupportedMobileProfile');
    }
    if (context.storageQuotaSufficient === false) {
        return refuseAction(action, 'InsufficientStorageQuota');
    }

    return undefined;
};

const evaluateUnavailableFutureAction = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        bridgeMobileCertificateActions.has(action) &&
        context.bridgeMobileCertificatePresent === false
    ) {
        return refuseAction(action, 'MissingBridgeMobileCertificate');
    }
    if (
        oneShotDecryptionProofCertificateActions.has(action) &&
        context.oneShotDecryptionProofCertificatePresent === false
    ) {
        return refuseAction(action, 'MissingOneShotDecryptionProofCertificate');
    }

    return refuseAction(action, 'OperationUnavailable');
};

export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.browserSupported === false) {
        return refuseAction(action, 'UnsupportedBrowserContext');
    }
    if (!context.pollSpecValid) {
        return refuseAction(action, 'PollSpecInvalid');
    }
    if (
        claimBearingActions.has(action) &&
        !context.thresholdProfile.claimBearing
    ) {
        return refuseAction(action, 'ProfileNotClaimBearing');
    }

    const environmentRefusal = evaluateClaimBearingEnvironment(action, context);
    if (environmentRefusal !== undefined) {
        return environmentRefusal;
    }

    switch (action) {
        case 'CreatePoll':
            return context.lifecycleState === 'DraftPoll'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'OpenRegistration':
            return evaluateLifecycleAction(action, context, 'RegistrationOpen');
        case 'CreateRegistrationEntry':
            return context.lifecycleState === 'RegistrationOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CreateTrusteeSetupEntry':
            return context.lifecycleState === 'TrusteeSetupOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CloseRegistration':
            return evaluateLifecycleAction(
                action,
                context,
                'RegistrationClosed',
            );
        case 'FreezeRoster':
            return evaluateLifecycleAction(action, context, 'RosterFrozen');
        case 'OpenVoting':
            return evaluateLifecycleAction(action, context, 'VotingOpen');
        case 'SubmitVote':
            return context.lifecycleState === 'VotingOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CloseVoting':
            return evaluateLifecycleAction(action, context, 'VotingClosed');
        case 'DeriveAggregateContribution':
            return evaluateAggregateContribution(action, context);
        case 'ReplayEvaluation':
            return evaluateReplay(action, context);
        case 'AttestReplay':
            return evaluateReplayAttestation(action, context);
        case 'AcceptTarget':
            return evaluateTargetAcceptance(action, context);
        case 'CreateTargetBoundDecryptionShare':
            return evaluateDecryptionShare(action, context);
        case 'RecombineAcceptedTarget':
            return evaluateRecombination(action, context);
        case 'DecodeVerifiedTopK':
            return evaluateUnavailableFutureAction(action, context);
        case 'CreateRecoveryEpochUpdate':
            return refuseAction(action, 'OperationUnavailable');
        case 'VerifyDecryptionShare':
            return evaluateUnavailableFutureAction(action, context);
        case 'VerifyEncryptedEnvelope':
            return refuseAction(action, 'OperationUnavailable');
    }
};
