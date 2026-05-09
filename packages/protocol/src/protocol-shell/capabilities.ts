import { isValidLifecycleTransition } from './lifecycle.js';
import { allowAction, refuseAction } from './refusal.js';
import type {
    CapabilityContext,
    CapabilityDecision,
    LifecycleState,
    ProtocolAction,
    RefusalReason,
    RecoveryState,
} from './types.js';

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

const requiresValidPollSpec = (action: ProtocolAction): boolean =>
    action !== 'CreatePoll';

const countAtLeast = (actual: number | undefined, required: number): boolean =>
    actual !== undefined && actual >= required;

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
            context.thresholdProfile.qSetupComplete,
        )
    ) {
        return refuseAction(action, 'SetupIncomplete');
    }
    if (
        !countAtLeast(context.turnoutCount, context.thresholdProfile.qRelease)
    ) {
        return refuseAction(action, 'TurnoutBelowReleaseFloor');
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
        return refuseAction(action, 'EvaluationReplayThresholdNotReached');
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
            context.thresholdProfile.qEval,
        )
    ) {
        return refuseAction(action, 'EvaluationReplayThresholdNotReached');
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
    if (context.targetAccepted === false) {
        return refuseAction(action, 'TargetNotAccepted');
    }

    const recoveryRefusal = isRecoveryRefused(context.recoveryState);
    if (recoveryRefusal !== undefined) {
        return refuseAction(action, recoveryRefusal);
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
    if (context.targetAccepted === false) {
        return refuseAction(action, 'TargetNotAccepted');
    }
    if (
        !countAtLeast(
            context.decryptionShareCount,
            context.thresholdProfile.qDec,
        )
    ) {
        return refuseAction(action, 'FirstThresholdSharesNotReached');
    }

    return allowAction(action);
};

export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.browserSupported === false) {
        return refuseAction(action, 'UnsupportedBrowserContext');
    }
    if (requiresValidPollSpec(action) && !context.pollSpecValid) {
        return refuseAction(action, 'PollSpecInvalid');
    }
    if (
        claimBearingActions.has(action) &&
        !context.thresholdProfile.claimBearing
    ) {
        return refuseAction(action, 'UnsafeMicroRosterNotClaimBearing');
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
        case 'CreateRecoveryEpochUpdate':
        case 'VerifyDecryptionShare':
        case 'VerifyEncryptedEnvelope':
            return refuseAction(action, 'NotImplementedUntilLaterMilestone');
    }
};
