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
    'SubmitVote',
    'DeriveAggregateContribution',
    'CreateBridgeProof',
    'VerifyBridgeProof',
    'VerifyEvaluationProof',
    'AcceptTarget',
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'VerifyOneShotSharePolicy',
    'VerifyCPADProfile',
    'RecombineAcceptedTarget',
    'DecodeVerifiedTopK',
]);

const bridgeMobileCertificateActions = new Set<ProtocolAction>([
    'CreateBridgeProof',
    'VerifyBridgeProof',
    'DeriveAggregateContribution',
    'VerifyEvaluationProof',
    'AcceptTarget',
]);

const decryptionCertificateActions = new Set<ProtocolAction>([
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'VerifyOneShotSharePolicy',
    'VerifyCPADProfile',
    'RecombineAcceptedTarget',
    'DecodeVerifiedTopK',
]);

const countAtLeast = (actual: number | undefined, required: number): boolean =>
    actual !== undefined && actual >= required;

const getCertifiedDecryptionShareQuorum = (
    context: CapabilityContext,
): number | undefined => {
    if (context.thresholdProfile.targetBoundShareSelectionProfile === null) {
        return undefined;
    }

    return context.thresholdProfile.decryptionShareQuorum ?? undefined;
};

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

const evaluateEvaluationProof = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'TargetFinalityReached' &&
        context.lifecycleState !== 'EvaluationProofOpen'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.evaluationProofCertificatePresent !== true) {
        return refuseAction(action, 'MissingEvaluationProofCertificate');
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
    if (context.lifecycleState !== 'EvaluationProofVerified') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.evaluationProofVerified !== true) {
        return refuseAction(action, 'EvaluationProofMissing');
    }
    if (context.bridgeMobileCertificatePresent !== true) {
        return refuseAction(action, 'MissingBridgeMobileCertificate');
    }

    return allowAction(action);
};

const evaluateLocalReplay = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'TargetAccepted' &&
        context.lifecycleState !== 'AwaitingFirstDecryptionShares' &&
        context.lifecycleState !== 'FirstThresholdSharesReached' &&
        context.lifecycleState !== 'CPADProfileVerified' &&
        context.lifecycleState !== 'FullyVerifiedResult'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetAccepted !== true) {
        return refuseAction(action, 'TargetNotAccepted');
    }
    if (context.evaluationProofVerified !== true) {
        return refuseAction(action, 'EvaluationProofMissing');
    }

    return allowAction(action);
};

const evaluateDecryptionShare = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'TargetAccepted' &&
        context.lifecycleState !== 'AwaitingFirstDecryptionShares'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.targetAccepted !== true) {
        return refuseAction(action, 'TargetNotAccepted');
    }
    if (context.evaluationProofVerified !== true) {
        return refuseAction(action, 'EvaluationProofMissing');
    }
    if (getCertifiedDecryptionShareQuorum(context) === undefined) {
        return refuseAction(action, 'ThresholdDecryptionProfileNotCertified');
    }

    const recoveryRefusal = isRecoveryRefused(context.recoveryState);
    if (recoveryRefusal !== undefined) {
        return refuseAction(action, recoveryRefusal);
    }
    if (context.oneShotDecryptionProofCertificatePresent !== true) {
        return refuseAction(action, 'MissingOneShotDecryptionProofCertificate');
    }
    if (context.thresholdDecryptionCertificatePresent !== true) {
        return refuseAction(action, 'MissingThresholdDecryptionCertificate');
    }

    return allowAction(action);
};

const evaluateCPADProfile = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'FirstThresholdSharesReached') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.cpadCertificatePresent !== true) {
        return refuseAction(action, 'MissingCPADCertificate');
    }
    const certifiedDecryptionShareQuorum =
        getCertifiedDecryptionShareQuorum(context);
    if (certifiedDecryptionShareQuorum === undefined) {
        return refuseAction(action, 'ThresholdDecryptionProfileNotCertified');
    }
    if (
        !countAtLeast(
            context.decryptionShareCount,
            certifiedDecryptionShareQuorum,
        )
    ) {
        return refuseAction(action, 'FirstThresholdSharesNotReached');
    }
    if (context.thresholdDecryptionCertificatePresent !== true) {
        return refuseAction(action, 'MissingThresholdDecryptionCertificate');
    }

    return allowAction(action);
};

const evaluateRecombination = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'FirstThresholdSharesReached' &&
        context.lifecycleState !== 'CPADProfileVerified' &&
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
    if (context.evaluationProofVerified !== true) {
        return refuseAction(action, 'EvaluationProofMissing');
    }
    if (context.cpadProfileVerified !== true) {
        return refuseAction(action, 'CPADProfileNotVerified');
    }
    const certifiedDecryptionShareQuorum =
        getCertifiedDecryptionShareQuorum(context);
    if (certifiedDecryptionShareQuorum === undefined) {
        return refuseAction(action, 'ThresholdDecryptionProfileNotCertified');
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
    if (context.localRosterExternallyAccepted !== true) {
        return refuseAction(action, 'LocalRosterNotAccepted');
    }
    if (
        context.rosterExternalAcceptanceDigest === undefined ||
        context.rosterExternalAcceptanceDigest.length === 0 ||
        context.actionContextRosterExternalAcceptanceDigest === undefined ||
        context.actionContextRosterExternalAcceptanceDigest === null ||
        context.actionContextRosterExternalAcceptanceDigest.length === 0
    ) {
        return refuseAction(action, 'RosterExternalAcceptanceDigestMissing');
    }
    if (
        context.actionContextRosterExternalAcceptanceDigest !==
        context.rosterExternalAcceptanceDigest
    ) {
        return refuseAction(action, 'RosterExternalAcceptanceDigestMismatch');
    }
    if (!context.thresholdProfile.claimBearing) {
        return refuseAction(action, 'ProfileNotClaimBearing');
    }
    if (context.mobileProfileSupported === false) {
        return refuseAction(action, 'UnsupportedMobileProfile');
    }
    if (context.storageQuotaSufficient === false) {
        return refuseAction(action, 'InsufficientStorageQuota');
    }

    return undefined;
};

const nonEmptyDigest = (digest: string | undefined): boolean =>
    digest !== undefined && digest.length > 0;

const evaluateOpenVoting = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (!lifecycleAllows(context, 'VotingOpen')) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (!context.thresholdProfile.claimBearing) {
        return refuseAction(action, 'ProfileNotClaimBearing');
    }
    if (
        !nonEmptyDigest(context.finalRosterDigest) ||
        !nonEmptyDigest(context.frozenRosterProfileDigest) ||
        context.ballotProofProfileFrozen !== true ||
        context.shareLayoutFrozen !== true ||
        context.targetOutputLayoutFrozen !== true ||
        context.cpadProfileReferencePresent !== true
    ) {
        return refuseAction(action, 'ClaimClosureMissing');
    }
    if (
        context.receiverKeyCoverageComplete !== true ||
        context.trusteeSetupComplete !== true ||
        !countAtLeast(
            context.setupCompleteCount,
            context.thresholdProfile.setupCompletionQuorum,
        )
    ) {
        return refuseAction(action, 'SetupIncomplete');
    }
    if (context.localRosterExternallyAccepted !== true) {
        return refuseAction(action, 'LocalRosterNotAccepted');
    }

    return allowAction(action);
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
        decryptionCertificateActions.has(action) &&
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
            return evaluateOpenVoting(action, context);
        case 'SubmitVote':
            return context.lifecycleState === 'VotingOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CloseVoting':
            return evaluateLifecycleAction(action, context, 'VotingClosed');
        case 'VerifyTranscript':
            return evaluateUnavailableFutureAction(action, context);
        case 'DeriveAggregateContribution':
            return evaluateAggregateContribution(action, context);
        case 'CreateBridgeProof':
        case 'VerifyBridgeProof':
            return evaluateUnavailableFutureAction(action, context);
        case 'VerifyEvaluationProof':
            return evaluateEvaluationProof(action, context);
        case 'AcceptTarget':
            return evaluateTargetAcceptance(action, context);
        case 'ReplayEvaluation':
        case 'CreateLocalReplayRecord':
            return evaluateLocalReplay(action, context);
        case 'CreateTargetBoundDecryptionShare':
            return evaluateDecryptionShare(action, context);
        case 'VerifyCPADProfile':
            return evaluateCPADProfile(action, context);
        case 'RecombineAcceptedTarget':
            return evaluateRecombination(action, context);
        case 'DecodeVerifiedTopK':
            return evaluateUnavailableFutureAction(action, context);
        case 'CreateRecoveryEpochUpdate':
            return refuseAction(action, 'OperationUnavailable');
        case 'VerifyDecryptionShare':
        case 'VerifyOneShotSharePolicy':
            return evaluateUnavailableFutureAction(action, context);
        case 'VerifyEncryptedEnvelope':
            return refuseAction(action, 'OperationUnavailable');
        default:
            return refuseAction(action as ProtocolAction, 'ForbiddenOperation');
    }
};
