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
    'VerifyBridgeProof',
    'VerifyEvaluationProof',
    'AcceptTarget',
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'VerifyOneShotSharePolicy',
    'VerifyKllpsTargetDecryptionProfile',
    'RecombineAcceptedTarget',
    'DecodeVerifiedTopK',
]);

const bridgeBenchmarkReportActions = new Set<ProtocolAction>([
    'VerifyBridgeProof',
    'DeriveAggregateContribution',
    'VerifyEvaluationProof',
    'AcceptTarget',
]);

const decryptionCertificateActions = new Set<ProtocolAction>([
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'VerifyOneShotSharePolicy',
    'VerifyKllpsTargetDecryptionProfile',
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
        context.lifecycleState !== 'votingClosed' &&
        context.lifecycleState !== 'aggregatePending'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (
        !countAtLeast(
            context.setupCompleteCount,
            context.thresholdProfile.setupCompletionQuorum,
        )
    ) {
        return refuseAction(action, 'setupIncomplete');
    }
    if (
        !countAtLeast(
            context.turnoutCount,
            context.thresholdProfile.releaseQuorum,
        )
    ) {
        return refuseAction(action, 'turnoutFloorNotReached');
    }
    if (context.bridgeBenchmarkReportPresent !== true) {
        return refuseAction(action, 'MissingBridgeBenchmarkReport');
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
        context.lifecycleState !== 'targetFinalityReached' &&
        context.lifecycleState !== 'evaluationProofPending'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.evaluationProofCertificatePresent !== true) {
        return refuseAction(action, 'MissingEvaluationProofCertificate');
    }
    if (context.bridgeBenchmarkReportPresent !== true) {
        return refuseAction(action, 'MissingBridgeBenchmarkReport');
    }

    return allowAction(action);
};

const evaluateTargetAcceptance = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'evaluationProofVerified') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
    }
    if (context.evaluationProofVerified !== true) {
        return refuseAction(action, 'EvaluationProofMissing');
    }
    if (context.bridgeBenchmarkReportPresent !== true) {
        return refuseAction(action, 'MissingBridgeBenchmarkReport');
    }

    return allowAction(action);
};

const evaluateLocalReplay = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'targetAccepted' &&
        context.lifecycleState !== 'decryptionPending' &&
        context.lifecycleState !== 'decryptionSharesReady' &&
        context.lifecycleState !== 'cpadProfileVerified' &&
        context.lifecycleState !== 'fullyVerified'
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
        context.lifecycleState !== 'targetAccepted' &&
        context.lifecycleState !== 'decryptionPending'
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

const evaluateKllpsCpadProfile = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'decryptionSharesReady') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.kllpsCpadCertificatePresent !== true) {
        return refuseAction(action, 'MissingKllpsCpadCertificate');
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
        context.lifecycleState !== 'decryptionSharesReady' &&
        context.lifecycleState !== 'cpadProfileVerified' &&
        context.lifecycleState !== 'fullyVerified'
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
        return refuseAction(action, 'KllpsCpadProfileNotVerified');
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
    if (context.localRosterAccepted !== true) {
        return refuseAction(action, 'LocalRosterNotAccepted');
    }
    if (
        context.rosterExternalAcceptanceHash === undefined ||
        context.rosterExternalAcceptanceHash.length === 0 ||
        context.actionContextRosterExternalAcceptanceHash === undefined ||
        context.actionContextRosterExternalAcceptanceHash === null ||
        context.actionContextRosterExternalAcceptanceHash.length === 0
    ) {
        return refuseAction(action, 'RosterExternalAcceptanceHashMissing');
    }
    if (
        context.actionContextRosterExternalAcceptanceHash !==
        context.rosterExternalAcceptanceHash
    ) {
        return refuseAction(action, 'RosterExternalAcceptanceHashMismatch');
    }
    if (!context.thresholdProfile.claimBearing) {
        return refuseAction(action, 'ProfileNotClaimBearing');
    }
    if (context.runtimeProfileSupported === false) {
        return refuseAction(action, 'OutsideMeasuredRuntimeProfile');
    }
    return undefined;
};

const nonEmptyHash = (hash: string | undefined): boolean =>
    hash !== undefined && hash.length > 0;

const evaluateOpenVoting = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (!lifecycleAllows(context, 'votingOpen')) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (!context.thresholdProfile.claimBearing) {
        return refuseAction(action, 'ProfileNotClaimBearing');
    }
    if (
        !nonEmptyHash(context.finalRosterHash) ||
        !nonEmptyHash(context.frozenRosterProfileHash) ||
        context.ballotProofProfileFrozen !== true ||
        context.shareLayoutFrozen !== true ||
        context.targetOutputLayoutFrozen !== true ||
        context.kllpsCpadProfileReferencePresent !== true
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
        return refuseAction(action, 'setupIncomplete');
    }
    if (context.localRosterAccepted !== true) {
        return refuseAction(action, 'LocalRosterNotAccepted');
    }

    return allowAction(action);
};

const evaluateUnavailableFutureAction = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        bridgeBenchmarkReportActions.has(action) &&
        context.bridgeBenchmarkReportPresent === false
    ) {
        return refuseAction(action, 'MissingBridgeBenchmarkReport');
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
    if (!context.pollSpecValid) {
        return refuseAction(action, 'PollSpecInvalid');
    }

    const environmentRefusal = evaluateClaimBearingEnvironment(action, context);
    if (environmentRefusal !== undefined) {
        return environmentRefusal;
    }

    switch (action) {
        case 'CreatePoll':
            return context.lifecycleState === 'draft'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'OpenRegistration':
            return evaluateLifecycleAction(action, context, 'registrationOpen');
        case 'CreateRegistrationEntry':
            return context.lifecycleState === 'registrationOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CreateTrusteeSetupEntry':
            return context.lifecycleState === 'trusteeSetupOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CloseRegistration':
            return evaluateLifecycleAction(
                action,
                context,
                'registrationClosed',
            );
        case 'FreezeRoster':
            return evaluateLifecycleAction(action, context, 'rosterFrozen');
        case 'OpenVoting':
            return evaluateOpenVoting(action, context);
        case 'SubmitVote':
            return context.lifecycleState === 'votingOpen'
                ? allowAction(action)
                : refuseAction(action, 'InvalidLifecycleState');
        case 'CloseVoting':
            return evaluateLifecycleAction(action, context, 'votingClosed');
        case 'VerifyTranscript':
            return evaluateUnavailableFutureAction(action, context);
        case 'DeriveAggregateContribution':
            return evaluateAggregateContribution(action, context);
        case 'VerifyBridgeProof':
            return evaluateUnavailableFutureAction(action, context);
        case 'VerifyEvaluationProof':
            return evaluateEvaluationProof(action, context);
        case 'AcceptTarget':
            return evaluateTargetAcceptance(action, context);
        case 'ReplayEvaluation':
        case 'CreateLocalReplayDiagnostic':
            return evaluateLocalReplay(action, context);
        case 'CreateTargetBoundDecryptionShare':
            return evaluateDecryptionShare(action, context);
        case 'VerifyKllpsTargetDecryptionProfile':
            return evaluateKllpsCpadProfile(action, context);
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
