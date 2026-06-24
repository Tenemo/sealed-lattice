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

const rosterBoundActions = new Set<ProtocolAction>([
    'SubmitVote',
    'VerifyEncryptedBallotProofs',
    'AggregateEncryptedBallots',
    'ReplayEvaluator',
    'AcceptTarget',
    'CreateTargetBoundDecryptionShare',
    'VerifyDecryptionShare',
    'VerifyTargetDecryptionParameters',
    'RecombineAcceptedTarget',
    'DecodeVerifiedTopK',
]);

const countAtLeast = (actual: number | undefined, required: number): boolean =>
    actual !== undefined && actual >= required;

const getCertifiedDecryptionShareQuorum = (
    context: CapabilityContext,
): number | undefined => {
    if (
        context.thresholdParameters.targetBoundShareSelectionParameters === null
    ) {
        return undefined;
    }

    return context.thresholdParameters.decryptionShareQuorum ?? undefined;
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

const nonEmptyHash = (hash: string | undefined): boolean =>
    hash !== undefined && hash.length > 0;

const evaluateOpenVoting = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (!lifecycleAllows(context, 'votingOpen')) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (
        !nonEmptyHash(context.finalRosterHash) ||
        !nonEmptyHash(context.frozenRosterParametersHash) ||
        context.encryptedBallotLayoutFrozen !== true ||
        context.ballotValidityProofParametersFrozen !== true ||
        context.evaluatorReplayParametersFrozen !== true ||
        context.targetOutputLayoutFrozen !== true ||
        context.targetDecryptionParametersReferencePresent !== true
    ) {
        return refuseAction(action, 'FrozenStateIncomplete');
    }
    if (
        context.trusteeSetupComplete !== true ||
        !countAtLeast(
            context.setupCompleteCount,
            context.thresholdParameters.setupCompletionQuorum,
        )
    ) {
        return refuseAction(action, 'setupIncomplete');
    }
    if (context.localRosterAccepted !== true) {
        return refuseAction(action, 'LocalRosterNotAccepted');
    }

    return allowAction(action);
};

const evaluateEncryptedBallotProofs = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'votingClosed' &&
        context.lifecycleState !== 'encryptedBallotsSelected'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (
        !countAtLeast(
            context.setupCompleteCount,
            context.thresholdParameters.setupCompletionQuorum,
        )
    ) {
        return refuseAction(action, 'setupIncomplete');
    }
    if (
        !countAtLeast(
            context.turnoutCount,
            context.thresholdParameters.releaseQuorum,
        )
    ) {
        return refuseAction(action, 'turnoutFloorNotReached');
    }
    if (context.directProofTransportPresent !== true) {
        return refuseAction(action, 'MissingDirectProofTransport');
    }

    return allowAction(action);
};

const evaluateEncryptedBallotAggregation = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'ballotProofsVerified') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.ballotProofsVerified !== true) {
        return refuseAction(action, 'BallotProofsMissing');
    }

    return allowAction(action);
};

const evaluateEvaluatorReplay = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'encryptedBallotAggregateComputed') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.encryptedBallotAggregateComputed !== true) {
        return refuseAction(action, 'EncryptedBallotAggregateMissing');
    }
    if (context.mobileReplayEvidencePresent !== true) {
        return refuseAction(action, 'MissingMobileReplayEvidence');
    }

    return allowAction(action);
};

const evaluateTargetAcceptance = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'evaluatorReplayed' &&
        context.lifecycleState !== 'targetFinalityReached'
    ) {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    if (context.evaluatorReplaySucceeded !== true) {
        return refuseAction(action, 'EvaluatorReplayMissing');
    }
    if (context.targetFinalityAccepted !== true) {
        return refuseAction(action, 'TargetFinalityCheckpointMissing');
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
    if (getCertifiedDecryptionShareQuorum(context) === undefined) {
        return refuseAction(action, 'TargetDecryptionParametersNotCertified');
    }

    const recoveryRefusal = isRecoveryRefused(context.recoveryState);
    if (recoveryRefusal !== undefined) {
        return refuseAction(action, recoveryRefusal);
    }
    if (context.targetDecryptionCertificatePresent !== true) {
        return refuseAction(action, 'MissingTargetDecryptionCertificate');
    }

    return allowAction(action);
};

const evaluateTargetDecryptionParameters = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (context.lifecycleState !== 'decryptionSharesReady') {
        return refuseAction(action, 'InvalidLifecycleState');
    }
    const certifiedDecryptionShareQuorum =
        getCertifiedDecryptionShareQuorum(context);
    if (certifiedDecryptionShareQuorum === undefined) {
        return refuseAction(action, 'TargetDecryptionParametersNotCertified');
    }
    if (
        !countAtLeast(
            context.decryptionShareCount,
            certifiedDecryptionShareQuorum,
        )
    ) {
        return refuseAction(action, 'FirstThresholdSharesNotReached');
    }
    if (context.targetDecryptionCertificatePresent !== true) {
        return refuseAction(action, 'MissingTargetDecryptionCertificate');
    }

    return allowAction(action);
};

const evaluateRecombination = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (
        context.lifecycleState !== 'decryptionSharesReady' &&
        context.lifecycleState !== 'resultDecoded' &&
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
    if (context.targetDecryptionParametersVerified !== true) {
        return refuseAction(action, 'TargetDecryptionParametersNotCertified');
    }
    const certifiedDecryptionShareQuorum =
        getCertifiedDecryptionShareQuorum(context);
    if (certifiedDecryptionShareQuorum === undefined) {
        return refuseAction(action, 'TargetDecryptionParametersNotCertified');
    }
    if (
        !countAtLeast(
            context.decryptionShareCount,
            certifiedDecryptionShareQuorum,
        )
    ) {
        return refuseAction(action, 'FirstThresholdSharesNotReached');
    }
    if (context.targetDecryptionClosureApplied !== true) {
        return refuseAction(action, 'TargetDecryptionClosureMissing');
    }

    return allowAction(action);
};

const evaluateRosterBoundEnvironment = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision | undefined => {
    if (!rosterBoundActions.has(action)) {
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
    if (context.runtimeParametersSupported === false) {
        return refuseAction(action, 'OutsideMeasuredRuntimeParameters');
    }
    return undefined;
};

export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => {
    if (!context.pollSpecValid) {
        return refuseAction(action, 'PollSpecInvalid');
    }

    const environmentRefusal = evaluateRosterBoundEnvironment(action, context);
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
        case 'VerifyEncryptedBallotProofs':
            return evaluateEncryptedBallotProofs(action, context);
        case 'AggregateEncryptedBallots':
            return evaluateEncryptedBallotAggregation(action, context);
        case 'ReplayEvaluator':
            return evaluateEvaluatorReplay(action, context);
        case 'AcceptTarget':
            return evaluateTargetAcceptance(action, context);
        case 'CreateTargetBoundDecryptionShare':
        case 'VerifyDecryptionShare':
            return evaluateDecryptionShare(action, context);
        case 'VerifyTargetDecryptionParameters':
            return evaluateTargetDecryptionParameters(action, context);
        case 'RecombineAcceptedTarget':
            return evaluateRecombination(action, context);
        case 'DecodeVerifiedTopK':
            return evaluateRecombination(action, context);
        case 'VerifyTranscript':
        case 'CreateRecoveryEpochUpdate':
        case 'VerifyEncryptedEnvelope':
            return refuseAction(action, 'OperationUnavailable');
        default:
            return refuseAction(action, 'ForbiddenOperation');
    }
};
