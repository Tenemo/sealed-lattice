import {
    deriveLifecycleLabels as deriveLifecycleLabelsInternal,
    deriveThresholdProfile as deriveThresholdProfileInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    validatePollSpec as validatePollSpecInternal,
} from './internal/protocol-shell/index.js';
import { loadTranscriptCoreKernel } from './kernel.js';
import type {
    CapabilityContext,
    CapabilityDecision,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleTransition,
    PollSpecValidation,
    ProtocolAction,
    ThresholdProfile,
    ThresholdProfileInput,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
} from './types.js';

export type {
    CanonicalError,
    CanonicalErrorCode,
    BaseClaimProfile,
    CapabilityContext,
    CapabilityDecision,
    DuplicateBallotPolicy,
    EvaluationProofMode,
    FailureStatusLabel,
    HeBackendCorruptionModel,
    GoldenTranscriptCoreFixture,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleState,
    LifecycleTransition,
    MalformedObjectFixture,
    ModeStatusLabel,
    MheSecurityStage,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    PrimaryStatusLabel,
    ProtocolAction,
    RecoveryState,
    RefusalReason,
    ResultClaimLabel,
    RosterProfileKind,
    ScoreDomain,
    ThresholdProfile,
    ThresholdProfileInput,
    ThresholdWarning,
    TiePolicy,
    TranscriptCoreMheSecurityStage,
    TranscriptCoreFixture,
    TranscriptCoreReplayFixture,
    TranscriptCoreStatusLabel,
    TranscriptCoreVerificationLabel,
    TranscriptCoreVerificationResult,
} from './types.js';

export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => deriveThresholdProfileInternal(input);

export const validatePollSpec = (input: unknown): PollSpecValidation =>
    validatePollSpecInternal(input);

export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => isValidLifecycleTransitionInternal(transition);

export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => deriveLifecycleLabelsInternal(input);

export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => evaluateActionCapabilityInternal(action, context);

export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreVerificationResult> => {
    const kernel = await loadTranscriptCoreKernel();
    const verification = kernel.verifyFixture(fixture);

    if ('expectedErrorCode' in verification) {
        return {
            caseName: verification.caseName,
            label: 'TranscriptCoreRejected',
            statusLabels: [],
            rejection: {
                code: verification.expectedErrorCode,
            },
        };
    }

    return {
        caseName: verification.caseName,
        label: 'TranscriptCoreVerified',
        objectHash512: verification.objectHash512,
        chunkRoot: verification.chunkRoot,
        statusLabels: verification.statusLabels,
    };
};
