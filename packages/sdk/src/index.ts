import {
    deriveValidatedFirstComeOrder as deriveValidatedFirstComeOrderInternal,
    deriveLifecycleLabels as deriveLifecycleLabelsInternal,
    deriveThresholdProfile as deriveThresholdProfileInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    verifyCastReceiptShell as verifyCastReceiptShellInternal,
    verifyCloseRecordShell as verifyCloseRecordShellInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    isActionCurrentForRecoveryEpoch as isActionCurrentForRecoveryEpochInternal,
    validatePollSpecFromUnknown as validatePollSpecFromUnknownInternal,
    verifyBoardConsistency as verifyBoardConsistencyInternal,
    verifyFirstComePolicy as verifyFirstComePolicyInternal,
    verifyRecoveryEpochUpdate as verifyRecoveryEpochUpdateInternal,
    verifyRosterManifestTranscript as verifyRosterManifestTranscriptInternal,
    verifyTargetFinality as verifyTargetFinalityInternal,
} from '@sealed-lattice/protocol';
import type {
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    CastReceiptVerification,
    CastReceiptVerificationInput,
    CapabilityContext,
    CapabilityDecision,
    CloseRecordVerification,
    CloseRecordVerificationInput,
    FirstComeOrderingInput,
    FirstComeOrderingVerification,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    ThresholdProfile,
    ThresholdProfileInput,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
} from '@sealed-lattice/types';

import { loadTranscriptCoreKernel } from './kernel.js';

export type {
    AcceptedTargetFinalityCheckpoint,
    ActionContext,
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    AppendOnlyConsistencyProof,
    BaseClaimProfile,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    CanonicalError,
    CanonicalErrorCode,
    CanonicalSignedRootObject,
    CapabilityContext,
    CapabilityDecision,
    CastReceipt,
    CastReceiptVerification,
    CastReceiptVerificationInput,
    CloseRecord,
    CloseRecordKind,
    CloseRecordVerification,
    CloseRecordVerificationInput,
    ConflictingHeadEvidence,
    ConflictingManifestEvidence,
    DuplicateBallotPolicy,
    ElectionManifest,
    EvaluationProofMode,
    FailureStatusLabel,
    FirstComeOrderingInput,
    FirstComeOrderingVerification,
    GoldenTranscriptCoreFixture,
    GoldenTranscriptCoreFixtureVerification,
    HeBackendCorruptionModel,
    InclusionProof,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleState,
    LifecycleTransition,
    MalformedObjectFixture,
    MalformedObjectFixtureVerification,
    ManifestOpaqueBindings,
    ManifestPolicyDigests,
    MheSecurityStage,
    MlDsaSignatureMode,
    MlDsaSignatureProfile,
    ModeStatusLabel,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    PrimaryStatusLabel,
    ProtocolAction,
    ProtocolDigest,
    ProtocolObjectType,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    ProtocolVerificationStatusLabel,
    ReceiverKeyRegistration,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RecoveryState,
    RefusalReason,
    RefusalRecord,
    RegistrationEntry,
    ResultClaimLabel,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterProfileKind,
    ScoreDomain,
    SignatureVerificationResult,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    StructuredProtocolVerificationResult,
    TargetFinalityPolicy,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    ThresholdProfile,
    ThresholdProfileInput,
    ThresholdWarning,
    TiePolicy,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
    TranscriptCoreMheSecurityStage,
    TranscriptCoreReplayFixture,
    TranscriptCoreStatusLabel,
    TranscriptCoreVerificationLabel,
    TranscriptCoreVerificationResult,
    TrusteeSetupEntry,
    ValidatedFirstComeCandidate,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

/** Derives threshold, quorum, and warning parameters for a roster profile. */
export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => deriveThresholdProfileInternal(input);

/** Validates and normalizes a poll specification from trusted or untrusted input. */
export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecFromUnknownInternal(input);
}

/** Returns whether a lifecycle transition is part of the supported state graph. */
export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => isValidLifecycleTransitionInternal(transition);

/** Derives user-facing lifecycle, failure, and mode labels for one state. */
export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => deriveLifecycleLabelsInternal(input);

/** Evaluates whether a protocol action is allowed in the current context. */
export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => evaluateActionCapabilityInternal(action, context);

/** Verifies signed board heads, inclusion proofs, and append-only evidence. */
export const verifyBoardConsistency = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => verifyBoardConsistencyInternal(input);

/** Verifies the signed shell and inclusion evidence for a cast receipt. */
export const verifyCastReceiptShell = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => verifyCastReceiptShellInternal(input);

/** Verifies the signed shell and inclusion evidence for a close record. */
export const verifyCloseRecordShell = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => verifyCloseRecordShellInternal(input);

/** Verifies witness checkpoints and board evidence for a target finality record. */
export const verifyTargetFinality = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => verifyTargetFinalityInternal(input);

/** Derives the deterministic first-come order for validated candidates. */
export const deriveValidatedFirstComeOrder = (
    input: FirstComeOrderingInput,
): FirstComeOrderingVerification =>
    deriveValidatedFirstComeOrderInternal(input);

/** Verifies a first-come policy input and returns its deterministic ordering. */
export const verifyFirstComePolicy = (
    input: FirstComeOrderingInput,
): FirstComeOrderingVerification => verifyFirstComePolicyInternal(input);

/** Verifies roster freeze inputs, manifest evidence, and setup uniqueness. */
export const verifyRosterManifestTranscript = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification =>
    verifyRosterManifestTranscriptInternal(input);

/** Checks whether an action context is current for a signer recovery epoch. */
export const isActionCurrentForRecoveryEpoch = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult =>
    isActionCurrentForRecoveryEpochInternal(input);

/** Verifies a recovery epoch update and returns the accepted epoch entry. */
export const verifyRecoveryEpochUpdate = (
    input: RecoveryEpochVerificationInput,
): RecoveryEpochVerification => verifyRecoveryEpochUpdateInternal(input);

/** Verifies a transcript-core fixture with the packaged WASM kernel. */
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
