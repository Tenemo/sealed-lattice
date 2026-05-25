import {
    deriveValidatedFirstValidOrder as deriveValidatedFirstValidOrderInternal,
    deriveLifecycleLabels as deriveLifecycleLabelsInternal,
    deriveFrozenRosterProfile as deriveFrozenRosterProfileInternal,
    derivePollSpecDigest as derivePollSpecDigestInternal,
    deriveThresholdProfile as deriveThresholdProfileInternal,
    deriveThresholdProfileDigest as deriveThresholdProfileDigestInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    verifyCastReceiptShell as verifyCastReceiptShellInternal,
    verifyCloseRecordShell as verifyCloseRecordShellInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    isActionCurrentForRecoveryEpoch as isActionCurrentForRecoveryEpochInternal,
    validatePollSpec as validatePollSpecInternal,
    verifyBoardConsistency as verifyBoardConsistencyInternal,
    verifyFirstValidPolicy as verifyFirstValidPolicyInternal,
    verifyRecoveryEpochUpdate as verifyRecoveryEpochUpdateInternal,
    verifyRosterExternalAcceptance as verifyRosterExternalAcceptanceInternal,
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
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FutureProtocolOperationResult,
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
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
} from '@sealed-lattice/types';
import type {
    BallotPrivacyKernelVerification,
    BallotPrivacyProofBackendStatus,
    TranscriptCoreKernel,
} from '@sealed-lattice/wasm';

import { loadTranscriptCoreKernel } from './kernel.js';

export type {
    AcceptedTargetFinalityCheckpoint,
    ActionContext,
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    AggregateDerivationComponent,
    AggregateDerivationPackageReference,
    AggregateDerivationProofRecord,
    AggregateDerivationProofVerificationInput,
    AggregateDerivationStatement,
    AggregateDerivationVerification,
    AggregateShareCommitment,
    TargetBoundShareSelectionProfile,
    AppendOnlyConsistencyProof,
    BaseClaimProfile,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    BoardEntryMerklePathStep,
    BallotPrivacyRosterProfileEvidence,
    BallotPrivacyVerification,
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    BallotProofComponentProofStatementFormat,
    BallotProofComponentProofVerificationInput,
    BallotProofRecord,
    BallotProofReceiverPayloadReference,
    BallotProofReceiverPublicKeyReference,
    BallotProofShareCommitmentReference,
    BallotProofStatement,
    CanonicalError,
    CanonicalErrorCode,
    CanonicalSignedRootObject,
    ClaimBearingBallotPackage,
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
    DecryptionShareFilteringMode,
    DecryptionShareSelectionRule,
    EvaluationProofMode,
    FailureStatusLabel,
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FrozenRosterProfile,
    FutureProtocolOperationResult,
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
    MheSecurityClosure,
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
    ReceiverKeyProof,
    ReceiverKeyProofRootEvidence,
    ReceiverEncryptionPublicKey,
    ReceiverPayload,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RecoveryState,
    RefusalReason,
    RefusalRecord,
    RegistrationEntry,
    ResultClaimLabel,
    RosterExternalAcceptance,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterProfileKind,
    RosterPolicy,
    ScoreDomain,
    SignatureVerificationResult,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    ShareCommitment,
    SmallRosterPolicy,
    StructuredProtocolVerificationResult,
    TargetFinalityPolicy,
    TargetFinalityCheckpoint,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    TargetProposal,
    ThresholdProfile,
    ThresholdProfileClaimBoundary,
    ThresholdProfileFamily,
    ThresholdProfileInput,
    ThresholdWarning,
    TiePolicy,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
    TranscriptCoreMheSecurityClosure,
    TranscriptCoreReplayFixture,
    TranscriptCoreStatusLabel,
    TranscriptCoreVerificationLabel,
    TranscriptCoreVerificationResult,
    TrusteeSetupEntry,
    ValidatedFirstValidObject,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';
export type {
    BallotPrivacyKernelVerification,
    BallotPrivacyProofBackendStatus,
};

/** Derives threshold, quorum, and warning parameters for a roster profile. */
export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => deriveThresholdProfileInternal(input);

/** Derives the concrete roster profile after registration closes and the roster freezes. */
export const deriveFrozenRosterProfile = deriveFrozenRosterProfileInternal;

/** Derives the canonical poll-spec digest including roster policy fields. */
export const derivePollSpecDigest = derivePollSpecDigestInternal;

/** Derives the canonical threshold-profile digest for a frozen roster profile. */
export const deriveThresholdProfileDigest =
    deriveThresholdProfileDigestInternal;

/** Validates and normalizes a poll specification from trusted or untrusted input. */
export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecInternal(input);
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

const unavailableFutureProtocolOperation = (
    operation: string,
): FutureProtocolOperationResult => ({
    ok: false,
    statusLabels: [],
    acceptedDigests: [],
    refusedObjects: [
        {
            code: 'OperationUnavailable',
            message: `${operation} is reserved for later protocol implementation and is not implemented in this package build.`,
        },
    ],
    unresolvedReason: 'OperationUnavailable',
    operation,
});

/** Reserved transcript verifier entry point for the future complete protocol path. */
export const verifyTranscript = (): FutureProtocolOperationResult =>
    unavailableFutureProtocolOperation('verifyTranscript');

/** Reserved bridge-proof verification entry point for the future aggregate path. */
export const verifyBridgeProof = (): FutureProtocolOperationResult =>
    unavailableFutureProtocolOperation('verifyBridgeProof');

/** Reserved one-shot decryption-share policy verifier for the future target path. */
export const verifyOneShotSharePolicy = (): FutureProtocolOperationResult =>
    unavailableFutureProtocolOperation('verifyOneShotSharePolicy');

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

/** Derives the deterministic first-valid order for validated objects. */
export const deriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification =>
    deriveValidatedFirstValidOrderInternal(input);

/** Verifies a first-valid policy input and returns its deterministic ordering. */
export const verifyFirstValidPolicy = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification => verifyFirstValidPolicyInternal(input);

/** Verifies one participant's local acceptance of the frozen public roster. */
export const verifyRosterExternalAcceptance = (
    input: RosterExternalAcceptanceVerificationInput,
): RosterExternalAcceptanceVerification =>
    verifyRosterExternalAcceptanceInternal(input);

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

/** Input accepted by the packaged WASM receiver-key proof verifier. */
export type ReceiverKeyProofVerificationInput = Parameters<
    TranscriptCoreKernel['verifyReceiverKeyProof']
>[0];

/** Input accepted by the packaged WASM ballot proof verifier. */
export type BallotProofVerificationInput = Parameters<
    TranscriptCoreKernel['verifyBallotProof']
>[0];

/** Input accepted by the packaged WASM scoped relation-bearing ballot package verifier. */
export type ClaimBearingBallotPackageVerificationInput = Parameters<
    TranscriptCoreKernel['verifyClaimBearingBallotPackage']
>[0];

/** Input accepted by the packaged WASM aggregate derivation component checker. */
export type AggregateDerivationComponentVerificationInput = Parameters<
    TranscriptCoreKernel['verifyAggregateDerivationProof']
>[0];

/** Verifies a receiver-key proof with the packaged WASM proof backend. */
export const verifyReceiverKeyProof = async (
    input: ReceiverKeyProofVerificationInput,
): Promise<BallotPrivacyKernelVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyReceiverKeyProof(input);
};

/** Verifies a ballot proof record with the packaged WASM proof backend. */
export const verifyBallotProof = async (
    input: BallotProofVerificationInput,
): Promise<BallotPrivacyKernelVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyBallotProof(input);
};

/** Verifies a proof-byte-bearing scoped relation-bearing ballot package with the packaged WASM proof backend. */
export const verifyClaimBearingBallotPackage = async (
    input: ClaimBearingBallotPackageVerificationInput,
): Promise<BallotPrivacyKernelVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyClaimBearingBallotPackage(input);
};

/** Checks an aggregate derivation component with the packaged WASM backend. */
export const verifyAggregateDerivationComponent = async (
    input: AggregateDerivationComponentVerificationInput,
): Promise<BallotPrivacyKernelVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyAggregateDerivationProof(input);
};
