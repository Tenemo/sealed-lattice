import {
    createSetupPackageVerificationInput as createSetupPackageVerificationInputInternal,
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    deriveValidatedFirstValidOrder as deriveValidatedFirstValidOrderInternal,
    deriveFrozenRosterParameters as deriveFrozenRosterParametersInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    deriveThresholdParameters as deriveThresholdParametersInternal,
    deriveThresholdParametersHash as deriveThresholdParametersHashInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    verifyFoundationTranscript as verifyFoundationTranscriptInternal,
    verifyCastReceiptShell as verifyCastReceiptShellInternal,
    verifyCloseRecordShell as verifyCloseRecordShellInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    isActionCurrentForRecoveryEpoch as isActionCurrentForRecoveryEpochInternal,
    validatePollSpec as validatePollSpecInternal,
    verifyBoardConsistency as verifyBoardConsistencyInternal,
    verifyRecoveryEpochUpdate as verifyRecoveryEpochUpdateInternal,
    verifyRosterExternalAcceptance as verifyRosterExternalAcceptanceInternal,
    verifyRosterManifestTranscript as verifyRosterManifestTranscriptInternal,
    verifyTargetFinality as verifyTargetFinalityInternal,
} from '@sealed-lattice/protocol';
import type {
    SetupTransportedPublicKeyShareMaterial as ProtocolSetupTransportedPublicKeyShareMaterial,
    EvaluationKeyShareComponentMaterialChunkStream as ProtocolEvaluationKeyShareComponentMaterialChunkStream,
    VerifiedSetupProofMaterial as ProtocolVerifiedSetupProofMaterial,
    VerifiedSetupProofMaterialSet as ProtocolVerifiedSetupProofMaterialSet,
    TransportedPublicKeyShareProofMaterialSet as ProtocolTransportedPublicKeyShareProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet as ProtocolTransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet as ProtocolTransportedSameSecretBridgeProofMaterialSet,
    TransportedEvaluationKeyAggregateBindingOpeningSet as ProtocolTransportedEvaluationKeyAggregateBindingOpeningSet,
    TransportedEvaluationKeyShareComponentMaterialSet as ProtocolTransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet as ProtocolTransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicEvaluationKeyMaterialSet as ProtocolTransportedPublicEvaluationKeyMaterialSet,
    SetupPackage as ProtocolSetupPackage,
    SetupPackageVerificationInputSource as ProtocolSetupPackageVerificationInputSource,
    CollectiveBgvSetupRosterEntryInput as ProtocolCollectiveBgvSetupRosterEntryInput,
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
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    ProtocolHash,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    ThresholdParameters,
    ThresholdParametersInput,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
} from '@sealed-lattice/types';
import type { BgvTargetDecryptionResultReleaseCompletion } from '@sealed-lattice/wasm';

import { loadTranscriptCoreKernel } from './kernel.js';
import { prepareSetupPackageVerificationInputForKernel } from './setup-verification-input.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;

function assertProtocolHash(
    value: unknown,
    fieldName: string,
): asserts value is ProtocolHash {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
}

const assertSetupPackageVerificationBindings = (
    input: VerifySetupPackageInput,
): void => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');
};

export type {
    AcceptedTargetFinalityCheckpoint,
    ActionContext,
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    TargetBoundShareSelectionParameters,
    AppendOnlyConsistencyProof,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    BoardEntryMerklePathStep,
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
    ElectionManifest,
    DecryptionShareFilteringMode,
    FoundationTranscriptComponentResults,
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FrozenRosterParameters,
    GoldenTranscriptCoreFixture,
    GoldenTranscriptCoreFixtureVerification,
    HeBackendCorruptionModel,
    InclusionProof,
    LifecycleState,
    LifecycleTransition,
    MalformedObjectFixture,
    MalformedObjectFixtureVerification,
    ManifestOpaqueBindings,
    ManifestPolicyHashes,
    MlDsaSignatureMode,
    MlDsaSignatureProfile,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    ProtocolAction,
    ProtocolHash,
    ProtocolObjectType,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RecoveryState,
    RefusalReason,
    RefusalRecord,
    RegistrationEntry,
    RosterExternalAcceptance,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterParametersKind,
    ScoreDomain,
    SignatureVerificationResult,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    SmallRosterPolicy,
    StructuredProtocolVerificationResult,
    TargetFinalityPolicy,
    TargetFinalityCheckpoint,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    TargetProposal,
    ThresholdParameters,
    ThresholdParametersInput,
    ThresholdWarning,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
    TranscriptCoreVerificationResult,
    TrusteeSetupEntry,
    ValidatedFirstValidObject,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

export type VerifyPrivateVssShareInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly privateEnvelope: unknown;
    readonly transportedPrivateVssShareProofMaterial?: unknown;
    readonly expectedPrivateEnvelopeHash?: ProtocolHash;
    readonly expectedLocalVerificationRoot?: ProtocolHash;
}>;

export type PrivateVssShareVerification = Readonly<{
    readonly isValid: boolean;
    readonly operation: 'verifyPrivateVssShareEnvelope';
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly ringDegree?: number;
    readonly limbVerifications: readonly Readonly<{
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly proofStatementRoot: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
    }>[];
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

export type SetupPackage = ProtocolSetupPackage;
export type CollectiveBgvSetupRosterEntryInput =
    ProtocolCollectiveBgvSetupRosterEntryInput;

export type VerifiedSetupProofMaterial = ProtocolVerifiedSetupProofMaterial;
export type VerifiedSetupProofMaterialSet =
    ProtocolVerifiedSetupProofMaterialSet;
export type SetupTransportedPublicKeyShareMaterial =
    ProtocolSetupTransportedPublicKeyShareMaterial;
export type TransportedPublicKeyShareProofMaterialSet =
    ProtocolTransportedPublicKeyShareProofMaterialSet;
export type TransportedVssShareLinkageProofMaterialSet =
    ProtocolTransportedVssShareLinkageProofMaterialSet;
export type TransportedSameSecretBridgeProofMaterialSet =
    ProtocolTransportedSameSecretBridgeProofMaterialSet;
export type TransportedEvaluationKeyShareProofMaterialSet =
    ProtocolTransportedEvaluationKeyShareProofMaterialSet;
export type TransportedEvaluationKeyShareComponentMaterialSet =
    ProtocolTransportedEvaluationKeyShareComponentMaterialSet;
export type TransportedEvaluationKeyAggregateBindingOpeningSet =
    ProtocolTransportedEvaluationKeyAggregateBindingOpeningSet;
export type EvaluationKeyShareComponentMaterialChunkStream =
    ProtocolEvaluationKeyShareComponentMaterialChunkStream;
export type TransportedPublicEvaluationKeyMaterialSet =
    ProtocolTransportedPublicEvaluationKeyMaterialSet;

export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial?: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial?: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    // Raw chunk bytes for the transported evaluation-key component material,
    // supplied out of band so the verifier streams each component through the
    // file-backed component material transport before the terminal setup package
    // verification. The terminal accepted-setup verifier refuses inline chunks on
    // the transported component material itself, so the bytes travel here.
    readonly evaluationKeyShareComponentMaterialChunkStreams?: readonly EvaluationKeyShareComponentMaterialChunkStream[];
    // Optional per-trustee batched linear-evaluation openings for the package
    // aggregate binding, forwarded to the kernel verbatim. The kernel runs the
    // committed-material aggregate binding only when the evaluation-key set
    // publishes an aggregateBinding; otherwise the openings are unused.
    readonly transportedEvaluationKeyAggregateBindingOpenings?: TransportedEvaluationKeyAggregateBindingOpeningSet;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
    readonly verifiedSetupProofMaterials?: VerifiedSetupProofMaterialSet;
}>;

export type SetupPackageVerificationInputSource = Readonly<
    Omit<ProtocolSetupPackageVerificationInputSource, 'setupPackage'> & {
        readonly setupPackage: SetupPackage;
    }
>;

export type AcceptedSetupHandoff = Readonly<{
    readonly objectType: 'CollectiveBgvAcceptedSetupHandoff';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly setupPackageHash: ProtocolHash;
    readonly directBallotEncryptionHandoff: Readonly<{
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    }>;
    readonly publicAggregationHandoff: Readonly<{
        readonly thresholdShareCommitmentRoot: ProtocolHash;
    }>;
    readonly boundedEvaluatorReplayHandoff: Readonly<{
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly trusteeEvaluationKeyProofSetRoot: ProtocolHash;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
    }>;
    readonly certificateRoots: Readonly<{
        readonly setupTransportCertificateHash: ProtocolHash;
    }>;
    readonly acceptedSetupHandoffRoot: ProtocolHash;
}>;

export type SetupPackageVerification = Readonly<{
    readonly isValid: boolean;
    readonly operation: 'verifyCollectiveBgvSetupPackage';
    readonly currentPhase: string | null;
    readonly phaseOrderHash: ProtocolHash;
    readonly acceptedSetupHandoff?: AcceptedSetupHandoff;
    readonly missingObjects: readonly string[];
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

// The target-decryption share proofs, accepted record, ciphertexts, and share
// profile are opaque protocol records that the kernel binds and recomputes; the
// SDK forwards them without a precise protocol type, matching how the protocol
// package itself types these target-decryption inputs.
export type TargetDecryptionResultReleaseInput = Readonly<{
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
    readonly releaseVerificationId: string;
    readonly shareProofs: readonly unknown[];
}>;

export type TargetDecryptionResultRelease =
    BgvTargetDecryptionResultReleaseCompletion;

export const deriveThresholdParameters = (
    input: ThresholdParametersInput,
): ThresholdParameters => deriveThresholdParametersInternal(input);

export const deriveFrozenRosterParameters =
    deriveFrozenRosterParametersInternal;

export const deriveCollectiveBgvSetupRosterHash = (
    entries: readonly CollectiveBgvSetupRosterEntryInput[],
): ProtocolHash => deriveCollectiveBgvSetupRosterHashInternal(entries);

export const derivePollSpecHash = derivePollSpecHashInternal;

export const deriveThresholdParametersHash =
    deriveThresholdParametersHashInternal;

export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecInternal(input);
}

export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => isValidLifecycleTransitionInternal(transition);

export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => evaluateActionCapabilityInternal(action, context);

export const verifyFoundationTranscript = (
    input: FoundationTranscriptInput,
): FoundationTranscriptVerification =>
    verifyFoundationTranscriptInternal(input);

export const verifyBoardConsistency = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => verifyBoardConsistencyInternal(input);

export const verifyCastReceiptShell = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => verifyCastReceiptShellInternal(input);

export const verifyCloseRecordShell = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => verifyCloseRecordShellInternal(input);

export const verifyTargetFinality = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => verifyTargetFinalityInternal(input);

export const deriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification =>
    deriveValidatedFirstValidOrderInternal(input);

export const verifyRosterExternalAcceptance = (
    input: RosterExternalAcceptanceVerificationInput,
): RosterExternalAcceptanceVerification =>
    verifyRosterExternalAcceptanceInternal(input);

export const verifyRosterManifestTranscript = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification =>
    verifyRosterManifestTranscriptInternal(input);

export const isActionCurrentForRecoveryEpoch = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult =>
    isActionCurrentForRecoveryEpochInternal(input);

export const verifyRecoveryEpochUpdate = (
    input: RecoveryEpochVerificationInput,
): RecoveryEpochVerification => verifyRecoveryEpochUpdateInternal(input);

export const verifyPrivateVssShare = async (
    input: VerifyPrivateVssShareInput,
): Promise<PrivateVssShareVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyPrivateVssShareEnvelope(input);
};

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): VerifySetupPackageInput =>
    createSetupPackageVerificationInputInternal(input);

export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    assertSetupPackageVerificationBindings(input);

    const kernel = await loadTranscriptCoreKernel();
    const verificationInput = prepareSetupPackageVerificationInputForKernel(
        kernel,
        input,
    );

    return kernel.verifyCollectiveBgvSetup(verificationInput);
};

/**
 * Drives the development-evidence staged target-decryption result release with
 * the packaged Rust/WASM kernel: derive the release setup context from the
 * accepted setup package, begin the staged session, absorb each trustee share
 * proof, then finish and return the released target result. Each stage is bound
 * and recomputed by the kernel; this path is development evidence, not certified
 * decryption.
 */
export const verifyTargetDecryptionResult = async (
    input: TargetDecryptionResultReleaseInput,
): Promise<TargetDecryptionResultRelease> => {
    const kernel = await loadTranscriptCoreKernel();
    const releaseSetupContext =
        kernel.deriveBgvTargetDecryptionResultReleaseSetupContext({
            setupPackage: input.setupPackage,
        });
    kernel.beginBgvTargetDecryptionResultRelease({
        releaseVerificationId: input.releaseVerificationId,
        releaseSetupContext,
        targetAcceptedRecord: input.targetAcceptedRecord,
        targetCiphertexts: input.targetCiphertexts,
        targetCiphertextBinding: input.targetCiphertextBinding,
        targetShareProfile: input.targetShareProfile,
    });
    for (const targetShareProof of input.shareProofs) {
        kernel.absorbBgvTargetDecryptionResultReleaseShare({
            releaseVerificationId: input.releaseVerificationId,
            targetShareProof,
        });
    }

    return kernel.finishBgvTargetDecryptionResultRelease({
        releaseVerificationId: input.releaseVerificationId,
    });
};

export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreVerificationResult> => {
    const kernel = await loadTranscriptCoreKernel();
    const verification = kernel.verifyFixture(fixture);

    if ('expectedErrorCode' in verification) {
        return {
            isValid: false,
            caseName: verification.caseName,
            rejection: {
                code: verification.expectedErrorCode,
            },
        };
    }

    return {
        isValid: true,
        caseName: verification.caseName,
        objectHash512: verification.objectHash512,
        chunkRoot: verification.chunkRoot,
    };
};
