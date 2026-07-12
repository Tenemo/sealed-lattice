import {
    createSetupPackageVerificationInput as createSetupPackageVerificationInputInternal,
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    deriveValidatedFirstValidOrder as deriveValidatedFirstValidOrderInternal,
    deriveFrozenRosterParameters as deriveFrozenRosterParametersInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    deriveThresholdParameters as deriveThresholdParametersInternal,
    deriveThresholdParametersHash as deriveThresholdParametersHashInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    verifyCastReceiptShell as verifyCastReceiptShellInternal,
    verifyCloseRecordShell as verifyCloseRecordShellInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    isActionCurrentForRecoveryEpoch as isActionCurrentForRecoveryEpochInternal,
    validatePollSpec as validatePollSpecInternal,
    verifyBoardConsistency as verifyBoardConsistencyInternal,
    verifyRecoveryEpochUpdate as verifyRecoveryEpochUpdateInternal,
    verifyRosterExternalAcceptance as verifyRosterExternalAcceptanceInternal,
    verifyRosterManifestTranscript as verifyRosterManifestTranscriptInternal,
} from '@sealed-lattice/protocol';
import type {
    SetupTransportedPublicKeyShareMaterial as ProtocolSetupTransportedPublicKeyShareMaterial,
    EvaluationKeyShareComponentMaterialChunkStream as ProtocolEvaluationKeyShareComponentMaterialChunkStream,
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
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    ProtocolHash,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    ThresholdParameters,
    ThresholdParametersInput,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    VerificationResult,
} from '@sealed-lattice/types';
import {
    foundationBoardCandidateObjectHash as foundationBoardCandidateObjectHashInternal,
    openFoundationBoardSession as openFoundationBoardSessionInternal,
    type BgvTargetDecryptionResultReleaseCompletion,
} from '@sealed-lattice/wasm';

import { loadTranscriptCoreKernel } from './kernel.js';
import {
    preparePrivateVssShareVerificationInputForKernel,
    prepareSetupPackageVerificationInputForKernel,
} from './setup-verification-input.js';

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
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FrozenRosterParameters,
    HeBackendCorruptionModel,
    InclusionProof,
    LifecycleState,
    LifecycleTransition,
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
    TargetProposal,
    ThresholdParameters,
    ThresholdParametersInput,
    ThresholdWarning,
    TrusteeSetupEntry,
    ValidatedFirstValidObject,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

declare const foundationBoardCandidateBrand: unique symbol;

/** An opaque carrier candidate issued only after the kernel's fixed verifier route accepts it. */
export type FoundationBoardCandidate = Readonly<{
    readonly [foundationBoardCandidateBrand]: true;
}>;

export type FoundationBoardIngestionLimits = Readonly<{
    maximumCarrierByteLength: number;
    maximumCarrierCount: number;
    maximumRetainedCarrierByteLength: number;
    maximumUnresolvedDependencyCount: number;
}>;

export type FoundationBoardSessionInput = Readonly<{
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    limits: FoundationBoardIngestionLimits;
    publicSetupSeedObjectHash?: Uint8Array;
    suiteIdentifier: Uint8Array;
    verifiedSetupSourceObjectHash?: Uint8Array;
}>;

export type FoundationBoardSessionState = 'active' | 'cancelled';

export type FoundationBoardSession = Readonly<{
    cancel(): void;
    ingest(
        canonicalCarrierBytes: Uint8Array,
    ): VerificationResult<FoundationBoardCandidate>;
    requireCompleteCarrierGraph(): VerificationResult<undefined>;
    state(): FoundationBoardSessionState;
}>;

type InternalFoundationBoardCandidate = Parameters<
    typeof foundationBoardCandidateObjectHashInternal
>[0];
type InternalFoundationBoardSession = Extract<
    ReturnType<typeof openFoundationBoardSessionInternal>,
    { readonly isValid: true }
>['value'];

const internalCandidates = new WeakMap<
    FoundationBoardCandidate,
    InternalFoundationBoardCandidate
>();

/** Returns a defensive copy of a genuine candidate's recomputed object hash. */
export const foundationBoardCandidateObjectHash = (
    candidate: FoundationBoardCandidate,
): Uint8Array => {
    const internalCandidate = internalCandidates.get(candidate);
    if (internalCandidate === undefined) {
        throw new TypeError(
            'The foundation board candidate was not issued by this SDK instance.',
        );
    }
    return foundationBoardCandidateObjectHashInternal(internalCandidate);
};

const wrapFoundationBoardSession = (
    internalSession: InternalFoundationBoardSession,
): FoundationBoardSession =>
    Object.freeze({
        cancel: (): void => {
            internalSession.cancel();
        },
        ingest: (
            canonicalCarrierBytes: Uint8Array,
        ): VerificationResult<FoundationBoardCandidate> => {
            const result = internalSession.ingest(canonicalCarrierBytes);
            if (!result.isValid) {
                return result;
            }
            const candidate = Object.freeze(
                Object.create(null) as FoundationBoardCandidate,
            );
            internalCandidates.set(candidate, result.value);
            return Object.freeze({ isValid: true, value: candidate });
        },
        requireCompleteCarrierGraph: (): VerificationResult<undefined> =>
            internalSession.requireCompleteCarrierGraph(),
        state: (): FoundationBoardSessionState => internalSession.state(),
    });

/** Opens the sole bounded board-ingestion session in the packaged Rust/WASM kernel. */
export const createFoundationBoardSession = async (
    configuration: FoundationBoardSessionInput,
): Promise<VerificationResult<FoundationBoardSession>> => {
    const kernel = await loadTranscriptCoreKernel();
    const result = openFoundationBoardSessionInternal({
        configuration,
        kernel,
    });
    return result.isValid
        ? Object.freeze({
              isValid: true,
              value: wrapFoundationBoardSession(result.value),
          })
        : result;
};

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

export const verifyBoardConsistency = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => verifyBoardConsistencyInternal(input);

export const verifyCastReceiptShell = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => verifyCastReceiptShellInternal(input);

export const verifyCloseRecordShell = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => verifyCloseRecordShellInternal(input);

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

    return kernel.verifyPrivateVssShareEnvelope(
        preparePrivateVssShareVerificationInputForKernel(kernel, input),
    );
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
