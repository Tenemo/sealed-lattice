import {
    createSetupPackageVerificationInput as createSetupPackageVerificationInputInternal,
    deriveValidatedFirstValidOrder as deriveValidatedFirstValidOrderInternal,
    deriveFrozenRosterProfile as deriveFrozenRosterProfileInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    deriveThresholdProfile as deriveThresholdProfileInternal,
    deriveThresholdProfileHash as deriveThresholdProfileHashInternal,
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
    SetupTransportedVssCoefficientCommitmentMaterialLike as ProtocolSetupTransportedVssCoefficientCommitmentMaterialLike,
    VerifiedVssCoefficientCommitmentMaterial as ProtocolVerifiedVssCoefficientCommitmentMaterial,
    VerifiedSetupProofMaterial as ProtocolVerifiedSetupProofMaterial,
    VerifiedSetupProofMaterialSet as ProtocolVerifiedSetupProofMaterialSet,
    TransportedSameSecretProofMaterialSet as ProtocolTransportedSameSecretProofMaterialSet,
    TransportedPublicKeyShareProofMaterialSet as ProtocolTransportedPublicKeyShareProofMaterialSet,
    TransportedEvaluationKeyShareComponentMaterialSet as ProtocolTransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet as ProtocolTransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicEvaluationKeyMaterialSet as ProtocolTransportedPublicEvaluationKeyMaterialSet,
    SetupPackage as ProtocolSetupPackage,
    SetupPackageVerificationInputSource as ProtocolSetupPackageVerificationInputSource,
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
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    ProtocolHash,
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
import type { TranscriptCoreKernel } from '@sealed-lattice/wasm';

import { loadTranscriptCoreKernel } from './kernel.js';

export type {
    AcceptedTargetFinalityCheckpoint,
    ActionContext,
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    TargetBoundShareSelectionProfile,
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
    FrozenRosterProfile,
    FutureProtocolOperationResult,
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
    RosterProfileKind,
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
    ThresholdProfile,
    ThresholdProfileInput,
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

type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly qShareHash: ProtocolHash;
    readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
    readonly commitmentProfileHash: ProtocolHash;
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
    readonly ok: boolean;
    readonly operation: 'verifyPrivateVssShareEnvelope';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verifierStatus: 'accepted' | 'refused';
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly ringDegree?: number;
    readonly ringDegreeStatus?: 'profile-ring' | 'development-reduced-ring';
    readonly verifiedRnsLimbCount?: number;
    readonly verifiedShamirCoefficientCommitmentCount?: number;
    readonly verifiedPrivateVssShareProofCount?: number;
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

export type SetupTransportedVssCoefficientCommitmentMaterialLike =
    ProtocolSetupTransportedVssCoefficientCommitmentMaterialLike;
export type VerifiedVssCoefficientCommitmentMaterial =
    ProtocolVerifiedVssCoefficientCommitmentMaterial;
export type VerifiedSetupProofMaterial = ProtocolVerifiedSetupProofMaterial;
export type VerifiedSetupProofMaterialSet =
    ProtocolVerifiedSetupProofMaterialSet;
export type SetupTransportedPublicKeyShareMaterial =
    ProtocolSetupTransportedPublicKeyShareMaterial;
export type TransportedSameSecretProofMaterialSet =
    ProtocolTransportedSameSecretProofMaterialSet;
export type TransportedPublicKeyShareProofMaterialSet =
    ProtocolTransportedPublicKeyShareProofMaterialSet;
export type TransportedEvaluationKeyShareProofMaterialSet =
    ProtocolTransportedEvaluationKeyShareProofMaterialSet;
export type TransportedEvaluationKeyShareComponentMaterialSet =
    ProtocolTransportedEvaluationKeyShareComponentMaterialSet;
export type TransportedPublicEvaluationKeyMaterialSet =
    ProtocolTransportedPublicEvaluationKeyMaterialSet;

export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash?: ProtocolHash;
    readonly expectedRosterHash?: ProtocolHash;
    readonly transportedVssCoefficientCommitmentMaterial?: SetupTransportedVssCoefficientCommitmentMaterialLike;
    readonly verifiedVssCoefficientCommitmentMaterial?: VerifiedVssCoefficientCommitmentMaterial;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
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
    readonly objectVersion: 1;
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly qShareHash: ProtocolHash;
    readonly commitmentProfileHash: ProtocolHash;
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
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
        readonly heSecurityCertificateHash: ProtocolHash;
    }>;
    readonly acceptedSetupHandoffRoot: ProtocolHash;
}>;

export type SetupPackageVerification = Readonly<{
    readonly ok: boolean;
    readonly operation: 'verifyCollectiveBgvSetupPackage';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verifierStatus:
        | 'accepted'
        | 'pending'
        | 'refused'
        | 'aborted'
        | 'forkDetected'
        | 'outsideProfile';
    readonly currentPhase: string | null;
    readonly phaseOrderHash: ProtocolHash;
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly acceptedSetupHandoff?: AcceptedSetupHandoff;
    readonly missingObjects: readonly string[];
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

/** Derives threshold, quorum, and warning parameters for a roster profile. */
export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => deriveThresholdProfileInternal(input);

/** Derives the concrete roster profile after registration closes and the roster freezes. */
export const deriveFrozenRosterProfile = deriveFrozenRosterProfileInternal;

/** Derives the canonical poll-spec hash including roster policy fields. */
export const derivePollSpecHash = derivePollSpecHashInternal;

/** Derives the canonical threshold-profile hash for a frozen roster profile. */
export const deriveThresholdProfileHash = deriveThresholdProfileHashInternal;

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

/** Evaluates whether a protocol action is allowed in the current context. */
export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => evaluateActionCapabilityInternal(action, context);

// Fail-closed result builder for the reserved future complete-protocol entry points
// below: each returns a structured OperationUnavailable refusal (ok:false) rather than
// throwing, so callers get a typed, non-crashing refusal until the path is implemented.
const unavailableFutureProtocolOperation = (
    operation: string,
): FutureProtocolOperationResult => ({
    ok: false,
    acceptedHashes: [],
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

/** Verifies the integrated foundation transcript without claiming full election verification. */
export const verifyFoundationTranscript = (
    input: FoundationTranscriptInput,
): FoundationTranscriptVerification =>
    verifyFoundationTranscriptInternal(input);

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

/** Verifies one private VSS share envelope locally without returning raw shares. */
export const verifyPrivateVssShare = async (
    input: VerifyPrivateVssShareInput,
): Promise<PrivateVssShareVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyPrivateVssShareEnvelope(input);
};

/** Builds the public-only setup package verification input from package and transported setup material. */
export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): VerifySetupPackageInput =>
    createSetupPackageVerificationInputInternal(input);

type SetupProofMaterialTransportFieldName =
    | 'transportedSameSecretProofMaterial'
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportSet =
    | TransportedSameSecretProofMaterialSet
    | TransportedPublicKeyShareProofMaterialSet
    | TransportedEvaluationKeyShareProofMaterialSet;

type SetupProofMaterialChunk = Readonly<{
    readonly chunkIndex: number;
    readonly bytesHex: string;
}>;

const setupProofMaterialTransportFieldNames = [
    'transportedSameSecretProofMaterial',
    'transportedPublicKeyShareProofMaterial',
    'transportedEvaluationKeyShareProofMaterial',
] as const satisfies readonly SetupProofMaterialTransportFieldName[];

let setupProofMaterialVerificationSequence = 0;

// Verification ids are process-local kernel stream handles, not security bindings; the cryptographic binding is the full proof material root.
const setupProofMaterialVerificationId = (
    fieldName: SetupProofMaterialTransportFieldName,
    materialIndex: number,
    proofMaterial: JsonRecord,
): string => {
    setupProofMaterialVerificationSequence += 1;
    const proofMaterialRoot =
        typeof proofMaterial.proofMaterialRoot === 'string'
            ? proofMaterial.proofMaterialRoot.slice(0, 24)
            : 'unbound';

    return [
        'sdk-proof-material',
        String(setupProofMaterialVerificationSequence),
        fieldName,
        String(materialIndex),
        proofMaterialRoot,
    ].join('-');
};

const setupProofMaterialReference = (proofMaterial: JsonRecord): JsonRecord => {
    const { chunks: omittedChunks, ...reference } = proofMaterial;
    void omittedChunks;

    return reference;
};

// Safe only because proofMaterialRoot is the collision-resistant commitment the kernel rebinds; chunks are dropped only after that root is in the verified set.
const compactSetupProofMaterialSet = <
    MaterialSet extends SetupProofMaterialTransportSet | undefined,
>(
    materialSet: MaterialSet,
    verifiedSetupProofMaterials: VerifiedSetupProofMaterialSet | undefined,
): MaterialSet => {
    if (
        materialSet === undefined ||
        verifiedSetupProofMaterials === undefined
    ) {
        return materialSet;
    }

    const verifiedProofMaterialRoots = new Set(
        verifiedSetupProofMaterials.proofMaterials.map(
            (proofMaterial) => proofMaterial.proofMaterialRoot,
        ),
    );
    let strippedAnyChunks = false;
    const proofMaterials = materialSet.proofMaterials.map((proofMaterial) => {
        if (
            !Object.prototype.hasOwnProperty.call(proofMaterial, 'chunks') ||
            typeof proofMaterial.proofMaterialRoot !== 'string' ||
            !verifiedProofMaterialRoots.has(proofMaterial.proofMaterialRoot)
        ) {
            return proofMaterial;
        }
        strippedAnyChunks = true;

        return setupProofMaterialReference(proofMaterial);
    });

    if (!strippedAnyChunks) {
        return materialSet;
    }

    return {
        ...materialSet,
        proofMaterials,
    };
};

const setupProofMaterialChunks = (
    proofMaterial: unknown,
): readonly SetupProofMaterialChunk[] | undefined => {
    if (
        proofMaterial === null ||
        typeof proofMaterial !== 'object' ||
        !Object.prototype.hasOwnProperty.call(proofMaterial, 'chunks')
    ) {
        return undefined;
    }

    const chunks = (proofMaterial as JsonRecord).chunks;

    return Array.isArray(chunks)
        ? (chunks as readonly SetupProofMaterialChunk[])
        : undefined;
};

const streamSetupProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialTransportSet | undefined,
): readonly VerifiedSetupProofMaterial[] => {
    if (
        materialSet === undefined ||
        !Array.isArray(materialSet.proofMaterials)
    ) {
        return [];
    }

    const verifiedMaterials: VerifiedSetupProofMaterial[] = [];
    materialSet.proofMaterials.forEach((proofMaterialValue, materialIndex) => {
        const chunks = setupProofMaterialChunks(proofMaterialValue);
        if (chunks === undefined) {
            return;
        }
        const proofMaterial = proofMaterialValue as JsonRecord;
        const proofMaterialReference =
            setupProofMaterialReference(proofMaterial);
        const verificationId = setupProofMaterialVerificationId(
            fieldName,
            materialIndex,
            proofMaterial,
        );
        kernel.beginSetupProofMaterialTransportStream({
            verificationId,
            transportedSetupProofMaterial: proofMaterialReference,
        });
        chunks.forEach((chunk) => {
            kernel.absorbSetupProofMaterialTransportStreamChunk({
                verificationId,
                chunkIndex: chunk.chunkIndex,
                bytesHex: chunk.bytesHex,
            });
        });
        const verification = kernel.finishSetupProofMaterialTransportStream({
            verificationId,
        });
        verifiedMaterials.push(
            verification.verifiedSetupProofMaterial as VerifiedSetupProofMaterial,
        );
    });

    return verifiedMaterials;
};

const prepareSetupPackageVerificationInputForKernel = (
    kernel: TranscriptCoreKernel,
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    if (input.verifiedSetupProofMaterials !== undefined) {
        return {
            ...input,
            transportedSameSecretProofMaterial: compactSetupProofMaterialSet(
                input.transportedSameSecretProofMaterial,
                input.verifiedSetupProofMaterials,
            ),
            transportedPublicKeyShareProofMaterial:
                compactSetupProofMaterialSet(
                    input.transportedPublicKeyShareProofMaterial,
                    input.verifiedSetupProofMaterials,
                ),
            transportedEvaluationKeyShareProofMaterial:
                compactSetupProofMaterialSet(
                    input.transportedEvaluationKeyShareProofMaterial,
                    input.verifiedSetupProofMaterials,
                ),
        };
    }

    const verifiedMaterials = setupProofMaterialTransportFieldNames.flatMap(
        (fieldName) =>
            streamSetupProofMaterialSet(kernel, fieldName, input[fieldName]),
    );
    if (verifiedMaterials.length === 0) {
        return input;
    }

    const verifiedSetupProofMaterials = {
        objectType: 'VerifiedSetupProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofMaterials: verifiedMaterials,
    } as const satisfies VerifiedSetupProofMaterialSet;

    return {
        ...input,
        transportedSameSecretProofMaterial: compactSetupProofMaterialSet(
            input.transportedSameSecretProofMaterial,
            verifiedSetupProofMaterials,
        ),
        transportedPublicKeyShareProofMaterial: compactSetupProofMaterialSet(
            input.transportedPublicKeyShareProofMaterial,
            verifiedSetupProofMaterials,
        ),
        transportedEvaluationKeyShareProofMaterial:
            compactSetupProofMaterialSet(
                input.transportedEvaluationKeyShareProofMaterial,
                verifiedSetupProofMaterials,
            ),
        verifiedSetupProofMaterials,
    };
};

/** Verifies an accepted setup package with the packaged Rust/WASM kernel. */
export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    const kernel = await loadTranscriptCoreKernel();
    const verificationInput = prepareSetupPackageVerificationInputForKernel(
        kernel,
        input,
    );

    return kernel.verifyCollectiveBgvSetup(verificationInput);
};

/** Verifies a transcript-core fixture with the packaged WASM kernel. */
export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreVerificationResult> => {
    const kernel = await loadTranscriptCoreKernel();
    const verification = kernel.verifyFixture(fixture);

    if ('expectedErrorCode' in verification) {
        return {
            ok: false,
            caseName: verification.caseName,
            rejection: {
                code: verification.expectedErrorCode,
            },
        };
    }

    return {
        ok: true,
        caseName: verification.caseName,
        objectHash512: verification.objectHash512,
        chunkRoot: verification.chunkRoot,
    };
};
