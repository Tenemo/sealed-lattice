import {
    createSetupPackageVerificationInput as createSetupPackageVerificationInputInternal,
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    deriveValidatedFirstValidOrder as deriveValidatedFirstValidOrderInternal,
    deriveFrozenRosterParameters as deriveFrozenRosterParametersInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    deriveThresholdParameters as deriveThresholdParametersInternal,
    deriveThresholdParametersHash as deriveThresholdParametersHashInternal,
    verifyCastReceiptShell as verifyCastReceiptShellInternal,
    verifyCloseRecordShell as verifyCloseRecordShellInternal,
    isActionCurrentForRecoveryEpoch as isActionCurrentForRecoveryEpochInternal,
    validatePollSpec as validatePollSpecInternal,
    verifyBoardConsistency as verifyBoardConsistencyInternal,
    verifyRecoveryEpochUpdate as verifyRecoveryEpochUpdateInternal,
    verifyRosterExternalAcceptance as verifyRosterExternalAcceptanceInternal,
    verifyRosterManifestTranscript as verifyRosterManifestTranscriptInternal,
    createBgvTargetDecryptionShareCanonicalProofMaterialTransport,
} from '@sealed-lattice/protocol';
import type {
    BgvTargetDecryptionShareCanonicalProofMaterialTransport,
    BgvTargetDecryptionShareProofMaterial,
    CanonicalProofMaterialChunkPull as ProtocolCanonicalProofMaterialChunkPull,
    CanonicalProofMaterialChunkSink as ProtocolCanonicalProofMaterialChunkSink,
    SetupProofMaterialChunkSource as ProtocolSetupProofMaterialChunkSource,
    SetupTransportedPublicKeyShareMaterial as ProtocolSetupTransportedPublicKeyShareMaterial,
    PublicKeyShareMaterialChunkSource as ProtocolPublicKeyShareMaterialChunkSource,
    EvaluationKeyShareComponentMaterialChunkSource as ProtocolEvaluationKeyShareComponentMaterialChunkSource,
    PublicEvaluationKeyMaterialChunkSource as ProtocolPublicEvaluationKeyMaterialChunkSource,
    TransportedPublicKeyShareProofMaterialSet as ProtocolTransportedPublicKeyShareProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet as ProtocolTransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet as ProtocolTransportedSameSecretBridgeProofMaterialSet,
    TransportedEvaluationKeyShareComponentMaterialSet as ProtocolTransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet as ProtocolTransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicEvaluationKeyMaterialSet as ProtocolTransportedPublicEvaluationKeyMaterialSet,
    SetupPackage as ProtocolSetupPackage,
    SetupPackageVerificationInputSource as ProtocolSetupPackageVerificationInputSource,
    CollectiveBgvSetupRosterEntryInput as ProtocolCollectiveBgvSetupRosterEntryInput,
} from '@sealed-lattice/protocol';
import type {
    PollSpecInput,
    PollSpecValidation,
    ProtocolHash,
    VerificationResult,
} from '@sealed-lattice/types';
import {
    foundationBoardCandidateObjectHash as foundationBoardCandidateObjectHashInternal,
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    openFoundationBoardSession as openFoundationBoardSessionInternal,
    type BgvTargetDecryptionResultReleaseCompletion,
} from '@sealed-lattice/wasm';

import {
    chargeKernelJsonSnapshotValues,
    createKernelJsonSnapshotState,
    dataPropertyValue,
    ordinaryArrayDescriptors,
    plainRecordDescriptors,
    snapshotKernelJsonValue,
    type KernelJsonSnapshotState,
} from './kernel-json-snapshot.js';
import {
    loadFreshTranscriptCoreKernel,
    loadTranscriptCoreKernel,
} from './kernel.js';
import {
    prepareSnapshottedPrivateVssShareVerificationInputForKernel,
    prepareSnapshottedSetupPackageVerificationInputForKernel,
    snapshotPrivateVssShareVerificationInput,
    snapshotSetupPackageVerificationInput,
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
    ActionContext,
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    AppendOnlyConsistencyProof,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    BoardEntryMerklePathStep,
    CanonicalSignedRootObject,
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
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FrozenRosterParameters,
    InclusionProof,
    ManifestOpaqueBindings,
    ManifestPolicyHashes,
    MlDsaSignatureMode,
    MlDsaSignatureProfile,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    ProtocolHash,
    ProtocolObjectType,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RefusalReason,
    RefusalRecord,
    RegistrationEntry,
    RosterExternalAcceptance,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    ScoreDomain,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    SmallRosterPolicy,
    StructuredProtocolVerificationResult,
    ThresholdParameters,
    ThresholdParametersInput,
    TrusteeSetupEntry,
    ValidatedFirstValidObject,
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
    /** Externally trusted anchor; the board session does not establish its provenance. */
    publicSetupSeedObjectHash?: Uint8Array;
    /** Externally trusted anchor; the board session does not establish its provenance. */
    setupSourceObjectHash?: Uint8Array;
    suiteIdentifier: Uint8Array;
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
    readonly privateVssShareProofMaterialChunkSources?: readonly SetupProofMaterialChunkSource[];
    readonly expectedPrivateEnvelopeHash?: ProtocolHash;
    readonly expectedLocalVerificationRoot?: ProtocolHash;
}>;

export type PrivateVssShareVerification = Readonly<{
    readonly isValid: boolean;
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
export type PublicKeyShareMaterialChunkSource =
    ProtocolPublicKeyShareMaterialChunkSource;
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
export type EvaluationKeyShareComponentMaterialChunkSource =
    ProtocolEvaluationKeyShareComponentMaterialChunkSource;
export type PublicEvaluationKeyMaterialChunkSource =
    ProtocolPublicEvaluationKeyMaterialChunkSource;
export type CanonicalProofMaterialChunkPull =
    ProtocolCanonicalProofMaterialChunkPull;
export type CanonicalProofMaterialChunkSink =
    ProtocolCanonicalProofMaterialChunkSink;
export type SetupProofMaterialChunkSource =
    ProtocolSetupProofMaterialChunkSource;
export type TransportedPublicEvaluationKeyMaterialSet =
    ProtocolTransportedPublicEvaluationKeyMaterialSet;

export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareMaterialChunkSource?: PublicKeyShareMaterialChunkSource;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial?: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial?: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly setupProofMaterialChunkSources?: readonly SetupProofMaterialChunkSource[];
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    // Bounded evaluation-key component sources are supplied out of band. Each
    // source is authenticated against the descriptor on its transported
    // component reference before terminal setup verification.
    readonly evaluationKeyShareComponentMaterialChunkSources?: readonly EvaluationKeyShareComponentMaterialChunkSource[];
    // Public evaluation-key bytes are supplied out of band and authenticated
    // against the descriptor on each transported material reference.
    readonly publicEvaluationKeyMaterialChunkSources?: readonly PublicEvaluationKeyMaterialChunkSource[];
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
}>;

export type SetupPackageVerificationInputSource = Readonly<
    Omit<ProtocolSetupPackageVerificationInputSource, 'setupPackage'> & {
        readonly setupPackage: SetupPackage;
        readonly publicKeyShareMaterialChunkSource?: PublicKeyShareMaterialChunkSource;
        readonly setupProofMaterialChunkSources?: readonly SetupProofMaterialChunkSource[];
        readonly evaluationKeyShareComponentMaterialChunkSources?: readonly EvaluationKeyShareComponentMaterialChunkSource[];
        readonly publicEvaluationKeyMaterialChunkSources?: readonly PublicEvaluationKeyMaterialChunkSource[];
    }
>;

export type SetupPackageVerification = Readonly<{
    readonly isValid: boolean;
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

// These target-decryption records are opaque at the SDK boundary. In
// particular, targetAcceptedRecord is a caller-supplied target binding whose
// internal context and hashes are structurally checked by the kernel; this
// function does not authenticate board inclusion, evaluator replay, finality,
// or state authorization for that binding.
export type TargetDecryptionResultReleaseInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
    readonly releaseVerificationId: string;
    readonly shareProofs: readonly TargetDecryptionShareProof[];
}>;

export type TargetDecryptionShareProof = Readonly<{
    readonly targetDecryptionShare: unknown;
    readonly proofStatement: unknown;
    readonly proofMaterial: BgvTargetDecryptionShareProofMaterial;
    readonly proofMaterialTransport: BgvTargetDecryptionShareCanonicalProofMaterialTransport;
    readonly pullProofMaterialChunk: CanonicalProofMaterialChunkPull;
}>;

const targetDecryptionShareProofSnapshot = (
    targetShareProofValue: unknown,
    proofIndex: number,
    state: KernelJsonSnapshotState,
): TargetDecryptionShareProof => {
    const proofPath = `shareProofs.${String(proofIndex)}`;
    const descriptors = plainRecordDescriptors(
        targetShareProofValue,
        proofPath,
    );
    const proofMaterial = snapshotKernelJsonValue(
        dataPropertyValue(
            descriptors,
            'proofMaterial',
            `${proofPath}.proofMaterial`,
        ),
        `${proofPath}.proofMaterial`,
        state,
    ) as BgvTargetDecryptionShareProofMaterial;
    const transportPath = `${proofPath}.proofMaterialTransport`;
    const transportDescriptors = plainRecordDescriptors(
        dataPropertyValue(descriptors, 'proofMaterialTransport', transportPath),
        transportPath,
    );
    const proofMaterialTransport =
        createBgvTargetDecryptionShareCanonicalProofMaterialTransport(
            proofMaterial,
            {
                descriptorBytes: dataPropertyValue(
                    transportDescriptors,
                    'descriptorBytes',
                    `${transportPath}.descriptorBytes`,
                ) as Uint8Array,
            },
        );
    const pullProofMaterialChunk = dataPropertyValue(
        descriptors,
        'pullProofMaterialChunk',
        `${proofPath}.pullProofMaterialChunk`,
    );
    if (typeof pullProofMaterialChunk !== 'function') {
        throw new TypeError(
            `${proofPath}.pullProofMaterialChunk must be a function.`,
        );
    }

    return {
        targetDecryptionShare: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetDecryptionShare',
                `${proofPath}.targetDecryptionShare`,
            ),
            `${proofPath}.targetDecryptionShare`,
            state,
        ),
        proofStatement: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'proofStatement',
                `${proofPath}.proofStatement`,
            ),
            `${proofPath}.proofStatement`,
            state,
        ),
        proofMaterial,
        proofMaterialTransport,
        pullProofMaterialChunk:
            pullProofMaterialChunk as CanonicalProofMaterialChunkPull,
    };
};

const targetDecryptionShareProofListSnapshot = (
    value: unknown,
    state: KernelJsonSnapshotState,
): readonly TargetDecryptionShareProof[] => {
    const { descriptors, length } = ordinaryArrayDescriptors(
        value,
        'shareProofs',
    );
    chargeKernelJsonSnapshotValues(state, length);
    const snapshots: TargetDecryptionShareProof[] = [];
    for (let proofIndex = 0; proofIndex < length; proofIndex += 1) {
        const descriptor = descriptors[String(proofIndex)];
        if (descriptor === undefined) {
            throw new TypeError('shareProofs cannot contain array holes.');
        }
        if ('get' in descriptor || 'set' in descriptor) {
            throw new TypeError(
                `shareProofs.${String(proofIndex)} cannot be an accessor property.`,
            );
        }
        snapshots.push(
            targetDecryptionShareProofSnapshot(
                descriptor.value,
                proofIndex,
                state,
            ),
        );
    }

    return snapshots;
};

const targetDecryptionResultReleaseInputSnapshot = (
    input: TargetDecryptionResultReleaseInput,
): TargetDecryptionResultReleaseInput => {
    const descriptors = plainRecordDescriptors(input, 'input');
    const state = createKernelJsonSnapshotState();
    const abortSignal = dataPropertyValue(
        descriptors,
        'abortSignal',
        'abortSignal',
    ) as AbortSignal | undefined;
    const releaseVerificationId = dataPropertyValue(
        descriptors,
        'releaseVerificationId',
        'releaseVerificationId',
    );
    if (typeof releaseVerificationId !== 'string') {
        throw new TypeError('releaseVerificationId must be a string.');
    }

    return {
        ...(abortSignal === undefined ? {} : { abortSignal }),
        setupPackage: snapshotKernelJsonValue(
            dataPropertyValue(descriptors, 'setupPackage', 'setupPackage'),
            'setupPackage',
            state,
        ),
        targetAcceptedRecord: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetAcceptedRecord',
                'targetAcceptedRecord',
            ),
            'targetAcceptedRecord',
            state,
        ),
        targetCiphertexts: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetCiphertexts',
                'targetCiphertexts',
            ),
            'targetCiphertexts',
            state,
        ),
        targetCiphertextBinding: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetCiphertextBinding',
                'targetCiphertextBinding',
            ),
            'targetCiphertextBinding',
            state,
        ),
        targetShareProfile: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetShareProfile',
                'targetShareProfile',
            ),
            'targetShareProfile',
            state,
        ),
        releaseVerificationId,
        shareProofs: targetDecryptionShareProofListSnapshot(
            dataPropertyValue(descriptors, 'shareProofs', 'shareProofs'),
            state,
        ),
    };
};

export type TargetDecryptionShareProofMaterialGenerationInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly emitProofMaterialChunk: CanonicalProofMaterialChunkSink;
    readonly setupPackage: unknown;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
    readonly trusteeIdentity: string;
    readonly localTargetShareWitness: unknown;
    readonly targetDecryptionShare: unknown;
    readonly proofStatement: unknown;
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
}>;

const targetDecryptionShareProofMaterialGenerationInputSnapshot = (
    input: TargetDecryptionShareProofMaterialGenerationInput,
): TargetDecryptionShareProofMaterialGenerationInput => {
    const descriptors = plainRecordDescriptors(input, 'input');
    const state = createKernelJsonSnapshotState();
    const abortSignal = dataPropertyValue(
        descriptors,
        'abortSignal',
        'abortSignal',
    ) as AbortSignal | undefined;
    const emitProofMaterialChunk = dataPropertyValue(
        descriptors,
        'emitProofMaterialChunk',
        'emitProofMaterialChunk',
    );
    if (typeof emitProofMaterialChunk !== 'function') {
        throw new TypeError('emitProofMaterialChunk must be a function.');
    }
    const trusteeIdentity = dataPropertyValue(
        descriptors,
        'trusteeIdentity',
        'trusteeIdentity',
    );
    if (typeof trusteeIdentity !== 'string') {
        throw new TypeError('trusteeIdentity must be a string.');
    }
    const proofRandomnessSeedHex = dataPropertyValue(
        descriptors,
        'proofRandomnessSeedHex',
        'proofRandomnessSeedHex',
    );
    if (typeof proofRandomnessSeedHex !== 'string') {
        throw new TypeError('proofRandomnessSeedHex must be a string.');
    }
    const proofRandomnessNonceHex = dataPropertyValue(
        descriptors,
        'proofRandomnessNonceHex',
        'proofRandomnessNonceHex',
    );
    if (typeof proofRandomnessNonceHex !== 'string') {
        throw new TypeError('proofRandomnessNonceHex must be a string.');
    }

    return {
        ...(abortSignal === undefined ? {} : { abortSignal }),
        emitProofMaterialChunk:
            emitProofMaterialChunk as CanonicalProofMaterialChunkSink,
        setupPackage: snapshotKernelJsonValue(
            dataPropertyValue(descriptors, 'setupPackage', 'setupPackage'),
            'setupPackage',
            state,
        ),
        targetAcceptedRecord: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetAcceptedRecord',
                'targetAcceptedRecord',
            ),
            'targetAcceptedRecord',
            state,
        ),
        targetCiphertexts: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetCiphertexts',
                'targetCiphertexts',
            ),
            'targetCiphertexts',
            state,
        ),
        targetCiphertextBinding: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetCiphertextBinding',
                'targetCiphertextBinding',
            ),
            'targetCiphertextBinding',
            state,
        ),
        targetShareProfile: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetShareProfile',
                'targetShareProfile',
            ),
            'targetShareProfile',
            state,
        ),
        trusteeIdentity,
        localTargetShareWitness: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'localTargetShareWitness',
                'localTargetShareWitness',
            ),
            'localTargetShareWitness',
            state,
        ),
        targetDecryptionShare: snapshotKernelJsonValue(
            dataPropertyValue(
                descriptors,
                'targetDecryptionShare',
                'targetDecryptionShare',
            ),
            'targetDecryptionShare',
            state,
        ),
        proofStatement: snapshotKernelJsonValue(
            dataPropertyValue(descriptors, 'proofStatement', 'proofStatement'),
            'proofStatement',
            state,
        ),
        proofRandomnessSeedHex,
        proofRandomnessNonceHex,
    };
};

export type TargetDecryptionShareProofMaterialGeneration = Readonly<{
    readonly proofMaterial: BgvTargetDecryptionShareProofMaterial;
    readonly proofMaterialTransport: BgvTargetDecryptionShareCanonicalProofMaterialTransport;
}>;

export type TargetDecryptionResultRelease =
    BgvTargetDecryptionResultReleaseCompletion;

class TargetDecryptionResultReleaseCleanupError extends Error {
    public readonly cleanupFailure: unknown;
    public readonly operationFailure: unknown;

    public constructor(operationFailure: unknown, cleanupFailure: unknown) {
        super(
            'Target-decryption result release failed and its incomplete session cleanup also refused.',
        );
        this.name = 'TargetDecryptionResultReleaseCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailure = cleanupFailure;
    }
}

export const deriveThresholdParameters = deriveThresholdParametersInternal;

export const deriveFrozenRosterParameters =
    deriveFrozenRosterParametersInternal;

export const deriveCollectiveBgvSetupRosterHash =
    deriveCollectiveBgvSetupRosterHashInternal;

export const derivePollSpecHash = derivePollSpecHashInternal;

export const deriveThresholdParametersHash =
    deriveThresholdParametersHashInternal;

export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecInternal(input);
}

export const verifyBoardConsistency = verifyBoardConsistencyInternal;

export const verifyCastReceiptShell = verifyCastReceiptShellInternal;

export const verifyCloseRecordShell = verifyCloseRecordShellInternal;

export const deriveValidatedFirstValidOrder =
    deriveValidatedFirstValidOrderInternal;

export const verifyRosterExternalAcceptance =
    verifyRosterExternalAcceptanceInternal;

export const verifyRosterManifestTranscript =
    verifyRosterManifestTranscriptInternal;

export const isActionCurrentForRecoveryEpoch =
    isActionCurrentForRecoveryEpochInternal;

export const verifyRecoveryEpochUpdate = verifyRecoveryEpochUpdateInternal;

export const verifyPrivateVssShare = async (
    input: VerifyPrivateVssShareInput,
): Promise<PrivateVssShareVerification> => {
    const verificationInputSnapshot =
        snapshotPrivateVssShareVerificationInput(input);
    const kernel = await loadFreshTranscriptCoreKernel();

    return kernel.verifyPrivateVssShareEnvelope(
        await prepareSnapshottedPrivateVssShareVerificationInputForKernel(
            kernel,
            verificationInputSnapshot,
        ),
    );
};

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): VerifySetupPackageInput => {
    const validatedInput = createSetupPackageVerificationInputInternal(input);

    return {
        setupPackage: validatedInput.setupPackage,
        expectedManifestHash: validatedInput.expectedManifestHash,
        expectedRosterHash: validatedInput.expectedRosterHash,
        ...(input.transportedPublicKeyShareMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      input.transportedPublicKeyShareMaterial,
              }),
        ...(input.publicKeyShareMaterialChunkSource === undefined
            ? {}
            : {
                  publicKeyShareMaterialChunkSource:
                      input.publicKeyShareMaterialChunkSource,
              }),
        ...(input.setupProofMaterialChunkSources === undefined
            ? {}
            : {
                  setupProofMaterialChunkSources:
                      input.setupProofMaterialChunkSources,
              }),
        ...(input.evaluationKeyShareComponentMaterialChunkSources === undefined
            ? {}
            : {
                  evaluationKeyShareComponentMaterialChunkSources:
                      input.evaluationKeyShareComponentMaterialChunkSources,
              }),
        ...(input.publicEvaluationKeyMaterialChunkSources === undefined
            ? {}
            : {
                  publicEvaluationKeyMaterialChunkSources:
                      input.publicEvaluationKeyMaterialChunkSources,
              }),
        ...(input.transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareProofMaterial:
                      input.transportedPublicKeyShareProofMaterial,
              }),
        ...(input.transportedVssShareLinkageProofMaterial === undefined
            ? {}
            : {
                  transportedVssShareLinkageProofMaterial:
                      input.transportedVssShareLinkageProofMaterial,
              }),
        ...(input.transportedSameSecretBridgeProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretBridgeProofMaterial:
                      input.transportedSameSecretBridgeProofMaterial,
              }),
        ...(input.transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareProofMaterial:
                      input.transportedEvaluationKeyShareProofMaterial,
              }),
        ...(input.transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      input.transportedEvaluationKeyShareComponentMaterial,
              }),
        ...(input.transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      input.transportedPublicEvaluationKeyMaterial,
              }),
    };
};

export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    const verificationInputSnapshot =
        snapshotSetupPackageVerificationInput(input);
    assertSetupPackageVerificationBindings(verificationInputSnapshot);

    const kernel = await loadFreshTranscriptCoreKernel();
    const verificationInput =
        await prepareSnapshottedSetupPackageVerificationInputForKernel(
            kernel,
            verificationInputSnapshot,
        );

    return kernel.verifyCollectiveBgvSetup(verificationInput);
};

export const generateTargetDecryptionShareProofMaterial = async (
    input: TargetDecryptionShareProofMaterialGenerationInput,
): Promise<TargetDecryptionShareProofMaterialGeneration> => {
    const inputSnapshot =
        targetDecryptionShareProofMaterialGenerationInputSnapshot(input);
    const kernel = await loadFreshTranscriptCoreKernel();
    // Construct the reader runtime before the kernel retains generated proof
    // material. This prevents a runtime-construction failure from stranding a
    // newly generated proof; after reader acquisition, writeMaterial owns
    // cancellation and eviction on completion or failure.
    const proofMaterialRuntime = openBgvCanonicalStreamRuntime({ kernel });
    const proofMaterial =
        kernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness(
            inputSnapshot,
        );
    const descriptorBytes = await proofMaterialRuntime.writeMaterial({
        ...(inputSnapshot.abortSignal === undefined
            ? {}
            : { abortSignal: inputSnapshot.abortSignal }),
        emitChunk: inputSnapshot.emitProofMaterialChunk,
        family: bgvCanonicalStreamFamilies.targetDecryptionShare,
        materialRoot: proofMaterial.proofMaterialRoot,
    });

    return {
        proofMaterial,
        proofMaterialTransport:
            createBgvTargetDecryptionShareCanonicalProofMaterialTransport(
                proofMaterial,
                { descriptorBytes },
            ),
    };
};

/**
 * Drives the development-evidence staged target-decryption result release with
 * the packaged Rust/WASM kernel: derive the release setup context from a
 * structurally checked caller-supplied setup package, begin the staged session,
 * absorb each trustee share proof, then finish and return the released target
 * result. Neither the setup package nor the caller-supplied target binding is a
 * verifier-issued authority capability for this call. Board inclusion,
 * evaluator replay, finality, and state authorization remain outside this path.
 */
export const verifyTargetDecryptionResult = async (
    input: TargetDecryptionResultReleaseInput,
): Promise<TargetDecryptionResultRelease> => {
    const inputSnapshot = targetDecryptionResultReleaseInputSnapshot(input);
    const abortSignal = inputSnapshot.abortSignal;
    const releaseVerificationId = inputSnapshot.releaseVerificationId;
    const targetShareProofs = inputSnapshot.shareProofs;
    const kernel = await loadTranscriptCoreKernel();
    const releaseSetupContext =
        kernel.deriveBgvTargetDecryptionResultReleaseSetupContext({
            setupPackage: inputSnapshot.setupPackage,
        });
    const releaseBegin = kernel.beginBgvTargetDecryptionResultRelease({
        releaseVerificationId,
        releaseSetupContext,
        targetAcceptedRecord: inputSnapshot.targetAcceptedRecord,
        targetCiphertexts: inputSnapshot.targetCiphertexts,
        targetCiphertextBinding: inputSnapshot.targetCiphertextBinding,
        targetShareProfile: inputSnapshot.targetShareProfile,
    });
    let absorbedShareCount = 0;
    let releaseSessionOpen = true;
    try {
        const proofMaterialRuntime = openBgvCanonicalStreamRuntime({ kernel });
        if (targetShareProofs.length !== releaseBegin.requiredShareCount) {
            throw new Error(
                'target-decryption share proof count must equal the required release quorum.',
            );
        }
        for (const targetShareProof of targetShareProofs) {
            const normalizedTransport = targetShareProof.proofMaterialTransport;
            await proofMaterialRuntime.readMaterial({
                ...(abortSignal === undefined ? {} : { abortSignal }),
                descriptorBytes: normalizedTransport.descriptorBytes,
                family: bgvCanonicalStreamFamilies.targetDecryptionShare,
                materialRoot: normalizedTransport.proofMaterialRoot,
                pullChunk: targetShareProof.pullProofMaterialChunk,
            });
            const absorption =
                kernel.absorbBgvTargetDecryptionResultReleaseShare({
                    releaseVerificationId,
                    targetShareProof: {
                        targetDecryptionShare:
                            targetShareProof.targetDecryptionShare,
                        proofStatement: targetShareProof.proofStatement,
                        proofMaterial: targetShareProof.proofMaterial,
                    },
                });
            if (
                absorption.requiredShareCount !==
                    releaseBegin.requiredShareCount ||
                absorption.absorbedShareCount !== absorbedShareCount + 1
            ) {
                throw new Error(
                    'target-decryption release absorption count does not match the active release session.',
                );
            }
            absorbedShareCount = absorption.absorbedShareCount;
            if (absorbedShareCount === releaseBegin.requiredShareCount) {
                releaseSessionOpen = false;
                return kernel.finishBgvTargetDecryptionResultRelease({
                    releaseVerificationId,
                });
            }
        }

        throw new Error(
            'target-decryption release did not absorb the required share quorum.',
        );
    } catch (operationFailure) {
        if (
            releaseSessionOpen &&
            absorbedShareCount < releaseBegin.requiredShareCount
        ) {
            try {
                kernel.finishBgvTargetDecryptionResultRelease({
                    releaseVerificationId,
                });
            } catch (cleanupFailure) {
                throw new TargetDecryptionResultReleaseCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
        }
        throw operationFailure;
    }
};
