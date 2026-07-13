import {
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
    TransportedPublicKeyShareProofMaterialSet as ProtocolTransportedPublicKeyShareProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet as ProtocolTransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet as ProtocolTransportedSameSecretBridgeProofMaterialSet,
    TransportedEvaluationKeyShareComponentMaterialSet as ProtocolTransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet as ProtocolTransportedEvaluationKeyShareProofMaterialSet,
    SetupPackage as ProtocolSetupPackage,
    CollectiveBgvSetupRosterEntryInput as ProtocolCollectiveBgvSetupRosterEntryInput,
    TargetDecryptionAggregateOpeningMaterialSource as ProtocolTargetDecryptionAggregateOpeningMaterialSource,
} from '@sealed-lattice/protocol';
import type {
    PollSpecInput,
    PollSpecValidation,
    ProtocolHash,
} from '@sealed-lattice/types';
import { ThresholdParameterDerivationError } from '@sealed-lattice/types';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
    type BgvTargetDecryptionResultReleaseCompletion,
} from '@sealed-lattice/wasm/published-sdk';

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
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    SmallRosterPolicy,
    StructuredProtocolVerificationResult,
    ThresholdParameters,
    ThresholdParametersInput,
    ThresholdParameterDerivationErrorCode,
    TrusteeSetupEntry,
    ValidatedFirstValidObject,
} from '@sealed-lattice/types';

export type { TargetDecryptionAggregateOpeningMaterialSource } from '@sealed-lattice/protocol';

export { ThresholdParameterDerivationError };
export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly participantCount: number;
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
    readonly limbVerifications: readonly Readonly<{
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
    }>[];
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath: string;
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
export type CanonicalProofMaterialChunkPull =
    ProtocolCanonicalProofMaterialChunkPull;
export type CanonicalProofMaterialChunkSink =
    ProtocolCanonicalProofMaterialChunkSink;
export type SetupProofMaterialChunkSource =
    ProtocolSetupProofMaterialChunkSource;
export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareMaterialChunkSource: PublicKeyShareMaterialChunkSource;
    readonly transportedPublicKeyShareProofMaterial: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
    readonly setupProofMaterialChunkSources?: readonly SetupProofMaterialChunkSource[];
    readonly transportedEvaluationKeyShareComponentMaterial: TransportedEvaluationKeyShareComponentMaterialSet;
    // Bounded evaluation-key component sources are supplied out of band. Each
    // source is authenticated against the descriptor on its transported
    // component reference before terminal setup verification.
    readonly evaluationKeyShareComponentMaterialChunkSources?: readonly EvaluationKeyShareComponentMaterialChunkSource[];
}>;

export type SetupPackageVerification = Readonly<
    {
        readonly refusedObjects: readonly Readonly<{
            readonly reasonCode: string;
            readonly message: string;
            readonly objectPath: string;
        }>[];
    } & (
        | {
              readonly isValid: true;
              readonly acceptedSetupHandle: number;
          }
        | {
              readonly isValid: false;
          }
    )
>;

// These target-decryption records are opaque at the SDK boundary. The accepted
// setup handle comes only from successful setup verification in this kernel.
export type TargetDecryptionResultReleaseInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly acceptedSetupHandle: number;
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
    const acceptedSetupHandle = dataPropertyValue(
        descriptors,
        'acceptedSetupHandle',
        'acceptedSetupHandle',
    );
    if (
        !Number.isInteger(acceptedSetupHandle) ||
        (acceptedSetupHandle as number) <= 0 ||
        (acceptedSetupHandle as number) > 0xffff_ffff
    ) {
        throw new TypeError('acceptedSetupHandle must be a positive u32.');
    }

    return {
        ...(abortSignal === undefined ? {} : { abortSignal }),
        acceptedSetupHandle: acceptedSetupHandle as number,
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
    readonly aggregateOpeningMaterialSources: readonly ProtocolTargetDecryptionAggregateOpeningMaterialSource[];
    readonly targetDecryptionShare: unknown;
    readonly proofStatement: unknown;
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
}>;

const targetDecryptionAggregateOpeningByteLength = 32_768 * 8;
const maximumTargetDecryptionAggregateOpeningSourceCount = 17;

const aggregateOpeningMaterialSourcesSnapshot = (
    value: unknown,
): readonly ProtocolTargetDecryptionAggregateOpeningMaterialSource[] => {
    const { descriptors, length } = ordinaryArrayDescriptors(
        value,
        'aggregateOpeningMaterialSources',
    );
    if (
        length === 0 ||
        length > maximumTargetDecryptionAggregateOpeningSourceCount
    ) {
        throw new RangeError(
            'aggregateOpeningMaterialSources must cover between one and 17 RNS limbs.',
        );
    }
    const seenRoots = new Set<string>();
    const sources: ProtocolTargetDecryptionAggregateOpeningMaterialSource[] =
        [];
    for (let sourceIndex = 0; sourceIndex < length; sourceIndex += 1) {
        const elementDescriptor = descriptors[String(sourceIndex)];
        const sourcePath = `aggregateOpeningMaterialSources.${String(sourceIndex)}`;
        if (elementDescriptor === undefined) {
            throw new TypeError(
                'aggregateOpeningMaterialSources cannot contain array holes.',
            );
        }
        if ('get' in elementDescriptor || 'set' in elementDescriptor) {
            throw new TypeError(
                `${sourcePath} cannot be an accessor property.`,
            );
        }
        const sourceDescriptors = plainRecordDescriptors(
            elementDescriptor.value,
            sourcePath,
        );
        const aggregateOpeningRoot = dataPropertyValue(
            sourceDescriptors,
            'aggregateOpeningRoot',
            `${sourcePath}.aggregateOpeningRoot`,
        );
        assertProtocolHash(
            aggregateOpeningRoot,
            `${sourcePath}.aggregateOpeningRoot`,
        );
        if (seenRoots.has(aggregateOpeningRoot)) {
            throw new TypeError(
                'aggregateOpeningMaterialSources cannot contain duplicate opening roots.',
            );
        }
        seenRoots.add(aggregateOpeningRoot);
        const totalByteLength = dataPropertyValue(
            sourceDescriptors,
            'totalByteLength',
            `${sourcePath}.totalByteLength`,
        );
        if (totalByteLength !== targetDecryptionAggregateOpeningByteLength) {
            throw new RangeError(
                `${sourcePath}.totalByteLength must equal the fixed ring byte length.`,
            );
        }
        const pullChunk = dataPropertyValue(
            sourceDescriptors,
            'pullChunk',
            `${sourcePath}.pullChunk`,
        );
        if (typeof pullChunk !== 'function') {
            throw new TypeError(`${sourcePath}.pullChunk must be a function.`);
        }
        sources.push({
            aggregateOpeningRoot,
            pullChunk:
                pullChunk as ProtocolTargetDecryptionAggregateOpeningMaterialSource['pullChunk'],
            totalByteLength,
        });
    }
    return sources;
};

const assertAggregateOpeningSourcesMatchWitness = (
    sources: readonly ProtocolTargetDecryptionAggregateOpeningMaterialSource[],
    localTargetShareWitness: unknown,
): void => {
    const witnessDescriptors = plainRecordDescriptors(
        localTargetShareWitness,
        'localTargetShareWitness',
    );
    const aggregateOpeningPath = 'localTargetShareWitness.aggregateOpening';
    const aggregateOpeningDescriptors = plainRecordDescriptors(
        dataPropertyValue(
            witnessDescriptors,
            'aggregateOpening',
            aggregateOpeningPath,
        ),
        aggregateOpeningPath,
    );
    const credentialsPath = `${aggregateOpeningPath}.aggregateOpeningCredentials`;
    const { descriptors, length } = ordinaryArrayDescriptors(
        dataPropertyValue(
            aggregateOpeningDescriptors,
            'aggregateOpeningCredentials',
            credentialsPath,
        ),
        credentialsPath,
    );
    if (length !== sources.length) {
        throw new TypeError(
            'aggregateOpeningMaterialSources must match the witness aggregate opening credential count.',
        );
    }
    for (
        let credentialIndex = 0;
        credentialIndex < length;
        credentialIndex += 1
    ) {
        const credentialPath = `${credentialsPath}.${String(credentialIndex)}`;
        const credentialDescriptor = descriptors[String(credentialIndex)];
        if (credentialDescriptor === undefined) {
            throw new TypeError(
                `${credentialsPath} cannot contain array holes.`,
            );
        }
        const credentialDescriptors = plainRecordDescriptors(
            credentialDescriptor.value,
            credentialPath,
        );
        const aggregateOpeningRoot = dataPropertyValue(
            credentialDescriptors,
            'aggregateOpeningRoot',
            `${credentialPath}.aggregateOpeningRoot`,
        );
        assertProtocolHash(
            aggregateOpeningRoot,
            `${credentialPath}.aggregateOpeningRoot`,
        );
        if (
            aggregateOpeningRoot !==
            sources[credentialIndex]?.aggregateOpeningRoot
        ) {
            throw new TypeError(
                'aggregateOpeningMaterialSources must match the witness aggregate opening roots in canonical credential order.',
            );
        }
    }
};

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

    const aggregateOpeningMaterialSources =
        aggregateOpeningMaterialSourcesSnapshot(
            dataPropertyValue(
                descriptors,
                'aggregateOpeningMaterialSources',
                'aggregateOpeningMaterialSources',
            ),
        );
    const localTargetShareWitness = snapshotKernelJsonValue(
        dataPropertyValue(
            descriptors,
            'localTargetShareWitness',
            'localTargetShareWitness',
        ),
        'localTargetShareWitness',
        state,
    );
    assertAggregateOpeningSourcesMatchWitness(
        aggregateOpeningMaterialSources,
        localTargetShareWitness,
    );

    return {
        ...(abortSignal === undefined ? {} : { abortSignal }),
        emitProofMaterialChunk:
            emitProofMaterialChunk as CanonicalProofMaterialChunkSink,
        aggregateOpeningMaterialSources,
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
        localTargetShareWitness,
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

export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    const verificationInputSnapshot =
        snapshotSetupPackageVerificationInput(input);
    assertSetupPackageVerificationBindings(verificationInputSnapshot);

    const kernel = await loadFreshTranscriptCoreKernel();
    const acceptedSetupSession = kernel.beginAcceptedSetupSession();
    try {
        const verificationInput =
            await prepareSnapshottedSetupPackageVerificationInputForKernel(
                kernel,
                verificationInputSnapshot,
                acceptedSetupSession,
            );

        return acceptedSetupSession.verifyCollectiveBgvSetup(verificationInput);
    } catch (error) {
        acceptedSetupSession.cancel();
        throw error;
    }
};

export const generateTargetDecryptionShareProofMaterial = async (
    input: TargetDecryptionShareProofMaterialGenerationInput,
): Promise<TargetDecryptionShareProofMaterialGeneration> => {
    const inputSnapshot =
        targetDecryptionShareProofMaterialGenerationInputSnapshot(input);
    const {
        abortSignal,
        aggregateOpeningMaterialSources,
        emitProofMaterialChunk,
        ...kernelInputSnapshot
    } = inputSnapshot;
    const kernel = await loadFreshTranscriptCoreKernel();
    // Construct the reader runtime before the kernel retains generated proof
    // material. This prevents a runtime-construction failure from stranding a
    // newly generated proof; after reader acquisition, writeMaterial owns
    // cancellation and eviction on completion or failure.
    const proofMaterialRuntime = openBgvCanonicalStreamRuntime({ kernel });
    await stageBgvTargetDecryptionAggregateOpeningMaterials({
        ...(abortSignal === undefined ? {} : { abortSignal }),
        kernel,
        sources: aggregateOpeningMaterialSources,
    });
    const proofMaterial =
        kernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness(
            kernelInputSnapshot,
        );
    const descriptorBytes = await proofMaterialRuntime.writeMaterial({
        ...(abortSignal === undefined ? {} : { abortSignal }),
        emitChunk: emitProofMaterialChunk,
        family: bgvCanonicalStreamFamilies.targetDecryptionShare,
        materialRoot: proofMaterial.proofBytesHash,
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

/** Verifies and releases one target result under a verifier-issued setup handle. */
export const verifyTargetDecryptionResult = async (
    input: TargetDecryptionResultReleaseInput,
): Promise<TargetDecryptionResultRelease> => {
    const inputSnapshot = targetDecryptionResultReleaseInputSnapshot(input);
    const abortSignal = inputSnapshot.abortSignal;
    const releaseVerificationId = inputSnapshot.releaseVerificationId;
    const targetShareProofs = inputSnapshot.shareProofs;
    const kernel = await loadTranscriptCoreKernel();
    const releaseBegin = kernel.beginBgvTargetDecryptionResultRelease({
        releaseVerificationId,
        acceptedSetupHandle: inputSnapshot.acceptedSetupHandle,
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
                materialRoot: normalizedTransport.proofBytesHash,
                pullChunk: targetShareProof.pullProofMaterialChunk,
            });
            kernel.absorbBgvTargetDecryptionResultReleaseShare({
                releaseVerificationId,
                targetShareProof: {
                    targetDecryptionShare:
                        targetShareProof.targetDecryptionShare,
                    proofStatement: targetShareProof.proofStatement,
                    proofMaterial: targetShareProof.proofMaterial,
                },
            });
            absorbedShareCount += 1;
        }
        releaseSessionOpen = false;
        return kernel.finishBgvTargetDecryptionResultRelease({
            releaseVerificationId,
        });
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
