import {
    deriveCollectiveBgvSetupRosterHash as deriveCollectiveBgvSetupRosterHashInternal,
    deriveFrozenRosterParameters as deriveFrozenRosterParametersInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    deriveThresholdParameters as deriveThresholdParametersInternal,
    deriveThresholdParametersHash as deriveThresholdParametersHashInternal,
    validatePollSpec as validatePollSpecInternal,
    createBgvTargetDecryptionShareCanonicalProofMaterialTransport,
} from '@sealed-lattice/protocol';
import type {
    BgvTargetDecryptionShareCanonicalProofMaterialTransport,
    BgvTargetDecryptionShareProofMaterial,
    CanonicalProofMaterialChunkPull as ProtocolCanonicalProofMaterialChunkPull,
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
} from '@sealed-lattice/protocol';
import type {
    PollSpecInput,
    PollSpecValidation,
    ProtocolHash,
    VerificationResult,
} from '@sealed-lattice/types';
import { ThresholdParameterDerivationError } from '@sealed-lattice/types';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
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
import { loadFreshTranscriptCoreKernel } from './kernel.js';
import {
    prepareSnapshottedPrivateVssShareVerificationInputForKernel,
    prepareSnapshottedSetupPackageVerificationInputForKernel,
    snapshotPrivateVssShareVerificationInput,
    snapshotSetupPackageVerificationInput,
} from './setup-verification-input.js';
import {
    issueVerifiedSetup,
    resolveVerifiedSetup,
    type VerifiedSetup,
} from './verified-setup-capability.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const targetReleaseSessionIdentifierByteLength = 32;
const activeTargetReleaseSessionIdentifiers = new Set<string>();

const issueTargetReleaseSessionIdentifier = (): string => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Target result verification requires Web Crypto getRandomValues.',
        );
    }
    const identifierBytes = new Uint8Array(
        targetReleaseSessionIdentifierByteLength,
    );
    cryptoProvider.getRandomValues(identifierBytes);
    const identifier = Array.from(identifierBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');
    if (activeTargetReleaseSessionIdentifiers.has(identifier)) {
        throw new Error(
            'Target result verification session identifier collided with an active session.',
        );
    }
    activeTargetReleaseSessionIdentifiers.add(identifier);

    return identifier;
};

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
    CanonicalSignedRootObject,
    FrozenRosterParameters,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RefusalReason,
    SignedObjectType,
    SignerRole,
    SmallRosterPolicy,
    ThresholdParameters,
    ThresholdParametersInput,
    ThresholdParameterDerivationErrorCode,
    VerificationResult,
} from '@sealed-lattice/types';

export type { VerifiedSetup } from './verified-setup-capability.js';

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

export type PrivateVssShareVerification = VerificationResult<{
    readonly privateEnvelopeHash: ProtocolHash;
    readonly localVerificationRoot: ProtocolHash;
    readonly limbVerifications: readonly Readonly<{
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
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

export type SetupPackageVerification = VerificationResult<{
    readonly verifiedSetup: VerifiedSetup;
}>;

// These target-decryption records are opaque at the SDK boundary. The setup
// capability retains the exact kernel instance that performed verification.
export type TargetDecryptionResultReleaseInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly verifiedSetup: VerifiedSetup;
    readonly targetAcceptedRecord: unknown;
    readonly targetCiphertexts: unknown;
    readonly targetCiphertextBinding: unknown;
    readonly targetShareProfile: unknown;
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
    const verifiedSetup = dataPropertyValue(
        descriptors,
        'verifiedSetup',
        'verifiedSetup',
    );
    resolveVerifiedSetup(verifiedSetup);

    return {
        ...(abortSignal === undefined ? {} : { abortSignal }),
        verifiedSetup: verifiedSetup as VerifiedSetup,
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
        shareProofs: targetDecryptionShareProofListSnapshot(
            dataPropertyValue(descriptors, 'shareProofs', 'shareProofs'),
            state,
        ),
    };
};

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

export const verifyPrivateVssShare = async (
    input: VerifyPrivateVssShareInput,
): Promise<PrivateVssShareVerification> => {
    const verificationInputSnapshot =
        snapshotPrivateVssShareVerificationInput(input);
    const kernel = await loadFreshTranscriptCoreKernel();

    const verification = kernel.verifyPrivateVssShareEnvelope(
        await prepareSnapshottedPrivateVssShareVerificationInputForKernel(
            kernel,
            verificationInputSnapshot,
        ),
    );
    if (!verification.isValid) {
        return verification;
    }

    return {
        isValid: true,
        value: {
            privateEnvelopeHash: verification.value.privateEnvelopeHash,
            localVerificationRoot: verification.value.localVerificationRoot,
            limbVerifications: verification.value.limbVerifications,
        },
    };
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

        const verification =
            acceptedSetupSession.verifyCollectiveBgvSetup(verificationInput);
        if (!verification.isValid) {
            return verification;
        }

        const setupPackage = verificationInputSnapshot.setupPackage as Record<
            string,
            unknown
        >;
        const setupPackageHash = setupPackage.setupPackageHash;
        assertProtocolHash(setupPackageHash, 'setupPackage.setupPackageHash');

        return {
            isValid: true,
            value: {
                verifiedSetup: issueVerifiedSetup({
                    acceptedSetupHandle: verification.value.acceptedSetupHandle,
                    kernel,
                    setupPackageHash,
                }),
            },
        };
    } catch (error) {
        acceptedSetupSession.cancel();
        throw error;
    }
};

/** Verifies and releases one target result under a verifier-issued setup capability. */
export const verifyTargetDecryptionResult = async (
    input: TargetDecryptionResultReleaseInput,
): Promise<TargetDecryptionResultRelease> => {
    const inputSnapshot = targetDecryptionResultReleaseInputSnapshot(input);
    const abortSignal = inputSnapshot.abortSignal;
    const releaseVerificationId = issueTargetReleaseSessionIdentifier();
    const targetShareProofs = inputSnapshot.shareProofs;
    const { acceptedSetupHandle, kernel } = resolveVerifiedSetup(
        inputSnapshot.verifiedSetup,
    );
    try {
        const releaseBegin = kernel.beginBgvTargetDecryptionResultRelease({
            releaseVerificationId,
            acceptedSetupHandle,
            targetAcceptedRecord: inputSnapshot.targetAcceptedRecord,
            targetCiphertexts: inputSnapshot.targetCiphertexts,
            targetCiphertextBinding: inputSnapshot.targetCiphertextBinding,
            targetShareProfile: inputSnapshot.targetShareProfile,
        });
        let absorbedShareCount = 0;
        let releaseSessionOpen = true;
        try {
            const proofMaterialRuntime = openBgvCanonicalStreamRuntime({
                kernel,
            });
            if (targetShareProofs.length !== releaseBegin.requiredShareCount) {
                throw new Error(
                    'target-decryption share proof count must equal the required release quorum.',
                );
            }
            for (const targetShareProof of targetShareProofs) {
                const normalizedTransport =
                    targetShareProof.proofMaterialTransport;
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
    } finally {
        activeTargetReleaseSessionIdentifiers.delete(releaseVerificationId);
    }
};
