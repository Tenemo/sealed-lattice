import {
    foundationProfile,
    refusalReasonCodes,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import {
    requireAcceptedSetupPackageBuilderKernelOwner,
    type AcceptedSetupPackageBuilder,
} from './accepted-setup-package-builder-runtime.js';
import {
    verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker,
    type AcceptedSetupProofVerificationInput,
} from './accepted-setup-proof-verification-runtime.js';
import { isUint8Array } from './byte-array.js';
import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamDomains,
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    clearCommonProofExternalMemoryRequest,
    decodeCommonProofExternalMemoryRequest,
    encodeCommonProofExternalMemoryResponseInto,
    maximumEncodedResponseByteLength,
    type CommonProofExternalMemoryRequest,
} from './common-proof-worker-runtime/external-memory.js';
import {
    canonicalCommonProofChunkByteLength,
    CompactPublicKeyGenerationKernelBoundary,
    yieldBrowserWorkerTurn,
    type CommonProofBrowserStorageAccounting,
    type CommonProofExternalMemoryUsageAccounting,
    type CommonProofGenerationExternalMemoryAccounting,
    type CompactPublicKeyGenerationStorageOwner,
    type CompactPublicKeyTransportBindings,
} from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    CommonProofStorageRequestSequence,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener,
    validateTransferredReadResults,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationExecutionOpener,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
} from './common-proof-worker-runtime/runtime.js';
import { deriveGeneratedCommonProofDescriptor } from './generated-common-proof-output-runtime.js';
import type { ClosedWorkerProductionOperationIdentifiers } from './local-storage-root-worker-kernel/authorities.js';
import { withClosedWorkerProductionOperationAuthority } from './local-storage-root-worker-kernel/worker-kernel.js';
import {
    resolveSetupGenerationAuthorityKernelAuthorization,
    type BrowserOwnedSetupGenerationAuthority,
} from './setup-generation-recipient-payload.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import {
    consumeVerifiedVssLowDegreeEvidence,
    resolveAggregatePublicRandomnessBoardAuthorization,
    resolveOrderedVerifiedBoardObjectAuthorization,
    type VerifiedVssLowDegreeEvidence,
} from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const checkpointLineageIdentifierByteLength = 32;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const defaultCompactPublicKeyMaximumWorkUnitCountPerPoll = 4_096;

type AcceptedSetupKeyRelationProofFamily = 'publicKeyShare' | 'sameSecret';

export type AcceptedSetupKeyRelationGenerationMode = 'fresh' | 'resumed';

export type CompactPublicKeyGenerationRuntimeStageIdentifier =
    | 'source-loading'
    | 'family-materialization'
    | 'post-lookup-response'
    | 'cross-epoch-response'
    | 'cfw'
    | 'pre-challenge-whir-sumcheck'
    | 'pre-challenge-whir-code-switch'
    | 'pre-challenge-whir-next-sumcheck-preparation'
    | 'pre-challenge-whir-base-fresh-response'
    | 'pre-challenge-whir-base-blinded-response'
    | 'main-whir-initial-preparation'
    | 'main-whir-sumcheck'
    | 'main-whir-code-switch'
    | 'main-whir-next-sumcheck-preparation'
    | 'main-whir-base-fresh-response'
    | 'main-whir-base-blinded-response';

export type CompactPublicKeyGenerationOperationOwnerIdentifier =
    | 'setup-generation-authorization'
    | 'reference-board-authorization'
    | 'setup-intent-authorization'
    | 'kernel-preparation'
    | 'kernel-poll'
    | 'storage-request-copy-and-decode'
    | 'storage-open'
    | 'storage-transaction'
    | 'storage-response-encode-and-supply'
    | 'storage-request-cleanup'
    | 'external-memory-accounting-copy'
    | 'transport-bindings-copy'
    | 'canonical-public-input-copy'
    | 'canonical-proof-copy'
    | 'selected-suite-release'
    | 'kernel-release'
    | 'kernel-cancellation';

export type CompactPublicKeyGenerationOperationObservation = Readonly<{
    checkpointSafeBoundaryOrdinal?: number;
    completedWorkUnitCount?: number;
    durationMilliseconds: number;
    finishedAtMilliseconds: number;
    firstOrdinal?: number;
    generationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
    operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier;
    pollKind?: 'progress' | 'storage-request-ready' | 'complete';
    precedingGenerationStageIdentifier?: CompactPublicKeyGenerationRuntimeStageIdentifier;
    startedAtMilliseconds: number;
    storageOwner?: CompactPublicKeyGenerationStorageOwner;
}>;

const compactPublicKeyGenerationRuntimeStageIdentifiers = Object.freeze([
    undefined,
    'source-loading',
    'family-materialization',
    'post-lookup-response',
    'cross-epoch-response',
    'cfw',
    'pre-challenge-whir-sumcheck',
    'pre-challenge-whir-code-switch',
    'pre-challenge-whir-next-sumcheck-preparation',
    'pre-challenge-whir-base-fresh-response',
    'pre-challenge-whir-base-blinded-response',
    'main-whir-initial-preparation',
    'main-whir-sumcheck',
    'main-whir-code-switch',
    'main-whir-next-sumcheck-preparation',
    'main-whir-base-fresh-response',
    'main-whir-base-blinded-response',
] as const);

const requireCompactPublicKeyGenerationRuntimeStageIdentifier = (
    stage: number,
): CompactPublicKeyGenerationRuntimeStageIdentifier => {
    const identifier = compactPublicKeyGenerationRuntimeStageIdentifiers[stage];
    if (identifier === undefined) {
        throw new CanonicalStreamInternalError(
            'The compact public-key generator exposed an unknown runtime stage.',
        );
    }
    return identifier;
};

export type AcceptedSetupCompactPublicKeyExternalMemoryOpening = Readonly<{
    runtimeBindingHash: Uint8Array<ArrayBuffer>;
    storageOwner: CompactPublicKeyGenerationStorageOwner;
}>;

export type AcceptedSetupCompactPublicKeyExternalMemoryOpener = (
    opening: AcceptedSetupCompactPublicKeyExternalMemoryOpening,
) =>
    | CommonProofExternalMemoryTransactionExecutor
    | Promise<CommonProofExternalMemoryTransactionExecutor>;

export type AcceptedSetupCompactPublicKeyGenerationInput = Readonly<{
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    kernel: TranscriptCoreKernel;
    maximumWorkUnitCountPerPoll?: number;
    observeOperation?: (
        observation: CompactPublicKeyGenerationOperationObservation,
    ) => void;
    openExternalMemory: AcceptedSetupCompactPublicKeyExternalMemoryOpener;
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    signal?: AbortSignal;
    workerKernel: BrowserActionStorageWorkerKernel;
    yieldControl?: () => Promise<void>;
}>;

export type CompactPublicKeyReferenceGenerationInput = Omit<
    AcceptedSetupCompactPublicKeyGenerationInput,
    'canonicalSuiteRecordBytes' | 'setupGenerationAuthority'
> &
    Readonly<{
        orderedPublicRandomnessCommitmentObjects: readonly VerifiedTranscriptObject[];
        orderedPublicRandomnessRevealObjects: readonly VerifiedTranscriptObject[];
        orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
    }>;

export type AcceptedSetupCompactPublicKeyGenerationStorageAccounting =
    Readonly<{
        actualUsage: CommonProofExternalMemoryUsageAccounting;
        browserStorage?: CommonProofBrowserStorageAccounting;
    }>;

export type AcceptedSetupCompactPublicKeyGenerationWorkerAccounting = Readonly<{
    browserToWasmStorageResponseByteLength: bigint;
    browserToWasmStorageResponseCount: bigint;
    canonicalOutputCopyByteLength: bigint;
    canonicalOutputCopyCount: bigint;
    finalWasmMemoryByteLength: number;
    initialWasmMemoryByteLength: number;
    maximumWasmMemoryByteLength: number;
    readResultTransferByteLength: bigint;
    readResultTransferCount: bigint;
    wasmToBrowserStorageRequestByteLength: bigint;
    wasmToBrowserStorageRequestCount: bigint;
}>;

export type GeneratedCompactPublicKeyReferenceProof = Readonly<{
    canonicalProofBytes: Uint8Array<ArrayBuffer>;
    canonicalPublicInputBytes: Uint8Array<ArrayBuffer>;
    externalMemoryAccounting: Readonly<{
        cfw: AcceptedSetupCompactPublicKeyGenerationStorageAccounting;
        responseTrees: AcceptedSetupCompactPublicKeyGenerationStorageAccounting;
        worker: AcceptedSetupCompactPublicKeyGenerationWorkerAccounting;
    }>;
    observedSafeBoundaryOrdinals: readonly number[];
    transportBindings: CompactPublicKeyTransportBindings;
}>;

export type GeneratedAcceptedSetupCompactPublicKeyProof =
    GeneratedCompactPublicKeyReferenceProof;

const generatedAcceptedSetupKeyRelationProofBrand = Symbol(
    'generated accepted-setup key-relation proof',
);

/** Same-worker custody of one generated proof until positive package verification. */
export type GeneratedAcceptedSetupKeyRelationProof = Readonly<{
    readonly [generatedAcceptedSetupKeyRelationProofBrand]: true;
    copyExternalMemoryAccounting(): CommonProofGenerationExternalMemoryAccounting;
    copyProofDescriptorBytes(): Uint8Array<ArrayBuffer>;
    release(): void;
}>;

type GeneratedAcceptedSetupKeyRelationProofRecord = Readonly<{
    capability: ClosedWorkerGeneratedCommonProofCapability;
    context: TranscriptCoreKernelCommandRuntime;
    externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting;
    family: AcceptedSetupKeyRelationProofFamily;
    kernel: TranscriptCoreKernel;
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
    statementSourceHandle: number;
}>;

const generatedProofRecords = new WeakMap<
    GeneratedAcceptedSetupKeyRelationProof,
    GeneratedAcceptedSetupKeyRelationProofRecord
>();

export type AcceptedSetupKeyRelationGenerationInput = Readonly<{
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    generationMode: AcceptedSetupKeyRelationGenerationMode;
    kernel: TranscriptCoreKernel;
    openProofGenerationExecution: CommonProofGenerationExecutionOpener;
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

export type AcceptedSetupSameSecretGenerationInput =
    AcceptedSetupKeyRelationGenerationInput &
        Readonly<{
            vssLowDegreeEvidence: VerifiedVssLowDegreeEvidence;
        }>;

type AcceptedSetupKeyRelationGenerationRuntimeInput =
    AcceptedSetupKeyRelationGenerationInput &
        Partial<
            Pick<AcceptedSetupSameSecretGenerationInput, 'vssLowDegreeEvidence'>
        >;

export type GeneratedAcceptedSetupKeyRelationProofVerificationInput = Omit<
    AcceptedSetupProofVerificationInput,
    'canonicalApplicationStatementBytes'
> &
    Readonly<{
        generatedProof: GeneratedAcceptedSetupKeyRelationProof;
    }>;

export type GeneratedAcceptedSetupSameSecretProofVerificationInput =
    GeneratedAcceptedSetupKeyRelationProofVerificationInput;

type GeneratedAcceptedSetupKeyRelationProofVerificationRuntimeInput =
    GeneratedAcceptedSetupKeyRelationProofVerificationInput;

type GeneratedAcceptedSetupKeyRelationPackageContributionInput = Readonly<{
    generatedProof: GeneratedAcceptedSetupKeyRelationProof;
    packageBuilder: AcceptedSetupPackageBuilder;
}>;

type PrepareSetupKeyRelationGeneration = (
    selectedSuiteHandle: number,
    setupGenerationAuthorityHandle: number,
    vssLowDegreeEvidenceHandle: number | undefined,
    actionRandomnessHandle: number,
    stateVerifierSessionHandle: number,
    stateVerifierSessionCapabilityPointer: number,
    stateVerifierSessionCapabilityByteLength: number,
    verifiedReservationHandle: number,
    boardVerifierSessionHandle: number,
    boardVerifierSessionCapabilityPointer: number,
    boardVerifierSessionCapabilityByteLength: number,
    setupIntentObjectHandle: number,
    checkpointLineageIdentifierPointer: number,
    checkpointLineageIdentifierByteLength: number,
    statementSourceHandleOutputPointer: number,
    statusPointer: number,
) => number;

type SelectedSuiteKernel = Readonly<{
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_select_suite']
    >;
}>;

type SetupKeyRelationGenerationKernel = SelectedSuiteKernel &
    Readonly<{
        cancelGeneratedSource: NonNullable<
            TranscriptCoreKernelExports['sealed_lattice_same_secret_generation_cancel']
        >;
        contributePackage: NonNullable<
            TranscriptCoreKernelExports['sealed_lattice_same_secret_generation_contribute_package']
        >;
        discardStatementSource: NonNullable<
            TranscriptCoreKernelExports['sealed_lattice_setup_key_relation_generation_statement_discard']
        >;
        prepareGeneration: PrepareSetupKeyRelationGeneration;
        prepareResumedGeneration: PrepareSetupKeyRelationGeneration;
        supplyAuthenticatedTranscriptPrefix?: NonNullable<
            TranscriptCoreKernelExports['sealed_lattice_same_secret_generation_supply_authenticated_transcript_prefix']
        >;
    }>;

type CompactPublicKeyGenerationPreparationKernel = SelectedSuiteKernel &
    Readonly<{
        prepareGeneration: NonNullable<
            TranscriptCoreKernelExports['sealed_lattice_compact_public_key_share_prepare_generation']
        >;
    }>;

type CompactPublicKeyReferenceGenerationPreparationKernel = Readonly<{
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_compact_public_key_reference_prepare_generation']
    >;
}>;

const createStatusBoundary = (
    family: AcceptedSetupKeyRelationProofFamily,
): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage: `The accepted-setup ${family} generator failed internally.`,
        unknownStatusMessage: `The accepted-setup ${family} generator returned an unknown status code.`,
    });

const requireLiveHandle = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return value;
};

const requireOwnedFixedBytes = (
    value: Uint8Array,
    expectedByteLength: number,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireCanonicalSuiteRecordBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireGenerationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
    family: AcceptedSetupKeyRelationProofFamily,
): SetupKeyRelationGenerationKernel => {
    const {
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
        sealed_lattice_setup_key_relation_generation_statement_discard:
            discardStatementSource,
    } = context.wasmExports;
    const rawPrepareGeneration =
        family === 'sameSecret'
            ? context.wasmExports.sealed_lattice_same_secret_prepare_generation
            : context.wasmExports
                  .sealed_lattice_public_key_share_prepare_generation;
    const rawPrepareResumedGeneration =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_same_secret_prepare_resumed_generation
            : context.wasmExports
                  .sealed_lattice_public_key_share_prepare_resumed_generation;
    const cancelGeneratedSource =
        family === 'sameSecret'
            ? context.wasmExports.sealed_lattice_same_secret_generation_cancel
            : context.wasmExports
                  .sealed_lattice_public_key_share_generation_cancel;
    const contributePackage =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_same_secret_generation_contribute_package
            : context.wasmExports
                  .sealed_lattice_public_key_share_generation_contribute_package;
    const supplyAuthenticatedTranscriptPrefix =
        family === 'sameSecret'
            ? context.wasmExports
                  .sealed_lattice_same_secret_generation_supply_authenticated_transcript_prefix
            : undefined;
    if (
        typeof cancelGeneratedSource !== 'function' ||
        typeof contributePackage !== 'function' ||
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function' ||
        typeof discardStatementSource !== 'function' ||
        typeof rawPrepareGeneration !== 'function' ||
        typeof rawPrepareResumedGeneration !== 'function' ||
        (family === 'sameSecret' &&
            typeof supplyAuthenticatedTranscriptPrefix !== 'function')
    ) {
        throw new CanonicalStreamInternalError(
            `The transcript-core kernel lacks the accepted-setup ${family} generation boundary.`,
        );
    }
    const normalizePreparation = (
        rawPreparation:
            | NonNullable<
                  TranscriptCoreKernelExports['sealed_lattice_same_secret_prepare_generation']
              >
            | NonNullable<
                  TranscriptCoreKernelExports['sealed_lattice_same_secret_prepare_resumed_generation']
              >
            | NonNullable<
                  TranscriptCoreKernelExports['sealed_lattice_public_key_share_prepare_generation']
              >
            | NonNullable<
                  TranscriptCoreKernelExports['sealed_lattice_public_key_share_prepare_resumed_generation']
              >,
    ): PrepareSetupKeyRelationGeneration =>
        family === 'sameSecret'
            ? (
                  selectedSuiteHandle,
                  setupGenerationAuthorityHandle,
                  vssLowDegreeEvidenceHandle,
                  ...remainingArguments
              ) => {
                  if (vssLowDegreeEvidenceHandle === undefined) {
                      throw new CanonicalStreamInternalError(
                          'The same-secret generator lacks its VSS low-degree evidence.',
                      );
                  }
                  return rawPreparation(
                      selectedSuiteHandle,
                      setupGenerationAuthorityHandle,
                      vssLowDegreeEvidenceHandle,
                      ...remainingArguments,
                  );
              }
            : (
                  selectedSuiteHandle,
                  setupGenerationAuthorityHandle,
                  _vssLowDegreeEvidenceHandle,
                  ...remainingArguments
              ) =>
                  (
                      rawPreparation as NonNullable<
                          TranscriptCoreKernelExports['sealed_lattice_public_key_share_prepare_generation']
                      >
                  )(
                      selectedSuiteHandle,
                      setupGenerationAuthorityHandle,
                      ...remainingArguments,
                  );
    return Object.freeze({
        cancelGeneratedSource,
        contributePackage,
        discardStatementSource,
        prepareGeneration: normalizePreparation(rawPrepareGeneration),
        prepareResumedGeneration: normalizePreparation(
            rawPrepareResumedGeneration,
        ),
        releaseSelectedSuite,
        selectSuite,
        ...(supplyAuthenticatedTranscriptPrefix === undefined
            ? {}
            : { supplyAuthenticatedTranscriptPrefix }),
    });
};

const requireCompactPublicKeyGenerationPreparationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): CompactPublicKeyGenerationPreparationKernel => {
    const {
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
        sealed_lattice_compact_public_key_share_prepare_generation:
            prepareGeneration,
    } = context.wasmExports;
    if (
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function' ||
        typeof prepareGeneration !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the compact public-key generation preparation boundary.',
        );
    }
    return Object.freeze({
        prepareGeneration,
        releaseSelectedSuite,
        selectSuite,
    });
};

const requireCompactPublicKeyReferenceGenerationPreparationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): CompactPublicKeyReferenceGenerationPreparationKernel => {
    const {
        sealed_lattice_compact_public_key_reference_prepare_generation:
            prepareGeneration,
    } = context.wasmExports;
    if (typeof prepareGeneration !== 'function') {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the non-authorizing compact public-key reference generation boundary.',
        );
    }
    return Object.freeze({ prepareGeneration });
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: SelectedSuiteKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive(
        'accepted-setup key-relation selected-suite acquisition',
        () => {
            const suiteBytes = requireCanonicalSuiteRecordBytes(
                input.canonicalSuiteRecordBytes,
            );
            const suitePointer = input.memoryBoundary.copy(suiteBytes);
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            let selectedSuiteHandle = 0;
            try {
                selectedSuiteHandle = input.kernel.selectSuite(
                    suitePointer,
                    suiteBytes.byteLength,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return requireLiveHandle(
                    selectedSuiteHandle,
                    'The selected-suite handle',
                );
            } catch (error) {
                if (selectedSuiteHandle !== 0) {
                    input.kernel.releaseSelectedSuite(selectedSuiteHandle);
                }
                throw error;
            } finally {
                suiteBytes.fill(0);
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    suitePointer,
                    suiteBytes.byteLength,
                );
            }
        },
    );

const releaseSelectedSuite = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: SelectedSuiteKernel;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.kernel.releaseSelectedSuite(input.handle),
    );
    input.statusBoundary.throwIfError(status);
};

const discardStatementSource = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: SetupKeyRelationGenerationKernel;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'accepted-setup key-relation statement-source discard',
        () => input.kernel.discardStatementSource(input.handle),
    );
    if (status >>> 0 === refusalReasonCodes.consumedState) {
        return;
    }
    input.statusBoundary.throwIfError(status);
};

const requireGeneratedProofRecord = (
    proof: GeneratedAcceptedSetupKeyRelationProof,
): GeneratedAcceptedSetupKeyRelationProofRecord => {
    const record =
        typeof proof === 'object' && proof !== null
            ? generatedProofRecords.get(proof)
            : undefined;
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const cancelGeneratedSource = (input: {
    capability: ClosedWorkerGeneratedCommonProofCapability;
    context: TranscriptCoreKernelCommandRuntime;
    family: AcceptedSetupKeyRelationProofFamily;
    statementSourceHandle: number;
}): void => {
    const kernel = requireGenerationKernel(input.context, input.family);
    const status = applyClosedWorkerGeneratedCommonProofCapability(
        input.capability,
        input.context,
        (generatedCommonProofHandle) => {
            const result = input.context.runExclusive(
                `accepted-setup ${input.family} generated-source cancellation`,
                () =>
                    kernel.cancelGeneratedSource(
                        input.statementSourceHandle,
                        generatedCommonProofHandle,
                    ),
            );
            return Object.freeze({
                consumed: result === 0,
                result,
            });
        },
    );
    createStatusBoundary(input.family).throwIfError(status);
};

const retireConsumedGeneratedProof = (
    proof: GeneratedAcceptedSetupKeyRelationProof,
    record: GeneratedAcceptedSetupKeyRelationProofRecord,
): void => {
    record.proofDescriptorBytes.fill(0);
    generatedProofRecords.delete(proof);
};

const copyExternalMemoryUsageAccounting = (
    accounting: CommonProofGenerationExternalMemoryAccounting['actualUsage'],
): CommonProofGenerationExternalMemoryAccounting['actualUsage'] =>
    Object.freeze({ ...accounting });

const copyExternalMemoryAccounting = (
    accounting: CommonProofGenerationExternalMemoryAccounting,
): CommonProofGenerationExternalMemoryAccounting =>
    Object.freeze({
        actualUsage: copyExternalMemoryUsageAccounting(accounting.actualUsage),
        ...(accounting.browserStorage === undefined
            ? {}
            : {
                  browserStorage: Object.freeze({
                      ...accounting.browserStorage,
                  }),
              }),
        compiledRequirement: Object.freeze({
            ...accounting.compiledRequirement,
        }),
        ...(accounting.deterministicPrefixReplayUsage === undefined
            ? {}
            : {
                  deterministicPrefixReplayUsage:
                      copyExternalMemoryUsageAccounting(
                          accounting.deterministicPrefixReplayUsage,
                      ),
              }),
        ...(accounting.workerTransport === undefined
            ? {}
            : {
                  workerTransport: Object.freeze({
                      ...accounting.workerTransport,
                  }),
              }),
    });

const createGeneratedProof = (
    record: GeneratedAcceptedSetupKeyRelationProofRecord,
): GeneratedAcceptedSetupKeyRelationProof => {
    const proof: GeneratedAcceptedSetupKeyRelationProof = Object.freeze({
        [generatedAcceptedSetupKeyRelationProofBrand]: true as const,
        copyExternalMemoryAccounting: () =>
            copyExternalMemoryAccounting(
                requireGeneratedProofRecord(proof).externalMemoryAccounting,
            ),
        copyProofDescriptorBytes: () =>
            requireGeneratedProofRecord(proof).proofDescriptorBytes.slice(),
        release: (): void => {
            const activeRecord = requireGeneratedProofRecord(proof);
            cancelGeneratedSource({
                capability: activeRecord.capability,
                context: activeRecord.context,
                family: activeRecord.family,
                statementSourceHandle: activeRecord.statementSourceHandle,
            });
            retireConsumedGeneratedProof(proof, activeRecord);
        },
    });
    generatedProofRecords.set(proof, record);
    return proof;
};

const generateAcceptedSetupKeyRelationInClosedWorker = async (
    family: AcceptedSetupKeyRelationProofFamily,
    input: AcceptedSetupKeyRelationGenerationRuntimeInput,
): Promise<GeneratedAcceptedSetupKeyRelationProof> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Accepted-setup key-relation generation may only run inside the dedicated WASM worker.',
        );
    }
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        typeof input.openProofGenerationExecution !== 'function' ||
        (family === 'sameSecret') !== (input.vssLowDegreeEvidence !== undefined)
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireGenerationKernel(context, family);
    const statusBoundary = createStatusBoundary(family);
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: `accepted-setup ${family} generation`,
    });
    const checkpointLineageIdentifier = requireOwnedFixedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const setupGenerationAuthorization =
        resolveSetupGenerationAuthorityKernelAuthorization(
            input.setupGenerationAuthority,
            context,
        );
    const setupIntentAuthorization =
        resolveOrderedVerifiedBoardObjectAuthorization({
            context,
            expectedObjectCount: 1,
            kernel: input.kernel,
            objects: [input.setupIntentObject],
        });
    if (
        setupIntentAuthorization.handleBytes.byteLength !== wasm32WordByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The accepted-setup key-relation generation authorities do not belong to one WASM worker.',
        );
    }

    let selectedSuiteHandle = 0;
    let statementSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let proofDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let result: GeneratedAcceptedSetupKeyRelationProof | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        let prepared:
            | Readonly<{
                  adapterHandle: number;
                  statementSourceHandle: number;
              }>
            | undefined;
        await withClosedWorkerProductionOperationAuthority(
            input.workerKernel,
            input.productionOperationIdentifiers,
            (productionOperationAuthority) =>
                productionOperationAuthority.withExactKernelAuthorization(
                    (authorization) => {
                        if (
                            authorization.kernel !== input.kernel ||
                            authorization.actionRandomnessContext.memory !==
                                context.memory ||
                            authorization.stateReservationCapabilityMemory !==
                                context.memory ||
                            authorization.stateReservationCapabilityPointer <=
                                0 ||
                            authorization.stateReservationCapabilityPointer +
                                verifierCapabilityByteLength >
                                context.memory.buffer.byteLength
                        ) {
                            throw new CanonicalStreamInternalError(
                                'The accepted-setup key-relation generation authorities do not belong to one WASM worker.',
                            );
                        }
                        prepared = context.runExclusive(
                            `accepted-setup ${family} generation preparation`,
                            () => {
                                const checkpointPointer = memoryBoundary.copy(
                                    checkpointLineageIdentifier,
                                );
                                const metadataPointer =
                                    memoryBoundary.allocateZeroedWords(2);
                                try {
                                    const prepare =
                                        input.generationMode === 'fresh'
                                            ? kernel.prepareGeneration
                                            : kernel.prepareResumedGeneration;
                                    const prepareWithEvidenceHandle = (
                                        vssLowDegreeEvidenceHandle:
                                            | number
                                            | undefined,
                                    ): number =>
                                        prepare(
                                            selectedSuiteHandle,
                                            setupGenerationAuthorization.handle,
                                            vssLowDegreeEvidenceHandle,
                                            authorization.actionRandomnessHandle,
                                            authorization.stateVerifierSessionHandle,
                                            authorization.stateReservationCapabilityPointer,
                                            verifierCapabilityByteLength,
                                            authorization.stateReservationHandle,
                                            setupIntentAuthorization.sessionHandle,
                                            setupIntentAuthorization.capabilityPointer,
                                            verifierCapabilityByteLength,
                                            new DataView(
                                                setupIntentAuthorization
                                                    .handleBytes.buffer,
                                                setupIntentAuthorization
                                                    .handleBytes.byteOffset,
                                                setupIntentAuthorization
                                                    .handleBytes.byteLength,
                                            ).getUint32(0, true),
                                            checkpointPointer,
                                            checkpointLineageIdentifier.byteLength,
                                            metadataPointer,
                                            metadataPointer +
                                                wasm32WordByteLength,
                                        );
                                    const adapterHandle =
                                        family === 'sameSecret'
                                            ? consumeVerifiedVssLowDegreeEvidence(
                                                  {
                                                      consume:
                                                          prepareWithEvidenceHandle,
                                                      context,
                                                      evidence:
                                                          input.vssLowDegreeEvidence ??
                                                          (() => {
                                                              throw new CanonicalStreamRefusalError(
                                                                  'wrongContext',
                                                              );
                                                          })(),
                                                      kernel: input.kernel,
                                                  },
                                              )
                                            : prepareWithEvidenceHandle(
                                                  undefined,
                                              );
                                    const [sourceHandle, status] =
                                        memoryBoundary.readWords(
                                            metadataPointer,
                                            2,
                                        );
                                    statusBoundary.throwIfError(status);
                                    return Object.freeze({
                                        adapterHandle: requireLiveHandle(
                                            adapterHandle,
                                            `The accepted-setup ${family} generation family-adapter handle`,
                                        ),
                                        statementSourceHandle:
                                            requireLiveHandle(
                                                sourceHandle,
                                                `The accepted-setup ${family} statement-source handle`,
                                            ),
                                    });
                                } finally {
                                    memoryBoundary.zeroAndDeallocate(
                                        metadataPointer,
                                        wasm32WordByteLength * 2,
                                    );
                                    memoryBoundary.zeroAndDeallocate(
                                        checkpointPointer,
                                        checkpointLineageIdentifier.byteLength,
                                    );
                                }
                            },
                        );
                    },
                ),
        );
        if (prepared === undefined) {
            throw new CanonicalStreamInternalError(
                'The production operation completed without a key-relation adapter.',
            );
        }
        statementSourceHandle = prepared.statementSourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName: `accepted-setup ${family} generation selected-suite release`,
            statusBoundary,
        });
        selectedSuiteHandle = 0;

        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const authenticatedTranscriptPrefixAuthority =
            family === 'sameSecret'
                ? Object.freeze({
                      supply: (operationHandle: number): void => {
                          const supplyAuthenticatedTranscriptPrefix =
                              kernel.supplyAuthenticatedTranscriptPrefix;
                          if (
                              supplyAuthenticatedTranscriptPrefix === undefined
                          ) {
                              throw new CanonicalStreamInternalError(
                                  'The same-secret generator lost its authenticated transcript-prefix boundary.',
                              );
                          }
                          context.runExclusive(
                              'accepted-setup same-secret authenticated transcript prefix',
                              () =>
                                  statusBoundary.throwIfError(
                                      supplyAuthenticatedTranscriptPrefix(
                                          statementSourceHandle,
                                          operationHandle,
                                      ),
                                  ),
                          );
                      },
                  })
                : undefined;
        const execution =
            await runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener(
                adapterForRun,
                input.openProofGenerationExecution,
                authenticatedTranscriptPrefixAuthority,
            );
        generatedCapability = execution.generatedCapability;
        proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor({
            kernel: input.kernel,
            outputChunkByteLengths: execution.outputChunkByteLengths,
            outputStore: execution.outputStore,
            proofFamilyLabel:
                family === 'sameSecret' ? 'same-secret' : 'public-key-share',
            streamDomain:
                family === 'sameSecret'
                    ? canonicalStreamDomains.sameSecretProof
                    : canonicalStreamDomains.publicKeyShareProof,
        });
        result = createGeneratedProof(
            Object.freeze({
                capability: generatedCapability,
                context,
                externalMemoryAccounting: execution.externalMemoryAccounting,
                family,
                kernel: input.kernel,
                proofDescriptorBytes,
                statementSourceHandle,
            }),
        );
        generatedCapability = undefined;
        statementSourceHandle = 0;
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    } finally {
        checkpointLineageIdentifier.fill(0);
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                operationName: `accepted-setup ${family} selected-suite failure release`,
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (generatedCapability !== undefined && statementSourceHandle !== 0) {
        try {
            cancelGeneratedSource({
                capability: generatedCapability,
                context,
                family,
                statementSourceHandle,
            });
            generatedCapability = undefined;
            statementSourceHandle = 0;
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (generatedCapability !== undefined) {
        try {
            generatedCapability.release();
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (statementSourceHandle !== 0) {
        try {
            discardStatementSource({
                context,
                handle: statementSourceHandle,
                kernel,
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamCleanupError(
            operationFailure,
            new CanonicalStreamInternalError(
                'Accepted-setup key-relation generation failed to retire all worker-owned authority.',
                Object.freeze({ cleanupFailures }),
            ),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'Accepted-setup key-relation generation completed without its proof authority.',
        );
    }
    return result;
};

/** Generates one same-secret proof for later positive package verification. */
export const generateAcceptedSetupSameSecretInClosedWorker = (
    input: AcceptedSetupSameSecretGenerationInput,
): Promise<GeneratedAcceptedSetupKeyRelationProof> =>
    generateAcceptedSetupKeyRelationInClosedWorker('sameSecret', input);

/**
 * Generates one public-key-share proof for later positive package verification.
 */
export const generateAcceptedSetupPublicKeyShareInClosedWorker = (
    input: AcceptedSetupKeyRelationGenerationInput,
): Promise<GeneratedAcceptedSetupKeyRelationProof> =>
    generateAcceptedSetupKeyRelationInClosedWorker('publicKeyShare', input);

const requireCompactPublicKeyExternalMemoryExecutor = (
    value: CommonProofExternalMemoryTransactionExecutor,
): CommonProofExternalMemoryTransactionExecutor => {
    if (
        typeof value !== 'object' ||
        value === null ||
        typeof value.executeTransaction !== 'function' ||
        (value.copyBrowserStorageAccounting !== undefined &&
            typeof value.copyBrowserStorageAccounting !== 'function')
    ) {
        throw new CanonicalStreamInternalError(
            'The compact public-key external-memory opener returned a malformed executor.',
        );
    }
    return value;
};

const compactPublicKeyStorageAccounting = (
    actualUsage: CommonProofExternalMemoryUsageAccounting,
    executor: CommonProofExternalMemoryTransactionExecutor | undefined,
): AcceptedSetupCompactPublicKeyGenerationStorageAccounting => {
    const browserStorage = executor?.copyBrowserStorageAccounting?.();
    return Object.freeze({
        actualUsage,
        ...(browserStorage === undefined ? {} : { browserStorage }),
    });
};

type CompactPublicKeyGenerationRequest =
    | Readonly<{
          input: AcceptedSetupCompactPublicKeyGenerationInput;
          kind: 'acceptedSetup';
      }>
    | Readonly<{
          input: CompactPublicKeyReferenceGenerationInput;
          kind: 'reference';
      }>;

type CompactPublicKeyGenerationOperationObservationDetails = Omit<
    CompactPublicKeyGenerationOperationObservation,
    | 'durationMilliseconds'
    | 'finishedAtMilliseconds'
    | 'operationOwnerIdentifier'
    | 'startedAtMilliseconds'
>;

const generateCompactPublicKeyInClosedWorker = async (
    generationRequest: CompactPublicKeyGenerationRequest,
): Promise<GeneratedCompactPublicKeyReferenceProof> => {
    const { input } = generationRequest;
    const observeCompletedOperation = (
        operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier,
        startedAtMilliseconds: number,
        details: CompactPublicKeyGenerationOperationObservationDetails = {},
    ): void => {
        if (input.observeOperation === undefined) {
            return;
        }
        const finishedAtMilliseconds = performance.now();
        input.observeOperation(
            Object.freeze({
                ...details,
                durationMilliseconds:
                    finishedAtMilliseconds - startedAtMilliseconds,
                finishedAtMilliseconds,
                operationOwnerIdentifier,
                startedAtMilliseconds,
            }),
        );
    };
    const runObservedOperation = <Result>(
        operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier,
        operation: () => Result,
        describeResult?: (
            result: Result,
        ) => CompactPublicKeyGenerationOperationObservationDetails,
    ): Result => {
        if (input.observeOperation === undefined) {
            return operation();
        }
        const startedAtMilliseconds = performance.now();
        const result = operation();
        observeCompletedOperation(
            operationOwnerIdentifier,
            startedAtMilliseconds,
            describeResult?.(result),
        );
        return result;
    };
    const runObservedAsyncOperation = async <Result>(
        operationOwnerIdentifier: CompactPublicKeyGenerationOperationOwnerIdentifier,
        operation: () => Promise<Result>,
        describeResult?: (
            result: Result,
        ) => CompactPublicKeyGenerationOperationObservationDetails,
    ): Promise<Result> => {
        if (input.observeOperation === undefined) {
            return await operation();
        }
        const startedAtMilliseconds = performance.now();
        const result = await operation();
        observeCompletedOperation(
            operationOwnerIdentifier,
            startedAtMilliseconds,
            describeResult?.(result),
        );
        return result;
    };
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Accepted-setup compact public-key generation may only run inside the dedicated WASM worker.',
        );
    }
    if (typeof input.openExternalMemory !== 'function') {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const maximumWorkUnitCountPerPoll =
        input.maximumWorkUnitCountPerPoll ??
        defaultCompactPublicKeyMaximumWorkUnitCountPerPoll;
    if (
        !Number.isSafeInteger(maximumWorkUnitCountPerPoll) ||
        maximumWorkUnitCountPerPoll <= 0 ||
        maximumWorkUnitCountPerPoll > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamResourceError(
            'The compact public-key generation work-unit bound must be a positive unsigned 32-bit integer.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const preparationKernel =
        generationRequest.kind === 'acceptedSetup'
            ? requireCompactPublicKeyGenerationPreparationKernel(context)
            : undefined;
    const referencePreparationKernel =
        generationRequest.kind === 'reference'
            ? requireCompactPublicKeyReferenceGenerationPreparationKernel(
                  context,
              )
            : undefined;
    const generationKernel = new CompactPublicKeyGenerationKernelBoundary(
        context,
    );
    const statusBoundary = createStatusBoundary('publicKeyShare');
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'accepted-setup compact public-key generation',
    });
    const checkpointLineageIdentifier = requireOwnedFixedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const setupGenerationAuthorization =
        generationRequest.kind === 'acceptedSetup'
            ? runObservedOperation('setup-generation-authorization', () =>
                  resolveSetupGenerationAuthorityKernelAuthorization(
                      generationRequest.input.setupGenerationAuthority,
                      context,
                  ),
              )
            : undefined;
    const referenceBoardAuthorization =
        generationRequest.kind === 'reference'
            ? runObservedOperation('reference-board-authorization', () =>
                  resolveAggregatePublicRandomnessBoardAuthorization({
                      context,
                      kernel: input.kernel,
                      orderedCommitmentObjects:
                          generationRequest.input
                              .orderedPublicRandomnessCommitmentObjects,
                      orderedRevealObjects:
                          generationRequest.input
                              .orderedPublicRandomnessRevealObjects,
                      orderedSetupIntentObjects:
                          generationRequest.input.orderedSetupIntentObjects,
                  }),
              )
            : undefined;
    const setupIntentAuthorization = runObservedOperation(
        'setup-intent-authorization',
        () =>
            resolveOrderedVerifiedBoardObjectAuthorization({
                context,
                expectedObjectCount: 1,
                kernel: input.kernel,
                objects: [input.setupIntentObject],
            }),
    );
    if (
        setupIntentAuthorization.handleBytes.byteLength !==
            wasm32WordByteLength ||
        (referenceBoardAuthorization !== undefined &&
            (referenceBoardAuthorization.sessionHandle !==
                setupIntentAuthorization.sessionHandle ||
                referenceBoardAuthorization.capabilityPointer !==
                    setupIntentAuthorization.capabilityPointer ||
                referenceBoardAuthorization.handleBytes.byteLength !==
                    foundationProfile.participantCount *
                        3 *
                        wasm32WordByteLength))
    ) {
        throw new CanonicalStreamInternalError(
            'The compact public-key generation authorities do not belong to one WASM worker.',
        );
    }

    const initialWasmMemoryByteLength = context.memory.buffer.byteLength;
    let maximumWasmMemoryByteLength = initialWasmMemoryByteLength;
    const observeWasmMemory = (): void => {
        const currentByteLength = context.memory.buffer.byteLength;
        if (currentByteLength > foundationProfile.maximumWasmMemoryByteLength) {
            throw new CanonicalStreamResourceError(
                'The compact public-key generator exceeded the absolute WASM memory bound.',
            );
        }
        maximumWasmMemoryByteLength = Math.max(
            maximumWasmMemoryByteLength,
            currentByteLength,
        );
    };
    observeWasmMemory();

    const requestSequences: Readonly<
        Record<
            CompactPublicKeyGenerationStorageOwner,
            CommonProofStorageRequestSequence
        >
    > = Object.freeze({
        cfw: new CommonProofStorageRequestSequence(),
        responseTrees: new CommonProofStorageRequestSequence(),
    });
    const externalMemoryExecutors = new Map<
        CompactPublicKeyGenerationStorageOwner,
        CommonProofExternalMemoryTransactionExecutor
    >();
    const observedSafeBoundaryOrdinals: number[] = [];
    const observedSafeBoundarySet = new Set<number>();
    const yieldControl = input.yieldControl ?? yieldBrowserWorkerTurn;

    let browserToWasmStorageResponseByteLength = 0n;
    let browserToWasmStorageResponseCount = 0n;
    let readResultTransferByteLength = 0n;
    let readResultTransferCount = 0n;
    let wasmToBrowserStorageRequestByteLength = 0n;
    let wasmToBrowserStorageRequestCount = 0n;
    let selectedSuiteHandle = 0;
    let operationHandle = 0;
    let operationReleased = false;
    let canonicalProofBytes: Uint8Array<ArrayBuffer> | undefined;
    let canonicalPublicInputBytes: Uint8Array<ArrayBuffer> | undefined;
    let transportBindings: CompactPublicKeyTransportBindings | undefined;
    let reusableStorageResponseBuffer: Uint8Array<ArrayBuffer> | undefined;
    let result: GeneratedCompactPublicKeyReferenceProof | undefined;
    let operationFailure: unknown;
    let lastSuccessfulGenerationPollKind:
        | 'none'
        | 'progress'
        | 'storage-request-ready'
        | 'complete' = 'none';
    let lastSuccessfulGenerationPollStage = 0;
    let lastSuccessfulGenerationPollFirstOrdinal = 0;
    let lastSuccessfulGenerationPollCompletedWorkUnitCount = 0;
    let lastSuccessfulGenerationPollStorageOwner:
        | CompactPublicKeyGenerationStorageOwner
        | undefined;

    const lastSuccessfulGenerationPollDescription = (): string => {
        switch (lastSuccessfulGenerationPollKind) {
            case 'none':
                return 'no successful poll';
            case 'progress':
                return `progress stage ${String(lastSuccessfulGenerationPollStage)}, first ordinal ${String(lastSuccessfulGenerationPollFirstOrdinal)}, and ${String(lastSuccessfulGenerationPollCompletedWorkUnitCount)} completed work units`;
            case 'storage-request-ready':
                return `a ${lastSuccessfulGenerationPollStorageOwner ?? 'missing-owner'} storage request`;
            case 'complete':
                return 'the completion poll';
        }
    };

    try {
        if (generationRequest.kind === 'acceptedSetup') {
            if (
                preparationKernel === undefined ||
                setupGenerationAuthorization === undefined
            ) {
                throw new CanonicalStreamInternalError(
                    'The accepted-setup compact public-key preparation boundary is unavailable.',
                );
            }
            selectedSuiteHandle = selectSuite({
                canonicalSuiteRecordBytes:
                    generationRequest.input.canonicalSuiteRecordBytes,
                context,
                kernel: preparationKernel,
                memoryBoundary,
                statusBoundary,
            });
            await runObservedAsyncOperation('kernel-preparation', () =>
                withClosedWorkerProductionOperationAuthority(
                    input.workerKernel,
                    input.productionOperationIdentifiers,
                    (productionOperationAuthority) =>
                        productionOperationAuthority.withExactKernelAuthorization(
                            (authorization) => {
                                if (
                                    authorization.kernel !== input.kernel ||
                                    authorization.actionRandomnessContext
                                        .memory !== context.memory ||
                                    authorization.stateReservationCapabilityMemory !==
                                        context.memory ||
                                    authorization.stateReservationCapabilityPointer <=
                                        0 ||
                                    authorization.stateReservationCapabilityPointer +
                                        verifierCapabilityByteLength >
                                        context.memory.buffer.byteLength
                                ) {
                                    throw new CanonicalStreamInternalError(
                                        'The compact public-key generation authorities do not belong to one WASM worker.',
                                    );
                                }
                                operationHandle = context.runExclusive(
                                    'accepted-setup compact public-key generation preparation',
                                    () => {
                                        const checkpointPointer =
                                            memoryBoundary.copy(
                                                checkpointLineageIdentifier,
                                            );
                                        const statusPointer =
                                            memoryBoundary.allocateZeroedWords(
                                                1,
                                            );
                                        try {
                                            const handle =
                                                preparationKernel.prepareGeneration(
                                                    selectedSuiteHandle,
                                                    setupGenerationAuthorization.handle,
                                                    authorization.actionRandomnessHandle,
                                                    authorization.stateVerifierSessionHandle,
                                                    authorization.stateReservationCapabilityPointer,
                                                    verifierCapabilityByteLength,
                                                    authorization.stateReservationHandle,
                                                    setupIntentAuthorization.sessionHandle,
                                                    setupIntentAuthorization.capabilityPointer,
                                                    verifierCapabilityByteLength,
                                                    new DataView(
                                                        setupIntentAuthorization
                                                            .handleBytes.buffer,
                                                        setupIntentAuthorization
                                                            .handleBytes
                                                            .byteOffset,
                                                        setupIntentAuthorization
                                                            .handleBytes
                                                            .byteLength,
                                                    ).getUint32(0, true),
                                                    checkpointPointer,
                                                    checkpointLineageIdentifier.byteLength,
                                                    statusPointer,
                                                );
                                            const [status] =
                                                memoryBoundary.readWords(
                                                    statusPointer,
                                                    1,
                                                );
                                            statusBoundary.throwIfError(status);
                                            return requireLiveHandle(
                                                handle,
                                                'The compact public-key generation operation handle',
                                            );
                                        } finally {
                                            memoryBoundary.zeroAndDeallocate(
                                                statusPointer,
                                                wasm32WordByteLength,
                                            );
                                            memoryBoundary.zeroAndDeallocate(
                                                checkpointPointer,
                                                checkpointLineageIdentifier.byteLength,
                                            );
                                        }
                                    },
                                );
                            },
                        ),
                ),
            );
            runObservedOperation('selected-suite-release', () => {
                releaseSelectedSuite({
                    context,
                    handle: selectedSuiteHandle,
                    kernel: preparationKernel,
                    operationName:
                        'accepted-setup compact public-key generation selected-suite release',
                    statusBoundary,
                });
                selectedSuiteHandle = 0;
            });
        } else {
            if (
                referencePreparationKernel === undefined ||
                referenceBoardAuthorization === undefined
            ) {
                throw new CanonicalStreamInternalError(
                    'The compact public-key reference preparation boundary is unavailable.',
                );
            }
            await runObservedAsyncOperation('kernel-preparation', () =>
                withClosedWorkerProductionOperationAuthority(
                    input.workerKernel,
                    input.productionOperationIdentifiers,
                    (productionOperationAuthority) =>
                        productionOperationAuthority.withExactKernelAuthorization(
                            (authorization) => {
                                if (
                                    authorization.kernel !== input.kernel ||
                                    authorization.actionRandomnessContext
                                        .memory !== context.memory ||
                                    authorization.stateReservationCapabilityMemory !==
                                        context.memory ||
                                    authorization.stateReservationCapabilityPointer <=
                                        0 ||
                                    authorization.stateReservationCapabilityPointer +
                                        verifierCapabilityByteLength >
                                        context.memory.buffer.byteLength
                                ) {
                                    throw new CanonicalStreamInternalError(
                                        'The compact public-key reference authorities do not belong to one WASM worker.',
                                    );
                                }
                                operationHandle = context.runExclusive(
                                    'compact public-key reference generation preparation',
                                    () => {
                                        const orderedHandlesPointer =
                                            memoryBoundary.copy(
                                                referenceBoardAuthorization.handleBytes,
                                            );
                                        const checkpointPointer =
                                            memoryBoundary.copy(
                                                checkpointLineageIdentifier,
                                            );
                                        const statusPointer =
                                            memoryBoundary.allocateZeroedWords(
                                                1,
                                            );
                                        try {
                                            const handle =
                                                referencePreparationKernel.prepareGeneration(
                                                    referenceBoardAuthorization.sessionHandle,
                                                    referenceBoardAuthorization.capabilityPointer,
                                                    verifierCapabilityByteLength,
                                                    orderedHandlesPointer,
                                                    referenceBoardAuthorization
                                                        .handleBytes.byteLength,
                                                    authorization.actionRandomnessHandle,
                                                    authorization.stateVerifierSessionHandle,
                                                    authorization.stateReservationCapabilityPointer,
                                                    verifierCapabilityByteLength,
                                                    authorization.stateReservationHandle,
                                                    new DataView(
                                                        setupIntentAuthorization
                                                            .handleBytes.buffer,
                                                        setupIntentAuthorization
                                                            .handleBytes
                                                            .byteOffset,
                                                        setupIntentAuthorization
                                                            .handleBytes
                                                            .byteLength,
                                                    ).getUint32(0, true),
                                                    checkpointPointer,
                                                    checkpointLineageIdentifier.byteLength,
                                                    statusPointer,
                                                );
                                            const [status] =
                                                memoryBoundary.readWords(
                                                    statusPointer,
                                                    1,
                                                );
                                            statusBoundary.throwIfError(status);
                                            return requireLiveHandle(
                                                handle,
                                                'The compact public-key reference generation operation handle',
                                            );
                                        } finally {
                                            memoryBoundary.zeroAndDeallocate(
                                                statusPointer,
                                                wasm32WordByteLength,
                                            );
                                            memoryBoundary.zeroAndDeallocate(
                                                checkpointPointer,
                                                checkpointLineageIdentifier.byteLength,
                                            );
                                            memoryBoundary.zeroAndDeallocate(
                                                orderedHandlesPointer,
                                                referenceBoardAuthorization
                                                    .handleBytes.byteLength,
                                            );
                                        }
                                    },
                                );
                            },
                        ),
                ),
            );
        }
        if (operationHandle === 0) {
            throw new CanonicalStreamInternalError(
                'The operation completed without a compact public-key generator.',
            );
        }

        for (;;) {
            if (input.signal?.aborted === true) {
                throw new CanonicalStreamCancellationError();
            }
            let poll: ReturnType<
                CompactPublicKeyGenerationKernelBoundary['poll']
            >;
            const pollStartedAtMilliseconds =
                input.observeOperation === undefined ? 0 : performance.now();
            try {
                poll = generationKernel.poll(
                    operationHandle,
                    maximumWorkUnitCountPerPoll,
                );
            } catch (pollFailure) {
                const failedPollWasmMemoryByteLength =
                    context.memory.buffer.byteLength;
                throw new CanonicalStreamInternalError(
                    `The compact public-key generation kernel trapped after ${lastSuccessfulGenerationPollDescription()}; WASM memory held ${String(failedPollWasmMemoryByteLength)} bytes.`,
                    pollFailure,
                );
            }
            if (poll.kind === 'progress') {
                observeCompletedOperation(
                    'kernel-poll',
                    pollStartedAtMilliseconds,
                    Object.freeze({
                        ...(poll.checkpointSafeBoundaryOrdinal === undefined
                            ? {}
                            : {
                                  checkpointSafeBoundaryOrdinal:
                                      poll.checkpointSafeBoundaryOrdinal,
                              }),
                        completedWorkUnitCount: poll.completedWorkUnitCount,
                        firstOrdinal: poll.firstOrdinal,
                        generationStageIdentifier:
                            requireCompactPublicKeyGenerationRuntimeStageIdentifier(
                                poll.stage,
                            ),
                        pollKind: poll.kind,
                    }),
                );
            } else {
                const precedingGenerationStageIdentifier =
                    lastSuccessfulGenerationPollStage === 0
                        ? undefined
                        : requireCompactPublicKeyGenerationRuntimeStageIdentifier(
                              lastSuccessfulGenerationPollStage,
                          );
                observeCompletedOperation(
                    'kernel-poll',
                    pollStartedAtMilliseconds,
                    Object.freeze({
                        pollKind: poll.kind,
                        ...(precedingGenerationStageIdentifier === undefined
                            ? {}
                            : { precedingGenerationStageIdentifier }),
                        ...(poll.kind === 'storage-request-ready'
                            ? { storageOwner: poll.storageOwner }
                            : {}),
                    }),
                );
            }
            lastSuccessfulGenerationPollKind = poll.kind;
            if (poll.kind === 'progress') {
                lastSuccessfulGenerationPollStage = poll.stage;
                lastSuccessfulGenerationPollFirstOrdinal = poll.firstOrdinal;
                lastSuccessfulGenerationPollCompletedWorkUnitCount =
                    poll.completedWorkUnitCount;
                lastSuccessfulGenerationPollStorageOwner = undefined;
            } else if (poll.kind === 'storage-request-ready') {
                lastSuccessfulGenerationPollStorageOwner = poll.storageOwner;
            } else {
                lastSuccessfulGenerationPollStorageOwner = undefined;
            }
            observeWasmMemory();
            if (poll.kind === 'progress') {
                if (
                    poll.checkpointSafeBoundaryOrdinal !== undefined &&
                    !observedSafeBoundarySet.has(
                        poll.checkpointSafeBoundaryOrdinal,
                    )
                ) {
                    observedSafeBoundarySet.add(
                        poll.checkpointSafeBoundaryOrdinal,
                    );
                    observedSafeBoundaryOrdinals.push(
                        poll.checkpointSafeBoundaryOrdinal,
                    );
                }
                await yieldControl();
                continue;
            }
            if (poll.kind === 'storage-request-ready') {
                const storageObservationDetails = Object.freeze({
                    ...(lastSuccessfulGenerationPollStage === 0
                        ? {}
                        : {
                              precedingGenerationStageIdentifier:
                                  requireCompactPublicKeyGenerationRuntimeStageIdentifier(
                                      lastSuccessfulGenerationPollStage,
                                  ),
                          }),
                    storageOwner: poll.storageOwner,
                });
                const requestCopyStartedAtMilliseconds =
                    input.observeOperation === undefined
                        ? 0
                        : performance.now();
                const encodedRequest = generationKernel.copyStorageRequest(
                    operationHandle,
                    poll.storageOwner,
                );
                observeWasmMemory();
                wasmToBrowserStorageRequestCount += 1n;
                wasmToBrowserStorageRequestByteLength += BigInt(
                    encodedRequest.byteLength,
                );
                let request: CommonProofExternalMemoryRequest | undefined;
                let storageRequestCompleted = false;
                try {
                    request =
                        decodeCommonProofExternalMemoryRequest(encodedRequest);
                    requestSequences[poll.storageOwner].accept(request);
                    observeCompletedOperation(
                        'storage-request-copy-and-decode',
                        requestCopyStartedAtMilliseconds,
                        storageObservationDetails,
                    );
                    let externalMemoryExecutor = externalMemoryExecutors.get(
                        poll.storageOwner,
                    );
                    if (externalMemoryExecutor === undefined) {
                        externalMemoryExecutor =
                            await runObservedAsyncOperation(
                                'storage-open',
                                async () =>
                                    requireCompactPublicKeyExternalMemoryExecutor(
                                        await input.openExternalMemory(
                                            Object.freeze({
                                                runtimeBindingHash:
                                                    request!.runtimeBindingHash.slice(),
                                                storageOwner: poll.storageOwner,
                                            }),
                                        ),
                                    ),
                                () => storageObservationDetails,
                            );
                        externalMemoryExecutors.set(
                            poll.storageOwner,
                            externalMemoryExecutor,
                        );
                    }
                    let readResults;
                    try {
                        readResults = await runObservedAsyncOperation(
                            'storage-transaction',
                            async () =>
                                validateTransferredReadResults(
                                    request!,
                                    await externalMemoryExecutor.executeTransaction(
                                        request!,
                                    ),
                                ),
                            () => storageObservationDetails,
                        );
                    } catch (error) {
                        throw new CanonicalStreamInternalError(
                            'The browser store could not execute the exact compact public-key transaction.',
                            error,
                        );
                    }
                    readResultTransferCount += BigInt(readResults.length);
                    for (const readResult of readResults) {
                        readResultTransferByteLength += BigInt(
                            readResult.bytes.byteLength,
                        );
                    }
                    reusableStorageResponseBuffer ??= new Uint8Array(
                        maximumEncodedResponseByteLength,
                    );
                    const encodedResponse = runObservedOperation(
                        'storage-response-encode-and-supply',
                        () => {
                            const response =
                                encodeCommonProofExternalMemoryResponseInto(
                                    request!,
                                    readResults,
                                    reusableStorageResponseBuffer!,
                                );
                            generationKernel.supplyStorageResponse(
                                operationHandle,
                                poll.storageOwner,
                                response,
                            );
                            return response;
                        },
                        () => storageObservationDetails,
                    );
                    browserToWasmStorageResponseCount += 1n;
                    browserToWasmStorageResponseByteLength += BigInt(
                        encodedResponse.byteLength,
                    );
                    observeWasmMemory();
                    requestSequences[poll.storageOwner].commit();
                    storageRequestCompleted = true;
                } finally {
                    const cleanupStartedAtMilliseconds =
                        input.observeOperation === undefined ||
                        !storageRequestCompleted
                            ? 0
                            : performance.now();
                    if (request !== undefined) {
                        clearCommonProofExternalMemoryRequest(request);
                    }
                    if (encodedRequest.byteLength > 0) {
                        encodedRequest.fill(0);
                    }
                    reusableStorageResponseBuffer?.fill(0);
                    if (storageRequestCompleted) {
                        observeCompletedOperation(
                            'storage-request-cleanup',
                            cleanupStartedAtMilliseconds,
                            storageObservationDetails,
                        );
                    }
                }
                await yieldControl();
                continue;
            }

            const externalMemoryUsage = runObservedOperation(
                'external-memory-accounting-copy',
                () => generationKernel.externalMemoryUsage(operationHandle),
            );
            transportBindings = runObservedOperation(
                'transport-bindings-copy',
                () => generationKernel.copyTransportBindings(operationHandle),
            );
            canonicalPublicInputBytes = runObservedOperation(
                'canonical-public-input-copy',
                () =>
                    generationKernel.copyCanonicalPublicInput(operationHandle),
            );
            observeWasmMemory();
            canonicalProofBytes = runObservedOperation(
                'canonical-proof-copy',
                () => generationKernel.copyCanonicalProof(operationHandle),
            );
            observeWasmMemory();
            const canonicalOutputCopyByteLength = BigInt(
                canonicalPublicInputBytes.byteLength +
                    canonicalProofBytes.byteLength,
            );
            const canonicalOutputCopyCount = BigInt(
                Math.ceil(
                    canonicalPublicInputBytes.byteLength /
                        canonicalCommonProofChunkByteLength,
                ) +
                    Math.ceil(
                        canonicalProofBytes.byteLength /
                            canonicalCommonProofChunkByteLength,
                    ),
            );
            runObservedOperation('kernel-release', () => {
                generationKernel.releaseCompleted(operationHandle);
                operationReleased = true;
                operationHandle = 0;
            });
            result = Object.freeze({
                canonicalProofBytes,
                canonicalPublicInputBytes,
                externalMemoryAccounting: Object.freeze({
                    cfw: compactPublicKeyStorageAccounting(
                        externalMemoryUsage.cfw,
                        externalMemoryExecutors.get('cfw'),
                    ),
                    responseTrees: compactPublicKeyStorageAccounting(
                        externalMemoryUsage.responseTrees,
                        externalMemoryExecutors.get('responseTrees'),
                    ),
                    worker: Object.freeze({
                        browserToWasmStorageResponseByteLength,
                        browserToWasmStorageResponseCount,
                        canonicalOutputCopyByteLength,
                        canonicalOutputCopyCount,
                        finalWasmMemoryByteLength:
                            context.memory.buffer.byteLength,
                        initialWasmMemoryByteLength,
                        maximumWasmMemoryByteLength,
                        readResultTransferByteLength,
                        readResultTransferCount,
                        wasmToBrowserStorageRequestByteLength,
                        wasmToBrowserStorageRequestCount,
                    }),
                }),
                observedSafeBoundaryOrdinals: Object.freeze([
                    ...observedSafeBoundaryOrdinals,
                ]),
                transportBindings,
            });
            canonicalProofBytes = undefined;
            canonicalPublicInputBytes = undefined;
            transportBindings = undefined;
            break;
        }
    } catch (error) {
        operationFailure = error;
    } finally {
        checkpointLineageIdentifier.fill(0);
        referenceBoardAuthorization?.handleBytes.fill(0);
        setupIntentAuthorization.handleBytes.fill(0);
        reusableStorageResponseBuffer?.fill(0);
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            if (preparationKernel === undefined) {
                throw new CanonicalStreamInternalError(
                    'The selected-suite cleanup boundary is unavailable.',
                );
            }
            runObservedOperation('selected-suite-release', () => {
                releaseSelectedSuite({
                    context,
                    handle: selectedSuiteHandle,
                    kernel: preparationKernel,
                    operationName:
                        'accepted-setup compact public-key selected-suite failure release',
                    statusBoundary,
                });
                selectedSuiteHandle = 0;
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (operationHandle !== 0 && !operationReleased) {
        try {
            runObservedOperation('kernel-cancellation', () => {
                generationKernel.cancel(operationHandle);
                operationHandle = 0;
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (operationFailure !== undefined) {
        canonicalProofBytes?.fill(0);
        canonicalPublicInputBytes?.fill(0);
        transportBindings?.applicationStatementHash.fill(0);
        transportBindings?.manifestHash.fill(0);
        transportBindings?.relationPlanHash.fill(0);
        transportBindings?.suiteIdentifier.fill(0);
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamCleanupError(
            operationFailure,
            new CanonicalStreamInternalError(
                'Accepted-setup compact public-key generation failed to retire all worker-owned authority.',
                Object.freeze({ cleanupFailures }),
            ),
        );
    }
    if (operationFailure !== undefined) {
        if (operationFailure instanceof Error) {
            throw operationFailure;
        }
        throw new CanonicalStreamInternalError(
            'Accepted-setup compact public-key generation failed with a non-error value.',
            operationFailure,
        );
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'The compact public-key generator returned no canonical output.',
        );
    }
    return result;
};

/**
 * Generates the exact compact public-key proof and public input from a selected
 * setup authority in scalar release WASM. The returned bytes have no
 * verification authority; only positive accepted-setup verification can mint
 * the corresponding capability.
 */
export const generateAcceptedSetupCompactPublicKeyShareInClosedWorker = (
    input: AcceptedSetupCompactPublicKeyGenerationInput,
): Promise<GeneratedAcceptedSetupCompactPublicKeyProof> =>
    generateCompactPublicKeyInClosedWorker(
        Object.freeze({ input, kind: 'acceptedSetup' }),
    );

/**
 * Generates exact compact public-key reference bytes from positively verified
 * setup sources. This path neither selects a suite nor produces a capability.
 */
export const generateCompactPublicKeyReferenceInClosedWorker = (
    input: CompactPublicKeyReferenceGenerationInput,
): Promise<GeneratedCompactPublicKeyReferenceProof> =>
    generateCompactPublicKeyInClosedWorker(
        Object.freeze({ input, kind: 'reference' }),
    );

const contributeGeneratedAcceptedSetupKeyRelationToPackage = (
    family: AcceptedSetupKeyRelationProofFamily,
    input: GeneratedAcceptedSetupKeyRelationPackageContributionInput,
): void => {
    const record = requireGeneratedProofRecord(input.generatedProof);
    if (record.family !== family) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const builderOwner = requireAcceptedSetupPackageBuilderKernelOwner(
        input.packageBuilder,
        record.kernel,
    );
    if (builderOwner.context !== record.context) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const kernel = requireGenerationKernel(record.context, family);
    const status = applyClosedWorkerGeneratedCommonProofCapability(
        record.capability,
        record.context,
        (generatedCommonProofHandle) =>
            Object.freeze({
                consumed: false,
                result: record.context.runExclusive(
                    `accepted-setup ${family} generated package contribution`,
                    () =>
                        kernel.contributePackage(
                            builderOwner.handle,
                            record.statementSourceHandle,
                            generatedCommonProofHandle,
                        ),
                ),
            }),
    );
    createStatusBoundary(family).throwIfError(status);
};

/** Contributes one locally generated same-secret source to the exact package. */
export const contributeGeneratedAcceptedSetupSameSecretToPackage = (
    input: GeneratedAcceptedSetupKeyRelationPackageContributionInput,
): void =>
    contributeGeneratedAcceptedSetupKeyRelationToPackage('sameSecret', input);

/**
 * Contributes one locally generated public-key-share source to the exact
 * package.
 */
export const contributeGeneratedAcceptedSetupPublicKeyShareToPackage = (
    input: GeneratedAcceptedSetupKeyRelationPackageContributionInput,
): void =>
    contributeGeneratedAcceptedSetupKeyRelationToPackage(
        'publicKeyShare',
        input,
    );

const verifyGeneratedAcceptedSetupKeyRelationInClosedWorker = async (
    family: AcceptedSetupKeyRelationProofFamily,
    input: GeneratedAcceptedSetupKeyRelationProofVerificationRuntimeInput,
): Promise<void> => {
    const record = requireGeneratedProofRecord(input.generatedProof);
    const context = resolveCommonProofKernelContext(input.kernel);
    if (
        context === undefined ||
        record.family !== family ||
        record.kernel !== input.kernel ||
        record.context !== context
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const verificationInput = Object.freeze({
        assembly: input.assembly,
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        inputStore: input.inputStore,
        kernel: input.kernel,
        options: input.options,
    });
    if (family === 'sameSecret') {
        await verifyGeneratedAcceptedSetupSameSecretCapabilityInClosedWorker(
            verificationInput,
            record.capability,
            record.statementSourceHandle,
        );
    } else {
        await verifyGeneratedAcceptedSetupPublicKeyShareCapabilityInClosedWorker(
            verificationInput,
            record.capability,
            record.statementSourceHandle,
        );
    }
    retireConsumedGeneratedProof(input.generatedProof, record);
};

/** Positively verifies one generated same-secret proof from its exact package. */
export const verifyGeneratedAcceptedSetupSameSecretInClosedWorker = (
    input: GeneratedAcceptedSetupSameSecretProofVerificationInput,
): Promise<void> =>
    verifyGeneratedAcceptedSetupKeyRelationInClosedWorker('sameSecret', input);

/**
 * Positively verifies one generated public-key-share proof from its exact
 * package.
 */
export const verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker = (
    input: GeneratedAcceptedSetupKeyRelationProofVerificationInput,
): Promise<void> =>
    verifyGeneratedAcceptedSetupKeyRelationInClosedWorker(
        'publicKeyShare',
        input,
    );
