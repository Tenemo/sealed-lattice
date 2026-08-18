import type { RefusalReason } from '@sealed-lattice/types';

import { byteArraysEqual } from '../byte-array.js';
import { decodeCommonProofCheckpointCursorManifest } from '../common-proof-checkpoint-cursor-manifest.js';
import {
    decodeCommonProofGenerationCursorManifest,
    maximumCommonProofGenerationCursorManifestByteLength,
} from '../common-proof-generation-cursor-manifest.js';
import { refusalReasonByCode } from '../transcript-core-bridge/kernel-errors.js';
import {
    resolveNumberExport,
    type TranscriptCoreKernelCommandRuntime,
} from '../transcript-core-bridge/kernel-runtime.js';
import { WasmMemoryBoundary } from '../wasm-memory-boundary.js';

import type {
    CommonProofApplicationFreshnessCoordinate,
    CommonProofApplicationStorageRootAccess,
    CommonProofGenerationCheckpoint,
} from './contracts.js';
import {
    CommonProofWorkerRuntimeError,
    maximumEncodedRequestByteLength,
    maximumWorkerOperationCount,
    maximumWorkerPayloadByteLength,
    requestHeaderByteLength,
    type CommonProofDiscardExportName,
} from './external-memory.js';
export const hashByteLength = 64;
const compactPublicKeyTransportBindingCount = 4;
const compactPublicKeyTransportBindingsByteLength =
    compactPublicKeyTransportBindingCount * hashByteLength;
const localStorageRootCapabilityByteLength = 32;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;

const wasm32WordByteLength = 4;
const noSecondPollValue = 0xffff_ffff;
const generationPollProgress = 1;
const generationPollStorageRequestReady = 2;
const generationPollOutputChunkReady = 3;
const generationPollOutputReadbackRequired = 4;
const generationPollComplete = 5;
const generationPollCancelled = 6;
const generationPollResumeComplete = 7;
const generationPollAuthenticatedSourceReadReady = 8;
const generationPollAuthenticatedTranscriptPrefixRequired = 9;
const authenticatedSourceRequestByteLength = 160;
const generationExternalMemoryAccountingByteLength = 20 * 8;
const verificationReadbackAccountingByteLength = 4 * 8;
const maximumExternalMemoryChunkByteLength = Number(
    maximumWorkerPayloadByteLength,
);
const maximumExternalScratchByteLength = 1_073_741_824n;
const firstGenerationStage = 1;
const finalGenerationStage = 14;
const verificationPollNeedsReadback = 1;
const verificationPollPrefixAccepted = 2;
const verificationPollQueryHeaderAccepted = 3;
const verificationPollQueryTreeAccepted = 4;
const verificationPollComplete = 5;
const compactPublicKeyAlgebraicVerificationPollProgress = 1;
const compactPublicKeyAlgebraicVerificationPollComplete = 5;
const compactPublicKeyAlgebraicVerificationPollResumeComplete = 7;
export const maximumCommonProofByteLength = 268_435_456;
export const canonicalCommonProofChunkByteLength = 1_048_576;
const maximumGenerationCheckpointStateByteLength = 4_096;
const canonicalCompactPublicKeyAlgebraicVerificationCheckpointByteLength = 400;
const canonicalCompactPublicKeyAlgebraicVerificationSafeBoundaryCount = 290;

const destroyOwnedKernelBoundaryInput = (bytes: Uint8Array): void => {
    if (!(bytes.buffer instanceof ArrayBuffer)) {
        bytes.fill(0);
        return;
    }
    const buffer = bytes.buffer;
    if (buffer.byteLength === 0) {
        return;
    }
    if (bytes.byteOffset !== 0 || bytes.byteLength !== buffer.byteLength) {
        bytes.fill(0);
        return;
    }
    new Uint8Array(buffer).fill(0);
    structuredClone(buffer, { transfer: [buffer] });
};

export type CommonProofGenerationCheckpointIdentityExpectation = Readonly<{
    applicationStatementSchemaIdentifier: number;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
    stableAttemptBindingHash: Uint8Array<ArrayBuffer>;
}>;

const copyCheckpointPrivateRandomnessStreamAttemptIdentifier = (
    manifestBytes: Uint8Array<ArrayBuffer>,
    stableAttemptBindingHash: Uint8Array<ArrayBuffer>,
    expectedIdentity?: CommonProofGenerationCheckpointIdentityExpectation,
): Uint8Array<ArrayBuffer> => {
    let decoded;
    try {
        const generationCursorManifest =
            decodeCommonProofGenerationCursorManifest(manifestBytes);
        decoded = decodeCommonProofCheckpointCursorManifest(
            generationCursorManifest.privateCoinCursorManifestBytes,
        );
    } catch (error) {
        throw new CommonProofWorkerRuntimeError(
            'KernelFailure',
            'The common-proof kernel exposed a malformed checkpoint cursor manifest.',
            error,
        );
    }
    if (!decoded.hasPrivateRandomnessIdentity) {
        throw new CommonProofWorkerRuntimeError(
            'KernelFailure',
            'The common-proof kernel exposed an inconsistent checkpoint cursor manifest.',
        );
    }
    try {
        if (
            !byteArraysEqual(
                decoded.derivationBindingHash,
                stableAttemptBindingHash,
            ) ||
            (expectedIdentity !== undefined &&
                (decoded.familySchemaIdentifier !==
                    expectedIdentity.applicationStatementSchemaIdentifier ||
                    !byteArraysEqual(
                        stableAttemptBindingHash,
                        expectedIdentity.stableAttemptBindingHash,
                    ) ||
                    !byteArraysEqual(
                        decoded.privateRandomnessStreamAttemptIdentifier,
                        expectedIdentity.proofAttemptLineageIdentifier,
                    )))
        ) {
            throw new CommonProofWorkerRuntimeError(
                'KernelFailure',
                'The common-proof kernel exposed an inconsistent checkpoint cursor identity.',
            );
        }
        return decoded.privateRandomnessStreamAttemptIdentifier;
    } catch (error) {
        decoded.privateRandomnessStreamAttemptIdentifier.fill(0);
        throw error;
    } finally {
        decoded.derivationBindingHash.fill(0);
    }
};
export const maximumCommonProofOutputChunkCount = Math.ceil(
    maximumCommonProofByteLength / canonicalCommonProofChunkByteLength,
);

export type ClosedWorkerCommonProofGenerationFamilyAdapterDescription =
    Readonly<{
        applicationStatementSchemaIdentifier: number;
        checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
        commonProofGenerationAuthorizationHash: Uint8Array<ArrayBuffer>;
        commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
        proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
    }>;

export type ClosedWorkerCommonProofVerificationFamilyAdapterDescription =
    Readonly<{
        commonProofVerificationBindingHash: Uint8Array<ArrayBuffer>;
    }>;

export type CompactPublicKeyTransportBindings = Readonly<{
    applicationStatementHash: Uint8Array;
    manifestHash: Uint8Array;
    relationPlanHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

export type CommonProofAuthenticatedSourceRangeRequest = Readonly<{
    authenticationChunkIndex: number;
    exactByteLength: number;
    sourceMaterialRoot: Uint8Array<ArrayBuffer>;
    sourceStreamByteOffset: bigint;
    sourceStreamDigest: Uint8Array<ArrayBuffer>;
    sourceStreamTotalByteLength: bigint;
    storageByteOffset: bigint;
}>;

type CommonProofExternalMemoryUsageAccounting = Readonly<{
    deletedObjectLifecycleCount: bigint;
    peakStoredByteLength: bigint;
    totalReadByteLength: bigint;
    totalWrittenByteLength: bigint;
    transactionCount: bigint;
}>;

export type CommonProofBrowserStorageAccounting = Readonly<{
    claimedBufferCount: bigint;
    claimedByteLength: bigint;
    maximumLiveBufferByteLength: bigint;
    maximumLiveBufferCount: number;
    releasedBufferCount: bigint;
    releasedByteLength: bigint;
    secretRecordOpenByteLength: bigint;
    secretRecordOpenCount: bigint;
    secretRecordSealByteLength: bigint;
    secretRecordSealCount: bigint;
    transferredBufferCount: bigint;
    transferredByteLength: bigint;
}>;

export type CommonProofWorkerStorageTransportAccounting = Readonly<{
    browserToWasmCopyByteLength: bigint;
    browserToWasmCopyCount: bigint;
    readResultTransferByteLength: bigint;
    readResultTransferCount: bigint;
    wasmToBrowserCopyByteLength: bigint;
    wasmToBrowserCopyCount: bigint;
}>;

export type CommonProofGenerationExternalMemoryAccounting = Readonly<{
    actualUsage: CommonProofExternalMemoryUsageAccounting;
    browserStorage?: CommonProofBrowserStorageAccounting;
    compiledRequirement: Readonly<{
        maximumChunkByteLength: number;
        maximumTransactionPayloadByteLength: bigint;
        distinctPhysicalObjectCount: number;
        objectLifecycleCount: number;
        peakStoredByteLength: bigint;
        stepCount: number;
        totalReadByteLength: bigint;
        totalWrittenByteLength: bigint;
        transactionCount: bigint;
    }>;
    deterministicPrefixReplayUsage?: CommonProofExternalMemoryUsageAccounting;
    workerTransport?: CommonProofWorkerStorageTransportAccounting;
}>;

type CommonProofVerificationReadbackAccounting = Readonly<{
    logicalRequiredByteLength: bigint;
    logicalRequiredRangeCount: bigint;
    suppliedFullChunkByteLength: bigint;
    suppliedFullChunkCount: bigint;
}>;

type CommonProofGenerationKernelPoll =
    | Readonly<{
          checkpointReady: boolean;
          kind: 'progress';
      }>
    | Readonly<{ kind: 'resume-complete' }>
    | Readonly<{
          encodedRequestByteLength: number;
          kind: 'storage-request-ready';
      }>
    | Readonly<{
          authenticationChunkIndex: number;
          kind: 'authenticated-source-read-ready';
          sourceByteLength: number;
      }>
    | Readonly<{ kind: 'authenticated-transcript-prefix-required' }>
    | Readonly<{
          chunkByteLength: number;
          chunkIndex: number;
          kind: 'output-chunk-ready';
      }>
    | Readonly<{
          chunkIndex: number;
          kind: 'output-readback-required';
      }>
    | Readonly<{ kind: 'complete' }>
    | Readonly<{ kind: 'cancelled' }>;

type CommonProofVerificationKernelPoll =
    | Readonly<{
          firstChunkIndex: number;
          kind: 'needs-readback';
          secondChunkIndex?: number;
      }>
    | Readonly<{ kind: 'prefix-accepted' }>
    | Readonly<{ kind: 'query-header-accepted' }>
    | Readonly<{
          catalogIndex: number;
          kind: 'query-tree-accepted';
      }>
    | Readonly<{ kind: 'complete' }>;

type CompactPublicKeyAlgebraicVerificationKernelBegin =
    | Readonly<{ kind: 'started'; operationHandle: number }>
    | Readonly<{ kind: 'refused'; refusalReason: RefusalReason }>;

type CompactPublicKeyAlgebraicVerificationKernelPoll =
    | Readonly<{
          checkpointSafeBoundaryOrdinal?: number;
          completedWorkUnitCount: number;
          kind: 'progress';
      }>
    | Readonly<{
          checkpointSafeBoundaryOrdinal: number;
          completedWorkUnitCount: number;
          kind: 'resume-complete';
      }>
    | Readonly<{ kind: 'complete' }>
    | Readonly<{ kind: 'refused'; refusalReason: RefusalReason }>;

type AcceptedSetupCompactPublicKeyVerificationKernelPreparation =
    | Readonly<{ kind: 'prepared'; preparedHandle: number }>
    | Readonly<{ kind: 'refused'; refusalReason: RefusalReason }>;

type AcceptedSetupCompactPublicKeyVerificationKernelBegin =
    | Readonly<{ kind: 'started'; operationHandle: number }>
    | Readonly<{ kind: 'refused'; refusalReason: RefusalReason }>;

type AcceptedSetupCompactPublicKeyVerificationKernelPoll =
    | Readonly<{
          checkpointSafeBoundaryOrdinal?: number;
          completedWorkUnitCount: number;
          kind: 'progress';
      }>
    | Readonly<{
          checkpointSafeBoundaryOrdinal: number;
          completedWorkUnitCount: number;
          kind: 'resume-complete';
      }>
    | Readonly<{ kind: 'complete'; verifiedCapabilityHandle: number }>
    | Readonly<{ kind: 'refused'; refusalReason: RefusalReason }>;

export const kernelFailure = (
    message: string,
    failureCause?: unknown,
): CommonProofWorkerRuntimeError =>
    new CommonProofWorkerRuntimeError('KernelFailure', message, failureCause);

export const resourceFailure = (
    message: string,
): CommonProofWorkerRuntimeError =>
    new CommonProofWorkerRuntimeError('ResourceLimit', message);

const requireUnsigned32 = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw kernelFailure(`${label} is outside the unsigned 32-bit range.`);
    }
    return value;
};

const requireNonzeroUnsigned16 = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff) {
        throw kernelFailure(`${label} is not a nonzero unsigned 16-bit value.`);
    }
    return value;
};

export const requireLiveHandle = (value: number, label: string): number => {
    requireUnsigned32(value, label);
    if (value === 0) {
        throw kernelFailure(`${label} is null.`);
    }
    return value;
};

export const requireUnsigned64 = (value: bigint, label: string): bigint => {
    if (typeof value !== 'bigint' || value < 0n || value > maximumUnsigned64) {
        throw kernelFailure(`${label} is outside the unsigned 64-bit range.`);
    }
    return value;
};

const readDiagnosticUnsigned64 = (
    bytes: Uint8Array,
    wordIndex: number,
): bigint =>
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(
        wordIndex * 8,
        true,
    );

const diagnosticUnsigned32 = (value: bigint, label: string): number => {
    if (value > 0xffff_ffffn) {
        throw kernelFailure(`${label} exceeds the unsigned 32-bit range.`);
    }
    return Number(value);
};

const externalMemoryUsageFromDiagnostic = (
    bytes: Uint8Array,
    firstWordIndex: number,
): CommonProofExternalMemoryUsageAccounting =>
    Object.freeze({
        totalWrittenByteLength: readDiagnosticUnsigned64(bytes, firstWordIndex),
        totalReadByteLength: readDiagnosticUnsigned64(
            bytes,
            firstWordIndex + 1,
        ),
        peakStoredByteLength: readDiagnosticUnsigned64(
            bytes,
            firstWordIndex + 2,
        ),
        transactionCount: readDiagnosticUnsigned64(bytes, firstWordIndex + 3),
        deletedObjectLifecycleCount: readDiagnosticUnsigned64(
            bytes,
            firstWordIndex + 4,
        ),
    });

const usageDoesNotExceed = (
    usage: CommonProofExternalMemoryUsageAccounting,
    limits: Readonly<{
        objectLifecycleCount: bigint;
        peakStoredByteLength: bigint;
        totalReadByteLength: bigint;
        totalWrittenByteLength: bigint;
        transactionCount: bigint;
    }>,
): boolean =>
    usage.totalWrittenByteLength <= limits.totalWrittenByteLength &&
    usage.totalReadByteLength <= limits.totalReadByteLength &&
    usage.peakStoredByteLength <= limits.peakStoredByteLength &&
    usage.transactionCount <= limits.transactionCount &&
    usage.deletedObjectLifecycleCount <= limits.objectLifecycleCount;

const requireExactApplicationBytes = (
    value: Uint8Array,
    exactByteLength: number,
    label: string,
): void => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== exactByteLength
    ) {
        throw kernelFailure(
            `${label} must be exactly ${String(exactByteLength)} bytes.`,
        );
    }
};

export const copyExactApplicationBytes = (
    value: Uint8Array,
    exactByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    requireExactApplicationBytes(value, exactByteLength, label);
    return Uint8Array.from(value);
};

export const requireKernelSuccess = (
    status: number,
    operation: string,
): void => {
    requireUnsigned32(status, `${operation} status`);
    if (status !== 0) {
        throw kernelFailure(
            `The common-proof kernel refused ${operation} with status ${status}.`,
        );
    }
};

const decodeCompactPublicKeyAlgebraicVerificationStatus = (
    status: number,
    operation: string,
): RefusalReason | undefined => {
    requireUnsigned32(status, `${operation} status`);
    if (status === 0) {
        return undefined;
    }
    const refusalReason = refusalReasonByCode.get(status);
    if (refusalReason === undefined) {
        throw kernelFailure(
            `The compact public-key algebraic verifier returned unknown status ${String(status)} during ${operation}.`,
        );
    }
    return refusalReason;
};

export const yieldBrowserWorkerTurn = (): Promise<void> =>
    new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = () => {
            channel.port1.close();
            channel.port2.close();
            resolve();
        };
        channel.port2.postMessage(undefined);
    });

export class CommonProofFamilyAdapterKernelBoundary {
    readonly #context: TranscriptCoreKernelCommandRuntime;
    readonly #memoryBoundary: WasmMemoryBoundary;

    public constructor(context: TranscriptCoreKernelCommandRuntime) {
        this.#context = context;
        this.#memoryBoundary = new WasmMemoryBoundary({
            context,
            createInternalError: (message) => kernelFailure(message),
            createResourceError: resourceFailure,
            label: 'common-proof family adapter',
        });
    }

    public describeGeneration(
        adapterHandle: number,
    ): ClosedWorkerCommonProofGenerationFamilyAdapterDescription {
        requireLiveHandle(
            adapterHandle,
            'The common-proof generation family-adapter handle',
        );
        return this.#context.runExclusive(
            'common-proof generation family-adapter description',
            () => {
                const outputByteLength =
                    hashByteLength + hashByteLength + 32 + 32;
                const outputPointer =
                    this.#memoryBoundary.allocate(outputByteLength);
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                const applicationStatementSchemaIdentifierPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_describe_generation_family_adapter',
                    )(
                        adapterHandle,
                        outputPointer,
                        outputPointer + hashByteLength,
                        outputPointer + 2 * hashByteLength,
                        outputPointer + 2 * hashByteLength + 32,
                        applicationStatementSchemaIdentifierPointer,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(
                        status,
                        'generation family-adapter description',
                    );
                    const [applicationStatementSchemaIdentifier] =
                        this.#memoryBoundary.readWords(
                            applicationStatementSchemaIdentifierPointer,
                            1,
                        );
                    const output = new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        outputByteLength,
                    );
                    return Object.freeze({
                        applicationStatementSchemaIdentifier:
                            requireNonzeroUnsigned16(
                                applicationStatementSchemaIdentifier,
                                'The common-proof application-statement schema identifier',
                            ),
                        commonProofRuntimeBindingHash: output
                            .subarray(0, hashByteLength)
                            .slice(),
                        commonProofGenerationAuthorizationHash: output
                            .subarray(hashByteLength, 2 * hashByteLength)
                            .slice(),
                        proofAttemptLineageIdentifier: output
                            .subarray(
                                2 * hashByteLength,
                                2 * hashByteLength + 32,
                            )
                            .slice(),
                        checkpointLineageIdentifier: output
                            .subarray(2 * hashByteLength + 32)
                            .slice(),
                    });
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        outputByteLength,
                    );
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    this.#memoryBoundary.zeroAndDeallocate(
                        applicationStatementSchemaIdentifierPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public describeVerification(
        adapterHandle: number,
    ): ClosedWorkerCommonProofVerificationFamilyAdapterDescription {
        requireLiveHandle(
            adapterHandle,
            'The common-proof verification family-adapter handle',
        );
        return this.#context.runExclusive(
            'common-proof verification family-adapter description',
            () => {
                const outputPointer =
                    this.#memoryBoundary.allocate(hashByteLength);
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_describe_verification_family_adapter',
                    )(adapterHandle, outputPointer, statusPointer);
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(
                        status,
                        'verification family-adapter description',
                    );
                    return Object.freeze({
                        commonProofVerificationBindingHash: new Uint8Array(
                            this.#context.memory.buffer,
                            outputPointer,
                            hashByteLength,
                        ).slice(),
                    });
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        hashByteLength,
                    );
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public checkpointStateByteLength(): number {
        return this.#context.runExclusive(
            'common-proof generation checkpoint state length',
            () => {
                const byteLength = requireUnsigned32(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_checkpoint_state_byte_length',
                    )(),
                    'The canonical common-proof checkpoint state byte length',
                );
                if (
                    byteLength === 0 ||
                    byteLength > maximumGenerationCheckpointStateByteLength
                ) {
                    throw kernelFailure(
                        'The common-proof kernel exposed a checkpoint state beyond the absolute safety bound.',
                    );
                }
                return byteLength;
            },
        );
    }

    public prepareGeneration(
        adapterHandle: number,
        authenticatedCheckpointState?: Uint8Array,
        authenticatedGenerationCursorManifest?: Uint8Array,
    ): number {
        requireLiveHandle(
            adapterHandle,
            'The common-proof generation family-adapter handle',
        );
        if (
            (authenticatedCheckpointState === undefined) !==
                (authenticatedGenerationCursorManifest === undefined) ||
            (authenticatedCheckpointState !== undefined &&
                (!(authenticatedCheckpointState instanceof Uint8Array) ||
                    authenticatedCheckpointState.byteLength !==
                        this.checkpointStateByteLength())) ||
            (authenticatedGenerationCursorManifest !== undefined &&
                (!(
                    authenticatedGenerationCursorManifest instanceof Uint8Array
                ) ||
                    authenticatedGenerationCursorManifest.byteLength === 0 ||
                    authenticatedGenerationCursorManifest.byteLength >
                        maximumCommonProofGenerationCursorManifestByteLength))
        ) {
            throw resourceFailure(
                'The authenticated common-proof checkpoint state and generation cursor manifest are inconsistent.',
            );
        }
        return this.#context.runExclusive(
            'common-proof generation family-adapter preparation',
            () => {
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                const checkpointPointer =
                    authenticatedCheckpointState === undefined
                        ? 0
                        : this.#memoryBoundary.copy(
                              authenticatedCheckpointState,
                          );
                const generationCursorManifestPointer =
                    authenticatedGenerationCursorManifest === undefined
                        ? 0
                        : this.#memoryBoundary.copy(
                              authenticatedGenerationCursorManifest,
                          );
                try {
                    const preparedHandle = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_prepare_generation_family_adapter',
                    )(
                        adapterHandle,
                        checkpointPointer,
                        authenticatedCheckpointState?.byteLength ?? 0,
                        generationCursorManifestPointer,
                        authenticatedGenerationCursorManifest?.byteLength ?? 0,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(
                        status,
                        'generation family-adapter preparation',
                    );
                    return requireLiveHandle(
                        preparedHandle,
                        'The prepared common-proof generation handle',
                    );
                } finally {
                    if (
                        checkpointPointer !== 0 &&
                        authenticatedCheckpointState !== undefined
                    ) {
                        this.#memoryBoundary.zeroAndDeallocate(
                            checkpointPointer,
                            authenticatedCheckpointState.byteLength,
                        );
                    }
                    if (
                        generationCursorManifestPointer !== 0 &&
                        authenticatedGenerationCursorManifest !== undefined
                    ) {
                        this.#memoryBoundary.zeroAndDeallocate(
                            generationCursorManifestPointer,
                            authenticatedGenerationCursorManifest.byteLength,
                        );
                    }
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public prepareVerification(adapterHandle: number): number {
        requireLiveHandle(
            adapterHandle,
            'The common-proof verification family-adapter handle',
        );
        return this.#context.runExclusive(
            'common-proof verification family-adapter preparation',
            () => {
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const preparedHandle = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_prepare_verification_family_adapter',
                    )(adapterHandle, statusPointer);
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(
                        status,
                        'verification family-adapter preparation',
                    );
                    return requireLiveHandle(
                        preparedHandle,
                        'The prepared common-proof verification handle',
                    );
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public discardGeneration(adapterHandle: number): void {
        this.#discard(
            adapterHandle,
            'sealed_lattice_common_proof_discard_generation_family_adapter',
            'generation family-adapter discard',
        );
    }

    public discardVerification(adapterHandle: number): void {
        this.#discard(
            adapterHandle,
            'sealed_lattice_common_proof_discard_verification_family_adapter',
            'verification family-adapter discard',
        );
    }

    public discardPreparedGeneration(preparedHandle: number): void {
        this.#discard(
            preparedHandle,
            'sealed_lattice_common_proof_discard_prepared_generation',
            'prepared-generation discard',
        );
    }

    public discardPreparedVerification(preparedHandle: number): void {
        this.#discard(
            preparedHandle,
            'sealed_lattice_common_proof_discard_prepared_verification',
            'prepared-verification discard',
        );
    }

    #discard(
        handle: number,
        exportName: CommonProofDiscardExportName,
        operation: string,
    ): void {
        requireLiveHandle(handle, `The ${operation} handle`);
        this.#context.runExclusive(operation, () => {
            requireKernelSuccess(
                resolveNumberExport(
                    this.#context.wasmExports,
                    exportName,
                )(handle),
                operation,
            );
        });
    }
}

export class CommonProofGenerationKernelBoundary {
    readonly #context: TranscriptCoreKernelCommandRuntime;
    readonly #memoryBoundary: WasmMemoryBoundary;

    public constructor(context: TranscriptCoreKernelCommandRuntime) {
        this.#context = context;
        this.#memoryBoundary = new WasmMemoryBoundary({
            context,
            createInternalError: (message) => kernelFailure(message),
            createResourceError: resourceFailure,
            label: 'common-proof worker',
        });
    }

    public begin(preparedGenerationHandle: number): number {
        requireLiveHandle(
            preparedGenerationHandle,
            'The prepared common-proof generation handle',
        );
        return this.#context.runExclusive(
            'common-proof generation begin',
            () => {
                const begin = resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_begin_generation',
                );
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const operationHandle = begin(
                        preparedGenerationHandle,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(status, 'generation begin');
                    return requireLiveHandle(
                        operationHandle,
                        'The common-proof generation operation handle',
                    );
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public resume(
        preparedGenerationHandle: number,
        authenticatedCheckpointState: Uint8Array,
        authenticatedGenerationCursorManifest: Uint8Array,
    ): number {
        requireLiveHandle(
            preparedGenerationHandle,
            'The prepared common-proof generation handle',
        );
        if (
            !(authenticatedCheckpointState instanceof Uint8Array) ||
            !(authenticatedGenerationCursorManifest instanceof Uint8Array) ||
            authenticatedCheckpointState.byteLength === 0 ||
            authenticatedGenerationCursorManifest.byteLength === 0 ||
            authenticatedGenerationCursorManifest.byteLength >
                maximumCommonProofGenerationCursorManifestByteLength
        ) {
            throw resourceFailure(
                'The authenticated common-proof checkpoint state and generation cursor manifest must be bounded byte arrays.',
            );
        }
        return this.#context.runExclusive(
            'common-proof generation resume',
            () => {
                const resume = resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_resume_generation',
                );
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                const checkpointPointer =
                    authenticatedCheckpointState.byteLength === 0
                        ? 0
                        : this.#memoryBoundary.copy(
                              authenticatedCheckpointState,
                          );
                const generationCursorManifestPointer =
                    this.#memoryBoundary.copy(
                        authenticatedGenerationCursorManifest,
                    );
                try {
                    const operationHandle = resume(
                        preparedGenerationHandle,
                        checkpointPointer,
                        authenticatedCheckpointState.byteLength,
                        generationCursorManifestPointer,
                        authenticatedGenerationCursorManifest.byteLength,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(status, 'generation resume');
                    return requireLiveHandle(
                        operationHandle,
                        'The resumed common-proof generation operation handle',
                    );
                } finally {
                    if (checkpointPointer !== 0) {
                        this.#memoryBoundary.zeroAndDeallocate(
                            checkpointPointer,
                            authenticatedCheckpointState.byteLength,
                        );
                    }
                    this.#memoryBoundary.zeroAndDeallocate(
                        generationCursorManifestPointer,
                        authenticatedGenerationCursorManifest.byteLength,
                    );
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public poll(operationHandle: number): CommonProofGenerationKernelPoll {
        return this.#context.runExclusive(
            'common-proof generation poll',
            () => {
                const poll = resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_poll',
                );
                const metadataPointer =
                    this.#memoryBoundary.allocateZeroedWords(3);
                try {
                    requireKernelSuccess(
                        poll(
                            operationHandle,
                            metadataPointer,
                            metadataPointer + wasm32WordByteLength,
                            metadataPointer + 2 * wasm32WordByteLength,
                        ),
                        'generation poll',
                    );
                    const [kind, primaryValue, secondaryValue] =
                        this.#memoryBoundary.readWords(metadataPointer, 3);
                    return this.#decodePoll(kind, primaryValue, secondaryValue);
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        3 * wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public copyCheckpoint(
        operationHandle: number,
        expectedIdentity?: CommonProofGenerationCheckpointIdentityExpectation,
    ): CommonProofGenerationCheckpoint {
        if (expectedIdentity !== undefined) {
            requireNonzeroUnsigned16(
                expectedIdentity.applicationStatementSchemaIdentifier,
                'The expected common-proof application-statement schema identifier',
            );
            requireExactApplicationBytes(
                expectedIdentity.stableAttemptBindingHash,
                hashByteLength,
                'The expected common-proof stable-attempt binding hash',
            );
            requireExactApplicationBytes(
                expectedIdentity.proofAttemptLineageIdentifier,
                32,
                'The expected common-proof proof-attempt lineage identifier',
            );
        }
        const canonicalStateByteLength = this.#context.runExclusive(
            'common-proof generation checkpoint state length',
            () =>
                requireUnsigned32(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_checkpoint_state_byte_length',
                    )(),
                    'The canonical common-proof checkpoint state byte length',
                ),
        );
        if (
            canonicalStateByteLength === 0 ||
            canonicalStateByteLength >
                maximumGenerationCheckpointStateByteLength
        ) {
            throw kernelFailure(
                'The common-proof kernel exposed a checkpoint state beyond the absolute safety bound.',
            );
        }
        const [safeBoundaryOrdinal, stateByteLength, cursorManifestByteLength] =
            this.#context.runExclusive(
                'common-proof generation checkpoint description',
                () => {
                    const describe = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_describe_checkpoint',
                    );
                    const metadataPointer =
                        this.#memoryBoundary.allocateZeroedWords(3);
                    try {
                        requireKernelSuccess(
                            describe(
                                operationHandle,
                                metadataPointer,
                                metadataPointer + wasm32WordByteLength,
                                metadataPointer + 2 * wasm32WordByteLength,
                            ),
                            'generation checkpoint description',
                        );
                        return this.#memoryBoundary.readWords(
                            metadataPointer,
                            3,
                        );
                    } finally {
                        this.#memoryBoundary.zeroAndDeallocate(
                            metadataPointer,
                            3 * wasm32WordByteLength,
                        );
                    }
                },
            );
        if (
            stateByteLength !== canonicalStateByteLength ||
            cursorManifestByteLength === 0 ||
            cursorManifestByteLength >
                maximumCommonProofGenerationCursorManifestByteLength
        ) {
            throw kernelFailure(
                'The common-proof kernel exposed a checkpoint description beyond the absolute safety bound.',
            );
        }
        const canonicalStateBytes = this.#copyKernelBytes(
            stateByteLength,
            'generation checkpoint state',
            (outputPointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_copy_checkpoint_state',
                )(operationHandle, outputPointer, stateByteLength),
        );
        let generationCursorManifestBytes: Uint8Array<ArrayBuffer> | undefined;
        let stableAttemptBindingHash: Uint8Array<ArrayBuffer> | undefined;
        try {
            generationCursorManifestBytes = this.#copyKernelBytes(
                cursorManifestByteLength,
                'generation checkpoint cursor manifest',
                (outputPointer) =>
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest',
                    )(operationHandle, outputPointer, cursorManifestByteLength),
            );
            stableAttemptBindingHash = this.#copyKernelBytes(
                hashByteLength,
                'generation checkpoint stable attempt binding hash',
                (outputPointer) =>
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash',
                    )(operationHandle, outputPointer, hashByteLength),
            );
            const privateRandomnessStreamAttemptIdentifier =
                copyCheckpointPrivateRandomnessStreamAttemptIdentifier(
                    generationCursorManifestBytes,
                    stableAttemptBindingHash,
                    expectedIdentity,
                );
            return Object.freeze({
                canonicalStateBytes,
                generationCursorManifestBytes,
                privateRandomnessStreamAttemptIdentifier,
                stableAttemptBindingHash,
                safeBoundaryOrdinal,
            });
        } catch (error) {
            canonicalStateBytes.fill(0);
            stableAttemptBindingHash?.fill(0);
            generationCursorManifestBytes?.fill(0);
            throw error;
        }
    }

    public acknowledgeCheckpoint(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof generation checkpoint acknowledgement',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_acknowledge_checkpoint',
                    )(operationHandle),
                    'generation checkpoint acknowledgement',
                );
            },
        );
    }

    public discardCheckpoint(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof generation checkpoint discard',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_discard_checkpoint',
                    )(operationHandle),
                    'generation checkpoint discard',
                );
            },
        );
    }

    public copyStorageRequest(
        operationHandle: number,
        encodedRequestByteLength: number,
    ): Uint8Array<ArrayBuffer> {
        if (
            !Number.isSafeInteger(encodedRequestByteLength) ||
            encodedRequestByteLength < requestHeaderByteLength ||
            encodedRequestByteLength > maximumEncodedRequestByteLength
        ) {
            throw resourceFailure(
                'The common-proof kernel requested a storage message beyond the absolute safety bound.',
            );
        }
        return this.#copyKernelBytes(
            encodedRequestByteLength,
            'storage request',
            (outputPointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_copy_storage_request',
                )(operationHandle, outputPointer, encodedRequestByteLength),
        );
    }

    public supplyStorageResponse(
        operationHandle: number,
        encodedResponse: Uint8Array,
    ): void {
        this.#withKernelInput(
            encodedResponse,
            'storage response',
            (responsePointer, responseByteLength) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_supply_storage_response',
                )(operationHandle, responsePointer, responseByteLength),
        );
    }

    public copyAuthenticatedSourceRequest(
        operationHandle: number,
        expectedSourceByteLength: number,
        expectedAuthenticationChunkIndex: number,
    ): CommonProofAuthenticatedSourceRangeRequest {
        const declaredByteLength = this.#context.runExclusive(
            'common-proof authenticated-source request length',
            () =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_authenticated_source_request_byte_length',
                )(),
        );
        if (declaredByteLength !== authenticatedSourceRequestByteLength) {
            throw kernelFailure(
                'The common-proof kernel declared an unexpected authenticated-source request length.',
            );
        }
        const encodedRequest = this.#copyKernelBytes(
            declaredByteLength,
            'authenticated-source request',
            (outputPointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_copy_authenticated_source_request',
                )(operationHandle, outputPointer, declaredByteLength),
        );
        try {
            const view = new DataView(encodedRequest.buffer);
            const sourceStreamTotalByteLength = view.getBigUint64(128, true);
            const sourceStreamByteOffset = view.getBigUint64(136, true);
            const storageByteOffset = view.getBigUint64(144, true);
            const exactByteLength = view.getUint32(152, true);
            const authenticationChunkIndex = view.getUint32(156, true);
            if (
                exactByteLength !== expectedSourceByteLength ||
                authenticationChunkIndex !== expectedAuthenticationChunkIndex ||
                exactByteLength === 0 ||
                exactByteLength > canonicalCommonProofChunkByteLength ||
                sourceStreamTotalByteLength === 0n ||
                sourceStreamByteOffset + BigInt(exactByteLength) >
                    sourceStreamTotalByteLength ||
                storageByteOffset + BigInt(exactByteLength) > maximumUnsigned64
            ) {
                throw kernelFailure(
                    'The common-proof kernel exposed an inconsistent authenticated-source request.',
                );
            }
            return Object.freeze({
                authenticationChunkIndex,
                exactByteLength,
                sourceMaterialRoot: encodedRequest.slice(0, hashByteLength),
                sourceStreamByteOffset,
                sourceStreamDigest: encodedRequest.slice(
                    hashByteLength,
                    2 * hashByteLength,
                ),
                sourceStreamTotalByteLength,
                storageByteOffset,
            });
        } finally {
            encodedRequest.fill(0);
        }
    }

    public supplyAuthenticatedSourceRange(
        operationHandle: number,
        sourceBytes: Uint8Array,
    ): void {
        if (
            sourceBytes.byteLength === 0 ||
            sourceBytes.byteLength > canonicalCommonProofChunkByteLength
        ) {
            throw resourceFailure(
                'The authenticated common-proof source range exceeds the absolute chunk bound.',
            );
        }
        this.#withKernelInput(
            sourceBytes,
            'authenticated-source range',
            (sourcePointer, sourceByteLength) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_supply_authenticated_source_range',
                )(operationHandle, sourcePointer, sourceByteLength),
        );
    }

    public copyOutputChunk(
        operationHandle: number,
        chunkIndex: number,
        chunkByteLength: number,
    ): Uint8Array<ArrayBuffer> {
        requireUnsigned32(chunkIndex, 'The common-proof output chunk index');
        if (
            !Number.isSafeInteger(chunkByteLength) ||
            chunkByteLength <= 0 ||
            BigInt(chunkByteLength) > maximumWorkerPayloadByteLength
        ) {
            throw resourceFailure(
                'The common-proof kernel exposed an output chunk beyond the absolute safety bound.',
            );
        }
        return this.#copyKernelBytes(
            chunkByteLength,
            'output chunk',
            (outputPointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_copy_output_chunk',
                )(operationHandle, chunkIndex, outputPointer, chunkByteLength),
        );
    }

    public acknowledgeOutputChunk(
        operationHandle: number,
        chunkIndex: number,
    ): void {
        this.#context.runExclusive(
            'common-proof generation output acknowledgement',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_acknowledge_output_chunk',
                    )(operationHandle, chunkIndex),
                    'output-chunk acknowledgement',
                );
            },
        );
    }

    public confirmOutputReadback(
        operationHandle: number,
        chunkIndex: number,
        readbackBytes: Uint8Array,
    ): void {
        this.#withKernelInput(
            readbackBytes,
            'output readback',
            (readbackPointer, readbackByteLength) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_confirm_output_readback',
                )(
                    operationHandle,
                    chunkIndex,
                    readbackPointer,
                    readbackByteLength,
                ),
        );
    }

    /** Reads terminal production counters for manual evidence before finish. */
    public externalMemoryAccounting(
        operationHandle: number,
    ): CommonProofGenerationExternalMemoryAccounting {
        requireLiveHandle(
            operationHandle,
            'The common-proof generation operation handle',
        );
        return this.#context.runExclusive(
            'common-proof generation external-memory accounting',
            () => {
                const declaredByteLength = requireUnsigned32(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_external_memory_accounting_byte_length',
                    )(),
                    'The generation external-memory accounting byte length',
                );
                if (
                    declaredByteLength !==
                    generationExternalMemoryAccountingByteLength
                ) {
                    throw kernelFailure(
                        'The common-proof kernel exposed a malformed generation external-memory accounting length.',
                    );
                }
                const outputPointer =
                    this.#memoryBoundary.allocate(declaredByteLength);
                try {
                    requireKernelSuccess(
                        resolveNumberExport(
                            this.#context.wasmExports,
                            'sealed_lattice_common_proof_generation_copy_external_memory_accounting',
                        )(operationHandle, outputPointer, declaredByteLength),
                        'generation external-memory accounting copy',
                    );
                    const bytes = new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        declaredByteLength,
                    );
                    const stepCount = diagnosticUnsigned32(
                        readDiagnosticUnsigned64(bytes, 0),
                        'The compiled external-memory step count',
                    );
                    const maximumChunkByteLength = diagnosticUnsigned32(
                        readDiagnosticUnsigned64(bytes, 1),
                        'The compiled external-memory chunk byte length',
                    );
                    const maximumTransactionPayloadByteLength =
                        readDiagnosticUnsigned64(bytes, 2);
                    const distinctPhysicalObjectCount = diagnosticUnsigned32(
                        readDiagnosticUnsigned64(bytes, 3),
                        'The compiled external-memory physical object count',
                    );
                    const objectLifecycleCount = diagnosticUnsigned32(
                        readDiagnosticUnsigned64(bytes, 4),
                        'The compiled external-memory object lifecycle count',
                    );
                    const compiledRequirement = Object.freeze({
                        stepCount,
                        maximumChunkByteLength,
                        maximumTransactionPayloadByteLength,
                        distinctPhysicalObjectCount,
                        objectLifecycleCount,
                        peakStoredByteLength: readDiagnosticUnsigned64(
                            bytes,
                            5,
                        ),
                        totalWrittenByteLength: readDiagnosticUnsigned64(
                            bytes,
                            6,
                        ),
                        totalReadByteLength: readDiagnosticUnsigned64(bytes, 7),
                        transactionCount: readDiagnosticUnsigned64(bytes, 8),
                    });
                    if (
                        stepCount === 0 ||
                        maximumChunkByteLength !==
                            maximumExternalMemoryChunkByteLength ||
                        maximumTransactionPayloadByteLength === 0n ||
                        maximumTransactionPayloadByteLength >
                            maximumWorkerPayloadByteLength ||
                        distinctPhysicalObjectCount === 0 ||
                        distinctPhysicalObjectCount >
                            maximumWorkerOperationCount ||
                        objectLifecycleCount < distinctPhysicalObjectCount ||
                        compiledRequirement.peakStoredByteLength === 0n ||
                        compiledRequirement.peakStoredByteLength >
                            maximumExternalScratchByteLength ||
                        compiledRequirement.totalWrittenByteLength === 0n ||
                        compiledRequirement.totalReadByteLength === 0n ||
                        compiledRequirement.transactionCount === 0n
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel exposed malformed compiled external-memory accounting.',
                        );
                    }
                    const actualUsage = externalMemoryUsageFromDiagnostic(
                        bytes,
                        9,
                    );
                    const compiledUsageLimits = Object.freeze({
                        objectLifecycleCount: BigInt(objectLifecycleCount),
                        peakStoredByteLength:
                            compiledRequirement.peakStoredByteLength,
                        totalReadByteLength:
                            compiledRequirement.totalReadByteLength,
                        totalWrittenByteLength:
                            compiledRequirement.totalWrittenByteLength,
                        transactionCount: compiledRequirement.transactionCount,
                    });
                    if (
                        !usageDoesNotExceed(actualUsage, compiledUsageLimits) ||
                        actualUsage.deletedObjectLifecycleCount !==
                            BigInt(objectLifecycleCount)
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel reported external-memory usage outside its compiled plan.',
                        );
                    }
                    const prefixPresence = readDiagnosticUnsigned64(bytes, 14);
                    const prefixUsage = externalMemoryUsageFromDiagnostic(
                        bytes,
                        15,
                    );
                    if (
                        prefixPresence > 1n ||
                        (prefixPresence === 0n &&
                            Object.values(prefixUsage).some(
                                (value) => value !== 0n,
                            )) ||
                        (prefixPresence === 1n &&
                            !usageDoesNotExceed(prefixUsage, {
                                objectLifecycleCount:
                                    actualUsage.deletedObjectLifecycleCount,
                                peakStoredByteLength:
                                    actualUsage.peakStoredByteLength,
                                totalReadByteLength:
                                    actualUsage.totalReadByteLength,
                                totalWrittenByteLength:
                                    actualUsage.totalWrittenByteLength,
                                transactionCount: actualUsage.transactionCount,
                            }))
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel exposed malformed deterministic-prefix external-memory accounting.',
                        );
                    }
                    return Object.freeze({
                        actualUsage,
                        compiledRequirement,
                        ...(prefixPresence === 1n
                            ? {
                                  deterministicPrefixReplayUsage: prefixUsage,
                              }
                            : {}),
                    });
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        declaredByteLength,
                    );
                }
            },
        );
    }

    public requestCancellation(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof generation cancellation request',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_request_cancellation',
                    )(operationHandle),
                    'generation cancellation request',
                );
            },
        );
    }

    public releaseCancelled(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof cancelled generation release',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_release_cancelled',
                    )(operationHandle),
                    'cancelled generation release',
                );
            },
        );
    }

    public retireFailed(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof failed generation retirement',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_retire_failed',
                    )(operationHandle),
                    'failed generation retirement',
                );
            },
        );
    }

    public finish(operationHandle: number): number {
        return this.#context.runExclusive(
            'common-proof generation finish',
            () => {
                const finish = resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_finish',
                );
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const capabilityHandle = finish(
                        operationHandle,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(status, 'generation finish');
                    return requireLiveHandle(
                        capabilityHandle,
                        'The generated common-proof capability handle',
                    );
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public releaseGenerated(capabilityHandle: number): void {
        this.#context.runExclusive(
            'common-proof generated capability release',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_release_generated_proof',
                    )(capabilityHandle),
                    'generated-proof capability release',
                );
            },
        );
    }

    #copyKernelBytes(
        byteLength: number,
        label: string,
        copy: (outputPointer: number) => number,
    ): Uint8Array<ArrayBuffer> {
        return this.#context.runExclusive(`common-proof ${label} copy`, () => {
            const outputPointer = this.#memoryBoundary.allocate(byteLength);
            try {
                requireKernelSuccess(copy(outputPointer), `${label} copy`);
                return Uint8Array.from(
                    new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        byteLength,
                    ),
                );
            } finally {
                this.#memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    byteLength,
                );
            }
        });
    }

    #withKernelInput(
        bytes: Uint8Array,
        label: string,
        invoke: (inputPointer: number, inputByteLength: number) => number,
    ): void {
        if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
            throw resourceFailure(
                `The common-proof ${label} must be a non-empty byte array.`,
            );
        }
        const byteLength = bytes.byteLength;
        this.#context.runExclusive(`common-proof ${label}`, () => {
            let inputPointer = 0;
            try {
                inputPointer = this.#memoryBoundary.copy(bytes);
                destroyOwnedKernelBoundaryInput(bytes);
                requireKernelSuccess(invoke(inputPointer, byteLength), label);
            } finally {
                destroyOwnedKernelBoundaryInput(bytes);
                if (inputPointer !== 0) {
                    this.#memoryBoundary.zeroAndDeallocate(
                        inputPointer,
                        byteLength,
                    );
                }
            }
        });
    }

    #decodePoll(
        kind: number,
        primaryValue: number,
        secondaryValue: number,
    ): CommonProofGenerationKernelPoll {
        switch (kind) {
            case generationPollProgress:
                if (
                    primaryValue < firstGenerationStage ||
                    primaryValue > finalGenerationStage ||
                    (secondaryValue !== 0 && secondaryValue !== 1)
                ) {
                    break;
                }
                return Object.freeze({
                    checkpointReady: secondaryValue === 1,
                    kind: 'progress',
                });
            case generationPollResumeComplete:
                if (
                    primaryValue >= firstGenerationStage &&
                    primaryValue <= finalGenerationStage &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({
                        kind: 'resume-complete',
                    });
                }
                break;
            case generationPollStorageRequestReady:
                if (
                    primaryValue >= requestHeaderByteLength &&
                    primaryValue <= maximumEncodedRequestByteLength &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({
                        encodedRequestByteLength: primaryValue,
                        kind: 'storage-request-ready',
                    });
                }
                break;
            case generationPollAuthenticatedSourceReadReady:
                if (
                    primaryValue > 0 &&
                    primaryValue <= canonicalCommonProofChunkByteLength
                ) {
                    return Object.freeze({
                        authenticationChunkIndex: secondaryValue,
                        kind: 'authenticated-source-read-ready',
                        sourceByteLength: primaryValue,
                    });
                }
                break;
            case generationPollAuthenticatedTranscriptPrefixRequired:
                if (
                    primaryValue === 0 &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({
                        kind: 'authenticated-transcript-prefix-required',
                    });
                }
                break;
            case generationPollOutputChunkReady:
                if (
                    secondaryValue > 0 &&
                    BigInt(secondaryValue) <= maximumWorkerPayloadByteLength
                ) {
                    return Object.freeze({
                        chunkByteLength: secondaryValue,
                        chunkIndex: primaryValue,
                        kind: 'output-chunk-ready',
                    });
                }
                break;
            case generationPollOutputReadbackRequired:
                if (secondaryValue === noSecondPollValue) {
                    return Object.freeze({
                        chunkIndex: primaryValue,
                        kind: 'output-readback-required',
                    });
                }
                break;
            case generationPollComplete:
                if (
                    primaryValue === 0 &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({ kind: 'complete' });
                }
                break;
            case generationPollCancelled:
                if (
                    primaryValue === 0 &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({ kind: 'cancelled' });
                }
                break;
        }
        throw kernelFailure(
            'The common-proof kernel returned malformed generation poll metadata.',
        );
    }
}

export class CommonProofVerificationKernelBoundary {
    readonly #context: TranscriptCoreKernelCommandRuntime;
    readonly #memoryBoundary: WasmMemoryBoundary;

    public constructor(context: TranscriptCoreKernelCommandRuntime) {
        this.#context = context;
        this.#memoryBoundary = new WasmMemoryBoundary({
            context,
            createInternalError: (message) => kernelFailure(message),
            createResourceError: resourceFailure,
            label: 'common-proof verifier worker',
        });
    }

    #requireCompactPublicKeyTransportBytes(
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
    ): void {
        if (
            !(proofBytes instanceof Uint8Array) ||
            proofBytes.byteLength === 0 ||
            proofBytes.byteLength > maximumCommonProofByteLength ||
            !(publicInputBytes instanceof Uint8Array) ||
            publicInputBytes.byteLength === 0 ||
            publicInputBytes.byteLength > maximumCommonProofByteLength
        ) {
            throw resourceFailure(
                'The compact transport bytes must be nonempty and remain within the accepted release boundary.',
            );
        }
    }

    #copyCompactPublicKeyTransportBindings(
        bindings: CompactPublicKeyTransportBindings,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
    ): Uint8Array<ArrayBuffer> {
        for (const [value, label] of [
            [bindings.suiteIdentifier, 'The compact suite identifier'],
            [
                bindings.applicationStatementHash,
                'The compact application-statement hash',
            ],
            [bindings.manifestHash, 'The compact manifest hash'],
            [bindings.relationPlanHash, 'The compact relation-plan hash'],
        ] as const) {
            requireExactApplicationBytes(value, hashByteLength, label);
        }
        this.#requireCompactPublicKeyTransportBytes(
            proofBytes,
            publicInputBytes,
        );
        const canonicalBindings = new Uint8Array(
            compactPublicKeyTransportBindingsByteLength,
        );
        canonicalBindings.set(bindings.suiteIdentifier, 0);
        canonicalBindings.set(
            bindings.applicationStatementHash,
            hashByteLength,
        );
        canonicalBindings.set(bindings.manifestHash, 2 * hashByteLength);
        canonicalBindings.set(bindings.relationPlanHash, 3 * hashByteLength);
        return canonicalBindings;
    }

    #requireCompactPublicKeyTransportBindingGeometry(): void {
        const reportedBindingByteLength = requireUnsigned32(
            resolveNumberExport(
                this.#context.wasmExports,
                'sealed_lattice_compact_public_key_transport_bindings_byte_length',
            )(),
            'The compact transport binding byte length',
        );
        if (
            reportedBindingByteLength !==
            compactPublicKeyTransportBindingsByteLength
        ) {
            throw kernelFailure(
                'The compact transport binding geometry disagrees with the worker.',
            );
        }
    }

    /**
     * Checks canonical compact transport framing, transcript chronology, and
     * salted Merkle openings only. Success is not CFW or WHIR proof validity
     * and must not mint a proof or workflow capability.
     */
    public validateCompactPublicKeyTransport(
        bindings: CompactPublicKeyTransportBindings,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
    ): void {
        const canonicalBindings = this.#copyCompactPublicKeyTransportBindings(
            bindings,
            proofBytes,
            publicInputBytes,
        );
        try {
            this.#context.runExclusive(
                'compact public-key transport validation',
                () => {
                    this.#requireCompactPublicKeyTransportBindingGeometry();
                    let bindingsPointer: number | undefined;
                    let proofPointer: number | undefined;
                    let publicInputPointer: number | undefined;
                    try {
                        bindingsPointer =
                            this.#memoryBoundary.copy(canonicalBindings);
                        proofPointer = this.#memoryBoundary.copy(proofBytes);
                        publicInputPointer =
                            this.#memoryBoundary.copy(publicInputBytes);
                        requireKernelSuccess(
                            resolveNumberExport(
                                this.#context.wasmExports,
                                'sealed_lattice_compact_public_key_validate_transport',
                            )(
                                bindingsPointer,
                                canonicalBindings.byteLength,
                                proofPointer,
                                proofBytes.byteLength,
                                publicInputPointer,
                                publicInputBytes.byteLength,
                            ),
                            'compact public-key transport validation',
                        );
                    } finally {
                        if (publicInputPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                publicInputPointer,
                                publicInputBytes.byteLength,
                            );
                        }
                        if (proofPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                proofPointer,
                                proofBytes.byteLength,
                            );
                        }
                        if (bindingsPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                bindingsPointer,
                                compactPublicKeyTransportBindingsByteLength,
                            );
                        }
                    }
                },
            );
        } finally {
            canonicalBindings.fill(0);
        }
    }

    /**
     * Copies one exact compact proof into Rust-owned verification custody after
     * strict transport validation. A refusal never returns a live handle.
     */
    public beginCompactPublicKeyAlgebraicVerification(
        bindings: CompactPublicKeyTransportBindings,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
    ): CompactPublicKeyAlgebraicVerificationKernelBegin {
        return this.#startCompactPublicKeyAlgebraicVerification(
            bindings,
            proofBytes,
            publicInputBytes,
        );
    }

    /**
     * Revalidates the exact transported bytes and retains a fresh verifier at
     * genesis. Bounded polls replay to the authenticated safe cursor before
     * live work can continue.
     */
    public resumeCompactPublicKeyAlgebraicVerification(
        bindings: CompactPublicKeyTransportBindings,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
        canonicalCheckpointBytes: Uint8Array,
    ): CompactPublicKeyAlgebraicVerificationKernelBegin {
        if (
            !(canonicalCheckpointBytes instanceof Uint8Array) ||
            canonicalCheckpointBytes.byteLength !==
                this.compactPublicKeyAlgebraicVerificationCheckpointByteLength()
        ) {
            throw resourceFailure(
                'The compact public-key algebraic verification checkpoint has the wrong byte length.',
            );
        }
        return this.#startCompactPublicKeyAlgebraicVerification(
            bindings,
            proofBytes,
            publicInputBytes,
            canonicalCheckpointBytes,
        );
    }

    public compactPublicKeyAlgebraicVerificationCheckpointByteLength(): number {
        return this.#context.runExclusive(
            'compact public-key algebraic verification checkpoint length',
            () => {
                const byteLength = requireUnsigned32(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length',
                    )(),
                    'The compact public-key algebraic verification checkpoint byte length',
                );
                if (
                    byteLength !==
                    canonicalCompactPublicKeyAlgebraicVerificationCheckpointByteLength
                ) {
                    throw kernelFailure(
                        'The compact public-key algebraic verification checkpoint geometry disagrees with the worker.',
                    );
                }
                return byteLength;
            },
        );
    }

    public compactPublicKeyAlgebraicVerificationSafeBoundaryCount(): number {
        return this.#context.runExclusive(
            'compact public-key algebraic verification safe-boundary count',
            () =>
                this.#requireCompactPublicKeyAlgebraicVerificationSafeBoundaryCount(),
        );
    }

    #requireCompactPublicKeyAlgebraicVerificationSafeBoundaryCount(): number {
        const safeBoundaryCount = requireUnsigned32(
            resolveNumberExport(
                this.#context.wasmExports,
                'sealed_lattice_compact_public_key_algebraic_verification_safe_boundary_count',
            )(),
            'The compact public-key algebraic verification safe-boundary count',
        );
        if (
            safeBoundaryCount !==
            canonicalCompactPublicKeyAlgebraicVerificationSafeBoundaryCount
        ) {
            throw kernelFailure(
                'The compact public-key algebraic verification checkpoint schedule disagrees with the worker.',
            );
        }
        return safeBoundaryCount;
    }

    #startCompactPublicKeyAlgebraicVerification(
        bindings: CompactPublicKeyTransportBindings,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
        canonicalCheckpointBytes?: Uint8Array,
    ): CompactPublicKeyAlgebraicVerificationKernelBegin {
        const canonicalBindings = this.#copyCompactPublicKeyTransportBindings(
            bindings,
            proofBytes,
            publicInputBytes,
        );
        try {
            return this.#context.runExclusive(
                'compact public-key algebraic verification begin',
                () => {
                    this.#requireCompactPublicKeyTransportBindingGeometry();
                    let bindingsPointer: number | undefined;
                    let proofPointer: number | undefined;
                    let publicInputPointer: number | undefined;
                    let checkpointPointer: number | undefined;
                    let statusPointer: number | undefined;
                    try {
                        bindingsPointer =
                            this.#memoryBoundary.copy(canonicalBindings);
                        proofPointer = this.#memoryBoundary.copy(proofBytes);
                        publicInputPointer =
                            this.#memoryBoundary.copy(publicInputBytes);
                        if (canonicalCheckpointBytes !== undefined) {
                            checkpointPointer = this.#memoryBoundary.copy(
                                canonicalCheckpointBytes,
                            );
                        }
                        statusPointer =
                            this.#memoryBoundary.allocateZeroedWords(1);
                        const operationHandle =
                            canonicalCheckpointBytes === undefined
                                ? resolveNumberExport(
                                      this.#context.wasmExports,
                                      'sealed_lattice_compact_public_key_begin_algebraic_verification',
                                  )(
                                      bindingsPointer,
                                      canonicalBindings.byteLength,
                                      proofPointer,
                                      proofBytes.byteLength,
                                      publicInputPointer,
                                      publicInputBytes.byteLength,
                                      statusPointer,
                                  )
                                : resolveNumberExport(
                                      this.#context.wasmExports,
                                      'sealed_lattice_compact_public_key_resume_algebraic_verification',
                                  )(
                                      bindingsPointer,
                                      canonicalBindings.byteLength,
                                      proofPointer,
                                      proofBytes.byteLength,
                                      publicInputPointer,
                                      publicInputBytes.byteLength,
                                      checkpointPointer!,
                                      canonicalCheckpointBytes.byteLength,
                                      statusPointer,
                                  );
                        const [status] = this.#memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        const refusalReason =
                            decodeCompactPublicKeyAlgebraicVerificationStatus(
                                status,
                                'algebraic verification begin',
                            );
                        if (refusalReason !== undefined) {
                            if (operationHandle !== 0) {
                                throw kernelFailure(
                                    'A refused compact public-key algebraic verifier begin returned a live handle.',
                                );
                            }
                            return Object.freeze({
                                kind: 'refused',
                                refusalReason,
                            });
                        }
                        return Object.freeze({
                            kind: 'started',
                            operationHandle: requireLiveHandle(
                                operationHandle,
                                'The compact public-key algebraic verification operation handle',
                            ),
                        });
                    } finally {
                        if (statusPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                statusPointer,
                                wasm32WordByteLength,
                            );
                        }
                        if (
                            checkpointPointer !== undefined &&
                            canonicalCheckpointBytes !== undefined
                        ) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                checkpointPointer,
                                canonicalCheckpointBytes.byteLength,
                            );
                        }
                        if (publicInputPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                publicInputPointer,
                                publicInputBytes.byteLength,
                            );
                        }
                        if (proofPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                proofPointer,
                                proofBytes.byteLength,
                            );
                        }
                        if (bindingsPointer !== undefined) {
                            this.#memoryBoundary.zeroAndDeallocate(
                                bindingsPointer,
                                canonicalBindings.byteLength,
                            );
                        }
                    }
                },
            );
        } finally {
            canonicalBindings.fill(0);
        }
    }

    /** Copies the source-bound cursor for the latest completed safe slice. */
    public copyCompactPublicKeyAlgebraicVerificationCheckpoint(
        operationHandle: number,
    ): Uint8Array<ArrayBuffer> {
        requireLiveHandle(
            operationHandle,
            'The compact public-key algebraic verification operation handle',
        );
        const checkpointByteLength =
            this.compactPublicKeyAlgebraicVerificationCheckpointByteLength();
        return this.#context.runExclusive(
            'compact public-key algebraic verification checkpoint copy',
            () => {
                const outputPointer =
                    this.#memoryBoundary.allocate(checkpointByteLength);
                try {
                    const status = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_compact_public_key_copy_algebraic_verification_checkpoint',
                    )(operationHandle, outputPointer, checkpointByteLength);
                    const refusalReason =
                        decodeCompactPublicKeyAlgebraicVerificationStatus(
                            status,
                            'algebraic verification checkpoint copy',
                        );
                    if (refusalReason !== undefined) {
                        throw kernelFailure(
                            `The compact public-key algebraic verifier refused checkpoint copy with ${refusalReason}.`,
                        );
                    }
                    return new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        checkpointByteLength,
                    ).slice();
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        checkpointByteLength,
                    );
                }
            },
        );
    }

    /** Advances one bounded algebraic-verifier slice without minting authority. */
    public pollCompactPublicKeyAlgebraicVerification(
        operationHandle: number,
        maximumWorkUnitCount: number,
    ): CompactPublicKeyAlgebraicVerificationKernelPoll {
        requireLiveHandle(
            operationHandle,
            'The compact public-key algebraic verification operation handle',
        );
        requireUnsigned32(
            maximumWorkUnitCount,
            'The compact public-key algebraic verification work-unit bound',
        );
        if (maximumWorkUnitCount === 0) {
            throw resourceFailure(
                'The compact public-key algebraic verification work-unit bound must be positive.',
            );
        }
        return this.#context.runExclusive(
            'compact public-key algebraic verification poll',
            () => {
                const safeBoundaryCount =
                    this.#requireCompactPublicKeyAlgebraicVerificationSafeBoundaryCount();
                const metadataPointer =
                    this.#memoryBoundary.allocateZeroedWords(3);
                try {
                    const status = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_compact_public_key_algebraic_verification_poll',
                    )(
                        operationHandle,
                        maximumWorkUnitCount,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                        metadataPointer + 2 * wasm32WordByteLength,
                    );
                    const refusalReason =
                        decodeCompactPublicKeyAlgebraicVerificationStatus(
                            status,
                            'algebraic verification poll',
                        );
                    if (refusalReason !== undefined) {
                        return Object.freeze({
                            kind: 'refused',
                            refusalReason,
                        });
                    }
                    const [
                        pollKind,
                        completedWorkUnitCount,
                        checkpointSafeBoundaryOrdinal,
                    ] = this.#memoryBoundary.readWords(metadataPointer, 3);
                    switch (pollKind) {
                        case compactPublicKeyAlgebraicVerificationPollProgress: {
                            if (
                                completedWorkUnitCount === 0 ||
                                completedWorkUnitCount > maximumWorkUnitCount
                            ) {
                                throw kernelFailure(
                                    'The compact public-key algebraic verifier reported invalid bounded progress.',
                                );
                            }
                            if (
                                checkpointSafeBoundaryOrdinal !==
                                    noSecondPollValue &&
                                checkpointSafeBoundaryOrdinal >=
                                    safeBoundaryCount
                            ) {
                                throw kernelFailure(
                                    'The compact public-key algebraic verifier reported an unassigned checkpoint boundary.',
                                );
                            }
                            return Object.freeze({
                                ...(checkpointSafeBoundaryOrdinal ===
                                noSecondPollValue
                                    ? {}
                                    : { checkpointSafeBoundaryOrdinal }),
                                completedWorkUnitCount,
                                kind: 'progress',
                            });
                        }
                        case compactPublicKeyAlgebraicVerificationPollResumeComplete: {
                            if (
                                completedWorkUnitCount === 0 ||
                                completedWorkUnitCount > maximumWorkUnitCount
                            ) {
                                throw kernelFailure(
                                    'The compact public-key algebraic verifier reported invalid bounded replay completion.',
                                );
                            }
                            if (
                                checkpointSafeBoundaryOrdinal ===
                                    noSecondPollValue ||
                                checkpointSafeBoundaryOrdinal >=
                                    safeBoundaryCount
                            ) {
                                throw kernelFailure(
                                    'The compact public-key algebraic verifier reported an unassigned replay checkpoint boundary.',
                                );
                            }
                            return Object.freeze({
                                checkpointSafeBoundaryOrdinal,
                                completedWorkUnitCount,
                                kind: 'resume-complete',
                            });
                        }
                        case compactPublicKeyAlgebraicVerificationPollComplete: {
                            if (
                                completedWorkUnitCount !== 0 ||
                                checkpointSafeBoundaryOrdinal !==
                                    noSecondPollValue
                            ) {
                                throw kernelFailure(
                                    'The completed compact public-key algebraic verifier reported residual work.',
                                );
                            }
                            return Object.freeze({ kind: 'complete' });
                        }
                        default:
                            throw kernelFailure(
                                `The compact public-key algebraic verifier returned unknown poll kind ${String(pollKind)}.`,
                            );
                    }
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        3 * wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public cancelCompactPublicKeyAlgebraicVerification(
        operationHandle: number,
    ): void {
        requireLiveHandle(
            operationHandle,
            'The compact public-key algebraic verification operation handle',
        );
        this.#context.runExclusive(
            'compact public-key algebraic verification cancellation',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_compact_public_key_cancel_algebraic_verification',
                    )(operationHandle),
                    'compact public-key algebraic verification cancellation',
                );
            },
        );
    }

    public prepareAcceptedSetupCompactPublicKeyVerification(
        assemblyHandle: number,
        canonicalApplicationStatementBytes: Uint8Array,
    ): AcceptedSetupCompactPublicKeyVerificationKernelPreparation {
        requireLiveHandle(
            assemblyHandle,
            'The accepted-setup verification assembly handle',
        );
        if (
            !(canonicalApplicationStatementBytes instanceof Uint8Array) ||
            canonicalApplicationStatementBytes.byteLength === 0 ||
            canonicalApplicationStatementBytes.byteLength >
                maximumCommonProofByteLength
        ) {
            throw resourceFailure(
                'The compact public-key application statement must be nonempty and remain within the accepted release boundary.',
            );
        }
        return this.#context.runExclusive(
            'accepted-setup compact public-key verification preparation',
            () => {
                const statementPointer = this.#memoryBoundary.copy(
                    canonicalApplicationStatementBytes,
                );
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const preparedHandle = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_public_key_share_prepare_compact_verification',
                    )(
                        assemblyHandle,
                        statementPointer,
                        canonicalApplicationStatementBytes.byteLength,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    const refusalReason =
                        decodeCompactPublicKeyAlgebraicVerificationStatus(
                            status,
                            'accepted-setup compact public-key verification preparation',
                        );
                    if (refusalReason !== undefined) {
                        if (preparedHandle !== 0) {
                            throw kernelFailure(
                                'A refused accepted-setup compact verifier preparation returned a live handle.',
                            );
                        }
                        return Object.freeze({
                            kind: 'refused',
                            refusalReason,
                        });
                    }
                    return Object.freeze({
                        kind: 'prepared',
                        preparedHandle: requireLiveHandle(
                            preparedHandle,
                            'The accepted-setup compact public-key prepared handle',
                        ),
                    });
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    this.#memoryBoundary.zeroAndDeallocate(
                        statementPointer,
                        canonicalApplicationStatementBytes.byteLength,
                    );
                }
            },
        );
    }

    public beginAcceptedSetupCompactPublicKeyVerification(
        preparedHandle: number,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
    ): AcceptedSetupCompactPublicKeyVerificationKernelBegin {
        return this.#startAcceptedSetupCompactPublicKeyVerification(
            preparedHandle,
            proofBytes,
            publicInputBytes,
        );
    }

    public resumeAcceptedSetupCompactPublicKeyVerification(
        preparedHandle: number,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
        canonicalCheckpointBytes: Uint8Array,
    ): AcceptedSetupCompactPublicKeyVerificationKernelBegin {
        if (
            !(canonicalCheckpointBytes instanceof Uint8Array) ||
            canonicalCheckpointBytes.byteLength !==
                this.compactPublicKeyAlgebraicVerificationCheckpointByteLength()
        ) {
            throw resourceFailure(
                'The accepted-setup compact public-key verification checkpoint has the wrong byte length.',
            );
        }
        return this.#startAcceptedSetupCompactPublicKeyVerification(
            preparedHandle,
            proofBytes,
            publicInputBytes,
            canonicalCheckpointBytes,
        );
    }

    #startAcceptedSetupCompactPublicKeyVerification(
        preparedHandle: number,
        proofBytes: Uint8Array,
        publicInputBytes: Uint8Array,
        canonicalCheckpointBytes?: Uint8Array,
    ): AcceptedSetupCompactPublicKeyVerificationKernelBegin {
        requireLiveHandle(
            preparedHandle,
            'The accepted-setup compact public-key prepared handle',
        );
        this.#requireCompactPublicKeyTransportBytes(
            proofBytes,
            publicInputBytes,
        );
        return this.#context.runExclusive(
            'accepted-setup compact public-key verification begin',
            () => {
                const proofPointer = this.#memoryBoundary.copy(proofBytes);
                const publicInputPointer =
                    this.#memoryBoundary.copy(publicInputBytes);
                const checkpointPointer =
                    canonicalCheckpointBytes === undefined
                        ? undefined
                        : this.#memoryBoundary.copy(canonicalCheckpointBytes);
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const operationHandle =
                        canonicalCheckpointBytes === undefined
                            ? resolveNumberExport(
                                  this.#context.wasmExports,
                                  'sealed_lattice_accepted_setup_compact_public_key_begin_verification',
                              )(
                                  preparedHandle,
                                  proofPointer,
                                  proofBytes.byteLength,
                                  publicInputPointer,
                                  publicInputBytes.byteLength,
                                  statusPointer,
                              )
                            : resolveNumberExport(
                                  this.#context.wasmExports,
                                  'sealed_lattice_accepted_setup_compact_public_key_resume_verification',
                              )(
                                  preparedHandle,
                                  proofPointer,
                                  proofBytes.byteLength,
                                  publicInputPointer,
                                  publicInputBytes.byteLength,
                                  checkpointPointer!,
                                  canonicalCheckpointBytes.byteLength,
                                  statusPointer,
                              );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    const refusalReason =
                        decodeCompactPublicKeyAlgebraicVerificationStatus(
                            status,
                            'accepted-setup compact public-key verification begin',
                        );
                    if (refusalReason !== undefined) {
                        if (operationHandle !== 0) {
                            throw kernelFailure(
                                'A refused accepted-setup compact verifier begin returned a live handle.',
                            );
                        }
                        return Object.freeze({
                            kind: 'refused',
                            refusalReason,
                        });
                    }
                    const liveOperationHandle = requireLiveHandle(
                        operationHandle,
                        'The accepted-setup compact public-key verification operation handle',
                    );
                    if (liveOperationHandle !== preparedHandle) {
                        throw kernelFailure(
                            'The accepted-setup compact verifier changed its linear handle during begin.',
                        );
                    }
                    return Object.freeze({
                        kind: 'started',
                        operationHandle: liveOperationHandle,
                    });
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    if (checkpointPointer !== undefined) {
                        this.#memoryBoundary.zeroAndDeallocate(
                            checkpointPointer,
                            canonicalCheckpointBytes!.byteLength,
                        );
                    }
                    this.#memoryBoundary.zeroAndDeallocate(
                        publicInputPointer,
                        publicInputBytes.byteLength,
                    );
                    this.#memoryBoundary.zeroAndDeallocate(
                        proofPointer,
                        proofBytes.byteLength,
                    );
                }
            },
        );
    }

    public copyAcceptedSetupCompactPublicKeyVerificationCheckpoint(
        operationHandle: number,
    ): Uint8Array<ArrayBuffer> {
        requireLiveHandle(
            operationHandle,
            'The accepted-setup compact public-key verification operation handle',
        );
        const checkpointByteLength =
            this.compactPublicKeyAlgebraicVerificationCheckpointByteLength();
        return this.#context.runExclusive(
            'accepted-setup compact public-key verification checkpoint copy',
            () => {
                const outputPointer =
                    this.#memoryBoundary.allocate(checkpointByteLength);
                try {
                    const status = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_compact_public_key_copy_verification_checkpoint',
                    )(operationHandle, outputPointer, checkpointByteLength);
                    const refusalReason =
                        decodeCompactPublicKeyAlgebraicVerificationStatus(
                            status,
                            'accepted-setup compact public-key verification checkpoint copy',
                        );
                    if (refusalReason !== undefined) {
                        throw kernelFailure(
                            `The accepted-setup compact verifier refused checkpoint copy with ${refusalReason}.`,
                        );
                    }
                    return new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        checkpointByteLength,
                    ).slice();
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        checkpointByteLength,
                    );
                }
            },
        );
    }

    public pollAcceptedSetupCompactPublicKeyVerification(
        operationHandle: number,
        maximumWorkUnitCount: number,
    ): AcceptedSetupCompactPublicKeyVerificationKernelPoll {
        requireLiveHandle(
            operationHandle,
            'The accepted-setup compact public-key verification operation handle',
        );
        requireUnsigned32(
            maximumWorkUnitCount,
            'The accepted-setup compact public-key verification work-unit bound',
        );
        if (maximumWorkUnitCount === 0) {
            throw resourceFailure(
                'The accepted-setup compact public-key verification work-unit bound must be positive.',
            );
        }
        return this.#context.runExclusive(
            'accepted-setup compact public-key verification poll',
            () => {
                const safeBoundaryCount =
                    this.#requireCompactPublicKeyAlgebraicVerificationSafeBoundaryCount();
                const metadataPointer =
                    this.#memoryBoundary.allocateZeroedWords(4);
                try {
                    const status = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_compact_public_key_verification_poll',
                    )(
                        operationHandle,
                        maximumWorkUnitCount,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                        metadataPointer + 2 * wasm32WordByteLength,
                        metadataPointer + 3 * wasm32WordByteLength,
                    );
                    const refusalReason =
                        decodeCompactPublicKeyAlgebraicVerificationStatus(
                            status,
                            'accepted-setup compact public-key verification poll',
                        );
                    if (refusalReason !== undefined) {
                        return Object.freeze({
                            kind: 'refused',
                            refusalReason,
                        });
                    }
                    const [
                        pollKind,
                        completedWorkUnitCount,
                        checkpointSafeBoundaryOrdinal,
                        verifiedCapabilityHandle,
                    ] = this.#memoryBoundary.readWords(metadataPointer, 4);
                    switch (pollKind) {
                        case compactPublicKeyAlgebraicVerificationPollProgress: {
                            if (
                                completedWorkUnitCount === 0 ||
                                completedWorkUnitCount > maximumWorkUnitCount ||
                                verifiedCapabilityHandle !== 0
                            ) {
                                throw kernelFailure(
                                    'The accepted-setup compact verifier reported invalid bounded progress.',
                                );
                            }
                            if (
                                checkpointSafeBoundaryOrdinal !==
                                    noSecondPollValue &&
                                checkpointSafeBoundaryOrdinal >=
                                    safeBoundaryCount
                            ) {
                                throw kernelFailure(
                                    'The accepted-setup compact verifier reported an unassigned checkpoint boundary.',
                                );
                            }
                            return Object.freeze({
                                ...(checkpointSafeBoundaryOrdinal ===
                                noSecondPollValue
                                    ? {}
                                    : { checkpointSafeBoundaryOrdinal }),
                                completedWorkUnitCount,
                                kind: 'progress',
                            });
                        }
                        case compactPublicKeyAlgebraicVerificationPollResumeComplete: {
                            if (
                                completedWorkUnitCount === 0 ||
                                completedWorkUnitCount > maximumWorkUnitCount ||
                                checkpointSafeBoundaryOrdinal ===
                                    noSecondPollValue ||
                                checkpointSafeBoundaryOrdinal >=
                                    safeBoundaryCount ||
                                verifiedCapabilityHandle !== 0
                            ) {
                                throw kernelFailure(
                                    'The accepted-setup compact verifier reported invalid replay completion.',
                                );
                            }
                            return Object.freeze({
                                checkpointSafeBoundaryOrdinal,
                                completedWorkUnitCount,
                                kind: 'resume-complete',
                            });
                        }
                        case compactPublicKeyAlgebraicVerificationPollComplete: {
                            if (
                                completedWorkUnitCount !== 0 ||
                                checkpointSafeBoundaryOrdinal !==
                                    noSecondPollValue
                            ) {
                                throw kernelFailure(
                                    'The completed accepted-setup compact verifier reported residual work.',
                                );
                            }
                            const liveCapabilityHandle = requireLiveHandle(
                                verifiedCapabilityHandle,
                                'The accepted-setup compact public-key verified capability handle',
                            );
                            if (liveCapabilityHandle !== operationHandle) {
                                throw kernelFailure(
                                    'The accepted-setup compact verifier changed its linear handle at capability handoff.',
                                );
                            }
                            return Object.freeze({
                                kind: 'complete',
                                verifiedCapabilityHandle: liveCapabilityHandle,
                            });
                        }
                        default:
                            throw kernelFailure(
                                `The accepted-setup compact verifier returned unknown poll kind ${String(pollKind)}.`,
                            );
                    }
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        4 * wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public cancelAcceptedSetupCompactPublicKeyVerification(
        operationHandle: number,
    ): void {
        requireLiveHandle(
            operationHandle,
            'The accepted-setup compact public-key verification operation handle',
        );
        this.#context.runExclusive(
            'accepted-setup compact public-key verification cancellation',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_compact_public_key_cancel_verification',
                    )(operationHandle),
                    'accepted-setup compact public-key verification cancellation',
                );
            },
        );
    }

    public discardAcceptedSetupCompactPublicKeyPreparedVerification(
        preparedHandle: number,
    ): void {
        requireLiveHandle(
            preparedHandle,
            'The accepted-setup compact public-key prepared handle',
        );
        this.#context.runExclusive(
            'accepted-setup compact public-key prepared-source discard',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_compact_public_key_discard_prepared_verification',
                    )(preparedHandle),
                    'accepted-setup compact public-key prepared-source discard',
                );
            },
        );
    }

    public finishAcceptedSetupCompactPublicKeyVerification(
        verifiedCapabilityHandle: number,
    ): RefusalReason | undefined {
        requireLiveHandle(
            verifiedCapabilityHandle,
            'The accepted-setup compact public-key verified capability handle',
        );
        return this.#context.runExclusive(
            'accepted-setup compact public-key verification finish',
            () =>
                decodeCompactPublicKeyAlgebraicVerificationStatus(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_compact_public_key_finish_verification',
                    )(verifiedCapabilityHandle),
                    'accepted-setup compact public-key verification finish',
                ),
        );
    }

    public discardAcceptedSetupCompactPublicKeyCapability(
        verifiedCapabilityHandle: number,
    ): void {
        requireLiveHandle(
            verifiedCapabilityHandle,
            'The accepted-setup compact public-key verified capability handle',
        );
        this.#context.runExclusive(
            'accepted-setup compact public-key capability discard',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_accepted_setup_compact_public_key_discard_capability',
                    )(verifiedCapabilityHandle),
                    'accepted-setup compact public-key capability discard',
                );
            },
        );
    }

    public begin(preparedVerificationHandle: number): number {
        requireLiveHandle(
            preparedVerificationHandle,
            'The prepared common-proof verification handle',
        );
        return this.#context.runExclusive(
            'common-proof verification begin',
            () => {
                const begin = resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_begin_verification',
                );
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const operationHandle = begin(
                        preparedVerificationHandle,
                        statusPointer,
                    );
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(status, 'verification begin');
                    return requireLiveHandle(
                        operationHandle,
                        'The common-proof verification operation handle',
                    );
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public absorbInputChunk(
        operationHandle: number,
        chunkIndex: number,
        chunkBytes: Uint8Array,
    ): void {
        requireUnsigned32(chunkIndex, 'The common-proof input chunk index');
        this.#withKernelInput(
            chunkBytes,
            'verification input chunk',
            (pointer, chunkByteLength) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_verification_absorb_input_chunk',
                )(operationHandle, chunkIndex, pointer, chunkByteLength),
        );
    }

    public finishInput(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof verification input finish',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_verification_finish_input',
                    )(operationHandle),
                    'verification input finish',
                );
            },
        );
    }

    public poll(operationHandle: number): CommonProofVerificationKernelPoll {
        return this.#context.runExclusive(
            'common-proof verification poll',
            () => {
                const metadataPointer =
                    this.#memoryBoundary.allocateZeroedWords(3);
                try {
                    requireKernelSuccess(
                        resolveNumberExport(
                            this.#context.wasmExports,
                            'sealed_lattice_common_proof_verification_poll',
                        )(
                            operationHandle,
                            metadataPointer,
                            metadataPointer + wasm32WordByteLength,
                            metadataPointer + 2 * wasm32WordByteLength,
                        ),
                        'verification poll',
                    );
                    const [kind, primaryValue, secondaryValue] =
                        this.#memoryBoundary.readWords(metadataPointer, 3);
                    return this.#decodePoll(kind, primaryValue, secondaryValue);
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        3 * wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public supplyReadbackChunk(
        operationHandle: number,
        chunkIndex: number,
        chunkBytes: Uint8Array,
    ): void {
        requireUnsigned32(chunkIndex, 'The common-proof readback chunk index');
        this.#withKernelInput(
            chunkBytes,
            'verification readback chunk',
            (pointer, chunkByteLength) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_verification_supply_readback_chunk',
                )(operationHandle, chunkIndex, pointer, chunkByteLength),
        );
    }

    /** Reads process-local traversal counters for manual evidence before finish. */
    public readbackAccounting(
        operationHandle: number,
    ): CommonProofVerificationReadbackAccounting {
        requireLiveHandle(
            operationHandle,
            'The common-proof verification operation handle',
        );
        return this.#context.runExclusive(
            'common-proof verification readback accounting',
            () => {
                const declaredByteLength = requireUnsigned32(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_verification_readback_accounting_byte_length',
                    )(),
                    'The verification readback accounting byte length',
                );
                if (
                    declaredByteLength !==
                    verificationReadbackAccountingByteLength
                ) {
                    throw kernelFailure(
                        'The common-proof kernel exposed a malformed verification readback accounting length.',
                    );
                }
                const outputPointer =
                    this.#memoryBoundary.allocate(declaredByteLength);
                try {
                    requireKernelSuccess(
                        resolveNumberExport(
                            this.#context.wasmExports,
                            'sealed_lattice_common_proof_verification_copy_readback_accounting',
                        )(operationHandle, outputPointer, declaredByteLength),
                        'verification readback accounting copy',
                    );
                    const bytes = new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        declaredByteLength,
                    );
                    return Object.freeze({
                        logicalRequiredRangeCount: readDiagnosticUnsigned64(
                            bytes,
                            0,
                        ),
                        logicalRequiredByteLength: readDiagnosticUnsigned64(
                            bytes,
                            1,
                        ),
                        suppliedFullChunkCount: readDiagnosticUnsigned64(
                            bytes,
                            2,
                        ),
                        suppliedFullChunkByteLength: readDiagnosticUnsigned64(
                            bytes,
                            3,
                        ),
                    });
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        declaredByteLength,
                    );
                }
            },
        );
    }

    public finish(operationHandle: number): number {
        return this.#context.runExclusive(
            'common-proof verification finish',
            () => {
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const capabilityHandle = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_verification_finish',
                    )(operationHandle, statusPointer);
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(status, 'verification finish');
                    return requireLiveHandle(
                        capabilityHandle,
                        'The verified common-proof capability handle',
                    );
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    public cancel(operationHandle: number): void {
        this.#context.runExclusive(
            'common-proof verification cancellation',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_verification_cancel',
                    )(operationHandle),
                    'verification cancellation',
                );
            },
        );
    }

    public discardVerified(capabilityHandle: number): void {
        this.#context.runExclusive(
            'common-proof verified capability disposal',
            () => {
                requireKernelSuccess(
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_discard_verified_proof',
                    )(capabilityHandle),
                    'verified-proof capability disposal',
                );
            },
        );
    }

    public prepareApplication(
        capabilityHandle: number,
        storageRootAccess: CommonProofApplicationStorageRootAccess,
        predecessor: CommonProofApplicationFreshnessCoordinate,
    ): Readonly<{
        authorizationFrame: Uint8Array<ArrayBuffer>;
        pendingHandle: number;
        proofApplicationSlotHash: Uint8Array<ArrayBuffer>;
    }> {
        this.#requireStorageRootContext(storageRootAccess);
        requireLiveHandle(
            capabilityHandle,
            'The verified common-proof capability handle',
        );
        requireLiveHandle(
            storageRootAccess.storageRootHandle,
            'The local storage-root handle',
        );
        requireUnsigned64(
            predecessor.freshnessSequence,
            'The predecessor freshness sequence',
        );
        requireExactApplicationBytes(
            storageRootAccess.storageRootCapability,
            localStorageRootCapabilityByteLength,
            'The local storage-root capability',
        );
        requireExactApplicationBytes(
            predecessor.authenticatedHeadDigest,
            hashByteLength,
            'The predecessor authenticated head digest',
        );
        requireExactApplicationBytes(
            predecessor.storageInstanceIdentity,
            hashByteLength,
            'The storage instance identity',
        );
        const storageRootCapability = copyExactApplicationBytes(
            storageRootAccess.storageRootCapability,
            localStorageRootCapabilityByteLength,
            'The local storage-root capability',
        );
        const predecessorHeadDigest = copyExactApplicationBytes(
            predecessor.authenticatedHeadDigest,
            hashByteLength,
            'The predecessor authenticated head digest',
        );
        const storageInstanceIdentity = copyExactApplicationBytes(
            predecessor.storageInstanceIdentity,
            hashByteLength,
            'The storage instance identity',
        );
        try {
            return this.#context.runExclusive(
                'common-proof application preparation',
                () => {
                    const applicationFrameByteLength = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_application_frame_byte_length',
                    )();
                    this.#memoryBoundary.validateAllocationByteLength(
                        applicationFrameByteLength,
                    );
                    const prepare = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_prepare_application',
                    );
                    let storageRootCapabilityPointer = 0;
                    let predecessorHeadDigestPointer = 0;
                    let storageInstanceIdentityPointer = 0;
                    let authorizationFramePointer = 0;
                    let proofApplicationSlotHashPointer = 0;
                    let statusPointer = 0;
                    try {
                        storageRootCapabilityPointer =
                            this.#memoryBoundary.copy(storageRootCapability);
                        predecessorHeadDigestPointer =
                            this.#memoryBoundary.copy(predecessorHeadDigest);
                        storageInstanceIdentityPointer =
                            this.#memoryBoundary.copy(storageInstanceIdentity);
                        authorizationFramePointer =
                            this.#memoryBoundary.allocate(
                                applicationFrameByteLength,
                            );
                        proofApplicationSlotHashPointer =
                            this.#memoryBoundary.allocate(hashByteLength);
                        statusPointer =
                            this.#memoryBoundary.allocateZeroedWords(1);
                        new Uint8Array(
                            this.#context.memory.buffer,
                            authorizationFramePointer,
                            applicationFrameByteLength,
                        ).fill(0);
                        new Uint8Array(
                            this.#context.memory.buffer,
                            proofApplicationSlotHashPointer,
                            hashByteLength,
                        ).fill(0);
                        const pendingHandle = prepare(
                            capabilityHandle,
                            storageRootAccess.storageRootHandle,
                            storageRootCapabilityPointer,
                            predecessor.freshnessSequence,
                            predecessorHeadDigestPointer,
                            storageInstanceIdentityPointer,
                            authorizationFramePointer,
                            applicationFrameByteLength,
                            proofApplicationSlotHashPointer,
                            hashByteLength,
                            statusPointer,
                        );
                        const [status] = this.#memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        requireKernelSuccess(
                            status,
                            'common-proof application preparation',
                        );
                        return Object.freeze({
                            authorizationFrame: Uint8Array.from(
                                new Uint8Array(
                                    this.#context.memory.buffer,
                                    authorizationFramePointer,
                                    applicationFrameByteLength,
                                ),
                            ),
                            pendingHandle: requireLiveHandle(
                                pendingHandle,
                                'The pending common-proof application handle',
                            ),
                            proofApplicationSlotHash: Uint8Array.from(
                                new Uint8Array(
                                    this.#context.memory.buffer,
                                    proofApplicationSlotHashPointer,
                                    hashByteLength,
                                ),
                            ),
                        });
                    } finally {
                        this.#memoryBoundary.zeroAndDeallocate(
                            storageRootCapabilityPointer,
                            storageRootCapability.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            predecessorHeadDigestPointer,
                            predecessorHeadDigest.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            storageInstanceIdentityPointer,
                            storageInstanceIdentity.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            authorizationFramePointer,
                            applicationFrameByteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            proofApplicationSlotHashPointer,
                            hashByteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            statusPointer,
                            wasm32WordByteLength,
                        );
                    }
                },
            );
        } finally {
            storageRootCapability.fill(0);
            predecessorHeadDigest.fill(0);
            storageInstanceIdentity.fill(0);
        }
    }

    public confirmApplication(
        pendingHandle: number,
        storageRootAccess: CommonProofApplicationStorageRootAccess,
        predecessor: CommonProofApplicationFreshnessCoordinate,
        successor: CommonProofApplicationFreshnessCoordinate,
        authenticatedAuthorizationFrame: Uint8Array,
    ): void {
        this.#requireStorageRootContext(storageRootAccess);
        requireLiveHandle(
            pendingHandle,
            'The pending common-proof application handle',
        );
        requireLiveHandle(
            storageRootAccess.storageRootHandle,
            'The local storage-root handle',
        );
        requireUnsigned64(
            predecessor.freshnessSequence,
            'The predecessor freshness sequence',
        );
        requireUnsigned64(
            successor.freshnessSequence,
            'The successor freshness sequence',
        );
        requireExactApplicationBytes(
            storageRootAccess.storageRootCapability,
            localStorageRootCapabilityByteLength,
            'The local storage-root capability',
        );
        requireExactApplicationBytes(
            predecessor.authenticatedHeadDigest,
            hashByteLength,
            'The predecessor authenticated head digest',
        );
        requireExactApplicationBytes(
            successor.authenticatedHeadDigest,
            hashByteLength,
            'The successor authenticated head digest',
        );
        requireExactApplicationBytes(
            successor.storageInstanceIdentity,
            hashByteLength,
            'The successor storage instance identity',
        );
        const storageRootCapability = copyExactApplicationBytes(
            storageRootAccess.storageRootCapability,
            localStorageRootCapabilityByteLength,
            'The local storage-root capability',
        );
        const predecessorHeadDigest = copyExactApplicationBytes(
            predecessor.authenticatedHeadDigest,
            hashByteLength,
            'The predecessor authenticated head digest',
        );
        const successorHeadDigest = copyExactApplicationBytes(
            successor.authenticatedHeadDigest,
            hashByteLength,
            'The successor authenticated head digest',
        );
        const storageInstanceIdentity = copyExactApplicationBytes(
            successor.storageInstanceIdentity,
            hashByteLength,
            'The successor storage instance identity',
        );
        try {
            this.#context.runExclusive(
                'common-proof application confirmation',
                () => {
                    const applicationFrameByteLength = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_application_frame_byte_length',
                    )();
                    const authorizationFrame = copyExactApplicationBytes(
                        authenticatedAuthorizationFrame,
                        applicationFrameByteLength,
                        'The authenticated common-proof authorization frame',
                    );
                    let storageRootCapabilityPointer = 0;
                    let predecessorHeadDigestPointer = 0;
                    let successorHeadDigestPointer = 0;
                    let storageInstanceIdentityPointer = 0;
                    let authorizationFramePointer = 0;
                    try {
                        storageRootCapabilityPointer =
                            this.#memoryBoundary.copy(storageRootCapability);
                        predecessorHeadDigestPointer =
                            this.#memoryBoundary.copy(predecessorHeadDigest);
                        successorHeadDigestPointer =
                            this.#memoryBoundary.copy(successorHeadDigest);
                        storageInstanceIdentityPointer =
                            this.#memoryBoundary.copy(storageInstanceIdentity);
                        authorizationFramePointer =
                            this.#memoryBoundary.copy(authorizationFrame);
                        requireKernelSuccess(
                            resolveNumberExport(
                                this.#context.wasmExports,
                                'sealed_lattice_common_proof_confirm_application',
                            )(
                                pendingHandle,
                                storageRootAccess.storageRootHandle,
                                storageRootCapabilityPointer,
                                predecessor.freshnessSequence,
                                predecessorHeadDigestPointer,
                                successor.freshnessSequence,
                                successorHeadDigestPointer,
                                storageInstanceIdentityPointer,
                                authorizationFramePointer,
                                authorizationFrame.byteLength,
                            ),
                            'common-proof application confirmation',
                        );
                    } finally {
                        authorizationFrame.fill(0);
                        this.#memoryBoundary.zeroAndDeallocate(
                            storageRootCapabilityPointer,
                            storageRootCapability.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            predecessorHeadDigestPointer,
                            predecessorHeadDigest.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            successorHeadDigestPointer,
                            successorHeadDigest.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            storageInstanceIdentityPointer,
                            storageInstanceIdentity.byteLength,
                        );
                        this.#memoryBoundary.zeroAndDeallocate(
                            authorizationFramePointer,
                            applicationFrameByteLength,
                        );
                    }
                },
            );
        } finally {
            storageRootCapability.fill(0);
            predecessorHeadDigest.fill(0);
            successorHeadDigest.fill(0);
            storageInstanceIdentity.fill(0);
        }
    }

    public abortApplication(pendingHandle: number): number {
        requireLiveHandle(
            pendingHandle,
            'The pending common-proof application handle',
        );
        return this.#context.runExclusive(
            'common-proof application abort',
            () => {
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const restoredCapabilityHandle = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_abort_application',
                    )(pendingHandle, statusPointer);
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(
                        status,
                        'common-proof application abort',
                    );
                    return requireLiveHandle(
                        restoredCapabilityHandle,
                        'The restored common-proof capability handle',
                    );
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    }

    #requireStorageRootContext(
        storageRootAccess: CommonProofApplicationStorageRootAccess,
    ): void {
        if (storageRootAccess.context !== this.#context) {
            throw kernelFailure(
                'The common-proof capability and local storage root belong to different WASM instances.',
            );
        }
    }

    #withKernelInput(
        bytes: Uint8Array,
        label: string,
        invoke: (inputPointer: number, inputByteLength: number) => number,
    ): void {
        if (
            !(bytes instanceof Uint8Array) ||
            bytes.byteLength === 0 ||
            bytes.byteLength > canonicalCommonProofChunkByteLength
        ) {
            throw resourceFailure(
                `The common-proof ${label} length exceeds the absolute worker safety bound.`,
            );
        }
        const byteLength = bytes.byteLength;
        this.#context.runExclusive(`common-proof ${label}`, () => {
            let inputPointer = 0;
            try {
                inputPointer = this.#memoryBoundary.copy(bytes);
                destroyOwnedKernelBoundaryInput(bytes);
                requireKernelSuccess(invoke(inputPointer, byteLength), label);
            } finally {
                destroyOwnedKernelBoundaryInput(bytes);
                if (inputPointer !== 0) {
                    this.#memoryBoundary.zeroAndDeallocate(
                        inputPointer,
                        byteLength,
                    );
                }
            }
        });
    }

    #decodePoll(
        kind: number,
        primaryValue: number,
        secondaryValue: number,
    ): CommonProofVerificationKernelPoll {
        switch (kind) {
            case verificationPollNeedsReadback:
                return Object.freeze({
                    firstChunkIndex: primaryValue,
                    kind: 'needs-readback',
                    ...(secondaryValue === noSecondPollValue
                        ? {}
                        : { secondChunkIndex: secondaryValue }),
                });
            case verificationPollPrefixAccepted:
                if (
                    primaryValue === 0 &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({ kind: 'prefix-accepted' });
                }
                break;
            case verificationPollQueryHeaderAccepted:
                if (
                    primaryValue === 0 &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({ kind: 'query-header-accepted' });
                }
                break;
            case verificationPollQueryTreeAccepted:
                if (secondaryValue === noSecondPollValue) {
                    return Object.freeze({
                        catalogIndex: primaryValue,
                        kind: 'query-tree-accepted',
                    });
                }
                break;
            case verificationPollComplete:
                if (
                    primaryValue === 0 &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({ kind: 'complete' });
                }
                break;
        }
        throw kernelFailure(
            'The common-proof kernel returned malformed verification poll metadata.',
        );
    }
}
