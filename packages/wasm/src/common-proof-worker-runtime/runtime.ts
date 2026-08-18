import type { VerificationResult } from '@sealed-lattice/types';

import { byteArraysEqual } from '../byte-array.js';
import {
    decodeCommonProofGenerationCursorManifest,
    maximumCommonProofGenerationCursorManifestByteLength,
} from '../common-proof-generation-cursor-manifest.js';
import {
    resolveNumberExport,
    type TranscriptCoreKernelCommandRuntime,
} from '../transcript-core-bridge/kernel-runtime.js';

import type {
    CommonProofApplicationFreshnessCoordinate,
    CommonProofApplicationStorageRootAccess,
    CommonProofGenerationCheckpoint,
} from './contracts.js';
import {
    CommonProofWorkerRuntimeError,
    clearCommonProofExternalMemoryRequest,
    decodeCommonProofExternalMemoryRequest,
    encodeCommonProofExternalMemoryResponseInto,
    maximumEncodedResponseByteLength,
    maximumWorkerOperationCount,
    type CommonProofDiscardExportName,
    type CommonProofExternalMemoryOperation,
    type CommonProofExternalMemoryReadResult,
    type CommonProofExternalMemoryRequest,
} from './external-memory.js';
import {
    CommonProofFamilyAdapterKernelBoundary,
    CommonProofGenerationKernelBoundary,
    CommonProofVerificationKernelBoundary,
    canonicalCommonProofChunkByteLength,
    copyExactApplicationBytes,
    hashByteLength,
    kernelFailure,
    maximumCommonProofByteLength,
    maximumCommonProofOutputChunkCount,
    requireKernelSuccess,
    requireLiveHandle,
    requireUnsigned64,
    resourceFailure,
    yieldBrowserWorkerTurn,
    type ClosedWorkerCommonProofGenerationFamilyAdapterDescription,
    type ClosedWorkerCommonProofVerificationFamilyAdapterDescription,
    type CompactPublicKeyTransportBindings,
    type CommonProofAuthenticatedSourceRangeRequest,
    type CommonProofBrowserStorageAccounting,
    type CommonProofGenerationExternalMemoryAccounting,
    type CommonProofGenerationCheckpointIdentityExpectation,
    type CommonProofWorkerStorageTransportAccounting,
} from './kernel-boundaries.js';

/**
 * Executes one storage transaction. Ownership of every returned read buffer
 * transfers to this runtime; the runtime validates and clears those buffers
 * after encoding the exact Rust response.
 */
export type CommonProofExternalMemoryTransactionExecutor = Readonly<{
    copyBrowserStorageAccounting?(): CommonProofBrowserStorageAccounting;
    executeTransaction(
        request: CommonProofExternalMemoryRequest,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]>;
}>;

/**
 * Replays the deterministic prefix of one generation attempt. The executor
 * must either serve the byte-identical result of an already committed request
 * or apply it in a copy-on-write namespace. It must never overwrite an
 * existing object merely because its ordinal matches.
 */
type CommonProofExternalMemoryPrefixReplayExecutor = Readonly<{
    confirmAuthenticatedCheckpointExternalMemoryState(): void;
    /** Returned read-buffer ownership transfers to this runtime. */
    executeDeterministicPrefixReplayTransaction(
        request: CommonProofExternalMemoryRequest,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]>;
}>;

/**
 * Browser-owned authenticated custody for generation checkpoints. Publication
 * must commit owned copies before resolving. Restoration must authenticate the
 * exact state before returning it; copied protocol fields are not a valid
 * restoration source.
 */
type CommonProofGenerationCheckpointCustody = Readonly<{
    publishAuthenticatedCheckpoint(
        checkpoint: CommonProofGenerationCheckpoint,
    ): Promise<void>;
    restoreAuthenticatedCheckpoint(): Promise<
        Readonly<{
            canonicalStateBytes: Uint8Array;
            generationCursorManifestBytes: Uint8Array;
        }>
    >;
}>;

type CommonProofGenerationResume = Readonly<{
    checkpointCustody: CommonProofGenerationCheckpointCustody;
    prefixReplayExternalMemory: CommonProofExternalMemoryPrefixReplayExecutor;
}>;

export type CommonProofCanonicalOutputStore = Readonly<{
    /** Commits an owned copy before this promise resolves. */
    commitChunk(
        chunkIndex: number,
        chunkBytes: Uint8Array<ArrayBuffer>,
    ): Promise<void>;
    /** Returns the complete committed chunk at the exact requested length. */
    readChunk(chunkIndex: number, exactByteLength: number): Promise<Uint8Array>;
}>;

export type CommonProofGenerationWorkerOptions = Readonly<{
    authenticatedSourceRangeReader?: CommonProofAuthenticatedSourceRangeReader;
    checkpointCustody?: CommonProofGenerationCheckpointCustody;
    resume?: CommonProofGenerationResume;
    signal?: AbortSignal;
    yieldControl?: () => Promise<void>;
}>;

/**
 * Opens browser-owned proof storage only after Rust has fixed the exact
 * family adapter and exposed its canonical custody bindings. This prevents a
 * caller from guessing or self-attesting the runtime and attempt namespaces
 * used for secret scratch, checkpoints, and canonical output.
 */
export type CommonProofGenerationExecutionOpener = (
    description: ClosedWorkerCommonProofGenerationFamilyAdapterDescription,
) =>
    | Promise<
          Readonly<{
              externalMemory: CommonProofExternalMemoryTransactionExecutor;
              options?: CommonProofGenerationWorkerOptions;
              outputStore: CommonProofCanonicalOutputStore;
          }>
      >
    | Readonly<{
          externalMemory: CommonProofExternalMemoryTransactionExecutor;
          options?: CommonProofGenerationWorkerOptions;
          outputStore: CommonProofCanonicalOutputStore;
      }>;

type CommonProofGenerationAuthenticatedTranscriptPrefixAuthority = Readonly<{
    supply(operationHandle: number): void;
}>;

type ClosedWorkerGeneratedCommonProofExecution = Readonly<{
    externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting;
    generatedCapability: ClosedWorkerGeneratedCommonProofCapability;
    options?: CommonProofGenerationWorkerOptions;
    outputChunkByteLengths: readonly number[];
    outputStore: CommonProofCanonicalOutputStore;
}>;

/** Browser custody transports only the exact range selected by Rust. */
export type CommonProofAuthenticatedSourceRangeReader = Readonly<{
    readExactRange(
        request: CommonProofAuthenticatedSourceRangeRequest,
    ): Promise<Uint8Array<ArrayBuffer>>;
}>;

/**
 * Browser-owned authenticated source for one already committed canonical proof
 * stream. Each call must authenticate and return a fresh owned copy of the
 * exact committed chunk; the verifier never accepts a caller-provided digest
 * or a decoded proof object as a substitute for these bytes.
 */
export type AuthenticatedCommonProofInputStore = Readonly<{
    declaredByteLength: number;
    readCommittedChunk(
        chunkIndex: number,
        exactByteLength: number,
    ): Promise<Uint8Array>;
}>;

export type CommonProofVerificationWorkerOptions = Readonly<{
    signal?: AbortSignal;
    yieldControl?: () => Promise<void>;
}>;

type CompactPublicKeyAlgebraicVerificationInput = Readonly<{
    bindings: CompactPublicKeyTransportBindings;
    proofBytes: Uint8Array;
    publicInputBytes: Uint8Array;
}>;

/**
 * Browser-owned authenticated custody for one source-bound algebraic-verifier
 * cursor. Publication must retain an owned copy before resolving; restoration
 * must authenticate the exact bytes before returning a fresh owned copy.
 */
type CompactPublicKeyAlgebraicVerificationCheckpointCustody = Readonly<{
    publishAuthenticatedCheckpoint(
        canonicalCheckpointBytes: Uint8Array<ArrayBuffer>,
    ): Promise<void>;
    restoreAuthenticatedCheckpoint(): Promise<Uint8Array>;
}>;

type CompactPublicKeyAlgebraicVerificationResume = Readonly<{
    checkpointCustody: CompactPublicKeyAlgebraicVerificationCheckpointCustody;
}>;

type CompactPublicKeyAlgebraicVerificationWorkerOptions = Readonly<{
    checkpointCustody?: CompactPublicKeyAlgebraicVerificationCheckpointCustody;
    maximumWorkUnitCountPerPoll?: number;
    resume?: CompactPublicKeyAlgebraicVerificationResume;
    signal?: AbortSignal;
    yieldControl?: () => Promise<void>;
}>;

/** Opaque generated-proof authority retained in the same WASM worker. */
export type ClosedWorkerGeneratedCommonProofCapability = Readonly<{
    release(): void;
}>;

const closedWorkerCommonProofGenerationFamilyAdapterBrand = Symbol(
    'closed-worker-common-proof-generation-family-adapter',
);
const closedWorkerCommonProofVerificationFamilyAdapterBrand = Symbol(
    'closed-worker-common-proof-verification-family-adapter',
);

const destroyTransferredWorkerBuffer = (bytes: Uint8Array): void => {
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

/**
 * Non-cloneable exact-family prover adapter retained in one WASM worker. A
 * resume adapter remains deferred until checkpoint custody authenticates its
 * canonical continuation state.
 */
export type ClosedWorkerCommonProofGenerationFamilyAdapter = Readonly<{
    readonly [closedWorkerCommonProofGenerationFamilyAdapterBrand]: true;
}>;

/**
 * Non-cloneable exact-family verifier adapter retained in one WASM worker. It
 * cannot be constructed from decoded proof bytes or a caller verdict.
 */
export type ClosedWorkerCommonProofVerificationFamilyAdapter = Readonly<{
    readonly [closedWorkerCommonProofVerificationFamilyAdapterBrand]: true;
}>;

type ClosedWorkerCommonProofGenerationFamilyAdapterRecord = {
    adapterHandle: number;
    applicationStatementSchemaIdentifier: number;
    checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
    commonProofGenerationAuthorizationHash: Uint8Array<ArrayBuffer>;
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    consumed: boolean;
    context: TranscriptCoreKernelCommandRuntime;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
};

type ClosedWorkerCommonProofVerificationFamilyAdapterRecord = {
    adapterHandle: number;
    commonProofVerificationBindingHash: Uint8Array<ArrayBuffer>;
    consumed: boolean;
    context: TranscriptCoreKernelCommandRuntime;
};

const closedWorkerCommonProofGenerationFamilyAdapterRecords = new WeakMap<
    ClosedWorkerCommonProofGenerationFamilyAdapter,
    ClosedWorkerCommonProofGenerationFamilyAdapterRecord
>();
const closedWorkerCommonProofVerificationFamilyAdapterRecords = new WeakMap<
    ClosedWorkerCommonProofVerificationFamilyAdapter,
    ClosedWorkerCommonProofVerificationFamilyAdapterRecord
>();

/**
 * Opaque proof-verification authority retained in the WASM worker. The numeric
 * handle and verifier-derived facts stay inside Rust; this object can only
 * retire the authority until an exact protocol-family consumer takes it.
 */
export type VerifiedCommonProofCapability = Readonly<{
    release(): void;
}>;

declare const preparedCommonProofApplicationAuthorityBrand: unique symbol;

/** Internal same-worker authority. Numeric pending handles never leave WASM. */
type PreparedCommonProofApplicationAuthority = Readonly<{
    readonly [preparedCommonProofApplicationAuthorityBrand]: true;
}>;

type PreparedCommonProofApplication = Readonly<{
    authorizationFrame: Uint8Array<ArrayBuffer>;
    authority: PreparedCommonProofApplicationAuthority;
    proofApplicationSlotHash: Uint8Array<ArrayBuffer>;
}>;

class CommonProofStorageRequestSequence {
    #nextRequestSequence = 1n;
    #runtimeBindingHash: Uint8Array<ArrayBuffer> | undefined;

    public accept(request: CommonProofExternalMemoryRequest): void {
        if (request.requestSequence !== this.#nextRequestSequence) {
            throw new CommonProofWorkerRuntimeError(
                'WrongSequence',
                'The common-proof worker received a reordered storage request.',
            );
        }
        if (this.#runtimeBindingHash === undefined) {
            this.#runtimeBindingHash = request.runtimeBindingHash.slice();
        } else if (
            !byteArraysEqual(
                this.#runtimeBindingHash,
                request.runtimeBindingHash,
            )
        ) {
            throw new CommonProofWorkerRuntimeError(
                'WrongRuntimeBinding',
                'The common-proof worker received a request from another operation.',
            );
        }
    }

    public commit(): void {
        this.#nextRequestSequence += 1n;
        if (this.#nextRequestSequence > 0xffff_ffff_ffff_ffffn) {
            throw new CommonProofWorkerRuntimeError(
                'ResourceLimit',
                'The common-proof storage request sequence is exhausted.',
            );
        }
    }
}

const validateTransferredReadResults = (
    request: CommonProofExternalMemoryRequest,
    readResults: readonly CommonProofExternalMemoryReadResult[],
): readonly CommonProofExternalMemoryReadResult[] => {
    const untrustedReadResults: unknown = readResults;
    if (!Array.isArray(untrustedReadResults)) {
        throw new CommonProofWorkerRuntimeError(
            'WrongStorageResult',
            'The browser store did not return a common-proof read-result list.',
        );
    }
    const readOperations = request.operations.filter(
        (
            operation,
        ): operation is Extract<
            CommonProofExternalMemoryOperation,
            { readonly operationKind: 'read' }
        > => operation.operationKind === 'read',
    );
    try {
        if (untrustedReadResults.length !== readOperations.length) {
            throw new CommonProofWorkerRuntimeError(
                'WrongStorageResult',
                'The browser store returned the wrong number of common-proof reads.',
            );
        }
        return untrustedReadResults.map((result: unknown, readIndex) => {
            const expectedOperation = readOperations[readIndex];
            const transferredBytes =
                typeof result === 'object' &&
                result !== null &&
                'bytes' in result
                    ? result.bytes
                    : undefined;
            if (
                expectedOperation === undefined ||
                typeof result !== 'object' ||
                result === null ||
                !('bytes' in result) ||
                !(transferredBytes instanceof Uint8Array) ||
                !(transferredBytes.buffer instanceof ArrayBuffer) ||
                transferredBytes.byteOffset !== 0 ||
                transferredBytes.byteLength !== expectedOperation.byteLength ||
                transferredBytes.buffer.byteLength !==
                    expectedOperation.byteLength ||
                !('objectOrdinal' in result) ||
                typeof result.objectOrdinal !== 'number' ||
                !Number.isSafeInteger(result.objectOrdinal) ||
                result.objectOrdinal < 0 ||
                result.objectOrdinal > 0xffff_ffff ||
                result.objectOrdinal !== expectedOperation.objectOrdinal ||
                !('offset' in result) ||
                typeof result.offset !== 'bigint' ||
                result.offset < 0n ||
                result.offset > 0xffff_ffff_ffff_ffffn ||
                result.offset !== expectedOperation.offset ||
                !('operationIndex' in result) ||
                typeof result.operationIndex !== 'number' ||
                !Number.isSafeInteger(result.operationIndex) ||
                result.operationIndex < 0 ||
                result.operationIndex > 0xffff_ffff ||
                result.operationIndex !== expectedOperation.operationIndex
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'WrongStorageResult',
                    'The browser store returned a malformed common-proof read result.',
                );
            }
            return Object.freeze({
                bytes: transferredBytes as Uint8Array<ArrayBuffer>,
                objectOrdinal: result.objectOrdinal,
                offset: result.offset,
                operationIndex: result.operationIndex,
            });
        });
    } catch (error) {
        const cleanupResultCount = Math.min(
            untrustedReadResults.length,
            maximumWorkerOperationCount,
        );
        for (
            let readIndex = 0;
            readIndex < cleanupResultCount;
            readIndex += 1
        ) {
            const untypedResult: unknown = untrustedReadResults[readIndex];
            const result: unknown = untypedResult;
            if (
                typeof result === 'object' &&
                result !== null &&
                'bytes' in result &&
                result.bytes instanceof Uint8Array
            ) {
                destroyTransferredWorkerBuffer(result.bytes);
            }
        }
        throw error;
    }
};

const createGeneratedCapability = (
    context: TranscriptCoreKernelCommandRuntime,
    kernel: CommonProofGenerationKernelBoundary,
    capabilityHandle: number,
    externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting,
): ClosedWorkerGeneratedCommonProofCapability => {
    const capability: ClosedWorkerGeneratedCommonProofCapability =
        Object.freeze({
            release: (): void => {
                const record =
                    generatedCommonProofCapabilityRecords.get(capability);
                if (record === undefined) {
                    throw kernelFailure(
                        'The generated common-proof capability was already released.',
                    );
                }
                generatedCommonProofCapabilityRecords.delete(capability);
                try {
                    record.kernel.releaseGenerated(record.capabilityHandle);
                } catch (releaseFailure) {
                    throw permanentRetirementFailure(
                        releaseFailure,
                        'The generated common-proof capability could not be released and its proof attempt was permanently retired.',
                    );
                }
            },
        });
    generatedCommonProofCapabilityRecords.set(capability, {
        capabilityHandle,
        context,
        externalMemoryAccounting,
        kernel,
    });
    return capability;
};

type GeneratedCommonProofCapabilityRecord = Readonly<{
    capabilityHandle: number;
    context: TranscriptCoreKernelCommandRuntime;
    externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting;
    kernel: CommonProofGenerationKernelBoundary;
}>;

const generatedCommonProofCapabilityRecords = new WeakMap<
    ClosedWorkerGeneratedCommonProofCapability,
    GeneratedCommonProofCapabilityRecord
>();

type VerifiedCommonProofCapabilityRecord = {
    readonly capabilityHandle: number;
    readonly context: TranscriptCoreKernelCommandRuntime;
    readonly kernel: CommonProofVerificationKernelBoundary;
};

const verifiedCommonProofCapabilityRecords = new WeakMap<
    VerifiedCommonProofCapability,
    VerifiedCommonProofCapabilityRecord
>();

const createVerifiedCapability = (
    context: TranscriptCoreKernelCommandRuntime,
    kernel: CommonProofVerificationKernelBoundary,
    capabilityHandle: number,
): VerifiedCommonProofCapability => {
    const capability: VerifiedCommonProofCapability = Object.freeze({
        release: (): void => {
            const record = verifiedCommonProofCapabilityRecords.get(capability);
            if (record === undefined) {
                throw kernelFailure(
                    'The verified common-proof capability was already released.',
                );
            }
            record.kernel.discardVerified(record.capabilityHandle);
            verifiedCommonProofCapabilityRecords.delete(capability);
        },
    });
    verifiedCommonProofCapabilityRecords.set(capability, {
        capabilityHandle,
        context,
        kernel,
    });
    return capability;
};

/**
 * Internal same-worker handoff for a protocol family that binds a generated
 * proof to positive Rust-owned authority. Numeric handles never cross the
 * worker boundary. The family reports whether Rust actually consumed the
 * capability so a refused board binding remains releasable.
 */
export const applyClosedWorkerGeneratedCommonProofCapability = <Result>(
    capability: ClosedWorkerGeneratedCommonProofCapability,
    expectedContext: TranscriptCoreKernelCommandRuntime,
    apply: (
        capabilityHandle: number,
    ) => Readonly<{ readonly consumed: boolean; readonly result: Result }>,
): Result => {
    const record =
        typeof capability === 'object' && capability !== null
            ? generatedCommonProofCapabilityRecords.get(capability)
            : undefined;
    if (record === undefined || record.context !== expectedContext) {
        throw kernelFailure(
            'The generated common-proof capability is unavailable or belongs to another WASM worker.',
        );
    }
    const outcome = apply(record.capabilityHandle);
    if (outcome.consumed) {
        generatedCommonProofCapabilityRecords.delete(capability);
    }
    return outcome.result;
};

/**
 * Internal same-worker handoff from the generic verifier to an exact Rust
 * terminal. The family reports whether its borrowed preflight reached the
 * infallible Rust consume/commit point, so a refused handoff remains available
 * for an exact retry or explicit release.
 */
export const applyClosedWorkerVerifiedCommonProofCapability = <Result>(
    capability: VerifiedCommonProofCapability,
    expectedContext: TranscriptCoreKernelCommandRuntime,
    apply: (
        capabilityHandle: number,
    ) => Readonly<{ readonly consumed: boolean; readonly result: Result }>,
): Result => {
    const record =
        typeof capability === 'object' && capability !== null
            ? verifiedCommonProofCapabilityRecords.get(capability)
            : undefined;
    if (record === undefined || record.context !== expectedContext) {
        throw kernelFailure(
            'The verified common-proof capability is unavailable or belongs to another WASM worker.',
        );
    }
    const outcome = apply(record.capabilityHandle);
    if (outcome.consumed) {
        verifiedCommonProofCapabilityRecords.delete(capability);
    }
    return outcome.result;
};

type PreparedCommonProofApplicationRecord = Readonly<{
    capability: VerifiedCommonProofCapability;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: CommonProofVerificationKernelBoundary;
    pendingHandle: number;
    predecessor: CommonProofApplicationFreshnessCoordinate;
}>;

const preparedCommonProofApplicationRecords = new WeakMap<
    PreparedCommonProofApplicationAuthority,
    PreparedCommonProofApplicationRecord
>();

const copyApplicationFreshnessCoordinate = (
    coordinate: CommonProofApplicationFreshnessCoordinate,
): CommonProofApplicationFreshnessCoordinate => {
    requireUnsigned64(
        coordinate.freshnessSequence,
        'The common-proof application freshness sequence',
    );
    let authenticatedHeadDigest: Uint8Array<ArrayBuffer> | undefined;
    let storageInstanceIdentity: Uint8Array<ArrayBuffer> | undefined;
    try {
        authenticatedHeadDigest = copyExactApplicationBytes(
            coordinate.authenticatedHeadDigest,
            hashByteLength,
            'The common-proof application authenticated head digest',
        );
        storageInstanceIdentity = copyExactApplicationBytes(
            coordinate.storageInstanceIdentity,
            hashByteLength,
            'The common-proof application storage instance identity',
        );
        return Object.freeze({
            authenticatedHeadDigest,
            freshnessSequence: coordinate.freshnessSequence,
            storageInstanceIdentity,
        });
    } catch (error) {
        authenticatedHeadDigest?.fill(0);
        storageInstanceIdentity?.fill(0);
        throw error;
    }
};

const destroyApplicationFreshnessCoordinate = (
    coordinate: CommonProofApplicationFreshnessCoordinate,
): void => {
    coordinate.authenticatedHeadDigest.fill(0);
    coordinate.storageInstanceIdentity.fill(0);
};

/**
 * Moves a genuinely completed verifier capability behind a pending Rust
 * application and copies only the fixed authorization frame and slot hash.
 * This source-level bridge is consumed by the closed storage-root worker and
 * is deliberately not re-exported from the WASM package entry point.
 */
export const prepareVerifiedCommonProofApplication = (
    capability: VerifiedCommonProofCapability,
    storageRootAccess: CommonProofApplicationStorageRootAccess,
    predecessor: CommonProofApplicationFreshnessCoordinate,
): PreparedCommonProofApplication => {
    const capabilityRecord =
        typeof capability === 'object' && capability !== null
            ? verifiedCommonProofCapabilityRecords.get(capability)
            : undefined;
    if (capabilityRecord === undefined) {
        throw kernelFailure(
            'The verified common-proof capability is unavailable, pending, or already consumed.',
        );
    }
    const copiedPredecessor = copyApplicationFreshnessCoordinate(predecessor);
    let prepared:
        | Readonly<{
              authorizationFrame: Uint8Array<ArrayBuffer>;
              pendingHandle: number;
              proofApplicationSlotHash: Uint8Array<ArrayBuffer>;
          }>
        | undefined;
    try {
        prepared = capabilityRecord.kernel.prepareApplication(
            capabilityRecord.capabilityHandle,
            storageRootAccess,
            copiedPredecessor,
        );
    } catch (error) {
        destroyApplicationFreshnessCoordinate(copiedPredecessor);
        throw error;
    }
    verifiedCommonProofCapabilityRecords.delete(capability);
    const authority = Object.freeze(
        Object.create(null) as object,
    ) as PreparedCommonProofApplicationAuthority;
    preparedCommonProofApplicationRecords.set(authority, {
        capability,
        context: capabilityRecord.context,
        kernel: capabilityRecord.kernel,
        pendingHandle: prepared.pendingHandle,
        predecessor: copiedPredecessor,
    });
    return Object.freeze({
        authorizationFrame: prepared.authorizationFrame,
        authority,
        proofApplicationSlotHash: prepared.proofApplicationSlotHash,
    });
};

/** Restores the exact original verifier capability after a definite abort. */
export const abortVerifiedCommonProofApplication = (
    authority: PreparedCommonProofApplicationAuthority,
): void => {
    const record = preparedCommonProofApplicationRecords.get(authority);
    if (record === undefined) {
        throw kernelFailure(
            'The pending common-proof application authority is unavailable or already consumed.',
        );
    }
    if (verifiedCommonProofCapabilityRecords.has(record.capability)) {
        throw kernelFailure(
            'The pending common-proof application conflicts with a live verifier capability.',
        );
    }
    const restoredCapabilityHandle = record.kernel.abortApplication(
        record.pendingHandle,
    );
    preparedCommonProofApplicationRecords.delete(authority);
    destroyApplicationFreshnessCoordinate(record.predecessor);
    verifiedCommonProofCapabilityRecords.set(record.capability, {
        capabilityHandle: restoredCapabilityHandle,
        context: record.context,
        kernel: record.kernel,
    });
};

/** Consumes the pending proof authority only for one exact authenticated +1. */
export const confirmVerifiedCommonProofApplication = (
    authority: PreparedCommonProofApplicationAuthority,
    storageRootAccess: CommonProofApplicationStorageRootAccess,
    successor: CommonProofApplicationFreshnessCoordinate,
    authenticatedAuthorizationFrame: Uint8Array,
): void => {
    const record = preparedCommonProofApplicationRecords.get(authority);
    if (record === undefined) {
        throw kernelFailure(
            'The pending common-proof application authority is unavailable or already consumed.',
        );
    }
    record.kernel.confirmApplication(
        record.pendingHandle,
        storageRootAccess,
        record.predecessor,
        successor,
        authenticatedAuthorizationFrame,
    );
    preparedCommonProofApplicationRecords.delete(authority);
    destroyApplicationFreshnessCoordinate(record.predecessor);
};

const storageFailure = (
    message: string,
    failureCause: unknown,
): CommonProofWorkerRuntimeError =>
    failureCause instanceof CommonProofWorkerRuntimeError
        ? failureCause
        : new CommonProofWorkerRuntimeError(
              'StorageFailure',
              message,
              failureCause,
          );

const clearGenerationCheckpoint = (
    checkpoint: CommonProofGenerationCheckpoint,
): void => {
    checkpoint.canonicalStateBytes.fill(0);
    checkpoint.stableAttemptBindingHash.fill(0);
    checkpoint.generationCursorManifestBytes.fill(0);
    checkpoint.privateRandomnessStreamAttemptIdentifier.fill(0);
};

const permanentRetirementFailure = (
    error: unknown,
    fallbackMessage: string,
): CommonProofWorkerRuntimeError =>
    error instanceof CommonProofWorkerRuntimeError
        ? new CommonProofWorkerRuntimeError(
              error.code,
              error.message,
              error.failureCause,
              true,
          )
        : new CommonProofWorkerRuntimeError(
              'KernelFailure',
              fallbackMessage,
              error,
              true,
          );

const requireClosedWorkerCommonProofFamilyAdapterRecord = <
    FamilyAdapter extends object,
    AdapterRecord extends { consumed: boolean },
>(
    records: WeakMap<FamilyAdapter, AdapterRecord>,
    familyAdapter: FamilyAdapter,
): AdapterRecord => {
    const record = records.get(familyAdapter);
    if (record === undefined || record.consumed) {
        throw resourceFailure(
            'The closed-worker common-proof family adapter is unavailable or already consumed.',
        );
    }
    return record;
};

const consumeClosedWorkerCommonProofFamilyAdapterRecord = <
    FamilyAdapter extends object,
    AdapterRecord extends { consumed: boolean },
>(
    records: WeakMap<FamilyAdapter, AdapterRecord>,
    familyAdapter: FamilyAdapter,
): AdapterRecord => {
    const record = requireClosedWorkerCommonProofFamilyAdapterRecord(
        records,
        familyAdapter,
    );
    record.consumed = true;
    records.delete(familyAdapter);
    return record;
};

const requireClosedWorkerFamilyAdapterContext = (
    context: TranscriptCoreKernelCommandRuntime,
): void => {
    if (
        typeof globalThis.document !== 'undefined' ||
        typeof context !== 'object' ||
        context === null
    ) {
        throw resourceFailure(
            'A common-proof family adapter may only be opened inside the dedicated WASM worker.',
        );
    }
};

const discardTransferredCommonProofHandle = (
    context: TranscriptCoreKernelCommandRuntime,
    handle: number,
    exportName: CommonProofDiscardExportName,
    operation: string,
): void => {
    requireLiveHandle(handle, `The ${operation} handle`);
    context.runExclusive(operation, () => {
        requireKernelSuccess(
            resolveNumberExport(context.wasmExports, exportName)(handle),
            operation,
        );
    });
};

const tryDiscardTransferredCommonProofHandle = (
    context: TranscriptCoreKernelCommandRuntime,
    handle: number,
    exportName: CommonProofDiscardExportName,
    operation: string,
): unknown => {
    try {
        discardTransferredCommonProofHandle(
            context,
            handle,
            exportName,
            operation,
        );
        return undefined;
    } catch (error) {
        return error;
    }
};

/**
 * Internal bridge used by exact-family WASM modules after Rust retains a
 * deferred adapter. It is intentionally absent from the public package entry.
 */
export const openClosedWorkerCommonProofGenerationFamilyAdapter = (
    context: TranscriptCoreKernelCommandRuntime,
    familyAdapterHandle: number,
): ClosedWorkerCommonProofGenerationFamilyAdapter => {
    const adapterHandle = requireLiveHandle(
        familyAdapterHandle,
        'The common-proof generation family-adapter handle',
    );
    let description:
        | ClosedWorkerCommonProofGenerationFamilyAdapterDescription
        | undefined;
    try {
        requireClosedWorkerFamilyAdapterContext(context);
        const kernel = new CommonProofFamilyAdapterKernelBoundary(context);
        description = kernel.describeGeneration(adapterHandle);
        const familyAdapter = Object.freeze({
            [closedWorkerCommonProofGenerationFamilyAdapterBrand]:
                true as const,
        });
        closedWorkerCommonProofGenerationFamilyAdapterRecords.set(
            familyAdapter,
            {
                adapterHandle,
                applicationStatementSchemaIdentifier:
                    description.applicationStatementSchemaIdentifier,
                checkpointLineageIdentifier:
                    description.checkpointLineageIdentifier,
                commonProofGenerationAuthorizationHash:
                    description.commonProofGenerationAuthorizationHash,
                commonProofRuntimeBindingHash:
                    description.commonProofRuntimeBindingHash,
                consumed: false,
                context,
                proofAttemptLineageIdentifier:
                    description.proofAttemptLineageIdentifier,
            },
        );
        return familyAdapter;
    } catch (error) {
        description?.commonProofRuntimeBindingHash.fill(0);
        description?.commonProofGenerationAuthorizationHash.fill(0);
        description?.proofAttemptLineageIdentifier.fill(0);
        description?.checkpointLineageIdentifier.fill(0);
        const discardError = tryDiscardTransferredCommonProofHandle(
            context,
            adapterHandle,
            'sealed_lattice_common_proof_discard_generation_family_adapter',
            'generation family-adapter adoption discard',
        );
        if (discardError !== undefined) {
            throw permanentRetirementFailure(
                { adoptionError: error, discardError },
                'The common-proof generation adapter could not be adopted or retired.',
            );
        }
        throw error;
    }
};

/** See {@link openClosedWorkerCommonProofGenerationFamilyAdapter}. */
export const openClosedWorkerCommonProofVerificationFamilyAdapter = (
    context: TranscriptCoreKernelCommandRuntime,
    familyAdapterHandle: number,
): ClosedWorkerCommonProofVerificationFamilyAdapter => {
    const adapterHandle = requireLiveHandle(
        familyAdapterHandle,
        'The common-proof verification family-adapter handle',
    );
    let description:
        | ClosedWorkerCommonProofVerificationFamilyAdapterDescription
        | undefined;
    try {
        requireClosedWorkerFamilyAdapterContext(context);
        const kernel = new CommonProofFamilyAdapterKernelBoundary(context);
        description = kernel.describeVerification(adapterHandle);
        const familyAdapter = Object.freeze({
            [closedWorkerCommonProofVerificationFamilyAdapterBrand]:
                true as const,
        });
        closedWorkerCommonProofVerificationFamilyAdapterRecords.set(
            familyAdapter,
            {
                adapterHandle,
                commonProofVerificationBindingHash:
                    description.commonProofVerificationBindingHash,
                consumed: false,
                context,
            },
        );
        return familyAdapter;
    } catch (error) {
        description?.commonProofVerificationBindingHash.fill(0);
        const discardError = tryDiscardTransferredCommonProofHandle(
            context,
            adapterHandle,
            'sealed_lattice_common_proof_discard_verification_family_adapter',
            'verification family-adapter adoption discard',
        );
        if (discardError !== undefined) {
            throw permanentRetirementFailure(
                { adoptionError: error, discardError },
                'The common-proof verification adapter could not be adopted or retired.',
            );
        }
        throw error;
    }
};

export const describeClosedWorkerCommonProofGenerationFamilyAdapter = (
    familyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter,
): ClosedWorkerCommonProofGenerationFamilyAdapterDescription => {
    const record = requireClosedWorkerCommonProofFamilyAdapterRecord(
        closedWorkerCommonProofGenerationFamilyAdapterRecords,
        familyAdapter,
    );
    return Object.freeze({
        applicationStatementSchemaIdentifier:
            record.applicationStatementSchemaIdentifier,
        checkpointLineageIdentifier: record.checkpointLineageIdentifier.slice(),
        commonProofGenerationAuthorizationHash:
            record.commonProofGenerationAuthorizationHash.slice(),
        commonProofRuntimeBindingHash:
            record.commonProofRuntimeBindingHash.slice(),
        proofAttemptLineageIdentifier:
            record.proofAttemptLineageIdentifier.slice(),
    });
};

export const describeClosedWorkerCommonProofVerificationFamilyAdapter = (
    familyAdapter: ClosedWorkerCommonProofVerificationFamilyAdapter,
): ClosedWorkerCommonProofVerificationFamilyAdapterDescription => {
    const record = requireClosedWorkerCommonProofFamilyAdapterRecord(
        closedWorkerCommonProofVerificationFamilyAdapterRecords,
        familyAdapter,
    );
    return Object.freeze({
        commonProofVerificationBindingHash:
            record.commonProofVerificationBindingHash.slice(),
    });
};

const destroyClosedWorkerCommonProofGenerationFamilyAdapterRecord = (
    record: ClosedWorkerCommonProofGenerationFamilyAdapterRecord,
): void => {
    record.checkpointLineageIdentifier.fill(0);
    record.commonProofRuntimeBindingHash.fill(0);
    record.commonProofGenerationAuthorizationHash.fill(0);
    record.proofAttemptLineageIdentifier.fill(0);
};

const destroyClosedWorkerCommonProofVerificationFamilyAdapterRecord = (
    record: ClosedWorkerCommonProofVerificationFamilyAdapterRecord,
): void => {
    record.commonProofVerificationBindingHash.fill(0);
};

export const releaseClosedWorkerCommonProofGenerationFamilyAdapter = (
    familyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter,
): void => {
    const record = requireClosedWorkerCommonProofFamilyAdapterRecord(
        closedWorkerCommonProofGenerationFamilyAdapterRecords,
        familyAdapter,
    );
    discardTransferredCommonProofHandle(
        record.context,
        record.adapterHandle,
        'sealed_lattice_common_proof_discard_generation_family_adapter',
        'generation family-adapter release',
    );
    record.consumed = true;
    closedWorkerCommonProofGenerationFamilyAdapterRecords.delete(familyAdapter);
    destroyClosedWorkerCommonProofGenerationFamilyAdapterRecord(record);
};

export const releaseClosedWorkerCommonProofVerificationFamilyAdapter = (
    familyAdapter: ClosedWorkerCommonProofVerificationFamilyAdapter,
): void => {
    const record = requireClosedWorkerCommonProofFamilyAdapterRecord(
        closedWorkerCommonProofVerificationFamilyAdapterRecords,
        familyAdapter,
    );
    discardTransferredCommonProofHandle(
        record.context,
        record.adapterHandle,
        'sealed_lattice_common_proof_discard_verification_family_adapter',
        'verification family-adapter release',
    );
    record.consumed = true;
    closedWorkerCommonProofVerificationFamilyAdapterRecords.delete(
        familyAdapter,
    );
    destroyClosedWorkerCommonProofVerificationFamilyAdapterRecord(record);
};

type AuthenticatedCommonProofGenerationCheckpoint = Readonly<{
    canonicalStateBytes: Uint8Array<ArrayBuffer>;
    generationCursorManifestBytes: Uint8Array<ArrayBuffer>;
}>;

const restoreAuthenticatedGenerationCheckpoint = async (
    kernel: CommonProofFamilyAdapterKernelBoundary,
    checkpointCustody: CommonProofGenerationCheckpointCustody,
): Promise<AuthenticatedCommonProofGenerationCheckpoint> => {
    let restoredCheckpoint:
        | Readonly<{
              canonicalStateBytes: Uint8Array;
              generationCursorManifestBytes: Uint8Array;
          }>
        | undefined;
    try {
        restoredCheckpoint =
            await checkpointCustody.restoreAuthenticatedCheckpoint();
        const exactByteLength = kernel.checkpointStateByteLength();
        if (
            typeof restoredCheckpoint !== 'object' ||
            restoredCheckpoint === null ||
            !(restoredCheckpoint.canonicalStateBytes instanceof Uint8Array) ||
            restoredCheckpoint.canonicalStateBytes.byteLength !==
                exactByteLength ||
            !(
                restoredCheckpoint.generationCursorManifestBytes instanceof
                Uint8Array
            ) ||
            restoredCheckpoint.generationCursorManifestBytes.byteLength === 0 ||
            restoredCheckpoint.generationCursorManifestBytes.byteLength >
                maximumCommonProofGenerationCursorManifestByteLength
        ) {
            throw new CommonProofWorkerRuntimeError(
                'WrongStorageResult',
                'Authenticated checkpoint custody returned an inconsistent state and generation cursor manifest.',
            );
        }
        decodeCommonProofGenerationCursorManifest(
            restoredCheckpoint.generationCursorManifestBytes,
        );
        return Object.freeze({
            canonicalStateBytes: restoredCheckpoint.canonicalStateBytes.slice(),
            generationCursorManifestBytes:
                restoredCheckpoint.generationCursorManifestBytes.slice(),
        });
    } catch (error) {
        throw error instanceof CommonProofWorkerRuntimeError &&
            error.code === 'StorageFailure'
            ? error
            : new CommonProofWorkerRuntimeError(
                  'StorageFailure',
                  'The browser store could not restore an authenticated common-proof checkpoint.',
                  error,
              );
    } finally {
        if (restoredCheckpoint?.canonicalStateBytes instanceof Uint8Array) {
            restoredCheckpoint.canonicalStateBytes.fill(0);
        }
        if (
            restoredCheckpoint?.generationCursorManifestBytes instanceof
            Uint8Array
        ) {
            restoredCheckpoint.generationCursorManifestBytes.fill(0);
        }
    }
};

export const runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability =
    async (
        familyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter,
        externalMemory: CommonProofExternalMemoryTransactionExecutor,
        outputStore: CommonProofCanonicalOutputStore,
        options: CommonProofGenerationWorkerOptions = {},
        authenticatedTranscriptPrefixAuthority?: CommonProofGenerationAuthenticatedTranscriptPrefixAuthority,
    ): Promise<ClosedWorkerGeneratedCommonProofCapability> => {
        const record = consumeClosedWorkerCommonProofFamilyAdapterRecord(
            closedWorkerCommonProofGenerationFamilyAdapterRecords,
            familyAdapter,
        );
        let kernel: CommonProofFamilyAdapterKernelBoundary | undefined;
        let authenticatedCheckpoint:
            | AuthenticatedCommonProofGenerationCheckpoint
            | undefined;
        let checkpointRestorationCompleted = false;
        let optionSnapshotCompleted = false;
        let resumedContinuationExpected = false;
        let generatedCapability:
            | ClosedWorkerGeneratedCommonProofCapability
            | undefined;
        let preparedGenerationHandle: number | undefined;
        try {
            const resume = options.resume;
            resumedContinuationExpected = resume !== undefined;
            const authenticatedSourceRangeReader =
                options.authenticatedSourceRangeReader;
            const checkpointCustody = options.checkpointCustody;
            const signal = options.signal;
            const yieldControl = options.yieldControl;
            const resumeCheckpointCustody = resume?.checkpointCustody;
            const prefixReplayExternalMemory =
                resume?.prefixReplayExternalMemory;
            const ownedOptions: CommonProofGenerationWorkerOptions =
                Object.freeze({
                    ...(authenticatedSourceRangeReader === undefined
                        ? {}
                        : { authenticatedSourceRangeReader }),
                    ...(checkpointCustody === undefined
                        ? {}
                        : { checkpointCustody }),
                    ...(resume === undefined
                        ? {}
                        : {
                              resume: Object.freeze({
                                  checkpointCustody: resumeCheckpointCustody!,
                                  prefixReplayExternalMemory:
                                      prefixReplayExternalMemory!,
                              }),
                          }),
                    ...(signal === undefined ? {} : { signal }),
                    ...(yieldControl === undefined ? {} : { yieldControl }),
                });
            optionSnapshotCompleted = true;
            checkpointRestorationCompleted = resume === undefined;
            kernel = new CommonProofFamilyAdapterKernelBoundary(record.context);
            if (resume !== undefined) {
                authenticatedCheckpoint =
                    await restoreAuthenticatedGenerationCheckpoint(
                        kernel,
                        resumeCheckpointCustody!,
                    );
                checkpointRestorationCompleted = true;
            }
            preparedGenerationHandle = kernel.prepareGeneration(
                record.adapterHandle,
                authenticatedCheckpoint?.canonicalStateBytes,
                authenticatedCheckpoint?.generationCursorManifestBytes,
            );
            generatedCapability =
                await runPreparedCommonProofGenerationWorkerWithAuthenticatedState(
                    record.context,
                    preparedGenerationHandle,
                    externalMemory,
                    outputStore,
                    ownedOptions,
                    authenticatedCheckpoint,
                    Object.freeze({
                        applicationStatementSchemaIdentifier:
                            record.applicationStatementSchemaIdentifier,
                        proofAttemptLineageIdentifier:
                            record.proofAttemptLineageIdentifier,
                        stableAttemptBindingHash:
                            record.commonProofRuntimeBindingHash,
                    }),
                    authenticatedTranscriptPrefixAuthority,
                );
            return generatedCapability;
        } catch (error) {
            if (generatedCapability !== undefined) {
                throw permanentRetirementFailure(
                    error,
                    'The generated common-proof capability could not be released and its proof attempt was permanently retired.',
                );
            }
            if (preparedGenerationHandle === undefined) {
                // The preparation FFI consumes the adapter before returning a
                // refusal, so a stale-handle discard is an expected no-op.
                const discardError = tryDiscardTransferredCommonProofHandle(
                    record.context,
                    record.adapterHandle,
                    'sealed_lattice_common_proof_discard_generation_family_adapter',
                    'generation family-adapter failed-preparation discard',
                );
                if (!optionSnapshotCompleted) {
                    throw permanentRetirementFailure(
                        {
                            adapterDiscardError: discardError,
                            optionError: error,
                        },
                        'The common-proof generation adapter could not adopt its worker options and was permanently retired.',
                    );
                }
                if (
                    resumedContinuationExpected &&
                    !checkpointRestorationCompleted
                ) {
                    if (discardError !== undefined) {
                        throw permanentRetirementFailure(
                            { discardError, restorationError: error },
                            'Authenticated common-proof continuation was unavailable and its deferred family authority could not be retired.',
                        );
                    }
                    throw permanentRetirementFailure(
                        error,
                        'Authenticated common-proof continuation was unavailable, so the deferred family authority was permanently retired.',
                    );
                }
                if (discardError !== undefined) {
                    throw permanentRetirementFailure(
                        {
                            adapterDiscardError: discardError,
                            operationError: error,
                        },
                        'Common-proof generation preparation failed and its deferred family authority could not be retired.',
                    );
                }
                throw permanentRetirementFailure(
                    error,
                    'Common-proof generation preparation consumed its exact deferred family authority and permanently retired the attempt.',
                );
            }
            throw error;
        } finally {
            authenticatedCheckpoint?.canonicalStateBytes.fill(0);
            authenticatedCheckpoint?.generationCursorManifestBytes.fill(0);
            destroyClosedWorkerCommonProofGenerationFamilyAdapterRecord(record);
        }
    };

/**
 * Runs one exact-family adapter with storage opened from the adapter's
 * verifier-derived custody bindings. The returned output shape is observed at
 * the canonical sink boundary and is therefore suitable for descriptor
 * derivation without a second proof copy.
 */
export const runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener =
    async (
        familyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter,
        openExecution: CommonProofGenerationExecutionOpener,
        authenticatedTranscriptPrefixAuthority?: CommonProofGenerationAuthenticatedTranscriptPrefixAuthority,
    ): Promise<ClosedWorkerGeneratedCommonProofExecution> => {
        const description =
            describeClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
            );
        let execution:
            | Awaited<ReturnType<CommonProofGenerationExecutionOpener>>
            | undefined;
        try {
            execution = await openExecution(description);
        } catch (error) {
            try {
                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                    familyAdapter,
                );
            } catch (releaseError) {
                throw permanentRetirementFailure(
                    { executionOpenError: error, releaseError },
                    'Common-proof execution custody could not open and the exact family adapter could not be retired.',
                );
            }
            throw error;
        } finally {
            description.checkpointLineageIdentifier.fill(0);
            description.commonProofGenerationAuthorizationHash.fill(0);
            description.commonProofRuntimeBindingHash.fill(0);
            description.proofAttemptLineageIdentifier.fill(0);
        }
        const outputChunkByteLengths: number[] = [];
        const trackedOutputStore: CommonProofCanonicalOutputStore =
            Object.freeze({
                commitChunk: async (chunkIndex, chunkBytes) => {
                    if (chunkIndex !== outputChunkByteLengths.length) {
                        throw new CommonProofWorkerRuntimeError(
                            'WrongStorageResult',
                            'The proof output store received a non-canonical chunk order.',
                        );
                    }
                    await execution.outputStore.commitChunk(
                        chunkIndex,
                        chunkBytes,
                    );
                    outputChunkByteLengths.push(chunkBytes.byteLength);
                },
                readChunk: (chunkIndex, exactByteLength) =>
                    execution.outputStore.readChunk(
                        chunkIndex,
                        exactByteLength,
                    ),
            });
        const generatedCapability =
            await runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability(
                familyAdapter,
                execution.externalMemory,
                trackedOutputStore,
                execution.options,
                authenticatedTranscriptPrefixAuthority,
            );
        const externalMemoryAccounting =
            generatedCommonProofCapabilityRecords.get(
                generatedCapability,
            )?.externalMemoryAccounting;
        if (externalMemoryAccounting === undefined) {
            throw kernelFailure(
                'The completed common-proof generation lost its external-memory accounting.',
            );
        }
        return Object.freeze({
            externalMemoryAccounting,
            generatedCapability,
            ...(execution.options === undefined
                ? {}
                : { options: execution.options }),
            outputChunkByteLengths: Object.freeze([...outputChunkByteLengths]),
            outputStore: execution.outputStore,
        });
    };

export const runClosedWorkerCommonProofGenerationFamilyAdapter = async (
    familyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter,
    externalMemory: CommonProofExternalMemoryTransactionExecutor,
    outputStore: CommonProofCanonicalOutputStore,
    options: CommonProofGenerationWorkerOptions = {},
): Promise<void> => {
    const generatedCapability =
        await runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability(
            familyAdapter,
            externalMemory,
            outputStore,
            options,
        );
    generatedCapability.release();
};

export const runClosedWorkerCommonProofVerificationFamilyAdapter = async (
    familyAdapter: ClosedWorkerCommonProofVerificationFamilyAdapter,
    inputStore: AuthenticatedCommonProofInputStore,
    options: CommonProofVerificationWorkerOptions = {},
): Promise<VerifiedCommonProofCapability> => {
    const record = consumeClosedWorkerCommonProofFamilyAdapterRecord(
        closedWorkerCommonProofVerificationFamilyAdapterRecords,
        familyAdapter,
    );
    let preparedVerificationHandle: number | undefined;
    try {
        const signal = options.signal;
        const yieldControl = options.yieldControl;
        const ownedOptions: CommonProofVerificationWorkerOptions =
            Object.freeze({
                ...(signal === undefined ? {} : { signal }),
                ...(yieldControl === undefined ? {} : { yieldControl }),
            });
        const kernel = new CommonProofFamilyAdapterKernelBoundary(
            record.context,
        );
        preparedVerificationHandle = kernel.prepareVerification(
            record.adapterHandle,
        );
        return await runPreparedCommonProofVerificationWorker(
            record.context,
            preparedVerificationHandle,
            inputStore,
            ownedOptions,
        );
    } catch (error) {
        if (preparedVerificationHandle === undefined) {
            // The preparation FFI consumes the adapter before returning a
            // refusal, so a stale-handle discard is an expected no-op.
            const discardError = tryDiscardTransferredCommonProofHandle(
                record.context,
                record.adapterHandle,
                'sealed_lattice_common_proof_discard_verification_family_adapter',
                'verification family-adapter failed-preparation discard',
            );
            if (discardError !== undefined) {
                throw permanentRetirementFailure(
                    {
                        adapterDiscardError: discardError,
                        operationError: error,
                    },
                    'Common-proof verification preparation failed and its deferred family authority could not be retired.',
                );
            }
        }
        throw error;
    } finally {
        destroyClosedWorkerCommonProofVerificationFamilyAdapterRecord(record);
    }
};

/**
 * Drives one Rust-owned prover to completion through bounded browser storage
 * and canonical chunk persistence. The prepared handle is produced only by an
 * exact proof-family adapter inside the same WASM worker; this module exposes
 * no constructor for it and is intentionally not part of the public SDK entry
 * point.
 */
export const runPreparedCommonProofGenerationWorker = async (
    context: TranscriptCoreKernelCommandRuntime,
    preparedGenerationHandle: number,
    externalMemory: CommonProofExternalMemoryTransactionExecutor,
    outputStore: CommonProofCanonicalOutputStore,
    options: CommonProofGenerationWorkerOptions = {},
): Promise<ClosedWorkerGeneratedCommonProofCapability> =>
    runPreparedCommonProofGenerationWorkerWithAuthenticatedState(
        context,
        preparedGenerationHandle,
        externalMemory,
        outputStore,
        options,
        undefined,
        undefined,
        undefined,
    );

const runPreparedCommonProofGenerationWorkerWithAuthenticatedState = async (
    context: TranscriptCoreKernelCommandRuntime,
    preparedGenerationHandle: number,
    externalMemory: CommonProofExternalMemoryTransactionExecutor,
    outputStore: CommonProofCanonicalOutputStore,
    options: CommonProofGenerationWorkerOptions,
    previouslyAuthenticatedCheckpoint:
        | AuthenticatedCommonProofGenerationCheckpoint
        | undefined,
    expectedCheckpointIdentity:
        | CommonProofGenerationCheckpointIdentityExpectation
        | undefined,
    authenticatedTranscriptPrefixAuthority:
        | CommonProofGenerationAuthenticatedTranscriptPrefixAuthority
        | undefined,
): Promise<ClosedWorkerGeneratedCommonProofCapability> => {
    let kernel: CommonProofGenerationKernelBoundary | undefined;
    let operationHandle: number | undefined;
    let operationTerminal = false;
    let reusableStorageResponseBuffer: Uint8Array<ArrayBuffer> | undefined;

    try {
        const resume = options.resume;
        const signal = options.signal;
        const yieldControl = options.yieldControl ?? yieldBrowserWorkerTurn;
        const checkpointCustody =
            options.checkpointCustody ?? resume?.checkpointCustody;
        const authenticatedSourceRangeReader =
            options.authenticatedSourceRangeReader;
        const requestSequence = new CommonProofStorageRequestSequence();
        const committedOutputChunkByteLengths = new Map<number, number>();
        let browserToWasmCopyByteLength = 0n;
        let browserToWasmCopyCount = 0n;
        let committedOutputByteLength = 0;
        let deterministicPrefixReplayComplete = resume === undefined;
        let authenticatedTranscriptPrefixSupplied = false;
        let cancellationRequested = false;
        let readResultTransferByteLength = 0n;
        let readResultTransferCount = 0n;
        let wasmToBrowserCopyByteLength = 0n;
        let wasmToBrowserCopyCount = 0n;
        kernel = new CommonProofGenerationKernelBoundary(context);
        if (resume === undefined) {
            operationHandle = kernel.begin(preparedGenerationHandle);
        } else {
            const authenticatedCheckpoint =
                previouslyAuthenticatedCheckpoint === undefined
                    ? await restoreAuthenticatedGenerationCheckpoint(
                          new CommonProofFamilyAdapterKernelBoundary(context),
                          resume.checkpointCustody,
                      )
                    : Object.freeze({
                          canonicalStateBytes:
                              previouslyAuthenticatedCheckpoint.canonicalStateBytes.slice(),
                          generationCursorManifestBytes:
                              previouslyAuthenticatedCheckpoint.generationCursorManifestBytes.slice(),
                      });
            try {
                operationHandle = kernel.resume(
                    preparedGenerationHandle,
                    authenticatedCheckpoint.canonicalStateBytes,
                    authenticatedCheckpoint.generationCursorManifestBytes,
                );
            } finally {
                authenticatedCheckpoint.canonicalStateBytes.fill(0);
                authenticatedCheckpoint.generationCursorManifestBytes.fill(0);
            }
        }
        const liveOperationHandle = operationHandle;
        for (;;) {
            if (signal?.aborted === true && !cancellationRequested) {
                kernel.requestCancellation(liveOperationHandle);
                cancellationRequested = true;
            }
            const poll = kernel.poll(liveOperationHandle);
            switch (poll.kind) {
                case 'progress': {
                    if (poll.checkpointReady) {
                        if (!deterministicPrefixReplayComplete) {
                            throw kernelFailure(
                                'The common-proof kernel exposed a checkpoint before deterministic prefix replay completed.',
                            );
                        }
                        const checkpoint = kernel.copyCheckpoint(
                            liveOperationHandle,
                            expectedCheckpointIdentity,
                        );
                        try {
                            if (checkpointCustody === undefined) {
                                kernel.discardCheckpoint(liveOperationHandle);
                            } else {
                                try {
                                    await checkpointCustody.publishAuthenticatedCheckpoint(
                                        checkpoint,
                                    );
                                } catch (error) {
                                    throw storageFailure(
                                        'The browser store could not atomically publish the common-proof checkpoint.',
                                        error,
                                    );
                                }
                                kernel.acknowledgeCheckpoint(
                                    liveOperationHandle,
                                );
                            }
                        } finally {
                            clearGenerationCheckpoint(checkpoint);
                        }
                    }
                    await yieldControl();
                    break;
                }
                case 'resume-complete':
                    if (
                        resume === undefined ||
                        deterministicPrefixReplayComplete
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel returned an unexpected resume-complete signal.',
                        );
                    }
                    try {
                        resume.prefixReplayExternalMemory.confirmAuthenticatedCheckpointExternalMemoryState();
                    } catch (error) {
                        throw storageFailure(
                            'The browser store could not confirm the authenticated common-proof external-memory state.',
                            error,
                        );
                    }
                    deterministicPrefixReplayComplete = true;
                    await yieldControl();
                    break;
                case 'authenticated-transcript-prefix-required':
                    if (
                        authenticatedTranscriptPrefixAuthority === undefined ||
                        authenticatedTranscriptPrefixSupplied
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel requested unavailable or repeated authenticated transcript-prefix authority.',
                        );
                    }
                    authenticatedTranscriptPrefixAuthority.supply(
                        liveOperationHandle,
                    );
                    authenticatedTranscriptPrefixSupplied = true;
                    break;
                case 'storage-request-ready': {
                    const encodedRequest = kernel.copyStorageRequest(
                        liveOperationHandle,
                        poll.encodedRequestByteLength,
                    );
                    wasmToBrowserCopyCount += 1n;
                    wasmToBrowserCopyByteLength += BigInt(
                        encodedRequest.byteLength,
                    );
                    let encodedResponse: Uint8Array<ArrayBuffer> | undefined;
                    let request: CommonProofExternalMemoryRequest | undefined;
                    try {
                        request =
                            decodeCommonProofExternalMemoryRequest(
                                encodedRequest,
                            );
                        requestSequence.accept(request);
                        let readResults: readonly CommonProofExternalMemoryReadResult[];
                        try {
                            let untrustedReadResults: readonly CommonProofExternalMemoryReadResult[];
                            if (deterministicPrefixReplayComplete) {
                                untrustedReadResults =
                                    await externalMemory.executeTransaction(
                                        request,
                                    );
                            } else {
                                if (resume === undefined) {
                                    throw kernelFailure(
                                        'Deterministic prefix replay has no authenticated resume source.',
                                    );
                                }
                                untrustedReadResults =
                                    await resume.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                                        request,
                                    );
                            }
                            readResults = validateTransferredReadResults(
                                request,
                                untrustedReadResults,
                            );
                            readResultTransferCount += BigInt(
                                readResults.length,
                            );
                            for (const readResult of readResults) {
                                readResultTransferByteLength += BigInt(
                                    readResult.bytes.byteLength,
                                );
                            }
                        } catch (error) {
                            throw storageFailure(
                                deterministicPrefixReplayComplete
                                    ? 'The browser store could not execute the exact common-proof transaction.'
                                    : 'The browser store could not replay the exact deterministic-prefix transaction.',
                                error,
                            );
                        }
                        reusableStorageResponseBuffer ??= new Uint8Array(
                            maximumEncodedResponseByteLength,
                        );
                        encodedResponse =
                            encodeCommonProofExternalMemoryResponseInto(
                                request,
                                readResults,
                                reusableStorageResponseBuffer,
                            );
                        browserToWasmCopyCount += 1n;
                        browserToWasmCopyByteLength += BigInt(
                            encodedResponse.byteLength,
                        );
                        kernel.supplyStorageResponse(
                            liveOperationHandle,
                            encodedResponse,
                        );
                        requestSequence.commit();
                    } finally {
                        if (request !== undefined) {
                            clearCommonProofExternalMemoryRequest(request);
                        }
                        destroyTransferredWorkerBuffer(encodedRequest);
                        if (encodedResponse !== undefined) {
                            reusableStorageResponseBuffer?.fill(0);
                        }
                    }
                    break;
                }
                case 'authenticated-source-read-ready': {
                    if (authenticatedSourceRangeReader === undefined) {
                        throw kernelFailure(
                            'The common-proof kernel requested authenticated source bytes without a family-owned source reader.',
                        );
                    }
                    const request = kernel.copyAuthenticatedSourceRequest(
                        liveOperationHandle,
                        poll.sourceByteLength,
                        poll.authenticationChunkIndex,
                    );
                    let sourceBytes: Uint8Array<ArrayBuffer> | undefined;
                    try {
                        try {
                            sourceBytes =
                                await authenticatedSourceRangeReader.readExactRange(
                                    request,
                                );
                        } catch (error) {
                            throw storageFailure(
                                'The browser store could not read the exact authenticated common-proof source range.',
                                error,
                            );
                        }
                        if (
                            !(sourceBytes instanceof Uint8Array) ||
                            !(sourceBytes.buffer instanceof ArrayBuffer) ||
                            sourceBytes.byteOffset !== 0 ||
                            sourceBytes.byteLength !==
                                request.exactByteLength ||
                            sourceBytes.buffer.byteLength !==
                                request.exactByteLength
                        ) {
                            throw storageFailure(
                                'The browser store did not return a fresh owned authenticated common-proof source range.',
                                undefined,
                            );
                        }
                        kernel.supplyAuthenticatedSourceRange(
                            liveOperationHandle,
                            sourceBytes,
                        );
                    } finally {
                        if (sourceBytes !== undefined) {
                            destroyTransferredWorkerBuffer(sourceBytes);
                        }
                        request.sourceMaterialRoot.fill(0);
                        request.sourceStreamDigest.fill(0);
                    }
                    break;
                }
                case 'output-chunk-ready': {
                    if (!deterministicPrefixReplayComplete) {
                        throw kernelFailure(
                            'The common-proof kernel emitted output before deterministic prefix replay completed.',
                        );
                    }
                    if (
                        poll.chunkIndex !== committedOutputChunkByteLengths.size
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel exposed a noncanonical output chunk sequence.',
                        );
                    }
                    const previousChunkByteLength =
                        poll.chunkIndex === 0
                            ? undefined
                            : committedOutputChunkByteLengths.get(
                                  poll.chunkIndex - 1,
                              );
                    if (
                        (previousChunkByteLength !== undefined &&
                            previousChunkByteLength <
                                canonicalCommonProofChunkByteLength) ||
                        committedOutputChunkByteLengths.size >=
                            maximumCommonProofOutputChunkCount ||
                        poll.chunkByteLength >
                            canonicalCommonProofChunkByteLength ||
                        poll.chunkByteLength >
                            maximumCommonProofByteLength -
                                committedOutputByteLength
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel exposed output beyond the absolute proof-stream safety bound.',
                        );
                    }
                    const chunkBytes = kernel.copyOutputChunk(
                        liveOperationHandle,
                        poll.chunkIndex,
                        poll.chunkByteLength,
                    );
                    try {
                        try {
                            await outputStore.commitChunk(
                                poll.chunkIndex,
                                chunkBytes,
                            );
                        } catch (error) {
                            throw storageFailure(
                                'The browser store could not commit a common-proof output chunk.',
                                error,
                            );
                        }
                        kernel.acknowledgeOutputChunk(
                            liveOperationHandle,
                            poll.chunkIndex,
                        );
                        committedOutputChunkByteLengths.set(
                            poll.chunkIndex,
                            poll.chunkByteLength,
                        );
                        committedOutputByteLength += poll.chunkByteLength;
                    } finally {
                        chunkBytes.fill(0);
                    }
                    break;
                }
                case 'output-readback-required': {
                    if (!deterministicPrefixReplayComplete) {
                        throw kernelFailure(
                            'The common-proof kernel requested output readback before deterministic prefix replay completed.',
                        );
                    }
                    const exactByteLength = committedOutputChunkByteLengths.get(
                        poll.chunkIndex,
                    );
                    if (exactByteLength === undefined) {
                        throw kernelFailure(
                            'The common-proof kernel requested readback before output commit.',
                        );
                    }
                    let storedChunk: Uint8Array;
                    try {
                        storedChunk = await outputStore.readChunk(
                            poll.chunkIndex,
                            exactByteLength,
                        );
                    } catch (error) {
                        throw storageFailure(
                            'The browser store could not reread a common-proof output chunk.',
                            error,
                        );
                    }
                    if (
                        !(storedChunk instanceof Uint8Array) ||
                        !(storedChunk.buffer instanceof ArrayBuffer) ||
                        storedChunk.byteOffset !== 0 ||
                        storedChunk.byteLength !== storedChunk.buffer.byteLength
                    ) {
                        if (storedChunk instanceof Uint8Array) {
                            storedChunk.fill(0);
                        }
                        throw new CommonProofWorkerRuntimeError(
                            'WrongStorageResult',
                            'The browser store did not return a fresh owned common-proof output chunk.',
                        );
                    }
                    if (storedChunk.byteLength !== exactByteLength) {
                        storedChunk.fill(0);
                        throw new CommonProofWorkerRuntimeError(
                            'WrongStorageResult',
                            'The browser store returned a common-proof output chunk with the wrong length.',
                        );
                    }
                    try {
                        kernel.confirmOutputReadback(
                            liveOperationHandle,
                            poll.chunkIndex,
                            storedChunk,
                        );
                    } finally {
                        destroyTransferredWorkerBuffer(storedChunk);
                    }
                    break;
                }
                case 'complete': {
                    if (cancellationRequested) {
                        throw kernelFailure(
                            'The common-proof kernel completed after accepting cancellation.',
                        );
                    }
                    if (!deterministicPrefixReplayComplete) {
                        throw kernelFailure(
                            'The common-proof kernel completed before deterministic prefix replay reached its authenticated target.',
                        );
                    }
                    const kernelAccounting =
                        kernel.externalMemoryAccounting(liveOperationHandle);
                    const browserStorage =
                        externalMemory.copyBrowserStorageAccounting?.();
                    const workerTransport: CommonProofWorkerStorageTransportAccounting =
                        Object.freeze({
                            browserToWasmCopyByteLength,
                            browserToWasmCopyCount,
                            readResultTransferByteLength,
                            readResultTransferCount,
                            wasmToBrowserCopyByteLength,
                            wasmToBrowserCopyCount,
                        });
                    const externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting =
                        Object.freeze({
                            actualUsage: kernelAccounting.actualUsage,
                            ...(browserStorage === undefined
                                ? {}
                                : { browserStorage }),
                            compiledRequirement:
                                kernelAccounting.compiledRequirement,
                            ...(kernelAccounting.deterministicPrefixReplayUsage ===
                            undefined
                                ? {}
                                : {
                                      deterministicPrefixReplayUsage:
                                          kernelAccounting.deterministicPrefixReplayUsage,
                                  }),
                            workerTransport,
                        });
                    const capabilityHandle = kernel.finish(liveOperationHandle);
                    operationTerminal = true;
                    return createGeneratedCapability(
                        context,
                        kernel,
                        capabilityHandle,
                        externalMemoryAccounting,
                    );
                }
                case 'cancelled':
                    kernel.releaseCancelled(liveOperationHandle);
                    operationTerminal = true;
                    throw new CommonProofWorkerRuntimeError(
                        'Cancelled',
                        'The common-proof generation operation was cancelled.',
                        signal?.reason,
                    );
            }
        }
    } catch (error) {
        if (operationHandle === undefined) {
            const discardError = tryDiscardTransferredCommonProofHandle(
                context,
                preparedGenerationHandle,
                'sealed_lattice_common_proof_discard_prepared_generation',
                'prepared generation failed-start discard',
            );
            if (discardError !== undefined) {
                throw permanentRetirementFailure(
                    { discardError, operationError: error },
                    'The prepared common-proof generation failed before start and could not be retired.',
                );
            }
        }
        if (
            !operationTerminal &&
            operationHandle !== undefined &&
            kernel !== undefined
        ) {
            try {
                kernel.retireFailed(operationHandle);
                operationTerminal = true;
            } catch (retirementError) {
                throw new CommonProofWorkerRuntimeError(
                    'KernelFailure',
                    'The common-proof worker failed and could not retire its generation authority.',
                    { operationError: error, retirementError },
                    true,
                );
            }
        }
        if (
            error instanceof CommonProofWorkerRuntimeError &&
            error.code === 'Cancelled'
        ) {
            throw error;
        }
        throw permanentRetirementFailure(
            error,
            'The common-proof generation authority was permanently retired after an unexpected failure.',
        );
    } finally {
        if (reusableStorageResponseBuffer !== undefined) {
            destroyTransferredWorkerBuffer(reusableStorageResponseBuffer);
        }
    }
};

const verificationChunkCount = (declaredByteLength: number): number => {
    if (
        !Number.isSafeInteger(declaredByteLength) ||
        declaredByteLength <= 0 ||
        declaredByteLength > maximumCommonProofByteLength
    ) {
        throw resourceFailure(
            'The committed common-proof byte length exceeds the absolute worker safety bound.',
        );
    }
    return Math.ceil(declaredByteLength / canonicalCommonProofChunkByteLength);
};

const verificationChunkByteLength = (
    declaredByteLength: number,
    chunkIndex: number,
): number => {
    const chunkCount = verificationChunkCount(declaredByteLength);
    if (
        !Number.isSafeInteger(chunkIndex) ||
        chunkIndex < 0 ||
        chunkIndex >= chunkCount
    ) {
        throw kernelFailure(
            'The common-proof verifier requested a chunk outside the committed stream.',
        );
    }
    return chunkIndex + 1 === chunkCount
        ? declaredByteLength - chunkIndex * canonicalCommonProofChunkByteLength
        : canonicalCommonProofChunkByteLength;
};

const readCommittedVerificationChunk = async (
    inputStore: AuthenticatedCommonProofInputStore,
    declaredByteLength: number,
    chunkIndex: number,
): Promise<Uint8Array<ArrayBuffer>> => {
    const exactByteLength = verificationChunkByteLength(
        declaredByteLength,
        chunkIndex,
    );
    let chunkBytes: Uint8Array;
    try {
        chunkBytes = await inputStore.readCommittedChunk(
            chunkIndex,
            exactByteLength,
        );
    } catch (error) {
        throw storageFailure(
            'The browser store could not authenticate and read a committed common-proof chunk.',
            error,
        );
    }
    if (
        !(chunkBytes instanceof Uint8Array) ||
        !(chunkBytes.buffer instanceof ArrayBuffer) ||
        chunkBytes.byteOffset !== 0 ||
        chunkBytes.byteLength !== exactByteLength ||
        chunkBytes.buffer.byteLength !== exactByteLength
    ) {
        if (chunkBytes instanceof Uint8Array) {
            destroyTransferredWorkerBuffer(chunkBytes);
        }
        throw new CommonProofWorkerRuntimeError(
            'WrongStorageResult',
            'The browser store returned a malformed committed common-proof chunk.',
        );
    }
    return chunkBytes as Uint8Array<ArrayBuffer>;
};

const throwIfVerificationCancelled = (signal?: AbortSignal): void => {
    if (signal?.aborted === true) {
        throw new CommonProofWorkerRuntimeError(
            'Cancelled',
            'The common-proof verification operation was cancelled.',
            signal.reason,
        );
    }
};

const defaultCompactPublicKeyMaximumWorkUnitCountPerPoll = 4_096;

const restoreCompactPublicKeyAlgebraicVerificationCheckpoint = async (
    kernel: CommonProofVerificationKernelBoundary,
    checkpointCustody: CompactPublicKeyAlgebraicVerificationCheckpointCustody,
): Promise<Uint8Array<ArrayBuffer>> => {
    let canonicalCheckpointBytes: Uint8Array;
    try {
        canonicalCheckpointBytes =
            await checkpointCustody.restoreAuthenticatedCheckpoint();
    } catch (error) {
        throw storageFailure(
            'The browser store could not authenticate and restore the compact public-key algebraic verification checkpoint.',
            error,
        );
    }
    const expectedByteLength =
        kernel.compactPublicKeyAlgebraicVerificationCheckpointByteLength();
    if (
        !(canonicalCheckpointBytes instanceof Uint8Array) ||
        !(canonicalCheckpointBytes.buffer instanceof ArrayBuffer) ||
        canonicalCheckpointBytes.byteOffset !== 0 ||
        canonicalCheckpointBytes.byteLength !== expectedByteLength ||
        canonicalCheckpointBytes.buffer.byteLength !== expectedByteLength
    ) {
        if (canonicalCheckpointBytes instanceof Uint8Array) {
            destroyTransferredWorkerBuffer(canonicalCheckpointBytes);
        }
        throw new CommonProofWorkerRuntimeError(
            'WrongStorageResult',
            'The browser store returned a malformed compact public-key algebraic verification checkpoint.',
        );
    }
    return canonicalCheckpointBytes as Uint8Array<ArrayBuffer>;
};

const publishCompactPublicKeyAlgebraicVerificationCheckpoint = async (
    kernel: CommonProofVerificationKernelBoundary,
    operationHandle: number,
    checkpointCustody: CompactPublicKeyAlgebraicVerificationCheckpointCustody,
): Promise<void> => {
    const canonicalCheckpointBytes =
        kernel.copyCompactPublicKeyAlgebraicVerificationCheckpoint(
            operationHandle,
        );
    try {
        try {
            await checkpointCustody.publishAuthenticatedCheckpoint(
                canonicalCheckpointBytes,
            );
        } catch (error) {
            throw storageFailure(
                'The browser store could not atomically publish the compact public-key algebraic verification checkpoint.',
                error,
            );
        }
    } finally {
        destroyTransferredWorkerBuffer(canonicalCheckpointBytes);
    }
};

/**
 * Verifies the exact compact public-key transport and every production CFW and
 * WHIR equation through bounded scalar WASM polls. This genuine verification
 * result deliberately carries no workflow capability; capability handoff stays
 * refused until the compact family adapter owns the complete lifecycle.
 */
export const verifyCompactPublicKeyAlgebraicallyInClosedWorker = async (
    context: TranscriptCoreKernelCommandRuntime,
    input: CompactPublicKeyAlgebraicVerificationInput,
    options: CompactPublicKeyAlgebraicVerificationWorkerOptions = {},
): Promise<VerificationResult<undefined>> => {
    const maximumWorkUnitCountPerPoll =
        options.maximumWorkUnitCountPerPoll ??
        defaultCompactPublicKeyMaximumWorkUnitCountPerPoll;
    if (
        !Number.isSafeInteger(maximumWorkUnitCountPerPoll) ||
        maximumWorkUnitCountPerPoll <= 0 ||
        maximumWorkUnitCountPerPoll > 0xffff_ffff
    ) {
        throw resourceFailure(
            'The compact public-key algebraic verification work-unit bound must be a positive unsigned 32-bit integer.',
        );
    }

    const kernel = new CommonProofVerificationKernelBoundary(context);
    const resume = options.resume;
    const signal = options.signal;
    const yieldControl = options.yieldControl ?? yieldBrowserWorkerTurn;
    const checkpointCustody =
        options.checkpointCustody ?? resume?.checkpointCustody;
    let operationHandle: number | undefined;
    let operationTerminal = false;
    let deterministicReplayComplete = resume === undefined;
    try {
        throwIfVerificationCancelled(signal);
        const begin =
            resume === undefined
                ? kernel.beginCompactPublicKeyAlgebraicVerification(
                      input.bindings,
                      input.proofBytes,
                      input.publicInputBytes,
                  )
                : await (async () => {
                      const canonicalCheckpointBytes =
                          await restoreCompactPublicKeyAlgebraicVerificationCheckpoint(
                              kernel,
                              resume.checkpointCustody,
                          );
                      try {
                          throwIfVerificationCancelled(signal);
                          return kernel.resumeCompactPublicKeyAlgebraicVerification(
                              input.bindings,
                              input.proofBytes,
                              input.publicInputBytes,
                              canonicalCheckpointBytes,
                          );
                      } finally {
                          destroyTransferredWorkerBuffer(
                              canonicalCheckpointBytes,
                          );
                      }
                  })();
        if (begin.kind === 'refused') {
            return Object.freeze({
                isValid: false,
                refusalReason: begin.refusalReason,
            });
        }
        operationHandle = begin.operationHandle;
        for (;;) {
            throwIfVerificationCancelled(signal);
            const poll = kernel.pollCompactPublicKeyAlgebraicVerification(
                operationHandle,
                maximumWorkUnitCountPerPoll,
            );
            switch (poll.kind) {
                case 'progress':
                    if (!deterministicReplayComplete) {
                        await yieldControl();
                        break;
                    }
                    if (checkpointCustody !== undefined) {
                        await publishCompactPublicKeyAlgebraicVerificationCheckpoint(
                            kernel,
                            operationHandle,
                            checkpointCustody,
                        );
                    }
                    await yieldControl();
                    break;
                case 'resume-complete':
                    if (resume === undefined || deterministicReplayComplete) {
                        throw kernelFailure(
                            'The compact public-key algebraic verifier returned an unexpected resume-complete signal.',
                        );
                    }
                    deterministicReplayComplete = true;
                    await yieldControl();
                    break;
                case 'refused':
                    operationTerminal = true;
                    return Object.freeze({
                        isValid: false,
                        refusalReason: poll.refusalReason,
                    });
                case 'complete':
                    if (!deterministicReplayComplete) {
                        throw kernelFailure(
                            'The compact public-key algebraic verifier completed before deterministic checkpoint replay.',
                        );
                    }
                    operationTerminal = true;
                    return Object.freeze({
                        isValid: true,
                        value: undefined,
                    });
            }
        }
    } catch (error) {
        if (operationHandle !== undefined && !operationTerminal) {
            try {
                kernel.cancelCompactPublicKeyAlgebraicVerification(
                    operationHandle,
                );
                operationTerminal = true;
            } catch (cancellationError) {
                throw permanentRetirementFailure(
                    { cancellationError, operationError: error },
                    'The compact public-key algebraic verifier failed and could not retire its operation.',
                );
            }
        }
        throw error;
    }
};

const supplyVerificationReadback = async (
    kernel: CommonProofVerificationKernelBoundary,
    operationHandle: number,
    inputStore: AuthenticatedCommonProofInputStore,
    declaredByteLength: number,
    chunkIndex: number,
    signal?: AbortSignal,
): Promise<void> => {
    const chunkBytes = await readCommittedVerificationChunk(
        inputStore,
        declaredByteLength,
        chunkIndex,
    );
    try {
        throwIfVerificationCancelled(signal);
        kernel.supplyReadbackChunk(operationHandle, chunkIndex, chunkBytes);
    } finally {
        destroyTransferredWorkerBuffer(chunkBytes);
    }
};

/**
 * Streams one committed canonical proof through the Rust-owned hostile-input
 * decoder and verifier. The prepared handle can only come from an exact family
 * adapter inside the same worker. A terminal opaque capability is created only
 * after Rust completes proof verification and all requested store readbacks.
 */
export const runPreparedCommonProofVerificationWorker = async (
    context: TranscriptCoreKernelCommandRuntime,
    preparedVerificationHandle: number,
    inputStore: AuthenticatedCommonProofInputStore,
    options: CommonProofVerificationWorkerOptions = {},
): Promise<VerifiedCommonProofCapability> => {
    let kernel: CommonProofVerificationKernelBoundary | undefined;
    let operationHandle: number | undefined;
    let operationTerminal = false;

    try {
        if (
            typeof inputStore !== 'object' ||
            inputStore === null ||
            typeof inputStore.readCommittedChunk !== 'function'
        ) {
            throw new CommonProofWorkerRuntimeError(
                'WrongStorageResult',
                'The common-proof verifier requires an authenticated committed input store.',
            );
        }
        const declaredByteLength = inputStore.declaredByteLength;
        const chunkCount = verificationChunkCount(declaredByteLength);
        const signal = options.signal;
        const yieldControl = options.yieldControl ?? yieldBrowserWorkerTurn;
        throwIfVerificationCancelled(signal);
        kernel = new CommonProofVerificationKernelBoundary(context);
        operationHandle = kernel.begin(preparedVerificationHandle);
        const liveOperationHandle = operationHandle;
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            throwIfVerificationCancelled(signal);
            const chunkBytes = await readCommittedVerificationChunk(
                inputStore,
                declaredByteLength,
                chunkIndex,
            );
            try {
                throwIfVerificationCancelled(signal);
                kernel.absorbInputChunk(
                    liveOperationHandle,
                    chunkIndex,
                    chunkBytes,
                );
            } finally {
                destroyTransferredWorkerBuffer(chunkBytes);
            }
            await yieldControl();
        }
        throwIfVerificationCancelled(signal);
        kernel.finishInput(liveOperationHandle);

        for (;;) {
            throwIfVerificationCancelled(signal);
            const poll = kernel.poll(liveOperationHandle);
            switch (poll.kind) {
                case 'needs-readback': {
                    verificationChunkByteLength(
                        declaredByteLength,
                        poll.firstChunkIndex,
                    );
                    if (
                        poll.secondChunkIndex !== undefined &&
                        poll.secondChunkIndex === poll.firstChunkIndex
                    ) {
                        throw kernelFailure(
                            'The common-proof verifier requested one chunk twice in the same readback step.',
                        );
                    }
                    await supplyVerificationReadback(
                        kernel,
                        liveOperationHandle,
                        inputStore,
                        declaredByteLength,
                        poll.firstChunkIndex,
                        signal,
                    );
                    if (poll.secondChunkIndex !== undefined) {
                        await supplyVerificationReadback(
                            kernel,
                            liveOperationHandle,
                            inputStore,
                            declaredByteLength,
                            poll.secondChunkIndex,
                            signal,
                        );
                    }
                    await yieldControl();
                    break;
                }
                case 'prefix-accepted':
                case 'query-header-accepted':
                case 'query-tree-accepted':
                    await yieldControl();
                    break;
                case 'complete': {
                    throwIfVerificationCancelled(signal);
                    const capabilityHandle = kernel.finish(liveOperationHandle);
                    operationTerminal = true;
                    return createVerifiedCapability(
                        context,
                        kernel,
                        capabilityHandle,
                    );
                }
            }
        }
    } catch (error) {
        if (operationHandle === undefined) {
            const discardError = tryDiscardTransferredCommonProofHandle(
                context,
                preparedVerificationHandle,
                'sealed_lattice_common_proof_discard_prepared_verification',
                'prepared verification failed-start discard',
            );
            if (discardError !== undefined) {
                throw permanentRetirementFailure(
                    { discardError, operationError: error },
                    'The prepared common-proof verifier failed before start and could not be retired.',
                );
            }
        } else if (!operationTerminal && kernel !== undefined) {
            try {
                kernel.cancel(operationHandle);
                operationTerminal = true;
            } catch (cancellationError) {
                throw permanentRetirementFailure(
                    { cancellationError, operationError: error },
                    'The common-proof verifier failed and could not retire its operation.',
                );
            }
        }
        throw error;
    }
};
