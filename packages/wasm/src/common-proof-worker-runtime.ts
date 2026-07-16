import { shake256 } from '@noble/hashes/sha3.js';

import {
    resolveNumberExport,
    type TranscriptCoreKernelCommandRuntime,
} from './transcript-core-bridge/kernel-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';

const hashByteLength = 64;
const localStorageRootCapabilityByteLength = 32;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const maximumWorkerOperationCount = 4_096;
const maximumWorkerPayloadByteLength = 1_048_576n;
const maximumExternalMemoryAppendByteLength = 49_152;
const operationHeaderByteLength = 32;
const readResultHeaderByteLength = 88;
const requestHeaderByteLength = 156;
const responseHeaderByteLength = 80;
const maximumEncodedRequestByteLength =
    requestHeaderByteLength +
    maximumWorkerOperationCount * operationHeaderByteLength +
    Number(maximumWorkerPayloadByteLength);
const schemaVersion = 1;
const requestMessageKind = 1;
const responseMessageKind = 2;
const requestDigestDomain =
    'sealed-lattice/common-proof/external-memory-request/v1';
const readDigestDomain = 'sealed-lattice/common-proof/external-memory-read/v1';
const hashPreimagePrefix = new TextEncoder().encode('sealed.vote/hash512');
const textEncoder = new TextEncoder();

export type CommonProofExternalMemoryProtection =
    | 'public-integrity'
    | 'secret-authenticated-encryption';

export type CommonProofExternalMemoryOperation =
    | Readonly<{
          exactByteLength: bigint;
          objectOrdinal: number;
          operationIndex: number;
          operationKind: 'create';
          protection: CommonProofExternalMemoryProtection;
      }>
    | Readonly<{
          bytes: Uint8Array;
          expectedOffset: bigint;
          objectOrdinal: number;
          operationIndex: number;
          operationKind: 'append';
      }>
    | Readonly<{
          objectOrdinal: number;
          operationIndex: number;
          operationKind: 'seal';
      }>
    | Readonly<{
          byteLength: number;
          objectOrdinal: number;
          offset: bigint;
          operationIndex: number;
          operationKind: 'read';
      }>
    | Readonly<{
          objectOrdinal: number;
          operationIndex: number;
          operationKind: 'delete';
      }>;

export type CommonProofExternalMemoryRequest = Readonly<{
    maximumOperationCount: number;
    maximumPayloadByteLength: bigint;
    operations: readonly CommonProofExternalMemoryOperation[];
    requestDigest: Uint8Array<ArrayBuffer>;
    requestSequence: bigint;
    runtimeBindingHash: Uint8Array<ArrayBuffer>;
}>;

export type CommonProofExternalMemoryReadResult = Readonly<{
    bytes: Uint8Array<ArrayBuffer>;
    objectOrdinal: number;
    offset: bigint;
    operationIndex: number;
}>;

type CommonProofWorkerRuntimeErrorCode =
    | 'Cancelled'
    | 'KernelFailure'
    | 'MalformedRequest'
    | 'ResourceLimit'
    | 'StorageFailure'
    | 'WrongRuntimeBinding'
    | 'WrongRequestDigest'
    | 'WrongSequence'
    | 'WrongStorageResult';

export class CommonProofWorkerRuntimeError extends Error {
    public override readonly name = 'CommonProofWorkerRuntimeError';

    public constructor(
        public readonly code: CommonProofWorkerRuntimeErrorCode,
        message: string,
        public readonly failureCause?: unknown,
        /** The same participant generation authority must never be reused. */
        public readonly permanentRetirementRequired = false,
    ) {
        super(message);
    }
}

const encodedVaruint = (input: bigint): Uint8Array<ArrayBuffer> => {
    if (input < 0n || input > 0xffff_ffff_ffff_ffffn) {
        throw new CommonProofWorkerRuntimeError(
            'ResourceLimit',
            'A common-proof hash-frame length is outside the unsigned 64-bit range.',
        );
    }
    const encoded: number[] = [];
    let remaining = input;
    do {
        let byte = Number(remaining & 0x7fn);
        remaining >>= 7n;
        if (remaining !== 0n) {
            byte |= 0x80;
        }
        encoded.push(byte);
    } while (remaining !== 0n);
    return Uint8Array.from(encoded);
};

const framedHash = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array<ArrayBuffer> => {
    const hash = shake256.create({ dkLen: hashByteLength });
    const domainBytes = textEncoder.encode(domain);
    hash.update(hashPreimagePrefix);
    hash.update(encodedVaruint(BigInt(domainBytes.byteLength)));
    hash.update(domainBytes);
    hash.update(encodedVaruint(BigInt(parts.length)));
    for (const part of parts) {
        hash.update(encodedVaruint(BigInt(part.byteLength)));
        hash.update(part);
    }
    return hash.digest().slice();
};

const unsigned16Bytes = (value: number): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32Bytes = (value: number): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const unsigned64Bytes = (value: bigint): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const byteArraysEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

class BoundedMessageReader {
    readonly #bytes: Uint8Array;
    #offset = 0;

    public constructor(bytes: Uint8Array) {
        this.#bytes = bytes;
    }

    public bytes(byteLength: number): Uint8Array {
        if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
            this.#malformed();
        }
        const end = this.#offset + byteLength;
        if (!Number.isSafeInteger(end) || end > this.#bytes.byteLength) {
            this.#malformed();
        }
        const value = this.#bytes.subarray(this.#offset, end);
        this.#offset = end;
        return value;
    }

    public complete(): boolean {
        return this.#offset === this.#bytes.byteLength;
    }

    public unsigned16(): number {
        const bytes = this.bytes(2);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    public unsigned32(): number {
        const bytes = this.bytes(4);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(0, true);
    }

    public unsigned64(): bigint {
        const bytes = this.bytes(8);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getBigUint64(0, true);
    }

    #malformed(): never {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'The common-proof storage request is truncated or malformed.',
        );
    }
}

const requireZero = (value: number, label: string): void => {
    if (value !== 0) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            `${label} must be zero.`,
        );
    }
};

const decodeOperation = (
    reader: BoundedMessageReader,
    operationIndex: number,
): CommonProofExternalMemoryOperation => {
    if (reader.unsigned32() !== operationIndex) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'Common-proof storage operation ordinals are not canonical.',
        );
    }
    const operationKind = reader.unsigned16();
    const protectionCode = reader.unsigned16();
    const objectOrdinal = reader.unsigned32();
    requireZero(reader.unsigned32(), 'The operation reserved field');
    const position = reader.unsigned64();
    const payloadByteLength = reader.unsigned64();
    switch (operationKind) {
        case 1: {
            if (
                position !== 0n ||
                payloadByteLength === 0n ||
                (protectionCode !== 1 && protectionCode !== 2)
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'MalformedRequest',
                    'A common-proof create operation has invalid metadata.',
                );
            }
            return Object.freeze({
                exactByteLength: payloadByteLength,
                objectOrdinal,
                operationIndex,
                operationKind: 'create',
                protection:
                    protectionCode === 1
                        ? 'public-integrity'
                        : 'secret-authenticated-encryption',
            });
        }
        case 2: {
            if (
                protectionCode !== 0 ||
                payloadByteLength === 0n ||
                payloadByteLength > maximumWorkerPayloadByteLength
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'MalformedRequest',
                    'A common-proof append operation has invalid metadata.',
                );
            }
            return Object.freeze({
                bytes: reader.bytes(Number(payloadByteLength)),
                expectedOffset: position,
                objectOrdinal,
                operationIndex,
                operationKind: 'append',
            });
        }
        case 3: {
            if (
                protectionCode !== 0 ||
                position !== 0n ||
                payloadByteLength !== 0n
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'MalformedRequest',
                    'A common-proof seal operation has invalid metadata.',
                );
            }
            return Object.freeze({
                objectOrdinal,
                operationIndex,
                operationKind: 'seal',
            });
        }
        case 4: {
            if (
                protectionCode !== 0 ||
                payloadByteLength === 0n ||
                payloadByteLength > maximumWorkerPayloadByteLength
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'MalformedRequest',
                    'A common-proof read operation has invalid metadata.',
                );
            }
            return Object.freeze({
                byteLength: Number(payloadByteLength),
                objectOrdinal,
                offset: position,
                operationIndex,
                operationKind: 'read',
            });
        }
        case 5: {
            if (
                protectionCode !== 0 ||
                position !== 0n ||
                payloadByteLength !== 0n
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'MalformedRequest',
                    'A common-proof delete operation has invalid metadata.',
                );
            }
            return Object.freeze({
                objectOrdinal,
                operationIndex,
                operationKind: 'delete',
            });
        }
        default:
            throw new CommonProofWorkerRuntimeError(
                'MalformedRequest',
                'The common-proof storage operation kind is unsupported.',
            );
    }
};

export const decodeCommonProofExternalMemoryRequest = (
    encodedRequest: Uint8Array,
): CommonProofExternalMemoryRequest => {
    if (
        !(encodedRequest instanceof Uint8Array) ||
        encodedRequest.byteLength < requestHeaderByteLength ||
        encodedRequest.byteLength > maximumEncodedRequestByteLength
    ) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'The common-proof storage request length is outside the fixed worker profile.',
        );
    }
    const exactViewSnapshot = encodedRequest.slice();
    const snapshotBuffer: ArrayBuffer = structuredClone(
        exactViewSnapshot.buffer,
        { transfer: [exactViewSnapshot.buffer] },
    );
    const ownedEncodedRequest = new Uint8Array(snapshotBuffer);
    const reader = new BoundedMessageReader(ownedEncodedRequest);
    if (
        reader.unsigned16() !== schemaVersion ||
        reader.unsigned16() !== requestMessageKind
    ) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'The common-proof storage request version or message kind is unsupported.',
        );
    }
    const maximumPayloadByteLength = reader.unsigned64();
    const maximumOperationCount = reader.unsigned32();
    const operationCount = reader.unsigned32();
    const requestSequence = reader.unsigned64();
    const runtimeBindingHash = reader.bytes(hashByteLength).slice();
    const suppliedRequestDigest = reader.bytes(hashByteLength).slice();
    if (
        maximumPayloadByteLength === 0n ||
        maximumPayloadByteLength > maximumWorkerPayloadByteLength ||
        maximumOperationCount === 0 ||
        maximumOperationCount > maximumWorkerOperationCount ||
        operationCount === 0 ||
        operationCount > maximumOperationCount ||
        requestSequence === 0n
    ) {
        throw new CommonProofWorkerRuntimeError(
            'ResourceLimit',
            'The common-proof storage request exceeds the fixed worker profile.',
        );
    }
    const minimumOperationByteLength =
        operationCount * operationHeaderByteLength;
    if (
        !Number.isSafeInteger(minimumOperationByteLength) ||
        ownedEncodedRequest.byteLength <
            requestHeaderByteLength + minimumOperationByteLength
    ) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'The common-proof storage operation list is truncated.',
        );
    }
    const operations: CommonProofExternalMemoryOperation[] = [];
    let transactionPayloadByteLength = 0n;
    for (
        let operationIndex = 0;
        operationIndex < operationCount;
        operationIndex += 1
    ) {
        const operation = decodeOperation(reader, operationIndex);
        operations.push(operation);
        if (operation.operationKind === 'append') {
            transactionPayloadByteLength += BigInt(operation.bytes.byteLength);
        } else if (operation.operationKind === 'read') {
            transactionPayloadByteLength += BigInt(operation.byteLength);
        }
        if (transactionPayloadByteLength > maximumPayloadByteLength) {
            throw new CommonProofWorkerRuntimeError(
                'ResourceLimit',
                'The common-proof storage transaction payload exceeds its declared bound.',
            );
        }
    }
    const firstOperationKind = operations[0]?.operationKind;
    if (
        firstOperationKind === undefined ||
        (operations.length > 1 &&
            (firstOperationKind !== 'delete' ||
                operations.some(
                    (operation) => operation.operationKind !== 'delete',
                ))) ||
        operations.some(
            (operation) =>
                operation.operationKind === 'append' &&
                operation.bytes.byteLength >
                    maximumExternalMemoryAppendByteLength,
        )
    ) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'The common-proof storage request does not use the fixed executor transaction grammar.',
        );
    }
    if (!reader.complete()) {
        throw new CommonProofWorkerRuntimeError(
            'MalformedRequest',
            'The common-proof storage request has trailing bytes.',
        );
    }
    const operationBytes = ownedEncodedRequest.subarray(
        requestHeaderByteLength,
    );
    const expectedRequestDigest = framedHash(requestDigestDomain, [
        unsigned16Bytes(schemaVersion),
        runtimeBindingHash,
        unsigned64Bytes(requestSequence),
        unsigned64Bytes(maximumPayloadByteLength),
        unsigned32Bytes(maximumOperationCount),
        unsigned32Bytes(operationCount),
        operationBytes,
    ]);
    if (!byteArraysEqual(suppliedRequestDigest, expectedRequestDigest)) {
        throw new CommonProofWorkerRuntimeError(
            'WrongRequestDigest',
            'The common-proof storage request digest does not bind its exact operation list.',
        );
    }
    return Object.freeze({
        maximumOperationCount,
        maximumPayloadByteLength,
        operations: Object.freeze(operations),
        requestDigest: expectedRequestDigest,
        requestSequence,
        runtimeBindingHash,
    });
};

const readDigest = (
    requestDigest: Uint8Array,
    operation: Extract<
        CommonProofExternalMemoryOperation,
        { readonly operationKind: 'read' }
    >,
    bytes: Uint8Array,
): Uint8Array<ArrayBuffer> =>
    framedHash(readDigestDomain, [
        requestDigest,
        unsigned32Bytes(operation.operationIndex),
        unsigned32Bytes(operation.objectOrdinal),
        unsigned64Bytes(operation.offset),
        unsigned64Bytes(BigInt(bytes.byteLength)),
        bytes,
    ]);

const clearReadResults = (
    readResults: readonly CommonProofExternalMemoryReadResult[],
): void => {
    for (const result of readResults) {
        result.bytes.fill(0);
    }
};

const encodeStorageResponse = (
    request: CommonProofExternalMemoryRequest,
    readResults: readonly CommonProofExternalMemoryReadResult[],
): Uint8Array<ArrayBuffer> => {
    const readOperations = request.operations.filter(
        (
            operation,
        ): operation is Extract<
            CommonProofExternalMemoryOperation,
            { readonly operationKind: 'read' }
        > => operation.operationKind === 'read',
    );
    if (readResults.length !== readOperations.length) {
        throw new CommonProofWorkerRuntimeError(
            'WrongStorageResult',
            'The browser store returned the wrong number of common-proof reads.',
        );
    }
    let responseByteLength =
        responseHeaderByteLength +
        readOperations.length * readResultHeaderByteLength;
    for (const [readIndex, operation] of readOperations.entries()) {
        const result = readResults[readIndex];
        const bytes = result?.bytes;
        if (
            result === undefined ||
            !(bytes instanceof Uint8Array) ||
            bytes.byteLength !== operation.byteLength ||
            result.operationIndex !== operation.operationIndex ||
            result.objectOrdinal !== operation.objectOrdinal ||
            result.offset !== operation.offset
        ) {
            throw new CommonProofWorkerRuntimeError(
                'WrongStorageResult',
                'The browser store returned a common-proof read with the wrong length.',
            );
        }
        responseByteLength += bytes.byteLength;
    }
    if (
        !Number.isSafeInteger(responseByteLength) ||
        BigInt(responseByteLength) >
            BigInt(responseHeaderByteLength) +
                BigInt(readOperations.length * readResultHeaderByteLength) +
                request.maximumPayloadByteLength
    ) {
        throw new CommonProofWorkerRuntimeError(
            'ResourceLimit',
            'The common-proof storage response exceeds its fixed bound.',
        );
    }
    const response = new Uint8Array(responseByteLength);
    const view = new DataView(response.buffer);
    let offset = 0;
    view.setUint16(offset, schemaVersion, true);
    offset += 2;
    view.setUint16(offset, responseMessageKind, true);
    offset += 2;
    view.setBigUint64(offset, request.requestSequence, true);
    offset += 8;
    response.set(request.requestDigest, offset);
    offset += hashByteLength;
    view.setUint32(offset, readOperations.length, true);
    offset += 4;
    for (const [readIndex, operation] of readOperations.entries()) {
        const bytes = readResults[readIndex].bytes;
        view.setUint32(offset, operation.operationIndex, true);
        offset += 4;
        view.setUint32(offset, operation.objectOrdinal, true);
        offset += 4;
        view.setBigUint64(offset, operation.offset, true);
        offset += 8;
        view.setUint32(offset, operation.byteLength, true);
        offset += 4;
        view.setUint32(offset, 0, true);
        offset += 4;
        response.set(
            readDigest(request.requestDigest, operation, bytes),
            offset,
        );
        offset += hashByteLength;
        response.set(bytes, offset);
        offset += bytes.byteLength;
    }
    if (offset !== response.byteLength) {
        response.fill(0);
        throw new CommonProofWorkerRuntimeError(
            'WrongStorageResult',
            'The common-proof storage response accounting diverged.',
        );
    }
    return response;
};

/**
 * Encodes the exact response to one Rust-issued request. The worker owns the
 * transaction and passes only its ordered read results here; every returned
 * read buffer is cleared after encoding, including on rejection.
 */
export const encodeCommonProofExternalMemoryResponse = (
    request: CommonProofExternalMemoryRequest,
    readResults: readonly CommonProofExternalMemoryReadResult[],
): Uint8Array<ArrayBuffer> => {
    try {
        return encodeStorageResponse(request, readResults);
    } finally {
        clearReadResults(readResults);
    }
};

const wasm32WordByteLength = 4;
const noSecondPollValue = 0xffff_ffff;
const generationPollProgress = 1;
const generationPollStorageRequestReady = 2;
const generationPollOutputChunkReady = 3;
const generationPollOutputReadbackRequired = 4;
const generationPollComplete = 5;
const generationPollCancelled = 6;
const generationPollResumeComplete = 7;
const firstGenerationStage = 1;
const finalGenerationStage = 14;
const verificationPollNeedsReadback = 1;
const verificationPollPrefixAccepted = 2;
const verificationPollQueryHeaderAccepted = 3;
const verificationPollQueryTreeAccepted = 4;
const verificationPollComplete = 5;
const maximumCommonProofByteLength = 5_242_880;
const canonicalCommonProofChunkByteLength = 1_048_576;
const maximumGenerationCheckpointStateByteLength = 4_096;
const maximumGenerationCheckpointCursorCount = 4_096;
const maximumGenerationCheckpointCursorByteLength = 1_048_576;
const maximumGenerationCheckpointCursorTotalByteLength = 1_048_576;
const maximumCommonProofOutputChunkCount =
    maximumCommonProofByteLength / canonicalCommonProofChunkByteLength;

/**
 * Executes one storage transaction. Ownership of every returned read buffer
 * transfers to this runtime; the runtime snapshots and clears those buffers
 * before continuing.
 */
export type CommonProofExternalMemoryTransactionExecutor = Readonly<{
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
    /** Returned read-buffer ownership transfers to this runtime. */
    executeDeterministicPrefixReplayTransaction(
        request: CommonProofExternalMemoryRequest,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]>;
}>;

export type CommonProofGenerationCheckpoint = Readonly<{
    /** Fixed canonical Rust-owned state. It contains no secret coin bytes. */
    canonicalStateBytes: Uint8Array<ArrayBuffer>;
    /** Canonical cursors in Rust-defined `(family, purpose)` order. */
    orderedPrivateRandomCursorBytes: readonly Uint8Array<ArrayBuffer>[];
    safeBoundaryOrdinal: number;
    /** Stable authenticated binding for this exact generation attempt. */
    stableAttemptBindingHash: Uint8Array<ArrayBuffer>;
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
    restoreAuthenticatedCheckpointState(): Promise<Uint8Array>;
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
    checkpointCustody?: CommonProofGenerationCheckpointCustody;
    resume?: CommonProofGenerationResume;
    signal?: AbortSignal;
    yieldControl?: () => Promise<void>;
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

/**
 * Opaque generated-proof authority retained in the WASM worker. It exposes no
 * numeric handle and can only be released until a downstream Rust capability
 * consumer is connected.
 */
type GeneratedCommonProofCapability = Readonly<{
    release(): void;
}>;

const closedWorkerPreparedCommonProofGenerationBrand = Symbol(
    'closed-worker-prepared-common-proof-generation',
);
const closedWorkerPreparedCommonProofVerificationBrand = Symbol(
    'closed-worker-prepared-common-proof-verification',
);

/**
 * Non-cloneable exact-family prover preparation retained in one WASM worker.
 * Its Rust handle and command runtime exist only in the private record below.
 */
export type ClosedWorkerPreparedCommonProofGeneration = Readonly<{
    readonly [closedWorkerPreparedCommonProofGenerationBrand]: true;
}>;

/**
 * Non-cloneable exact-family verifier preparation retained in one WASM worker.
 * It cannot be constructed from decoded proof bytes or a caller verdict.
 */
export type ClosedWorkerPreparedCommonProofVerification = Readonly<{
    readonly [closedWorkerPreparedCommonProofVerificationBrand]: true;
}>;

export type ClosedWorkerPreparedCommonProofDescription = Readonly<{
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
}>;

type ClosedWorkerPreparedCommonProofRecord = {
    commonProofRuntimeBindingHash: Uint8Array<ArrayBuffer>;
    consumed: boolean;
    context: TranscriptCoreKernelCommandRuntime;
    preparedOperationHandle: number;
    proofAttemptLineageIdentifier: Uint8Array<ArrayBuffer>;
};

const closedWorkerPreparedCommonProofGenerationRecords = new WeakMap<
    ClosedWorkerPreparedCommonProofGeneration,
    ClosedWorkerPreparedCommonProofRecord
>();
const closedWorkerPreparedCommonProofVerificationRecords = new WeakMap<
    ClosedWorkerPreparedCommonProofVerification,
    ClosedWorkerPreparedCommonProofRecord
>();

/**
 * Opaque proof-verification authority retained in the WASM worker. The numeric
 * handle and verifier-derived facts stay inside Rust; this object can only
 * retire the authority until an exact protocol-family consumer takes it.
 */
export type VerifiedCommonProofCapability = Readonly<{
    release(): void;
}>;

export type CommonProofApplicationFreshnessCoordinate = Readonly<{
    authenticatedHeadDigest: Uint8Array;
    freshnessSequence: bigint;
    storageInstanceIdentity: Uint8Array;
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

export type CommonProofApplicationStorageRootAccess = Readonly<{
    context: TranscriptCoreKernelCommandRuntime;
    storageRootCapability: Uint8Array;
    storageRootHandle: number;
}>;

type CommonProofGenerationKernelPoll =
    | Readonly<{
          checkpointReady: boolean;
          kind: 'progress';
          stage: number;
      }>
    | Readonly<{
          kind: 'resume-complete';
          stage: number;
      }>
    | Readonly<{
          encodedRequestByteLength: number;
          kind: 'storage-request-ready';
      }>
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

const kernelFailure = (
    message: string,
    failureCause?: unknown,
): CommonProofWorkerRuntimeError =>
    new CommonProofWorkerRuntimeError('KernelFailure', message, failureCause);

const resourceFailure = (message: string): CommonProofWorkerRuntimeError =>
    new CommonProofWorkerRuntimeError('ResourceLimit', message);

const requireUnsigned32 = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw kernelFailure(`${label} is outside the unsigned 32-bit range.`);
    }
    return value;
};

const requireLiveHandle = (value: number, label: string): number => {
    requireUnsigned32(value, label);
    if (value === 0) {
        throw kernelFailure(`${label} is null.`);
    }
    return value;
};

const requireUnsigned64 = (value: bigint, label: string): bigint => {
    if (typeof value !== 'bigint' || value < 0n || value > maximumUnsigned64) {
        throw kernelFailure(`${label} is outside the unsigned 64-bit range.`);
    }
    return value;
};

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

const copyExactApplicationBytes = (
    value: Uint8Array,
    exactByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    requireExactApplicationBytes(value, exactByteLength, label);
    return Uint8Array.from(value);
};

const requireKernelSuccess = (status: number, operation: string): void => {
    requireUnsigned32(status, `${operation} status`);
    if (status !== 0) {
        throw kernelFailure(
            `The common-proof kernel refused ${operation} with status ${status}.`,
        );
    }
};

const yieldBrowserWorkerTurn = (): Promise<void> =>
    new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = () => {
            channel.port1.close();
            channel.port2.close();
            resolve();
        };
        channel.port2.postMessage(undefined);
    });

class CommonProofGenerationKernelBoundary {
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
    ): number {
        requireLiveHandle(
            preparedGenerationHandle,
            'The prepared common-proof generation handle',
        );
        if (!(authenticatedCheckpointState instanceof Uint8Array)) {
            throw resourceFailure(
                'The authenticated common-proof checkpoint state must be a byte array.',
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
                try {
                    const operationHandle = resume(
                        preparedGenerationHandle,
                        checkpointPointer,
                        authenticatedCheckpointState.byteLength,
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
    ): CommonProofGenerationCheckpoint {
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
                'The common-proof kernel exposed an out-of-profile checkpoint state length.',
            );
        }
        const [safeBoundaryOrdinal, stateByteLength, cursorCount] =
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
            safeBoundaryOrdinal === 0 ||
            stateByteLength !== canonicalStateByteLength ||
            cursorCount > maximumGenerationCheckpointCursorCount
        ) {
            throw kernelFailure(
                'The common-proof kernel exposed an out-of-profile checkpoint description.',
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
        const orderedPrivateRandomCursorBytes: Uint8Array<ArrayBuffer>[] = [];
        let cursorTotalByteLength = 0;
        let stableAttemptBindingHash: Uint8Array<ArrayBuffer> | undefined;
        try {
            for (
                let cursorIndex = 0;
                cursorIndex < cursorCount;
                cursorIndex += 1
            ) {
                const cursorBytes = this.#copyCheckpointCursor(
                    operationHandle,
                    cursorIndex,
                );
                if (
                    cursorBytes.byteLength >
                    maximumGenerationCheckpointCursorTotalByteLength -
                        cursorTotalByteLength
                ) {
                    cursorBytes.fill(0);
                    throw kernelFailure(
                        'The common-proof kernel exposed checkpoint cursors whose aggregate length exceeds the fixed worker profile.',
                    );
                }
                cursorTotalByteLength += cursorBytes.byteLength;
                orderedPrivateRandomCursorBytes.push(cursorBytes);
            }
            stableAttemptBindingHash = this.#copyKernelBytes(
                hashByteLength,
                'generation checkpoint stable attempt binding hash',
                (outputPointer) =>
                    resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash',
                    )(operationHandle, outputPointer, hashByteLength),
            );
            return Object.freeze({
                canonicalStateBytes,
                orderedPrivateRandomCursorBytes: Object.freeze(
                    orderedPrivateRandomCursorBytes,
                ),
                stableAttemptBindingHash,
                safeBoundaryOrdinal,
            });
        } catch (error) {
            canonicalStateBytes.fill(0);
            stableAttemptBindingHash?.fill(0);
            for (const cursorBytes of orderedPrivateRandomCursorBytes) {
                cursorBytes.fill(0);
            }
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
                'The common-proof kernel requested an out-of-profile storage message.',
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
            (responsePointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_supply_storage_response',
                )(operationHandle, responsePointer, encodedResponse.byteLength),
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
                'The common-proof kernel exposed an out-of-profile output chunk.',
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
            (readbackPointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_confirm_output_readback',
                )(
                    operationHandle,
                    chunkIndex,
                    readbackPointer,
                    readbackBytes.byteLength,
                ),
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

    #copyCheckpointCursor(
        operationHandle: number,
        cursorIndex: number,
    ): Uint8Array<ArrayBuffer> {
        const cursorByteLength = this.#context.runExclusive(
            'common-proof generation checkpoint cursor length',
            () => {
                const statusPointer =
                    this.#memoryBoundary.allocateZeroedWords(1);
                try {
                    const byteLength = resolveNumberExport(
                        this.#context.wasmExports,
                        'sealed_lattice_common_proof_generation_checkpoint_cursor_byte_length',
                    )(operationHandle, cursorIndex, statusPointer);
                    const [status] = this.#memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    requireKernelSuccess(
                        status,
                        'generation checkpoint cursor length',
                    );
                    return byteLength;
                } finally {
                    this.#memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        if (
            cursorByteLength === 0 ||
            cursorByteLength > maximumGenerationCheckpointCursorByteLength
        ) {
            throw kernelFailure(
                'The common-proof kernel exposed an out-of-profile checkpoint cursor.',
            );
        }
        return this.#copyKernelBytes(
            cursorByteLength,
            'generation checkpoint cursor',
            (outputPointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_generation_copy_checkpoint_cursor',
                )(
                    operationHandle,
                    cursorIndex,
                    outputPointer,
                    cursorByteLength,
                ),
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
        invoke: (inputPointer: number) => number,
    ): void {
        if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
            throw resourceFailure(
                `The common-proof ${label} must be a non-empty byte array.`,
            );
        }
        this.#context.runExclusive(`common-proof ${label}`, () => {
            const inputPointer = this.#memoryBoundary.copy(bytes);
            try {
                requireKernelSuccess(invoke(inputPointer), label);
            } finally {
                this.#memoryBoundary.zeroAndDeallocate(
                    inputPointer,
                    bytes.byteLength,
                );
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
                    stage: primaryValue,
                });
            case generationPollResumeComplete:
                if (
                    primaryValue >= firstGenerationStage &&
                    primaryValue <= finalGenerationStage &&
                    secondaryValue === noSecondPollValue
                ) {
                    return Object.freeze({
                        kind: 'resume-complete',
                        stage: primaryValue,
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

class CommonProofVerificationKernelBoundary {
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
            (pointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_verification_absorb_input_chunk',
                )(operationHandle, chunkIndex, pointer, chunkBytes.byteLength),
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
            (pointer) =>
                resolveNumberExport(
                    this.#context.wasmExports,
                    'sealed_lattice_common_proof_verification_supply_readback_chunk',
                )(operationHandle, chunkIndex, pointer, chunkBytes.byteLength),
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
        invoke: (inputPointer: number) => number,
    ): void {
        if (
            !(bytes instanceof Uint8Array) ||
            bytes.byteLength === 0 ||
            bytes.byteLength > canonicalCommonProofChunkByteLength
        ) {
            throw resourceFailure(
                `The common-proof ${label} length is outside the fixed worker profile.`,
            );
        }
        this.#context.runExclusive(`common-proof ${label}`, () => {
            const inputPointer = this.#memoryBoundary.copy(bytes);
            try {
                requireKernelSuccess(invoke(inputPointer), label);
            } finally {
                this.#memoryBoundary.zeroAndDeallocate(
                    inputPointer,
                    bytes.byteLength,
                );
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

const snapshotReadResults = (
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
            if (
                expectedOperation === undefined ||
                typeof result !== 'object' ||
                result === null ||
                !('bytes' in result) ||
                !(result.bytes instanceof Uint8Array) ||
                result.bytes.byteLength !== expectedOperation.byteLength ||
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
                bytes: result.bytes.slice(),
                objectOrdinal: result.objectOrdinal,
                offset: result.offset,
                operationIndex: result.operationIndex,
            });
        });
    } finally {
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
                result.bytes.fill(0);
            }
        }
    }
};

const createGeneratedCapability = (
    kernel: CommonProofGenerationKernelBoundary,
    capabilityHandle: number,
): GeneratedCommonProofCapability => {
    let live = true;
    return Object.freeze({
        release: (): void => {
            if (!live) {
                throw kernelFailure(
                    'The generated common-proof capability was already released.',
                );
            }
            kernel.releaseGenerated(capabilityHandle);
            live = false;
        },
    });
};

type VerifiedCommonProofCapabilityRecord = {
    readonly capabilityHandle: number;
    readonly kernel: CommonProofVerificationKernelBoundary;
};

const verifiedCommonProofCapabilityRecords = new WeakMap<
    VerifiedCommonProofCapability,
    VerifiedCommonProofCapabilityRecord
>();

const createVerifiedCapability = (
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
        kernel,
    });
    return capability;
};

type PreparedCommonProofApplicationRecord = Readonly<{
    capability: VerifiedCommonProofCapability;
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
    for (const cursorBytes of checkpoint.orderedPrivateRandomCursorBytes) {
        cursorBytes.fill(0);
    }
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

type ClosedWorkerCommonProofFamilyPreparationInput = Readonly<{
    commonProofRuntimeBindingHash: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    proofAttemptLineageIdentifier: Uint8Array;
    /**
     * Exact-family code invokes its Rust preparer here. The returned process-local
     * handle is captured immediately and never becomes a protocol or worker-channel
     * value.
     */
    retainPreparedOperation(): number;
}>;

const copyClosedWorkerCommonProofPreparationBytes = (
    value: Uint8Array,
    exactByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== exactByteLength
    ) {
        throw resourceFailure(
            `${label} must contain exactly ${exactByteLength} bytes.`,
        );
    }
    return Uint8Array.from(value);
};

const createClosedWorkerPreparedCommonProofRecord = (
    input: ClosedWorkerCommonProofFamilyPreparationInput,
): ClosedWorkerPreparedCommonProofRecord => {
    if (typeof globalThis.document !== 'undefined') {
        throw resourceFailure(
            'Common-proof family preparation may only be retained inside the dedicated WASM worker.',
        );
    }
    if (
        typeof input !== 'object' ||
        input === null ||
        typeof input.context !== 'object' ||
        input.context === null ||
        typeof input.retainPreparedOperation !== 'function'
    ) {
        throw resourceFailure(
            'The common-proof family adapter preparation is malformed.',
        );
    }
    const commonProofRuntimeBindingHash =
        copyClosedWorkerCommonProofPreparationBytes(
            input.commonProofRuntimeBindingHash,
            hashByteLength,
            'The common-proof runtime-binding hash',
        );
    let proofAttemptLineageIdentifier = new Uint8Array(0);
    try {
        proofAttemptLineageIdentifier =
            copyClosedWorkerCommonProofPreparationBytes(
                input.proofAttemptLineageIdentifier,
                32,
                'The proof-attempt lineage identifier',
            );
        const preparedOperationHandle = requireLiveHandle(
            input.retainPreparedOperation(),
            'The exact-family prepared common-proof operation handle',
        );
        return {
            commonProofRuntimeBindingHash,
            consumed: false,
            context: input.context,
            preparedOperationHandle,
            proofAttemptLineageIdentifier,
        };
    } catch (error) {
        commonProofRuntimeBindingHash.fill(0);
        proofAttemptLineageIdentifier.fill(0);
        throw error;
    }
};

/**
 * Internal family-adapter entry. This is deliberately not a public SDK surface:
 * positive exact-family Rust inputs retain the handle synchronously in the same
 * worker, and callers receive only a non-cloneable branded operation.
 */
export const prepareClosedWorkerCommonProofGenerationFromFamilyAdapter = (
    input: ClosedWorkerCommonProofFamilyPreparationInput,
): ClosedWorkerPreparedCommonProofGeneration => {
    const record = createClosedWorkerPreparedCommonProofRecord(input);
    const prepared = Object.freeze({
        [closedWorkerPreparedCommonProofGenerationBrand]: true as const,
    });
    closedWorkerPreparedCommonProofGenerationRecords.set(prepared, record);
    return prepared;
};

/** See {@link prepareClosedWorkerCommonProofGenerationFromFamilyAdapter}. */
export const prepareClosedWorkerCommonProofVerificationFromFamilyAdapter = (
    input: ClosedWorkerCommonProofFamilyPreparationInput,
): ClosedWorkerPreparedCommonProofVerification => {
    const record = createClosedWorkerPreparedCommonProofRecord(input);
    const prepared = Object.freeze({
        [closedWorkerPreparedCommonProofVerificationBrand]: true as const,
    });
    closedWorkerPreparedCommonProofVerificationRecords.set(prepared, record);
    return prepared;
};

const requireClosedWorkerPreparedCommonProofRecord = <
    PreparedOperation extends object,
>(
    records: WeakMap<PreparedOperation, ClosedWorkerPreparedCommonProofRecord>,
    preparedOperation: PreparedOperation,
): ClosedWorkerPreparedCommonProofRecord => {
    const record = records.get(preparedOperation);
    if (record === undefined || record.consumed) {
        throw resourceFailure(
            'The closed-worker common-proof preparation is unavailable or already consumed.',
        );
    }
    return record;
};

const copyClosedWorkerPreparedCommonProofDescription = (
    record: ClosedWorkerPreparedCommonProofRecord,
): ClosedWorkerPreparedCommonProofDescription =>
    Object.freeze({
        commonProofRuntimeBindingHash:
            record.commonProofRuntimeBindingHash.slice(),
        proofAttemptLineageIdentifier:
            record.proofAttemptLineageIdentifier.slice(),
    });

export const describeClosedWorkerPreparedCommonProofGeneration = (
    preparedOperation: ClosedWorkerPreparedCommonProofGeneration,
): ClosedWorkerPreparedCommonProofDescription =>
    copyClosedWorkerPreparedCommonProofDescription(
        requireClosedWorkerPreparedCommonProofRecord(
            closedWorkerPreparedCommonProofGenerationRecords,
            preparedOperation,
        ),
    );

export const describeClosedWorkerPreparedCommonProofVerification = (
    preparedOperation: ClosedWorkerPreparedCommonProofVerification,
): ClosedWorkerPreparedCommonProofDescription =>
    copyClosedWorkerPreparedCommonProofDescription(
        requireClosedWorkerPreparedCommonProofRecord(
            closedWorkerPreparedCommonProofVerificationRecords,
            preparedOperation,
        ),
    );

const consumeClosedWorkerPreparedCommonProofRecord = <
    PreparedOperation extends object,
>(
    records: WeakMap<PreparedOperation, ClosedWorkerPreparedCommonProofRecord>,
    preparedOperation: PreparedOperation,
): ClosedWorkerPreparedCommonProofRecord => {
    const record = requireClosedWorkerPreparedCommonProofRecord(
        records,
        preparedOperation,
    );
    record.consumed = true;
    records.delete(preparedOperation);
    return record;
};

const destroyClosedWorkerPreparedCommonProofRecord = (
    record: ClosedWorkerPreparedCommonProofRecord,
): void => {
    record.commonProofRuntimeBindingHash.fill(0);
    record.proofAttemptLineageIdentifier.fill(0);
};

const discardClosedWorkerPreparedCommonProofRecord = (
    record: ClosedWorkerPreparedCommonProofRecord,
    exportName:
        | 'sealed_lattice_common_proof_discard_prepared_generation'
        | 'sealed_lattice_common_proof_discard_prepared_verification',
): void => {
    record.context.runExclusive(
        'common-proof prepared-operation discard',
        () => {
            requireKernelSuccess(
                resolveNumberExport(
                    record.context.wasmExports,
                    exportName,
                )(record.preparedOperationHandle),
                'prepared-operation discard',
            );
        },
    );
};

const releaseClosedWorkerPreparedCommonProof = <
    PreparedOperation extends object,
>(
    records: WeakMap<PreparedOperation, ClosedWorkerPreparedCommonProofRecord>,
    preparedOperation: PreparedOperation,
    exportName:
        | 'sealed_lattice_common_proof_discard_prepared_generation'
        | 'sealed_lattice_common_proof_discard_prepared_verification',
): void => {
    const record = consumeClosedWorkerPreparedCommonProofRecord(
        records,
        preparedOperation,
    );
    try {
        discardClosedWorkerPreparedCommonProofRecord(record, exportName);
    } finally {
        destroyClosedWorkerPreparedCommonProofRecord(record);
    }
};

export const releaseClosedWorkerPreparedCommonProofGeneration = (
    preparedOperation: ClosedWorkerPreparedCommonProofGeneration,
): void =>
    releaseClosedWorkerPreparedCommonProof(
        closedWorkerPreparedCommonProofGenerationRecords,
        preparedOperation,
        'sealed_lattice_common_proof_discard_prepared_generation',
    );

export const releaseClosedWorkerPreparedCommonProofVerification = (
    preparedOperation: ClosedWorkerPreparedCommonProofVerification,
): void =>
    releaseClosedWorkerPreparedCommonProof(
        closedWorkerPreparedCommonProofVerificationRecords,
        preparedOperation,
        'sealed_lattice_common_proof_discard_prepared_verification',
    );

export const runClosedWorkerPreparedCommonProofGeneration = async (
    preparedOperation: ClosedWorkerPreparedCommonProofGeneration,
    externalMemory: CommonProofExternalMemoryTransactionExecutor,
    outputStore: CommonProofCanonicalOutputStore,
    options: CommonProofGenerationWorkerOptions = {},
): Promise<void> => {
    const record = consumeClosedWorkerPreparedCommonProofRecord(
        closedWorkerPreparedCommonProofGenerationRecords,
        preparedOperation,
    );
    try {
        const capability = await runPreparedCommonProofGenerationWorker(
            record.context,
            record.preparedOperationHandle,
            externalMemory,
            outputStore,
            options,
        );
        capability.release();
    } catch (error) {
        try {
            discardClosedWorkerPreparedCommonProofRecord(
                record,
                'sealed_lattice_common_proof_discard_prepared_generation',
            );
        } catch {
            // A started prover consumed the preparation before retiring itself.
        }
        throw error;
    } finally {
        destroyClosedWorkerPreparedCommonProofRecord(record);
    }
};

export const runClosedWorkerPreparedCommonProofVerification = async (
    preparedOperation: ClosedWorkerPreparedCommonProofVerification,
    inputStore: AuthenticatedCommonProofInputStore,
    options: CommonProofVerificationWorkerOptions = {},
): Promise<VerifiedCommonProofCapability> => {
    const record = consumeClosedWorkerPreparedCommonProofRecord(
        closedWorkerPreparedCommonProofVerificationRecords,
        preparedOperation,
    );
    try {
        return await runPreparedCommonProofVerificationWorker(
            record.context,
            record.preparedOperationHandle,
            inputStore,
            options,
        );
    } catch (error) {
        try {
            discardClosedWorkerPreparedCommonProofRecord(
                record,
                'sealed_lattice_common_proof_discard_prepared_verification',
            );
        } catch {
            // A started verifier consumed the preparation before retiring itself.
        }
        throw error;
    } finally {
        destroyClosedWorkerPreparedCommonProofRecord(record);
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
): Promise<GeneratedCommonProofCapability> => {
    const kernel = new CommonProofGenerationKernelBoundary(context);
    const requestSequence = new CommonProofStorageRequestSequence();
    const committedOutputChunkByteLengths = new Map<number, number>();
    let committedOutputByteLength = 0;
    const yieldControl = options.yieldControl ?? yieldBrowserWorkerTurn;
    const checkpointCustody =
        options.checkpointCustody ?? options.resume?.checkpointCustody;
    let operationHandle: number | undefined;
    let deterministicPrefixReplayComplete = options.resume === undefined;
    let cancellationRequested = false;
    let operationTerminal = false;

    try {
        if (options.resume === undefined) {
            operationHandle = kernel.begin(preparedGenerationHandle);
        } else {
            let authenticatedCheckpointState: Uint8Array<ArrayBuffer>;
            try {
                const restoredState =
                    await options.resume.checkpointCustody.restoreAuthenticatedCheckpointState();
                if (
                    !(restoredState instanceof Uint8Array) ||
                    restoredState.byteLength === 0
                ) {
                    throw new CommonProofWorkerRuntimeError(
                        'WrongStorageResult',
                        'Authenticated checkpoint custody returned missing or malformed state.',
                    );
                }
                authenticatedCheckpointState = restoredState.slice();
            } catch (error) {
                try {
                    const unexpectedlyResumedHandle = kernel.resume(
                        preparedGenerationHandle,
                        new Uint8Array(),
                    );
                    kernel.retireFailed(unexpectedlyResumedHandle);
                } catch {
                    // The consuming resume call is expected to reject empty state.
                }
                throw storageFailure(
                    'The browser store could not restore an authenticated common-proof checkpoint.',
                    error,
                );
            }
            try {
                operationHandle = kernel.resume(
                    preparedGenerationHandle,
                    authenticatedCheckpointState,
                );
            } finally {
                authenticatedCheckpointState.fill(0);
            }
        }
        const liveOperationHandle = operationHandle;
        for (;;) {
            if (options.signal?.aborted === true && !cancellationRequested) {
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
                        const checkpoint =
                            kernel.copyCheckpoint(liveOperationHandle);
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
                        options.resume === undefined ||
                        deterministicPrefixReplayComplete
                    ) {
                        throw kernelFailure(
                            'The common-proof kernel returned an unexpected resume-complete signal.',
                        );
                    }
                    deterministicPrefixReplayComplete = true;
                    await yieldControl();
                    break;
                case 'storage-request-ready': {
                    const encodedRequest = kernel.copyStorageRequest(
                        liveOperationHandle,
                        poll.encodedRequestByteLength,
                    );
                    let encodedResponse: Uint8Array<ArrayBuffer> | undefined;
                    try {
                        const request =
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
                                if (options.resume === undefined) {
                                    throw kernelFailure(
                                        'Deterministic prefix replay has no authenticated resume source.',
                                    );
                                }
                                untrustedReadResults =
                                    await options.resume.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                                        request,
                                    );
                            }
                            readResults = snapshotReadResults(
                                request,
                                untrustedReadResults,
                            );
                        } catch (error) {
                            throw storageFailure(
                                deterministicPrefixReplayComplete
                                    ? 'The browser store could not execute the exact common-proof transaction.'
                                    : 'The browser store could not replay the exact deterministic-prefix transaction.',
                                error,
                            );
                        }
                        encodedResponse =
                            encodeCommonProofExternalMemoryResponse(
                                request,
                                readResults,
                            );
                        kernel.supplyStorageResponse(
                            liveOperationHandle,
                            encodedResponse,
                        );
                        requestSequence.commit();
                    } finally {
                        encodedRequest.fill(0);
                        encodedResponse?.fill(0);
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
                            'The common-proof kernel exposed output beyond the fixed proof-stream profile.',
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
                    if (!(storedChunk instanceof Uint8Array)) {
                        throw new CommonProofWorkerRuntimeError(
                            'WrongStorageResult',
                            'The browser store returned a common-proof output chunk with the wrong length.',
                        );
                    }
                    if (storedChunk.byteLength !== exactByteLength) {
                        storedChunk.fill(0);
                        throw new CommonProofWorkerRuntimeError(
                            'WrongStorageResult',
                            'The browser store returned a common-proof output chunk with the wrong length.',
                        );
                    }
                    const ownedReadback = storedChunk.slice();
                    try {
                        kernel.confirmOutputReadback(
                            liveOperationHandle,
                            poll.chunkIndex,
                            ownedReadback,
                        );
                    } finally {
                        ownedReadback.fill(0);
                        storedChunk.fill(0);
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
                    operationTerminal = true;
                    const capabilityHandle = kernel.finish(liveOperationHandle);
                    return createGeneratedCapability(kernel, capabilityHandle);
                }
                case 'cancelled':
                    kernel.releaseCancelled(liveOperationHandle);
                    operationTerminal = true;
                    throw new CommonProofWorkerRuntimeError(
                        'Cancelled',
                        'The common-proof generation operation was cancelled.',
                        options.signal?.reason,
                    );
            }
        }
    } catch (error) {
        if (!operationTerminal && operationHandle !== undefined) {
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
    }
};

const verificationChunkCount = (declaredByteLength: number): number => {
    if (
        !Number.isSafeInteger(declaredByteLength) ||
        declaredByteLength <= 0 ||
        declaredByteLength > maximumCommonProofByteLength
    ) {
        throw resourceFailure(
            'The committed common-proof byte length is outside the fixed worker profile.',
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
    chunkIndex: number,
): Promise<Uint8Array> => {
    const exactByteLength = verificationChunkByteLength(
        inputStore.declaredByteLength,
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
        chunkBytes.byteLength !== exactByteLength
    ) {
        throw new CommonProofWorkerRuntimeError(
            'WrongStorageResult',
            'The browser store returned a committed common-proof chunk with the wrong length.',
        );
    }
    return chunkBytes;
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

const supplyVerificationReadback = async (
    kernel: CommonProofVerificationKernelBoundary,
    operationHandle: number,
    inputStore: AuthenticatedCommonProofInputStore,
    chunkIndex: number,
    signal?: AbortSignal,
): Promise<void> => {
    const chunkBytes = await readCommittedVerificationChunk(
        inputStore,
        chunkIndex,
    );
    try {
        throwIfVerificationCancelled(signal);
        kernel.supplyReadbackChunk(operationHandle, chunkIndex, chunkBytes);
    } finally {
        chunkBytes.fill(0);
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
    const chunkCount = verificationChunkCount(inputStore.declaredByteLength);
    throwIfVerificationCancelled(options.signal);

    const kernel = new CommonProofVerificationKernelBoundary(context);
    const operationHandle = kernel.begin(preparedVerificationHandle);
    const yieldControl = options.yieldControl ?? yieldBrowserWorkerTurn;
    let operationTerminal = false;

    try {
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            throwIfVerificationCancelled(options.signal);
            const chunkBytes = await readCommittedVerificationChunk(
                inputStore,
                chunkIndex,
            );
            try {
                throwIfVerificationCancelled(options.signal);
                kernel.absorbInputChunk(
                    operationHandle,
                    chunkIndex,
                    chunkBytes,
                );
            } finally {
                chunkBytes.fill(0);
            }
            await yieldControl();
        }
        throwIfVerificationCancelled(options.signal);
        kernel.finishInput(operationHandle);

        for (;;) {
            throwIfVerificationCancelled(options.signal);
            const poll = kernel.poll(operationHandle);
            switch (poll.kind) {
                case 'needs-readback': {
                    verificationChunkByteLength(
                        inputStore.declaredByteLength,
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
                        operationHandle,
                        inputStore,
                        poll.firstChunkIndex,
                        options.signal,
                    );
                    if (poll.secondChunkIndex !== undefined) {
                        await supplyVerificationReadback(
                            kernel,
                            operationHandle,
                            inputStore,
                            poll.secondChunkIndex,
                            options.signal,
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
                    throwIfVerificationCancelled(options.signal);
                    operationTerminal = true;
                    const capabilityHandle = kernel.finish(operationHandle);
                    return createVerifiedCapability(kernel, capabilityHandle);
                }
            }
        }
    } catch (error) {
        if (!operationTerminal) {
            try {
                kernel.cancel(operationHandle);
                operationTerminal = true;
            } catch (cancellationError) {
                throw kernelFailure(
                    'The common-proof verifier failed and could not retire its operation.',
                    { cancellationError, operationError: error },
                );
            }
        }
        throw error;
    }
};
