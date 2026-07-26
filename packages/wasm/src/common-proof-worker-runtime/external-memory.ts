import { shake256 } from '@noble/hashes/sha3.js';
import { foundationProfile } from '@sealed-lattice/types';

import { byteArraysEqual } from '../byte-array.js';

const hashByteLength = 64;
export const maximumWorkerOperationCount = 4_096;
export const maximumWorkerPayloadByteLength = BigInt(
    foundationProfile.streamChunkByteLength,
);
const maximumExternalMemoryAppendByteLength = Number(
    maximumWorkerPayloadByteLength,
);
const operationHeaderByteLength = 32;
const readResultHeaderByteLength = 88;
export const requestHeaderByteLength = 156;
const responseHeaderByteLength = 80;
export const maximumEncodedRequestByteLength =
    requestHeaderByteLength +
    maximumWorkerOperationCount * operationHeaderByteLength +
    Number(maximumWorkerPayloadByteLength);
const schemaVersion = 1;
const requestMessageKind = 1;
const responseMessageKind = 2;
const externalMemoryOperationCodes = Object.freeze({
    create: 1,
    append: 2,
    seal: 3,
    read: 4,
    delete: 5,
} as const);
const externalMemoryProtectionCodes = Object.freeze({
    none: 0,
    publicIntegrity: 1,
    secretAuthenticatedEncryption: 2,
} as const);
const requestDigestDomain =
    'sealed-lattice/common-proof/external-memory-request/v1';
const readDigestDomain = 'sealed-lattice/common-proof/external-memory-read/v1';
const hashPreimagePrefix = new TextEncoder().encode('sealed.vote/hash512');
const textEncoder = new TextEncoder();

export type CommonProofDiscardExportName =
    | 'sealed_lattice_common_proof_discard_generation_family_adapter'
    | 'sealed_lattice_common_proof_discard_prepared_generation'
    | 'sealed_lattice_common_proof_discard_prepared_verification'
    | 'sealed_lattice_common_proof_discard_verification_family_adapter';

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

const ownedRequestBytes = new WeakMap<
    CommonProofExternalMemoryRequest,
    Uint8Array<ArrayBuffer>
>();

const destroyOwnedArrayBuffer = (bytes: Uint8Array): void => {
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

export const clearCommonProofExternalMemoryRequest = (
    request: CommonProofExternalMemoryRequest,
): void => {
    const bytes = ownedRequestBytes.get(request);
    if (bytes !== undefined) {
        destroyOwnedArrayBuffer(bytes);
        ownedRequestBytes.delete(request);
    }
    request.requestDigest.fill(0);
    request.runtimeBindingHash.fill(0);
};

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

class BoundedMessageReader {
    readonly #bytes: Uint8Array<ArrayBuffer>;
    #offset = 0;

    public constructor(bytes: Uint8Array<ArrayBuffer>) {
        this.#bytes = bytes;
    }

    public bytes(byteLength: number): Uint8Array<ArrayBuffer> {
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
        case externalMemoryOperationCodes.create: {
            if (
                position !== 0n ||
                payloadByteLength === 0n ||
                (protectionCode !==
                    externalMemoryProtectionCodes.publicIntegrity &&
                    protectionCode !==
                        externalMemoryProtectionCodes.secretAuthenticatedEncryption)
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
                    protectionCode ===
                    externalMemoryProtectionCodes.publicIntegrity
                        ? 'public-integrity'
                        : 'secret-authenticated-encryption',
            });
        }
        case externalMemoryOperationCodes.append: {
            if (
                protectionCode !== externalMemoryProtectionCodes.none ||
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
        case externalMemoryOperationCodes.seal: {
            if (
                protectionCode !== externalMemoryProtectionCodes.none ||
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
        case externalMemoryOperationCodes.read: {
            if (
                protectionCode !== externalMemoryProtectionCodes.none ||
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
        case externalMemoryOperationCodes.delete: {
            if (
                protectionCode !== externalMemoryProtectionCodes.none ||
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
            'The common-proof storage request length exceeds the absolute worker safety bound.',
        );
    }
    const exactOwnedView =
        encodedRequest.buffer instanceof ArrayBuffer &&
        encodedRequest.byteOffset === 0 &&
        encodedRequest.byteLength === encodedRequest.buffer.byteLength
            ? (encodedRequest as Uint8Array<ArrayBuffer>)
            : encodedRequest.slice();
    const exactOwnedBuffer: ArrayBuffer = structuredClone(
        exactOwnedView.buffer,
        { transfer: [exactOwnedView.buffer] },
    );
    const ownedEncodedRequest = new Uint8Array(exactOwnedBuffer);
    try {
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
                'The common-proof storage request exceeds the absolute worker safety bound.',
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
                transactionPayloadByteLength += BigInt(
                    operation.bytes.byteLength,
                );
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
        try {
            if (
                !byteArraysEqual(suppliedRequestDigest, expectedRequestDigest)
            ) {
                throw new CommonProofWorkerRuntimeError(
                    'WrongRequestDigest',
                    'The common-proof storage request digest does not bind its exact operation list.',
                );
            }
        } finally {
            expectedRequestDigest.fill(0);
        }
        const request = Object.freeze({
            maximumOperationCount,
            maximumPayloadByteLength,
            operations: Object.freeze(operations),
            requestDigest: suppliedRequestDigest,
            requestSequence,
            runtimeBindingHash,
        });
        ownedRequestBytes.set(request, ownedEncodedRequest);
        return request;
    } catch (error) {
        destroyOwnedArrayBuffer(ownedEncodedRequest);
        throw error;
    }
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
        destroyOwnedArrayBuffer(result.bytes);
    }
};

const encodeStorageResponse = (
    request: CommonProofExternalMemoryRequest,
    readResults: readonly CommonProofExternalMemoryReadResult[],
    reusableResponseBuffer?: Uint8Array<ArrayBuffer>,
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
    if (
        reusableResponseBuffer !== undefined &&
        reusableResponseBuffer.byteLength < responseByteLength
    ) {
        throw new CommonProofWorkerRuntimeError(
            'ResourceLimit',
            'The reusable common-proof response buffer is too small.',
        );
    }
    const response =
        reusableResponseBuffer === undefined
            ? new Uint8Array(responseByteLength)
            : reusableResponseBuffer.subarray(0, responseByteLength);
    response.fill(0);
    const view = new DataView(
        response.buffer,
        response.byteOffset,
        response.byteLength,
    );
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
        clearCommonProofExternalMemoryRequest(request);
    }
};

/**
 * Encodes one response into caller-owned bounded storage. The returned view is
 * valid until the caller reuses that buffer; read results and request bytes
 * are cleared with the same semantics as the allocating encoder.
 */
export const encodeCommonProofExternalMemoryResponseInto = (
    request: CommonProofExternalMemoryRequest,
    readResults: readonly CommonProofExternalMemoryReadResult[],
    reusableResponseBuffer: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> => {
    try {
        return encodeStorageResponse(
            request,
            readResults,
            reusableResponseBuffer,
        );
    } catch (error) {
        reusableResponseBuffer.fill(0);
        throw error;
    } finally {
        clearReadResults(readResults);
        clearCommonProofExternalMemoryRequest(request);
    }
};
