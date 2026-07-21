import { webcrypto } from 'node:crypto';

import { shake256 } from '@noble/hashes/sha3.js';
import { expect } from 'vitest';

import type { CommonProofExternalMemoryReadResult } from '../../../src/common-proof-worker-runtime.js';

import { commonProofApplicationHandoffLogicalRecordKey } from '#packages/protocol/src/runtime/common-proof-browser-custody';

export const hashByteLength = 64;
export const cryptoProvider = webcrypto as unknown as Crypto;
const requestHeaderByteLength = 156;
export const requestDigestOffset = 92;
const operationHeaderByteLength = 32;
const hashPrefix = new TextEncoder().encode('sealed.vote/hash512');
const requestDigestDomain =
    'sealed-lattice/common-proof/external-memory-request/v1';
export const applicationHandoffIndexKeySuffix = Array.from(
    new TextEncoder().encode(commonProofApplicationHandoffLogicalRecordKey),
    (byte) => byte.toString(16).padStart(2, '0'),
).join('');

export const consumesCommonProofApplicationHandoff = (mutation: {
    deletes: readonly string[];
}): boolean =>
    mutation.deletes.some((key) =>
        key.endsWith(applicationHandoffIndexKeySuffix),
    );

type EncodedOperation = Readonly<{
    encodedOrdinal?: number;
    kind: number;
    objectOrdinal: number;
    payload?: Uint8Array;
    payloadByteLength: bigint;
    position: bigint;
    protection: number;
}>;

const varuint = (input: bigint): Uint8Array => {
    const output: number[] = [];
    let remaining = input;
    do {
        let byte = Number(remaining & 0x7fn);
        remaining >>= 7n;
        if (remaining !== 0n) {
            byte |= 0x80;
        }
        output.push(byte);
    } while (remaining !== 0n);
    return Uint8Array.from(output);
};

const hashFramedParts = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => {
    const hash = shake256.create({ dkLen: hashByteLength });
    const domainBytes = new TextEncoder().encode(domain);
    hash.update(hashPrefix);
    hash.update(varuint(BigInt(domainBytes.byteLength)));
    hash.update(domainBytes);
    hash.update(varuint(BigInt(parts.length)));
    for (const part of parts) {
        hash.update(varuint(BigInt(part.byteLength)));
        hash.update(part);
    }
    return hash.digest();
};

const littleEndianBytes = (
    byteLength: 2 | 4 | 8,
    value: number | bigint,
): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    const view = new DataView(bytes.buffer);
    if (byteLength === 2) {
        view.setUint16(0, Number(value), true);
    } else if (byteLength === 4) {
        view.setUint32(0, Number(value), true);
    } else {
        view.setBigUint64(0, BigInt(value), true);
    }
    return bytes;
};

const encodeOperations = (
    operations: readonly EncodedOperation[],
): Uint8Array => {
    const byteLength = operations.reduce(
        (total, operation) =>
            total +
            operationHeaderByteLength +
            (operation.payload?.byteLength ?? 0),
        0,
    );
    const bytes = new Uint8Array(byteLength);
    const view = new DataView(bytes.buffer);
    let offset = 0;
    for (const [operationIndex, operation] of operations.entries()) {
        view.setUint32(
            offset,
            operation.encodedOrdinal ?? operationIndex,
            true,
        );
        offset += 4;
        view.setUint16(offset, operation.kind, true);
        offset += 2;
        view.setUint16(offset, operation.protection, true);
        offset += 2;
        view.setUint32(offset, operation.objectOrdinal, true);
        offset += 4;
        view.setUint32(offset, 0, true);
        offset += 4;
        view.setBigUint64(offset, operation.position, true);
        offset += 8;
        view.setBigUint64(offset, operation.payloadByteLength, true);
        offset += 8;
        if (operation.payload !== undefined) {
            bytes.set(operation.payload, offset);
            offset += operation.payload.byteLength;
        }
    }
    expect(offset).toBe(bytes.byteLength);
    return bytes;
};

export const encodeRequest = (input: {
    maximumOperationCount?: number;
    maximumPayloadByteLength: bigint;
    operations: readonly EncodedOperation[];
    requestSequence: bigint;
    runtimeBindingHash: Uint8Array;
}): Uint8Array<ArrayBuffer> => {
    const maximumOperationCount =
        input.maximumOperationCount ?? input.operations.length;
    const operationBytes = encodeOperations(input.operations);
    const digest = hashFramedParts(requestDigestDomain, [
        littleEndianBytes(2, 1),
        input.runtimeBindingHash,
        littleEndianBytes(8, input.requestSequence),
        littleEndianBytes(8, input.maximumPayloadByteLength),
        littleEndianBytes(4, maximumOperationCount),
        littleEndianBytes(4, input.operations.length),
        operationBytes,
    ]);
    const request = new Uint8Array(
        requestHeaderByteLength + operationBytes.byteLength,
    );
    const view = new DataView(request.buffer);
    let offset = 0;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setBigUint64(offset, input.maximumPayloadByteLength, true);
    offset += 8;
    view.setUint32(offset, maximumOperationCount, true);
    offset += 4;
    view.setUint32(offset, input.operations.length, true);
    offset += 4;
    view.setBigUint64(offset, input.requestSequence, true);
    offset += 8;
    request.set(input.runtimeBindingHash, offset);
    offset += hashByteLength;
    request.set(digest, offset);
    offset += hashByteLength;
    request.set(operationBytes, offset);
    return request;
};

export const runtimeBinding = (byte: number): Uint8Array<ArrayBuffer> =>
    new Uint8Array(hashByteLength).fill(byte);
export const installedCommonProofVerificationBindingHash = runtimeBinding(0x6b);
export const installedProofAttemptLineageIdentifier = new Uint8Array(32).fill(
    0x7c,
);

export const fourByteReadRequest = (
    binding: Uint8Array,
    requestSequence: bigint,
): Uint8Array<ArrayBuffer> =>
    encodeRequest({
        maximumPayloadByteLength: 4n,
        operations: [
            {
                kind: 4,
                objectOrdinal: 7,
                payloadByteLength: 4n,
                position: 3n,
                protection: 0,
            },
        ],
        requestSequence,
        runtimeBindingHash: binding,
    });

export const readResult = (
    operationIndex: number,
    objectOrdinal: number,
    offset: bigint,
    bytes: number[],
): CommonProofExternalMemoryReadResult => ({
    bytes: Uint8Array.from(bytes),
    objectOrdinal,
    offset,
    operationIndex,
});
