import { describe, expect, it } from 'vitest';

import {
    CommonProofWorkerRuntimeError,
    decodeCommonProofExternalMemoryRequest,
    encodeCommonProofExternalMemoryResponse,
} from '../../../src/common-proof-worker-runtime.js';

import {
    encodeRequest,
    fourByteReadRequest,
    readResult,
    requestDigestOffset,
    runtimeBinding,
} from './wire-fixtures.js';

describe('common-proof external-memory runtime', () => {
    it('decodes every assigned Rust operation and protection code', () => {
        const runtimeBindingHash = runtimeBinding(0x30);
        const assignedOperations = [
            {
                expectedOperationKind: 'create',
                expectedProtection: 'public-integrity',
                operation: {
                    kind: 1,
                    objectOrdinal: 1,
                    payloadByteLength: 8n,
                    position: 0n,
                    protection: 1,
                },
            },
            {
                expectedOperationKind: 'create',
                expectedProtection: 'secret-authenticated-encryption',
                operation: {
                    kind: 1,
                    objectOrdinal: 2,
                    payloadByteLength: 8n,
                    position: 0n,
                    protection: 2,
                },
            },
            {
                expectedOperationKind: 'append',
                operation: {
                    kind: 2,
                    objectOrdinal: 3,
                    payload: Uint8Array.from([1, 2, 3, 4]),
                    payloadByteLength: 4n,
                    position: 0n,
                    protection: 0,
                },
            },
            {
                expectedOperationKind: 'seal',
                operation: {
                    kind: 3,
                    objectOrdinal: 4,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            },
            {
                expectedOperationKind: 'read',
                operation: {
                    kind: 4,
                    objectOrdinal: 5,
                    payloadByteLength: 4n,
                    position: 6n,
                    protection: 0,
                },
            },
            {
                expectedOperationKind: 'delete',
                operation: {
                    kind: 5,
                    objectOrdinal: 6,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            },
        ] as const;

        for (const [
            operationIndex,
            assignedOperation,
        ] of assignedOperations.entries()) {
            const request = encodeRequest({
                maximumPayloadByteLength: 8n,
                operations: [assignedOperation.operation],
                requestSequence: BigInt(operationIndex + 1),
                runtimeBindingHash,
            });
            const decodedOperation =
                decodeCommonProofExternalMemoryRequest(request).operations[0];
            expect(decodedOperation?.operationKind).toBe(
                assignedOperation.expectedOperationKind,
            );
            const decodedProtection =
                decodedOperation?.operationKind === 'create'
                    ? decodedOperation.protection
                    : undefined;
            const expectedProtection =
                'expectedProtection' in assignedOperation
                    ? assignedOperation.expectedProtection
                    : undefined;
            expect(decodedProtection).toBe(expectedProtection);
        }
    });

    it('decodes exact single-operation Rust storage transactions', () => {
        const binding = runtimeBinding(0x31);
        const appendBytes = Uint8Array.from([9, 8, 7, 6]);
        const request = encodeRequest({
            maximumPayloadByteLength: 4n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 7,
                    payload: appendBytes,
                    payloadByteLength: 4n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        const decoded = decodeCommonProofExternalMemoryRequest(request);
        expect(decoded.requestSequence).toBe(1n);
        expect(decoded.maximumPayloadByteLength).toBe(4n);
        expect(decoded.operations).toHaveLength(1);
        const append = decoded.operations[0];
        expect(append?.operationKind).toBe('append');
        if (append?.operationKind !== 'append') {
            throw new Error('The append operation was not decoded.');
        }
        expect([...append.bytes]).toEqual([...appendBytes]);
        expect(append.bytes.buffer).not.toBe(request.buffer);

        const readRequest = decodeCommonProofExternalMemoryRequest(
            fourByteReadRequest(binding, 2n),
        );
        const transferredRead = Uint8Array.from([9, 8, 7, 6]);
        const response = encodeCommonProofExternalMemoryResponse(readRequest, [
            {
                bytes: transferredRead,
                objectOrdinal: 7,
                offset: 3n,
                operationIndex: 0,
            },
        ]);
        expect([...transferredRead]).toEqual([0, 0, 0, 0]);
        const responseView = new DataView(response.buffer);
        expect(responseView.getUint16(0, true)).toBe(1);
        expect(responseView.getUint16(2, true)).toBe(2);
        expect(responseView.getBigUint64(4, true)).toBe(2n);
        expect(responseView.getUint32(76, true)).toBe(1);
        expect(response.byteLength).toBe(80 + 88 + 4);
    });

    it('rejects truncation, trailing bytes, wrong digests, and noncanonical operation order', () => {
        const binding = runtimeBinding(0x32);
        const request = fourByteReadRequest(binding, 1n);
        expect(() =>
            decodeCommonProofExternalMemoryRequest(request.slice(0, -1)),
        ).toThrow(CommonProofWorkerRuntimeError);

        const trailing = new Uint8Array(request.byteLength + 1);
        trailing.set(request);
        expect(() => decodeCommonProofExternalMemoryRequest(trailing)).toThrow(
            CommonProofWorkerRuntimeError,
        );

        const wrongDigest = request.slice();
        wrongDigest[requestDigestOffset] ^= 1;
        expect(() =>
            decodeCommonProofExternalMemoryRequest(wrongDigest),
        ).toThrowError(expect.objectContaining({ code: 'WrongRequestDigest' }));

        const reordered = encodeRequest({
            maximumPayloadByteLength: 4n,
            operations: [
                {
                    encodedOrdinal: 1,
                    kind: 4,
                    objectOrdinal: 7,
                    payloadByteLength: 4n,
                    position: 3n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        expect(() =>
            decodeCommonProofExternalMemoryRequest(reordered),
        ).toThrowError(expect.objectContaining({ code: 'MalformedRequest' }));

        const mixedRequest = encodeRequest({
            maximumPayloadByteLength: 1n,
            operations: [
                {
                    kind: 1,
                    objectOrdinal: 3,
                    payloadByteLength: 1n,
                    position: 0n,
                    protection: 1,
                },
                {
                    kind: 3,
                    objectOrdinal: 3,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 2n,
            runtimeBindingHash: binding,
        });
        expect(() =>
            decodeCommonProofExternalMemoryRequest(mixedRequest),
        ).toThrowError(expect.objectContaining({ code: 'MalformedRequest' }));

        const deleteRequest = encodeRequest({
            maximumPayloadByteLength: 1n,
            operations: [
                {
                    kind: 5,
                    objectOrdinal: 3,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
                {
                    kind: 5,
                    objectOrdinal: 4,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 3n,
            runtimeBindingHash: binding,
        });
        expect(
            decodeCommonProofExternalMemoryRequest(deleteRequest).operations,
        ).toHaveLength(2);
    });

    it('rejects substituted single-read storage results', () => {
        const binding = runtimeBinding(0x35);
        const request = encodeRequest({
            maximumPayloadByteLength: 4n,
            operations: [
                {
                    kind: 4,
                    objectOrdinal: 4,
                    payloadByteLength: 4n,
                    position: 10n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        const substitutedResults = [readResult(0, 4, 11n, [4, 4, 4, 4])];
        const decodedRequest = decodeCommonProofExternalMemoryRequest(request);
        expect(() =>
            encodeCommonProofExternalMemoryResponse(
                decodedRequest,
                substitutedResults,
            ),
        ).toThrowError(expect.objectContaining({ code: 'WrongStorageResult' }));
        expect(
            encodeCommonProofExternalMemoryResponse(decodedRequest, [
                readResult(0, 4, 10n, [4, 4, 4, 4]),
            ]),
        ).toBeInstanceOf(Uint8Array);
    });

    it('owns the exact request view independently of its backing buffer', () => {
        const binding = runtimeBinding(0x36);
        const request = fourByteReadRequest(binding, 1n);
        const oversizedBackingBuffer = new Uint8Array(
            request.byteLength + 2_000_000,
        );
        const requestOffset = 17;
        oversizedBackingBuffer.set(request, requestOffset);
        const exactRequestView = oversizedBackingBuffer.subarray(
            requestOffset,
            requestOffset + request.byteLength,
        );
        const decodedView =
            decodeCommonProofExternalMemoryRequest(exactRequestView);
        exactRequestView.fill(0);
        expect(decodedView.requestSequence).toBe(1n);
        expect([...decodedView.runtimeBindingHash]).toEqual([...binding]);
        expect(decodedView.operations).toHaveLength(1);

        const appendPayload = new Uint8Array(49_152).fill(0x5a);
        const maximumRequest = encodeRequest({
            maximumPayloadByteLength: 49_152n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 9,
                    payload: appendPayload,
                    payloadByteLength: 49_152n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: runtimeBinding(0x37),
        });
        const decoded = decodeCommonProofExternalMemoryRequest(maximumRequest);
        const appendOperation = decoded.operations[0];
        expect(appendOperation?.operationKind).toBe('append');
        if (appendOperation?.operationKind !== 'append') {
            throw new Error('The maximum append operation was not decoded.');
        }
        expect(appendOperation.bytes.byteLength).toBe(49_152);
        expect(appendOperation.bytes.buffer).not.toBe(maximumRequest.buffer);
        maximumRequest.fill(0);
        expect(appendOperation.bytes[0]).toBe(0x5a);
        expect(appendOperation.bytes[appendOperation.bytes.length - 1]).toBe(
            0x5a,
        );

        const overlongAppendPayload = new Uint8Array(49_153).fill(0x6b);
        const overlongAppendRequest = encodeRequest({
            maximumPayloadByteLength: 49_153n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 9,
                    payload: overlongAppendPayload,
                    payloadByteLength: 49_153n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 2n,
            runtimeBindingHash: runtimeBinding(0x37),
        });
        expect(() =>
            decodeCommonProofExternalMemoryRequest(overlongAppendRequest),
        ).toThrowError(expect.objectContaining({ code: 'MalformedRequest' }));
    });
});
