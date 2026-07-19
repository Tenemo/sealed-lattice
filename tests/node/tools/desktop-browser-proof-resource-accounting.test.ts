import { describe, expect, it, vi } from 'vitest';

import { createDesktopBrowserProofResourceAccounting } from '#tests/support/desktop-browser-proof-resource-accounting';
import type {
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryRequest,
} from '@sealed-lattice/wasm';

type OmitOperationIndex<Operation> = Operation extends unknown
    ? Omit<Operation, 'operationIndex'>
    : never;

type CommonProofExternalMemoryOperationWithoutIndex =
    OmitOperationIndex<CommonProofExternalMemoryOperation>;

const createRequest = (
    requestSequence: bigint,
    operations: readonly CommonProofExternalMemoryOperation[],
): CommonProofExternalMemoryRequest =>
    Object.freeze({
        maximumOperationCount: 4_096,
        maximumPayloadByteLength: 1_048_576n,
        operations,
        requestDigest: new Uint8Array(64).fill(Number(requestSequence & 0xffn)),
        requestSequence,
        runtimeBindingHash: new Uint8Array(64).fill(0x91),
    });

const createOperation = (
    requestSequence: bigint,
    operation: CommonProofExternalMemoryOperationWithoutIndex,
): CommonProofExternalMemoryRequest =>
    createRequest(requestSequence, [
        Object.freeze({ ...operation, operationIndex: 0 }),
    ] as readonly CommonProofExternalMemoryOperation[]);

describe('Desktop-browser proof resource accounting', () => {
    it('tracks exact scratch residency, traffic, transactions, and returned buffers', async () => {
        const accounting = createDesktopBrowserProofResourceAccounting();
        const executeTransaction = vi.fn(
            (request: CommonProofExternalMemoryRequest) =>
                Promise.resolve(
                    request.operations[0]?.operationKind === 'read'
                        ? Object.freeze([
                              Object.freeze({
                                  bytes: new Uint8Array([1, 2, 3, 4]),
                                  objectOrdinal: 7,
                                  offset: 1n,
                                  operationIndex: 0,
                              }),
                          ])
                        : Object.freeze([]),
                ),
        );
        const tracked = accounting.wrapExternalMemoryExecutor({
            executeTransaction,
        });

        await tracked.executeTransaction(
            createOperation(0n, {
                exactByteLength: 5n,
                objectOrdinal: 7,
                operationKind: 'create',
                protection: 'secret-authenticated-encryption',
            }),
        );
        expect(accounting.externalScratchByteLength()).toBe(5);
        await tracked.executeTransaction(
            createOperation(1n, {
                bytes: new Uint8Array([11, 12, 13]),
                expectedOffset: 0n,
                objectOrdinal: 7,
                operationKind: 'append',
            }),
        );
        await tracked.executeTransaction(
            createOperation(2n, {
                bytes: new Uint8Array([14, 15]),
                expectedOffset: 3n,
                objectOrdinal: 7,
                operationKind: 'append',
            }),
        );
        await tracked.executeTransaction(
            createOperation(3n, {
                objectOrdinal: 7,
                operationKind: 'seal',
            }),
        );
        expect(accounting.externalScratchByteLength()).toBe(5);
        await expect(
            tracked.executeTransaction(
                createOperation(4n, {
                    byteLength: 4,
                    objectOrdinal: 7,
                    offset: 1n,
                    operationKind: 'read',
                }),
            ),
        ).resolves.toMatchObject([{ bytes: new Uint8Array([1, 2, 3, 4]) }]);
        await tracked.executeTransaction(
            createOperation(5n, {
                objectOrdinal: 7,
                operationKind: 'delete',
            }),
        );

        expect(accounting.externalScratchByteLength()).toBe(0);
        expect(accounting.snapshot()).toEqual({
            copiedBufferPeakByteLength: 4,
            externalScratchPeakByteLength: 5,
            externalScratchReadByteLength: 4,
            externalScratchTransactionCount: 6,
            externalScratchWriteByteLength: 5,
            fullBufferCopiedByteLength: 4,
            fullBufferCopyCount: 1,
            observedHostAllocationVolumeByteLength: 4,
        });
        expect(executeTransaction).toHaveBeenCalledTimes(6);
    });

    it('does not commit accounting state for a failed storage transaction', async () => {
        const accounting = createDesktopBrowserProofResourceAccounting();
        const tracked = accounting.wrapExternalMemoryExecutor({
            executeTransaction: () =>
                Promise.reject(new Error('Synthetic storage failure.')),
        });

        await expect(
            tracked.executeTransaction(
                createOperation(0n, {
                    exactByteLength: 1_000n,
                    objectOrdinal: 3,
                    operationKind: 'create',
                    protection: 'public-integrity',
                }),
            ),
        ).rejects.toThrow('Synthetic storage failure.');

        expect(accounting.externalScratchByteLength()).toBe(0);
        expect(accounting.snapshot()).toEqual({
            copiedBufferPeakByteLength: 0,
            externalScratchPeakByteLength: 0,
            externalScratchReadByteLength: 0,
            externalScratchTransactionCount: 0,
            externalScratchWriteByteLength: 0,
            fullBufferCopiedByteLength: 0,
            fullBufferCopyCount: 0,
            observedHostAllocationVolumeByteLength: 0,
        });
    });

    it('counts replay traffic without double-counting idempotent retained scratch', async () => {
        const accounting = createDesktopBrowserProofResourceAccounting();
        const tracked = accounting.wrapPrefixReplayExternalMemoryExecutor({
            executeDeterministicPrefixReplayTransaction: () =>
                Promise.resolve(Object.freeze([])),
        });
        const request = createOperation(0n, {
            exactByteLength: 32n,
            objectOrdinal: 11,
            operationKind: 'create',
            protection: 'public-integrity',
        });

        await tracked.executeDeterministicPrefixReplayTransaction(request);
        await tracked.executeDeterministicPrefixReplayTransaction(request);

        expect(accounting.externalScratchByteLength()).toBe(32);
        expect(accounting.snapshot()).toMatchObject({
            externalScratchPeakByteLength: 32,
            externalScratchTransactionCount: 2,
            externalScratchWriteByteLength: 0,
        });
    });

    it('rejects transaction drift and impossible object transitions before execution', async () => {
        const accounting = createDesktopBrowserProofResourceAccounting();
        const executeTransaction = vi.fn(() =>
            Promise.resolve(Object.freeze([])),
        );
        const tracked = accounting.wrapExternalMemoryExecutor({
            executeTransaction,
        });
        const create = createOperation(0n, {
            exactByteLength: 3n,
            objectOrdinal: 19,
            operationKind: 'create',
            protection: 'public-integrity',
        });

        await tracked.executeTransaction(create);
        await expect(
            tracked.executeTransaction(
                createOperation(1n, {
                    objectOrdinal: 19,
                    operationKind: 'seal',
                }),
            ),
        ).rejects.toThrow(/invalid object sealing/u);
        await expect(
            tracked.executeTransaction({
                ...create,
                requestDigest: new Uint8Array(64).fill(0x7a),
            }),
        ).rejects.toThrow(/changed its request digest/u);

        expect(executeTransaction).toHaveBeenCalledOnce();
        expect(accounting.externalScratchByteLength()).toBe(3);
        expect(accounting.snapshot()).toMatchObject({
            externalScratchPeakByteLength: 3,
            externalScratchTransactionCount: 1,
            externalScratchWriteByteLength: 0,
        });
    });

    it('accounts complete output and authenticated-input buffer boundaries', async () => {
        const accounting = createDesktopBrowserProofResourceAccounting();
        const commitChunk = vi.fn(() => Promise.resolve());
        const outputStore = accounting.wrapCanonicalOutputStore({
            commitChunk,
            readChunk: () => Promise.resolve(new Uint8Array(5).fill(0x32)),
        });
        const inputStore = accounting.wrapAuthenticatedInputStore({
            declaredByteLength: 4,
            readCommittedChunk: () =>
                Promise.resolve(new Uint8Array(4).fill(0x61)),
        });

        await outputStore.commitChunk(0, new Uint8Array(5).fill(0x21));
        await expect(outputStore.readChunk(0, 5)).resolves.toHaveLength(5);
        await expect(inputStore.readCommittedChunk(0, 4)).resolves.toHaveLength(
            4,
        );
        accounting.observeHostAllocation(3);
        accounting.observeFullBufferCopy(2);

        expect(commitChunk).toHaveBeenCalledOnce();
        expect(accounting.snapshot()).toEqual({
            copiedBufferPeakByteLength: 5,
            externalScratchPeakByteLength: 0,
            externalScratchReadByteLength: 0,
            externalScratchTransactionCount: 0,
            externalScratchWriteByteLength: 0,
            fullBufferCopiedByteLength: 16,
            fullBufferCopyCount: 4,
            observedHostAllocationVolumeByteLength: 19,
        });
    });

    it('rejects zero-length and unsafe manual observations', () => {
        const accounting = createDesktopBrowserProofResourceAccounting();

        expect(() => accounting.observeFullBufferCopy(0)).toThrow(
            'Full-buffer copy byte length must be positive.',
        );
        expect(() => accounting.observeHostAllocation(-1)).toThrow(
            'Observed host allocation byte length must be a nonnegative safe integer.',
        );
        expect(() =>
            accounting.observeHostAllocation(Number.MAX_SAFE_INTEGER),
        ).not.toThrow();
        expect(() => accounting.observeHostAllocation(1)).toThrow(
            'Observed host allocation volume exceeds the safe-integer range.',
        );
    });
});
