import { describe, expect, it, vi } from 'vitest';

import type {
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryRequest,
} from '../../src/index.js';
import {
    createSelectedProofRuntimeEvidenceAccounting,
    summarizeCanonicalBytes,
} from '../support/selected-proof-runtime-evidence-accounting.js';

const selectedSuiteIdentifier = '91'.repeat(64);
const processedWasmSha256Hex = '42'.repeat(32);

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
        runtimeBindingHash: new Uint8Array(64).fill(0xa3),
    });

const operation = <
    Operation extends Omit<
        CommonProofExternalMemoryOperation,
        'operationIndex'
    >,
>(
    operationIndex: number,
    value: Operation,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        ...value,
        operationIndex,
    }) as CommonProofExternalMemoryOperation;

const createAccounting = () =>
    createSelectedProofRuntimeEvidenceAccounting({
        caseIdentifier: 'vss-share-linkage-generation-fresh',
        executionKind: 'fresh-generation',
        runOrdinal: 1,
        suiteId: selectedSuiteIdentifier,
        wasmLinearMemoryByteLength: () => 65_536,
        wasmSha256Hex: processedWasmSha256Hex,
    });

describe('Selected proof runtime evidence accounting', () => {
    it('measures production-resident scratch records and exact boundary traffic', async () => {
        const accounting = createAccounting();
        const executeTransaction = vi.fn(
            (request: CommonProofExternalMemoryRequest) =>
                Promise.resolve(
                    request.operations.some(
                        ({ operationKind }) => operationKind === 'read',
                    )
                        ? Object.freeze([
                              Object.freeze({
                                  bytes: new Uint8Array([21, 22, 23, 24]),
                                  objectOrdinal: 7,
                                  offset: 1n,
                                  operationIndex: 0,
                              }),
                          ])
                        : Object.freeze([]),
                ),
        );
        const externalMemory = accounting.wrapExternalMemory({
            executeTransaction,
        });

        await externalMemory.executeTransaction(
            createRequest(0n, [
                operation(0, {
                    exactByteLength: 5n,
                    objectOrdinal: 7,
                    operationKind: 'create',
                    protection: 'secret-authenticated-encryption',
                }),
            ]),
        );
        await externalMemory.executeTransaction(
            createRequest(1n, [
                operation(0, {
                    bytes: new Uint8Array([11, 12, 13]),
                    expectedOffset: 0n,
                    objectOrdinal: 7,
                    operationKind: 'append',
                }),
            ]),
        );
        await externalMemory.executeTransaction(
            createRequest(2n, [
                operation(0, {
                    bytes: new Uint8Array([14, 15]),
                    expectedOffset: 3n,
                    objectOrdinal: 7,
                    operationKind: 'append',
                }),
                operation(1, {
                    objectOrdinal: 7,
                    operationKind: 'seal',
                }),
            ]),
        );
        await externalMemory.executeTransaction(
            createRequest(3n, [
                operation(0, {
                    byteLength: 4,
                    objectOrdinal: 7,
                    offset: 1n,
                    operationKind: 'read',
                }),
            ]),
        );
        await externalMemory.executeTransaction(
            createRequest(4n, [
                operation(0, {
                    objectOrdinal: 7,
                    operationKind: 'delete',
                }),
            ]),
        );

        const canonicalInput = summarizeCanonicalBytes(
            new Uint8Array([0x31, 0x32]),
        );
        const canonicalOutput = summarizeCanonicalBytes(new Uint8Array([0x41]));
        const measurement = accounting.finish({
            canonicalInput,
            canonicalOutput,
        });

        expect(measurement).toMatchObject({
            canonicalInputByteLength: 2,
            canonicalInputSha512Hex: canonicalInput.sha512Hex,
            canonicalOutputByteLength: 1,
            copiedBufferPeakByteLength: 4,
            externalScratchPeakByteLength: 14,
            externalScratchReadByteLength: 4,
            externalScratchTransactionCount: 5,
            externalScratchWriteByteLength: 5,
            fullBufferCopiedByteLength: 9,
            fullBufferCopyCount: 3,
            observedHostAllocationVolumeByteLength: 9,
            outputSha512Hex: canonicalOutput.sha512Hex,
            retainedResidentPeakByteLength: 4,
        });
        expect(executeTransaction).toHaveBeenCalledTimes(5);
    });

    it('hashes the exact ordered canonical output and rejects post-finalization writes', async () => {
        const accounting = createAccounting();
        const commitChunk = vi.fn(() => Promise.resolve());
        const readChunk = vi.fn(() =>
            Promise.resolve(new Uint8Array([7, 8, 9])),
        );
        const measuredOutput = accounting.wrapOutputStore({
            commitChunk,
            readChunk,
        });

        await measuredOutput.store.commitChunk(0, new Uint8Array([1, 2]));
        await measuredOutput.store.commitChunk(1, new Uint8Array([3, 4, 5]));
        const summary = measuredOutput.canonicalOutputSummary();

        expect(summary).toEqual(
            summarizeCanonicalBytes(new Uint8Array([1, 2, 3, 4, 5])),
        );
        await expect(
            measuredOutput.store.commitChunk(2, new Uint8Array([6])),
        ).rejects.toThrow(/finalized/u);
        await expect(measuredOutput.store.readChunk(0, 3)).resolves.toEqual(
            new Uint8Array([7, 8, 9]),
        );
        expect(commitChunk).toHaveBeenCalledTimes(2);
        expect(readChunk).toHaveBeenCalledWith(0, 3);
    });

    it('accounts authenticated proof input reads without copying the full proof', async () => {
        const accounting = createAccounting();
        const readCommittedChunk = vi.fn(() =>
            Promise.resolve(new Uint8Array([0x51, 0x52, 0x53, 0x54])),
        );
        const inputStore = accounting.wrapInputStore({
            declaredByteLength: 4,
            readCommittedChunk,
        });

        await expect(inputStore.readCommittedChunk(0, 4)).resolves.toEqual(
            new Uint8Array([0x51, 0x52, 0x53, 0x54]),
        );
        const emptyOutput = accounting.emptyCanonicalByteSummary();
        const measurement = accounting.finish({
            canonicalInput: summarizeCanonicalBytes(
                new Uint8Array([0x51, 0x52, 0x53, 0x54]),
            ),
            canonicalOutput: emptyOutput,
        });

        expect(measurement).toMatchObject({
            canonicalOutputByteLength: 0,
            copiedBufferPeakByteLength: 4,
            fullBufferCopiedByteLength: 4,
            fullBufferCopyCount: 1,
            observedHostAllocationVolumeByteLength: 4,
            outputSha512Hex: emptyOutput.sha512Hex,
        });
        expect(readCommittedChunk).toHaveBeenCalledWith(0, 4);
    });

    it('applies resumed prefix-replay operations to the same resident scratch model', async () => {
        const accounting = createAccounting();
        const executeDeterministicPrefixReplayTransaction = vi.fn(() =>
            Promise.resolve(Object.freeze([])),
        );
        const prefixReplay = accounting.wrapPrefixReplayExternalMemory({
            executeDeterministicPrefixReplayTransaction,
        });

        await prefixReplay.executeDeterministicPrefixReplayTransaction(
            createRequest(0n, [
                operation(0, {
                    exactByteLength: 3n,
                    objectOrdinal: 13,
                    operationKind: 'create',
                    protection: 'public-integrity',
                }),
                operation(1, {
                    bytes: new Uint8Array([1, 2, 3]),
                    expectedOffset: 0n,
                    objectOrdinal: 13,
                    operationKind: 'append',
                }),
                operation(2, {
                    objectOrdinal: 13,
                    operationKind: 'seal',
                }),
            ]),
        );

        const measurement = accounting.finish({
            canonicalInput: summarizeCanonicalBytes(new Uint8Array([0x61])),
            canonicalOutput: summarizeCanonicalBytes(new Uint8Array([0x62])),
        });
        expect(measurement).toMatchObject({
            externalScratchPeakByteLength: 12,
            externalScratchTransactionCount: 1,
            externalScratchWriteByteLength: 3,
        });
        expect(
            executeDeterministicPrefixReplayTransaction,
        ).toHaveBeenCalledOnce();
    });

    it('does not mutate measured scratch after a failed custody transaction', async () => {
        const accounting = createAccounting();
        const externalMemory = accounting.wrapExternalMemory({
            executeTransaction: () =>
                Promise.reject(new Error('Synthetic custody failure.')),
        });

        await expect(
            externalMemory.executeTransaction(
                createRequest(0n, [
                    operation(0, {
                        exactByteLength: 500n,
                        objectOrdinal: 2,
                        operationKind: 'create',
                        protection: 'public-integrity',
                    }),
                ]),
            ),
        ).rejects.toThrow('Synthetic custody failure.');

        const measurement = accounting.finish({
            canonicalInput: summarizeCanonicalBytes(new Uint8Array([0x71])),
            canonicalOutput: summarizeCanonicalBytes(new Uint8Array([0x72])),
        });
        expect(measurement).toMatchObject({
            externalScratchPeakByteLength: 0,
            externalScratchReadByteLength: 0,
            externalScratchTransactionCount: 1,
            externalScratchWriteByteLength: 0,
        });
    });
});
