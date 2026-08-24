import { describe, expect, it, vi } from 'vitest';

import type {
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryRequest,
    CommonProofGenerationExternalMemoryAccounting,
} from '../../src/index.js';
import {
    createSelectedProofRuntimeEvidenceAccounting,
    summarizeCanonicalBytes,
} from '../support/selected-proof-runtime-evidence-accounting.js';

import type { CommonProofBrowserCustodyPhysicalAccountingSnapshot } from '#packages/protocol/src/runtime/common-proof-browser-custody';

const selectedSuiteIdentifier = '91'.repeat(64);
const processedWasmSha256Hex = '42'.repeat(32);

type TerminalUsage = Readonly<{
    deletedObjectLifecycleCount: number;
    openCiphertextByteLength?: number;
    peakStoredByteLength: number;
    prefixReplay?: boolean;
    readByteLength: number;
    sealPlaintextByteLength?: number;
    transactionCount: number;
    writtenByteLength: number;
}>;

const terminalAccounting = (
    usage: TerminalUsage,
): CommonProofGenerationExternalMemoryAccounting => {
    const openCiphertextByteLength = usage.openCiphertextByteLength ?? 0;
    const sealPlaintextByteLength = usage.sealPlaintextByteLength ?? 0;
    const bufferClaimCount = usage.transactionCount === 0 ? 0n : 1n;
    const bufferClaimByteLength =
        usage.transactionCount === 0
            ? 0n
            : BigInt(
                  Math.max(1, usage.readByteLength, usage.writtenByteLength),
              );
    const actualUsage = Object.freeze({
        deletedObjectLifecycleCount: BigInt(usage.deletedObjectLifecycleCount),
        peakStoredByteLength: BigInt(usage.peakStoredByteLength),
        totalReadByteLength: BigInt(usage.readByteLength),
        totalWrittenByteLength: BigInt(usage.writtenByteLength),
        transactionCount: BigInt(usage.transactionCount),
    });
    return Object.freeze({
        actualUsage,
        browserStorage: Object.freeze({
            claimedBufferCount: bufferClaimCount,
            claimedByteLength: bufferClaimByteLength,
            maximumLiveBufferByteLength: bufferClaimByteLength,
            maximumLiveBufferCount: Number(bufferClaimCount),
            releasedBufferCount: bufferClaimCount,
            releasedByteLength: bufferClaimByteLength,
            secretRecordOpenByteLength: BigInt(openCiphertextByteLength),
            secretRecordOpenCount: openCiphertextByteLength === 0 ? 0n : 1n,
            secretRecordSealByteLength: BigInt(sealPlaintextByteLength),
            secretRecordSealCount: sealPlaintextByteLength === 0 ? 0n : 1n,
            transferredBufferCount: bufferClaimCount,
            transferredByteLength: bufferClaimByteLength,
        }),
        compiledRequirement: Object.freeze({
            distinctPhysicalObjectCount: Math.max(
                1,
                usage.deletedObjectLifecycleCount,
            ),
            maximumChunkByteLength: 1_048_576,
            maximumTransactionPayloadByteLength: 1_048_576n,
            objectLifecycleCount: Math.max(
                1,
                usage.deletedObjectLifecycleCount,
            ),
            peakStoredByteLength: BigInt(usage.peakStoredByteLength),
            stepCount: Math.max(1, usage.transactionCount),
            totalReadByteLength: BigInt(usage.readByteLength),
            totalWrittenByteLength: BigInt(usage.writtenByteLength),
            transactionCount: BigInt(usage.transactionCount),
        }),
        ...(usage.prefixReplay === true
            ? { deterministicPrefixReplayUsage: actualUsage }
            : {}),
        workerTransport: Object.freeze({
            browserToWasmCopyByteLength: BigInt(usage.transactionCount),
            browserToWasmCopyCount: BigInt(usage.transactionCount),
            readResultTransferByteLength: BigInt(usage.readByteLength),
            readResultTransferCount: usage.readByteLength === 0 ? 0n : 1n,
            wasmToBrowserCopyByteLength: BigInt(usage.transactionCount),
            wasmToBrowserCopyCount: BigInt(usage.transactionCount),
        }),
    });
};

const physicalStorageAccounting = (
    usage: TerminalUsage,
): CommonProofBrowserCustodyPhysicalAccountingSnapshot => {
    const openCiphertextByteLength = usage.openCiphertextByteLength ?? 0;
    const sealPlaintextByteLength = usage.sealPlaintextByteLength ?? 0;
    const physicalStoredPeakByteLength = usage.peakStoredByteLength;
    const physicalQuotaReservedByteLength = physicalStoredPeakByteLength;
    const physicalQuotaByteLength = Math.max(
        1,
        physicalQuotaReservedByteLength,
    );
    const cleanupDeletedByteLength =
        usage.deletedObjectLifecycleCount === 0
            ? 0
            : Math.max(1, usage.writtenByteLength);
    return Object.freeze({
        cleanupCompleted: true,
        cleanupDurationMilliseconds: 1,
        commitReadbackByteLength: 0,
        commitReadbackCallCount: 0,
        ciphertextReadByteLength: usage.readByteLength,
        ciphertextReadCallCount: usage.readByteLength === 0 ? 0 : 1,
        ciphertextWriteByteLength: usage.writtenByteLength,
        ciphertextWriteCallCount: usage.writtenByteLength === 0 ? 0 : 1,
        deletedByteLength: cleanupDeletedByteLength,
        deletionCount: usage.deletedObjectLifecycleCount,
        deletionDurationMilliseconds:
            usage.deletedObjectLifecycleCount === 0 ? 0 : 1,
        deterministicRegeneratedByteLength:
            usage.prefixReplay === true ? usage.writtenByteLength : 0,
        deterministicRegenerationCallCount:
            usage.prefixReplay === true && usage.writtenByteLength > 0 ? 1 : 0,
        openCallCount: openCiphertextByteLength === 0 ? 0 : 1,
        openCiphertextByteLength,
        openPlaintextByteLength:
            openCiphertextByteLength === 0 ? 0 : usage.readByteLength,
        physicalReadByteLength: usage.readByteLength,
        physicalReadCallCount: usage.readByteLength === 0 ? 0 : 1,
        physicalQuotaByteLength,
        physicalQuotaHeadroomByteLength:
            physicalQuotaByteLength - physicalQuotaReservedByteLength,
        physicalQuotaReservedByteLength,
        physicalStoredEndByteLength: 0,
        physicalStoredPeakByteLength,
        physicalStoredStartByteLength: 0,
        physicalWriteByteLength: usage.writtenByteLength,
        physicalWriteCallCount: usage.writtenByteLength === 0 ? 0 : 1,
        plaintextReadByteLength: usage.readByteLength,
        plaintextReadCallCount: usage.readByteLength === 0 ? 0 : 1,
        plaintextWriteByteLength: usage.writtenByteLength,
        plaintextWriteCallCount: usage.writtenByteLength === 0 ? 0 : 1,
        repairHashCallCount: 0,
        repairHashedByteLength: 0,
        sealCallCount: sealPlaintextByteLength === 0 ? 0 : 1,
        sealCiphertextByteLength:
            sealPlaintextByteLength === 0 ? 0 : sealPlaintextByteLength + 16,
        sealPlaintextByteLength,
        storageRequestCount: usage.transactionCount * 2,
        storageTransactionCount: usage.transactionCount,
    });
};

const terminalLedgers = (usage: TerminalUsage) => ({
    externalMemoryAccounting: terminalAccounting(usage),
    physicalStorageAccounting: physicalStorageAccounting(usage),
});

const emptyTerminalUsage = Object.freeze({
    deletedObjectLifecycleCount: 0,
    peakStoredByteLength: 0,
    readByteLength: 0,
    transactionCount: 0,
    writtenByteLength: 0,
} satisfies TerminalUsage);

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
        browserCacheState: 'cold',
        browserProcessResidentMemoryByteLength: () => 1_000_000,
        caseIdentifier: 'vss-share-linkage-generation-fresh',
        executionKind: 'fresh-generation',
        javascriptHeapByteLength: () => 10_000,
        runOrdinal: 1,
        suiteId: selectedSuiteIdentifier,
        wasmLinearMemoryByteLength: () => 65_536,
        wasmSha256Hex: processedWasmSha256Hex,
        workerInstanceIdentifier: 'accounting-worker-1',
        workerOperationOrdinal: 1,
    });

describe('Selected proof runtime evidence accounting', () => {
    it('measures production-resident scratch records and exact boundary traffic', async () => {
        const accounting = createAccounting();
        const usage = Object.freeze({
            deletedObjectLifecycleCount: 1,
            openCiphertextByteLength: 4,
            peakStoredByteLength: 5,
            readByteLength: 4,
            sealPlaintextByteLength: 5,
            transactionCount: 5,
            writtenByteLength: 5,
        } satisfies TerminalUsage);
        const browserStorageAccounting =
            terminalAccounting(usage).browserStorage;
        if (browserStorageAccounting === undefined) {
            throw new Error('The fixture omitted browser storage accounting.');
        }
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
            copyBrowserStorageAccounting: () => browserStorageAccounting,
            executeTransaction,
        });
        expect(externalMemory.copyBrowserStorageAccounting?.()).toBe(
            browserStorageAccounting,
        );

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
            ...terminalLedgers(usage),
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
            resourceAccounting: {
                indexedDbRequestCount: 10,
                indexedDbTransactionCount: 5,
                javascriptToWasmCopyCount: 5,
                kernelStorageRequestCount: 5,
                wasmToJavascriptCopyCount: 5,
                workerTransferByteLength: 4,
                workerTransferCount: 1,
            },
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
            ...terminalLedgers(emptyTerminalUsage),
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
        const confirmAuthenticatedCheckpointExternalMemoryState = vi.fn();
        const prefixReplay = accounting.wrapPrefixReplayExternalMemory({
            confirmAuthenticatedCheckpointExternalMemoryState,
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
            ...terminalLedgers({
                deletedObjectLifecycleCount: 0,
                peakStoredByteLength: 3,
                prefixReplay: true,
                readByteLength: 0,
                transactionCount: 1,
                writtenByteLength: 3,
            }),
        });
        expect(measurement).toMatchObject({
            externalScratchPeakByteLength: 12,
            externalScratchTransactionCount: 1,
            externalScratchWriteByteLength: 3,
        });
        expect(
            executeDeterministicPrefixReplayTransaction,
        ).toHaveBeenCalledOnce();
        prefixReplay.confirmAuthenticatedCheckpointExternalMemoryState();
        expect(
            confirmAuthenticatedCheckpointExternalMemoryState,
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
            ...terminalLedgers({
                ...emptyTerminalUsage,
                transactionCount: 1,
            }),
        });
        expect(measurement).toMatchObject({
            externalScratchPeakByteLength: 0,
            externalScratchReadByteLength: 0,
            externalScratchTransactionCount: 1,
            externalScratchWriteByteLength: 0,
        });
    });

    it('refuses a detailed kernel request count that differs from observed calls', async () => {
        const accounting = createAccounting();
        const externalMemory = accounting.wrapExternalMemory({
            executeTransaction: () => Promise.resolve(Object.freeze([])),
        });
        await externalMemory.executeTransaction(createRequest(0n, []));

        expect(() =>
            accounting.finish({
                canonicalInput: summarizeCanonicalBytes(new Uint8Array([0x81])),
                canonicalOutput: summarizeCanonicalBytes(
                    new Uint8Array([0x82]),
                ),
                ...terminalLedgers(emptyTerminalUsage),
            }),
        ).toThrow(/storage-request count differs/u);
    });

    it('refuses missing browser custody and worker terminal ledgers', () => {
        const accounting = createAccounting();
        const completeTerminalAccounting =
            terminalAccounting(emptyTerminalUsage);
        const withoutBrowserStorage = Object.freeze({
            actualUsage: completeTerminalAccounting.actualUsage,
            compiledRequirement: completeTerminalAccounting.compiledRequirement,
            workerTransport: completeTerminalAccounting.workerTransport,
        });
        expect(() =>
            accounting.finish({
                canonicalInput: summarizeCanonicalBytes(new Uint8Array([0x91])),
                canonicalOutput: summarizeCanonicalBytes(
                    new Uint8Array([0x92]),
                ),
                externalMemoryAccounting: withoutBrowserStorage,
                physicalStorageAccounting:
                    physicalStorageAccounting(emptyTerminalUsage),
            }),
        ).toThrow(/complete browser-storage and worker-transport/u);

        const secondAccounting = createAccounting();
        const withoutWorkerTransport = Object.freeze({
            actualUsage: completeTerminalAccounting.actualUsage,
            browserStorage: completeTerminalAccounting.browserStorage,
            compiledRequirement: completeTerminalAccounting.compiledRequirement,
        });
        expect(() =>
            secondAccounting.finish({
                canonicalInput: summarizeCanonicalBytes(new Uint8Array([0x93])),
                canonicalOutput: summarizeCanonicalBytes(
                    new Uint8Array([0x94]),
                ),
                externalMemoryAccounting: withoutWorkerTransport,
                physicalStorageAccounting:
                    physicalStorageAccounting(emptyTerminalUsage),
            }),
        ).toThrow(/complete browser-storage and worker-transport/u);
    });

    it('refuses worker-copy drift and incomplete authenticated cleanup', async () => {
        const usage = Object.freeze({
            ...emptyTerminalUsage,
            transactionCount: 1,
        });
        const accounting = createAccounting();
        await accounting
            .wrapExternalMemory({
                executeTransaction: () => Promise.resolve(Object.freeze([])),
            })
            .executeTransaction(createRequest(0n, []));
        const completeTerminalAccounting = terminalAccounting(usage);
        const completeWorkerTransport =
            completeTerminalAccounting.workerTransport;
        if (completeWorkerTransport === undefined) {
            throw new Error(
                'the complete accounting fixture needs worker transport',
            );
        }
        const divergentWorkerTransport = Object.freeze({
            ...completeWorkerTransport,
            wasmToBrowserCopyByteLength: 0n,
            wasmToBrowserCopyCount: 0n,
        });
        expect(() =>
            accounting.finish({
                canonicalInput: summarizeCanonicalBytes(new Uint8Array([0xa1])),
                canonicalOutput: summarizeCanonicalBytes(
                    new Uint8Array([0xa2]),
                ),
                externalMemoryAccounting: Object.freeze({
                    ...completeTerminalAccounting,
                    workerTransport: divergentWorkerTransport,
                }),
                physicalStorageAccounting: physicalStorageAccounting(usage),
            }),
        ).toThrow(/WebAssembly-to-browser copy count/u);

        const secondAccounting = createAccounting();
        expect(() =>
            secondAccounting.finish({
                canonicalInput: summarizeCanonicalBytes(new Uint8Array([0xa3])),
                canonicalOutput: summarizeCanonicalBytes(
                    new Uint8Array([0xa4]),
                ),
                externalMemoryAccounting:
                    terminalAccounting(emptyTerminalUsage),
                physicalStorageAccounting: Object.freeze({
                    ...physicalStorageAccounting(emptyTerminalUsage),
                    cleanupCompleted: false,
                }),
            }),
        ).toThrow(/physical-storage ledger/u);
    });
});
