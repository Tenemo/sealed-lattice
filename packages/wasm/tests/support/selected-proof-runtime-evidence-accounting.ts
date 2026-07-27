import { sha512 } from '@noble/hashes/sha2.js';

import type {
    CommonProofBrowserCustody,
    CommonProofBrowserCustodyPhysicalAccountingSnapshot,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import type {
    AuthenticatedCommonProofInputStore,
    CommonProofCanonicalOutputStore,
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofExternalMemoryTransactionExecutor,
    CommonProofGenerationExternalMemoryAccounting,
} from '#packages/wasm/src/index';
import {
    beginDesktopBrowserProofMeasurement,
    type DesktopBrowserProofCacheState,
    type DesktopBrowserProofCancellationBoundaryKind,
    type DesktopBrowserProofExecutionKind,
    type DesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofResourceAccounting,
} from '#tests/support/desktop-browser-proof-measurement';

type CanonicalByteSummary = Readonly<{
    byteLength: number;
    sha512Hex: string;
}>;

type ExternalObjectObservation = {
    appendedByteLength: number;
    exactByteLength: number;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const requireSafeByteLength = (value: bigint, label: string): number => {
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < 0) {
        throw new RangeError(`${label} is outside the safe byte-length range.`);
    }
    return number;
};

const requireEqualBigInt = (
    actual: bigint,
    expected: bigint,
    label: string,
): void => {
    if (actual !== expected) {
        throw new Error(
            `${label} does not match its independently observed ledger.`,
        );
    }
};

const requireCallAndByteLedger = (
    callCount: bigint,
    byteLength: bigint,
    label: string,
): void => {
    if ((callCount === 0n) !== (byteLength === 0n)) {
        throw new Error(`${label} has inconsistent call and byte totals.`);
    }
};

const emptyCanonicalByteSummary = (): CanonicalByteSummary => ({
    byteLength: 0,
    sha512Hex: bytesToHex(sha512(new Uint8Array(0))),
});

export const summarizeCanonicalBytes = (
    bytes: Uint8Array,
): CanonicalByteSummary =>
    Object.freeze({
        byteLength: bytes.byteLength,
        sha512Hex: bytesToHex(sha512(bytes)),
    });

/**
 * Counts only buffers observed at the JavaScript/WASM or authenticated-store
 * boundary. It does not infer allocator traffic that the browser did not
 * expose.
 */
export const createSelectedProofRuntimeEvidenceAccounting = (input: {
    browserCacheState: DesktopBrowserProofCacheState;
    browserProcessResidentMemoryByteLength(): number;
    caseIdentifier: string;
    executionKind: DesktopBrowserProofExecutionKind;
    javascriptHeapByteLength(): number;
    runOrdinal: number;
    suiteId: string;
    wasmLinearMemoryByteLength(): number;
    wasmSha256Hex: string;
    workerInstanceIdentifier: string;
    workerOperationOrdinal: number;
}) => {
    const externalObjects = new Map<number, ExternalObjectObservation>();
    let copiedBufferPeakByteLength = 0;
    let externalScratchByteLength = 0;
    let externalScratchPeakByteLength = 0;
    let externalScratchReadByteLength = 0;
    let externalScratchTransactionCount = 0;
    let externalScratchWriteByteLength = 0;
    let externalScratchDeletedObjectLifecycleCount = 0;
    let fullBufferCopiedByteLength = 0;
    let fullBufferCopyCount = 0;
    let observedHostAllocationVolumeByteLength = 0;
    let retainedResidentByteLength = 0;
    const measurement = beginDesktopBrowserProofMeasurement({
        browserCacheState: input.browserCacheState,
        caseIdentifier: input.caseIdentifier,
        emitConsoleEvent: false,
        executionKind: input.executionKind,
        memoryReaders: {
            browserProcessResidentMemoryByteLength: () =>
                input.browserProcessResidentMemoryByteLength(),
            externalScratchByteLength: () => externalScratchByteLength,
            javascriptHeapByteLength: () => input.javascriptHeapByteLength(),
            retainedResidentByteLength: () => retainedResidentByteLength,
            wasmLinearMemoryByteLength: () =>
                input.wasmLinearMemoryByteLength(),
        },
        runOrdinal: input.runOrdinal,
        suiteId: input.suiteId,
        wasmSha256Hex: input.wasmSha256Hex,
        workerInstanceIdentifier: input.workerInstanceIdentifier,
        workerOperationOrdinal: input.workerOperationOrdinal,
    });

    const observeBuffer = (bytes: Uint8Array): void => {
        const byteLength = bytes.byteLength;
        copiedBufferPeakByteLength = Math.max(
            copiedBufferPeakByteLength,
            byteLength,
        );
        fullBufferCopiedByteLength += byteLength;
        fullBufferCopyCount += 1;
        observedHostAllocationVolumeByteLength += byteLength;
        retainedResidentByteLength += byteLength;
        measurement.sample();
        retainedResidentByteLength -= byteLength;
    };

    const observeExternalMemoryOperation = (
        operation: CommonProofExternalMemoryOperation,
    ): void => {
        switch (operation.operationKind) {
            case 'create': {
                if (externalObjects.has(operation.objectOrdinal)) {
                    throw new Error(
                        'The measured common-proof runtime reused a live external-memory object ordinal.',
                    );
                }
                const exactByteLength = requireSafeByteLength(
                    operation.exactByteLength,
                    'The measured external-memory object',
                );
                externalObjects.set(operation.objectOrdinal, {
                    appendedByteLength: 0,
                    exactByteLength,
                });
                // The production custody counts its fixed object header in the
                // same scratch budget as appended object bytes.
                externalScratchByteLength += 9;
                break;
            }
            case 'append': {
                const object = externalObjects.get(operation.objectOrdinal);
                if (
                    object === undefined ||
                    object.appendedByteLength !==
                        requireSafeByteLength(
                            operation.expectedOffset,
                            'The measured append offset',
                        ) ||
                    object.appendedByteLength + operation.bytes.byteLength >
                        object.exactByteLength
                ) {
                    throw new Error(
                        'The measured common-proof append diverged from the external-memory lifecycle.',
                    );
                }
                object.appendedByteLength += operation.bytes.byteLength;
                externalScratchByteLength += operation.bytes.byteLength;
                externalScratchWriteByteLength += operation.bytes.byteLength;
                observeBuffer(operation.bytes);
                break;
            }
            case 'read':
                externalScratchReadByteLength += operation.byteLength;
                break;
            case 'delete': {
                const object = externalObjects.get(operation.objectOrdinal);
                if (object === undefined) {
                    throw new Error(
                        'The measured common-proof deletion named an absent external-memory object.',
                    );
                }
                externalScratchByteLength -= object.appendedByteLength + 9;
                externalObjects.delete(operation.objectOrdinal);
                externalScratchDeletedObjectLifecycleCount += 1;
                break;
            }
            case 'seal':
                break;
        }
        externalScratchPeakByteLength = Math.max(
            externalScratchPeakByteLength,
            externalScratchByteLength,
        );
        measurement.sample();
    };

    const observeExternalMemoryResult = (
        result: CommonProofExternalMemoryReadResult,
    ): void => observeBuffer(result.bytes);

    const wrapExternalMemory = (
        externalMemory: CommonProofExternalMemoryTransactionExecutor,
    ): CommonProofExternalMemoryTransactionExecutor => {
        const copyBrowserStorageAccounting =
            externalMemory.copyBrowserStorageAccounting;
        return Object.freeze({
            ...(copyBrowserStorageAccounting === undefined
                ? {}
                : {
                      copyBrowserStorageAccounting: () =>
                          copyBrowserStorageAccounting.call(externalMemory),
                  }),
            executeTransaction: async (
                request: CommonProofExternalMemoryRequest,
            ) => {
                externalScratchTransactionCount += 1;
                const results =
                    await externalMemory.executeTransaction(request);
                for (const operation of request.operations) {
                    observeExternalMemoryOperation(operation);
                }
                for (const result of results) {
                    observeExternalMemoryResult(result);
                }
                return results;
            },
        });
    };

    const wrapPrefixReplayExternalMemory = (
        prefixReplayExternalMemory: CommonProofBrowserCustody['prefixReplayExternalMemory'],
    ): CommonProofBrowserCustody['prefixReplayExternalMemory'] =>
        Object.freeze({
            executeDeterministicPrefixReplayTransaction: async (
                request: CommonProofExternalMemoryRequest,
            ) => {
                externalScratchTransactionCount += 1;
                const results =
                    await prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                        request,
                    );
                for (const operation of request.operations) {
                    observeExternalMemoryOperation(operation);
                }
                for (const result of results) {
                    observeExternalMemoryResult(result);
                }
                return results;
            },
        });

    const wrapOutputStore = (
        outputStore: CommonProofCanonicalOutputStore,
    ): Readonly<{
        canonicalOutputSummary(): CanonicalByteSummary;
        store: CommonProofCanonicalOutputStore;
    }> => {
        const outputHash = sha512.create();
        let outputByteLength = 0;
        let nextChunkIndex = 0;
        let finalizedSummary: CanonicalByteSummary | undefined;
        return Object.freeze({
            canonicalOutputSummary: () => {
                finalizedSummary ??= Object.freeze({
                    byteLength: outputByteLength,
                    sha512Hex: bytesToHex(outputHash.digest()),
                });
                return finalizedSummary;
            },
            store: Object.freeze({
                commitChunk: async (
                    chunkIndex: number,
                    chunkBytes: Uint8Array<ArrayBuffer>,
                ) => {
                    if (
                        finalizedSummary !== undefined ||
                        chunkIndex !== nextChunkIndex
                    ) {
                        throw new Error(
                            'The measured canonical proof output was finalized or emitted out of order.',
                        );
                    }
                    observeBuffer(chunkBytes);
                    await outputStore.commitChunk(chunkIndex, chunkBytes);
                    outputHash.update(chunkBytes);
                    outputByteLength += chunkBytes.byteLength;
                    nextChunkIndex += 1;
                },
                readChunk: async (
                    chunkIndex: number,
                    exactByteLength: number,
                ) => {
                    const bytes = await outputStore.readChunk(
                        chunkIndex,
                        exactByteLength,
                    );
                    observeBuffer(bytes);
                    return bytes;
                },
            }),
        });
    };

    const wrapInputStore = (
        store: AuthenticatedCommonProofInputStore,
    ): AuthenticatedCommonProofInputStore =>
        Object.freeze({
            declaredByteLength: store.declaredByteLength,
            readCommittedChunk: async (chunkIndex, exactByteLength) => {
                const bytes = await store.readCommittedChunk(
                    chunkIndex,
                    exactByteLength,
                );
                observeBuffer(bytes);
                return bytes;
            },
        });

    const deriveResourceAccounting = (finishInput: {
        externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting;
        physicalStorageAccounting: CommonProofBrowserCustodyPhysicalAccountingSnapshot;
    }): DesktopBrowserProofResourceAccounting => {
        const terminal = finishInput.externalMemoryAccounting;
        const browserStorage = terminal.browserStorage;
        const workerTransport = terminal.workerTransport;
        if (browserStorage === undefined || workerTransport === undefined) {
            throw new Error(
                'The measured generation did not expose complete browser-storage and worker-transport terminal ledgers.',
            );
        }

        const actual = terminal.actualUsage;
        const compiled = terminal.compiledRequirement;
        const actualTransactionCount = requireSafeByteLength(
            actual.transactionCount,
            'The terminal kernel transaction count',
        );
        if (actualTransactionCount !== externalScratchTransactionCount) {
            throw new Error(
                'The terminal kernel storage-request count differs from the observed transaction executor calls.',
            );
        }
        requireEqualBigInt(
            actual.totalReadByteLength,
            BigInt(externalScratchReadByteLength),
            'The terminal kernel read-byte count',
        );
        requireEqualBigInt(
            actual.totalWrittenByteLength,
            BigInt(externalScratchWriteByteLength),
            'The terminal kernel write-byte count',
        );
        requireEqualBigInt(
            actual.deletedObjectLifecycleCount,
            BigInt(externalScratchDeletedObjectLifecycleCount),
            'The terminal kernel deleted-object count',
        );
        if (
            requireSafeByteLength(
                actual.peakStoredByteLength,
                'The terminal kernel peak stored bytes',
            ) > externalScratchPeakByteLength ||
            actual.peakStoredByteLength > compiled.peakStoredByteLength ||
            actual.totalReadByteLength > compiled.totalReadByteLength ||
            actual.totalWrittenByteLength > compiled.totalWrittenByteLength ||
            actual.transactionCount > compiled.transactionCount ||
            actual.deletedObjectLifecycleCount >
                BigInt(compiled.objectLifecycleCount)
        ) {
            throw new Error(
                'The terminal kernel usage exceeds its observed scratch or compiled requirement ledger.',
            );
        }

        const prefixReplay = terminal.deterministicPrefixReplayUsage;
        if (
            prefixReplay !== undefined &&
            (prefixReplay.deletedObjectLifecycleCount >
                actual.deletedObjectLifecycleCount ||
                prefixReplay.peakStoredByteLength >
                    actual.peakStoredByteLength ||
                prefixReplay.totalReadByteLength > actual.totalReadByteLength ||
                prefixReplay.totalWrittenByteLength >
                    actual.totalWrittenByteLength ||
                prefixReplay.transactionCount > actual.transactionCount)
        ) {
            throw new Error(
                'The authenticated deterministic-prefix ledger exceeds terminal kernel usage.',
            );
        }

        if (
            browserStorage.claimedBufferCount !==
                browserStorage.releasedBufferCount ||
            browserStorage.claimedByteLength !==
                browserStorage.releasedByteLength ||
            browserStorage.maximumLiveBufferCount > 2 ||
            browserStorage.maximumLiveBufferByteLength >
                browserStorage.claimedByteLength
        ) {
            throw new Error(
                'The browser-storage terminal ledger retained payload ownership or exceeded its two-buffer boundary.',
            );
        }
        requireCallAndByteLedger(
            browserStorage.claimedBufferCount,
            browserStorage.claimedByteLength,
            'The browser payload-claim ledger',
        );
        requireCallAndByteLedger(
            browserStorage.transferredBufferCount,
            browserStorage.transferredByteLength,
            'The browser payload-transfer ledger',
        );
        requireCallAndByteLedger(
            browserStorage.secretRecordOpenCount,
            browserStorage.secretRecordOpenByteLength,
            'The browser secret-record open ledger',
        );
        requireCallAndByteLedger(
            browserStorage.secretRecordSealCount,
            browserStorage.secretRecordSealByteLength,
            'The browser secret-record seal ledger',
        );

        const physical = finishInput.physicalStorageAccounting;
        if (
            !physical.cleanupCompleted ||
            physical.storageRequestCount < physical.storageTransactionCount ||
            physical.storageTransactionCount < actualTransactionCount ||
            physical.storageRequestCount < actualTransactionCount ||
            physical.physicalStoredStartByteLength >
                physical.physicalStoredPeakByteLength ||
            physical.physicalStoredEndByteLength >
                physical.physicalStoredPeakByteLength ||
            physical.physicalStoredPeakByteLength >
                physical.physicalQuotaReservedByteLength ||
            physical.physicalQuotaReservedByteLength +
                physical.physicalQuotaHeadroomByteLength !==
                physical.physicalQuotaByteLength ||
            physical.plaintextReadByteLength <
                requireSafeByteLength(
                    actual.totalReadByteLength,
                    'The terminal kernel read bytes',
                ) ||
            physical.plaintextWriteByteLength <
                requireSafeByteLength(
                    actual.totalWrittenByteLength,
                    'The terminal kernel written bytes',
                )
        ) {
            throw new Error(
                'The authenticated physical-storage ledger does not reconcile with kernel usage, quota, and cleanup.',
            );
        }
        if (
            browserStorage.secretRecordOpenCount >
                BigInt(physical.openCallCount) ||
            browserStorage.secretRecordOpenByteLength >
                BigInt(physical.openCiphertextByteLength) ||
            browserStorage.secretRecordSealCount >
                BigInt(physical.sealCallCount) ||
            browserStorage.secretRecordSealByteLength >
                BigInt(physical.sealPlaintextByteLength)
        ) {
            throw new Error(
                'The authenticated record ledger fell below browser-owned secret-record work.',
            );
        }

        requireEqualBigInt(
            workerTransport.browserToWasmCopyCount,
            actual.transactionCount,
            'The browser-to-WebAssembly copy count',
        );
        requireEqualBigInt(
            workerTransport.wasmToBrowserCopyCount,
            actual.transactionCount,
            'The WebAssembly-to-browser copy count',
        );
        requireEqualBigInt(
            workerTransport.readResultTransferByteLength,
            actual.totalReadByteLength,
            'The worker read-result transfer bytes',
        );
        for (const [callCount, byteLength, label] of [
            [
                workerTransport.browserToWasmCopyCount,
                workerTransport.browserToWasmCopyByteLength,
                'The browser-to-WebAssembly copy ledger',
            ],
            [
                workerTransport.readResultTransferCount,
                workerTransport.readResultTransferByteLength,
                'The worker read-result transfer ledger',
            ],
            [
                workerTransport.wasmToBrowserCopyCount,
                workerTransport.wasmToBrowserCopyByteLength,
                'The WebAssembly-to-browser copy ledger',
            ],
        ] as const) {
            requireCallAndByteLedger(callCount, byteLength, label);
        }

        return Object.freeze({
            cleanupCompleted: true,
            cleanupDeletedByteLength: physical.deletedByteLength,
            cleanupDeletionCount: physical.deletionCount,
            cleanupDurationMilliseconds: physical.cleanupDurationMilliseconds,
            commitReadbackByteLength: physical.commitReadbackByteLength,
            commitReadbackCallCount: physical.commitReadbackCallCount,
            ciphertextReadByteLength: physical.ciphertextReadByteLength,
            ciphertextReadCallCount: physical.ciphertextReadCallCount,
            ciphertextWriteByteLength: physical.ciphertextWriteByteLength,
            ciphertextWriteCallCount: physical.ciphertextWriteCallCount,
            deletionDurationMilliseconds: physical.deletionDurationMilliseconds,
            deterministicRegeneratedByteLength:
                physical.deterministicRegeneratedByteLength,
            deterministicRegenerationCallCount:
                physical.deterministicRegenerationCallCount,
            indexedDbRequestCount: physical.storageRequestCount,
            indexedDbTransactionCount: physical.storageTransactionCount,
            javascriptToWasmCopyByteLength: requireSafeByteLength(
                workerTransport.browserToWasmCopyByteLength,
                'The browser-to-WebAssembly copy bytes',
            ),
            javascriptToWasmCopyCount: requireSafeByteLength(
                workerTransport.browserToWasmCopyCount,
                'The browser-to-WebAssembly copy count',
            ),
            kernelStorageRequestCount: actualTransactionCount,
            openCallCount: physical.openCallCount,
            openCiphertextByteLength: physical.openCiphertextByteLength,
            openPlaintextByteLength: physical.openPlaintextByteLength,
            physicalQuotaByteLength: physical.physicalQuotaByteLength,
            physicalQuotaHeadroomByteLength:
                physical.physicalQuotaHeadroomByteLength,
            physicalQuotaReservedByteLength:
                physical.physicalQuotaReservedByteLength,
            physicalStoredEndByteLength: physical.physicalStoredEndByteLength,
            physicalStoredPeakByteLength: physical.physicalStoredPeakByteLength,
            plaintextReadByteLength: physical.plaintextReadByteLength,
            plaintextReadCallCount: physical.plaintextReadCallCount,
            plaintextWriteByteLength: physical.plaintextWriteByteLength,
            plaintextWriteCallCount: physical.plaintextWriteCallCount,
            repairHashCallCount: physical.repairHashCallCount,
            repairHashedByteLength: physical.repairHashedByteLength,
            sealCallCount: physical.sealCallCount,
            sealCiphertextByteLength: physical.sealCiphertextByteLength,
            sealPlaintextByteLength: physical.sealPlaintextByteLength,
            simultaneousLiveBufferPeakByteLength: requireSafeByteLength(
                browserStorage.maximumLiveBufferByteLength,
                'The maximum live browser payload bytes',
            ),
            simultaneousLiveBufferPeakCount:
                browserStorage.maximumLiveBufferCount,
            wasmToJavascriptCopyByteLength: requireSafeByteLength(
                workerTransport.wasmToBrowserCopyByteLength,
                'The WebAssembly-to-browser copy bytes',
            ),
            wasmToJavascriptCopyCount: requireSafeByteLength(
                workerTransport.wasmToBrowserCopyCount,
                'The WebAssembly-to-browser copy count',
            ),
            workerTransferByteLength: requireSafeByteLength(
                workerTransport.readResultTransferByteLength,
                'The worker transfer bytes',
            ),
            workerTransferCount: requireSafeByteLength(
                workerTransport.readResultTransferCount,
                'The worker transfer count',
            ),
        });
    };

    return Object.freeze({
        emptyCanonicalByteSummary,
        finish: (finishInput: {
            canonicalInput: CanonicalByteSummary;
            canonicalOutput: CanonicalByteSummary;
            cancellationBoundaryCatalogSha512Hex?: string;
            cancellationBoundaryIdentifier?: string;
            cancellationBoundaryKind?: DesktopBrowserProofCancellationBoundaryKind;
            cancellationBoundaryOrdinal?: number;
            declaredSafeBoundaryCount?: number;
            declaredStorageYieldBoundaryCount?: number;
            deterministicCoinBindingSha512Hex?: string;
            nativeReferenceByteLength?: number;
            nativeReferenceSha512Hex?: string;
            refusalReasonIdentifier?: string;
            externalMemoryAccounting: CommonProofGenerationExternalMemoryAccounting;
            physicalStorageAccounting: CommonProofBrowserCustodyPhysicalAccountingSnapshot;
        }): DesktopBrowserProofMeasurementRecord => {
            const resourceAccounting = deriveResourceAccounting(finishInput);
            return measurement.finish({
                canonicalInputByteLength: finishInput.canonicalInput.byteLength,
                canonicalInputSha512Hex: finishInput.canonicalInput.sha512Hex,
                canonicalOutputByteLength:
                    finishInput.canonicalOutput.byteLength,
                copiedBufferPeakByteLength,
                externalScratchPeakByteLength,
                externalScratchReadByteLength,
                externalScratchTransactionCount,
                externalScratchWriteByteLength,
                fullBufferCopiedByteLength,
                fullBufferCopyCount,
                observedHostAllocationVolumeByteLength,
                outputSha512Hex: finishInput.canonicalOutput.sha512Hex,
                resourceAccounting,
                ...(finishInput.cancellationBoundaryCatalogSha512Hex ===
                undefined
                    ? {}
                    : {
                          cancellationBoundaryCatalogSha512Hex:
                              finishInput.cancellationBoundaryCatalogSha512Hex,
                      }),
                ...(finishInput.cancellationBoundaryIdentifier === undefined
                    ? {}
                    : {
                          cancellationBoundaryIdentifier:
                              finishInput.cancellationBoundaryIdentifier,
                      }),
                ...(finishInput.cancellationBoundaryKind === undefined
                    ? {}
                    : {
                          cancellationBoundaryKind:
                              finishInput.cancellationBoundaryKind,
                      }),
                ...(finishInput.cancellationBoundaryOrdinal === undefined
                    ? {}
                    : {
                          cancellationBoundaryOrdinal:
                              finishInput.cancellationBoundaryOrdinal,
                      }),
                ...(finishInput.declaredSafeBoundaryCount === undefined
                    ? {}
                    : {
                          declaredSafeBoundaryCount:
                              finishInput.declaredSafeBoundaryCount,
                      }),
                ...(finishInput.declaredStorageYieldBoundaryCount === undefined
                    ? {}
                    : {
                          declaredStorageYieldBoundaryCount:
                              finishInput.declaredStorageYieldBoundaryCount,
                      }),
                ...(finishInput.deterministicCoinBindingSha512Hex === undefined
                    ? {}
                    : {
                          deterministicCoinBindingSha512Hex:
                              finishInput.deterministicCoinBindingSha512Hex,
                      }),
                ...(finishInput.nativeReferenceByteLength === undefined
                    ? {}
                    : {
                          nativeReferenceByteLength:
                              finishInput.nativeReferenceByteLength,
                      }),
                ...(finishInput.nativeReferenceSha512Hex === undefined
                    ? {}
                    : {
                          nativeReferenceSha512Hex:
                              finishInput.nativeReferenceSha512Hex,
                      }),
                ...(finishInput.refusalReasonIdentifier === undefined
                    ? {}
                    : {
                          refusalReasonIdentifier:
                              finishInput.refusalReasonIdentifier,
                      }),
            });
        },
        observeBuffer,
        wrapExternalMemory,
        wrapInputStore,
        wrapOutputStore,
        wrapPrefixReplayExternalMemory,
    });
};
