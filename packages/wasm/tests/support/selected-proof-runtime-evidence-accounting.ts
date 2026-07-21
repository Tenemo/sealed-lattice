import { sha512 } from '@noble/hashes/sha2.js';

import type { CommonProofBrowserCustody } from '#packages/protocol/src/runtime/common-proof-browser-custody';
import type {
    AuthenticatedCommonProofInputStore,
    CommonProofCanonicalOutputStore,
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofExternalMemoryTransactionExecutor,
} from '#packages/wasm/src/index';
import {
    beginDesktopBrowserProofMeasurement,
    type DesktopBrowserProofExecutionKind,
    type DesktopBrowserProofMeasurementRecord,
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
    caseIdentifier: string;
    executionKind: DesktopBrowserProofExecutionKind;
    runOrdinal: number;
    suiteId: string;
    wasmLinearMemoryByteLength(): number;
    wasmSha256Hex: string;
}) => {
    const externalObjects = new Map<number, ExternalObjectObservation>();
    let copiedBufferPeakByteLength = 0;
    let externalScratchByteLength = 0;
    let externalScratchPeakByteLength = 0;
    let externalScratchReadByteLength = 0;
    let externalScratchTransactionCount = 0;
    let externalScratchWriteByteLength = 0;
    let fullBufferCopiedByteLength = 0;
    let fullBufferCopyCount = 0;
    let observedHostAllocationVolumeByteLength = 0;
    let retainedResidentByteLength = 0;
    const measurement = beginDesktopBrowserProofMeasurement({
        caseIdentifier: input.caseIdentifier,
        emitConsoleEvent: false,
        executionKind: input.executionKind,
        memoryReaders: {
            externalScratchByteLength: () => externalScratchByteLength,
            retainedResidentByteLength: () => retainedResidentByteLength,
            wasmLinearMemoryByteLength: () =>
                input.wasmLinearMemoryByteLength(),
        },
        runOrdinal: input.runOrdinal,
        suiteId: input.suiteId,
        wasmSha256Hex: input.wasmSha256Hex,
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
    ): CommonProofExternalMemoryTransactionExecutor =>
        Object.freeze({
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

    return Object.freeze({
        emptyCanonicalByteSummary,
        finish: (finishInput: {
            canonicalInput: CanonicalByteSummary;
            canonicalOutput: CanonicalByteSummary;
        }): DesktopBrowserProofMeasurementRecord =>
            measurement.finish({
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
            }),
        observeBuffer,
        wrapExternalMemory,
        wrapInputStore,
        wrapOutputStore,
        wrapPrefixReplayExternalMemory,
    });
};
