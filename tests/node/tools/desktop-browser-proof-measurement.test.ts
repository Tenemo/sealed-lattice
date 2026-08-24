import { describe, expect, it, vi } from 'vitest';

import {
    beginDesktopBrowserProofMeasurement,
    parseDesktopBrowserProofMeasurementRecord,
    type DesktopBrowserProofResourceAccounting,
} from '#tests/support/desktop-browser-proof-measurement';

const validResourceAccounting = (
    overrides: Partial<DesktopBrowserProofResourceAccounting> = {},
): DesktopBrowserProofResourceAccounting => ({
    cleanupCompleted: true,
    cleanupDeletedByteLength: 4_096,
    cleanupDeletionCount: 1,
    cleanupDurationMilliseconds: 2.5,
    commitReadbackByteLength: 2_048,
    commitReadbackCallCount: 2,
    ciphertextReadByteLength: 8_192,
    ciphertextReadCallCount: 4,
    ciphertextWriteByteLength: 4_096,
    ciphertextWriteCallCount: 2,
    deletionDurationMilliseconds: 1.5,
    deterministicRegeneratedByteLength: 1_024,
    deterministicRegenerationCallCount: 1,
    indexedDbRequestCount: 8,
    indexedDbTransactionCount: 5,
    javascriptToWasmCopyByteLength: 4_096,
    javascriptToWasmCopyCount: 2,
    kernelStorageRequestCount: 3,
    openCallCount: 2,
    openCiphertextByteLength: 4_096,
    openPlaintextByteLength: 4_000,
    physicalQuotaByteLength: 100_000,
    physicalQuotaHeadroomByteLength: 20_000,
    physicalQuotaReservedByteLength: 60_000,
    physicalStoredEndByteLength: 10_000,
    physicalStoredPeakByteLength: 50_000,
    plaintextReadByteLength: 4_000,
    plaintextReadCallCount: 2,
    plaintextWriteByteLength: 3_500,
    plaintextWriteCallCount: 2,
    repairHashCallCount: 1,
    repairHashedByteLength: 2_048,
    sealCallCount: 2,
    sealCiphertextByteLength: 4_096,
    sealPlaintextByteLength: 4_000,
    simultaneousLiveBufferPeakByteLength: 1_048_576,
    simultaneousLiveBufferPeakCount: 2,
    wasmToJavascriptCopyByteLength: 2_048,
    wasmToJavascriptCopyCount: 2,
    workerTransferByteLength: 2_048,
    workerTransferCount: 2,
    ...overrides,
});

const validMeasurement = () => ({
    browserCacheState: 'warm',
    browserProcessResidentMemoryEndByteLength: 1_050_000,
    browserProcessResidentMemoryPeakByteLength: 1_100_000,
    browserProcessResidentMemoryStartByteLength: 1_000_000,
    canonicalInputByteLength: 11,
    canonicalInputSha512Hex: '12'.repeat(64),
    canonicalOutputByteLength: 17,
    caseIdentifier: 'ballot-validity-verification',
    copiedBufferPeakByteLength: 1_048_576,
    durationMilliseconds: 12.5,
    executionKind: 'verification',
    externalScratchPeakByteLength: 4096,
    externalScratchReadByteLength: 8192,
    externalScratchTransactionCount: 3,
    externalScratchWriteByteLength: 4096,
    finishedAtUnixMilliseconds: 1_020,
    fullBufferCopiedByteLength: 3_145_728,
    fullBufferCopyCount: 3,
    observedHostAllocationVolumeByteLength: 4_194_304,
    javascriptHeapEndByteLength: 12_000,
    javascriptHeapPeakByteLength: 15_000,
    javascriptHeapStartByteLength: 10_000,
    outputSha512Hex: 'ab'.repeat(64),
    resourceAccounting: validResourceAccounting(),
    retainedResidentPeakByteLength: 8192,
    runOrdinal: 3,
    suiteId: 'cd'.repeat(64),
    startedAtUnixMilliseconds: 1_000,
    wasmSha256Hex: 'ef'.repeat(32),
    wasmLinearMemoryEndByteLength: 196_608,
    wasmLinearMemoryEndPageCount: 3,
    wasmLinearMemoryPeakByteLength: 262_144,
    wasmLinearMemoryPeakPageCount: 4,
    wasmLinearMemoryStartByteLength: 131_072,
    wasmLinearMemoryStartPageCount: 2,
    workerInstanceIdentifier: 'proof-worker-1',
    workerOperationOrdinal: 1,
});

describe('Desktop-browser proof measurements', () => {
    it('accepts exact observations with complete browser resource measurements', () => {
        expect(
            parseDesktopBrowserProofMeasurementRecord(validMeasurement()),
        ).toEqual(validMeasurement());
    });

    it('retains an exact transaction-derived scratch peak between memory samples', () => {
        const consoleInfo = vi
            .spyOn(console, 'info')
            .mockImplementation(() => undefined);
        const measurement = beginDesktopBrowserProofMeasurement({
            browserCacheState: 'cold',
            caseIdentifier: 'vss-share-linkage-generation-fresh',
            executionKind: 'fresh-generation',
            memoryReaders: {
                browserProcessResidentMemoryByteLength: () => 1_000_000,
                externalScratchByteLength: () => 0,
                javascriptHeapByteLength: () => 10_000,
                retainedResidentByteLength: () => 0,
                wasmLinearMemoryByteLength: () => 65_536,
            },
            runOrdinal: 1,
            suiteId: 'cd'.repeat(64),
            wasmSha256Hex: 'ef'.repeat(32),
            workerInstanceIdentifier: 'proof-worker-2',
            workerOperationOrdinal: 1,
        });

        const record = measurement.finish({
            canonicalInputByteLength: 128,
            canonicalInputSha512Hex: '12'.repeat(64),
            canonicalOutputByteLength: 256,
            copiedBufferPeakByteLength: 128,
            externalScratchPeakByteLength: 4_096,
            externalScratchReadByteLength: 2_048,
            externalScratchTransactionCount: 3,
            externalScratchWriteByteLength: 4_096,
            fullBufferCopiedByteLength: 256,
            fullBufferCopyCount: 2,
            observedHostAllocationVolumeByteLength: 384,
            outputSha512Hex: 'ab'.repeat(64),
            resourceAccounting: validResourceAccounting(),
        });

        expect(record.externalScratchPeakByteLength).toBe(4_096);
        expect(consoleInfo).toHaveBeenCalledOnce();
        consoleInfo.mockRestore();
    });

    it('lets a worker return one record without emitting a duplicate console event', () => {
        const consoleInfo = vi
            .spyOn(console, 'info')
            .mockImplementation(() => undefined);
        const measurement = beginDesktopBrowserProofMeasurement({
            browserCacheState: 'warm',
            caseIdentifier: 'galois-key-share-batch-generation-resumed',
            emitConsoleEvent: false,
            executionKind: 'resumed-generation',
            memoryReaders: {
                browserProcessResidentMemoryByteLength: () => 1_000_000,
                externalScratchByteLength: () => 0,
                javascriptHeapByteLength: () => 10_000,
                retainedResidentByteLength: () => 0,
                wasmLinearMemoryByteLength: () => 65_536,
            },
            runOrdinal: 1,
            suiteId: 'cd'.repeat(64),
            wasmSha256Hex: 'ef'.repeat(32),
            workerInstanceIdentifier: 'proof-worker-3',
            workerOperationOrdinal: 2,
        });

        expect(
            measurement.finish({
                canonicalInputByteLength: 128,
                canonicalInputSha512Hex: '12'.repeat(64),
                canonicalOutputByteLength: 256,
                copiedBufferPeakByteLength: 0,
                externalScratchPeakByteLength: 0,
                externalScratchReadByteLength: 0,
                externalScratchTransactionCount: 0,
                externalScratchWriteByteLength: 0,
                fullBufferCopiedByteLength: 0,
                fullBufferCopyCount: 0,
                observedHostAllocationVolumeByteLength: 0,
                outputSha512Hex: 'ab'.repeat(64),
                resourceAccounting: validResourceAccounting({
                    kernelStorageRequestCount: 0,
                }),
            }).executionKind,
        ).toBe('resumed-generation');
        expect(consoleInfo).not.toHaveBeenCalled();
        consoleInfo.mockRestore();
    });

    it('accepts complete zero copy and scratch accounting groups', () => {
        const record = {
            ...validMeasurement(),
            copiedBufferPeakByteLength: 0,
            externalScratchPeakByteLength: 0,
            externalScratchReadByteLength: 0,
            externalScratchTransactionCount: 0,
            externalScratchWriteByteLength: 0,
            fullBufferCopiedByteLength: 0,
            fullBufferCopyCount: 0,
            observedHostAllocationVolumeByteLength: 0,
            resourceAccounting: validResourceAccounting({
                kernelStorageRequestCount: 0,
            }),
        };

        expect(parseDesktopBrowserProofMeasurementRecord(record)).toEqual(
            record,
        );
    });

    it('requires every accounting instrument field to be present', () => {
        const { fullBufferCopyCount: _omitted, ...record } = validMeasurement();

        expect(() => parseDesktopBrowserProofMeasurementRecord(record)).toThrow(
            /fullBufferCopyCount/u,
        );
    });

    it('requires every detailed physical resource field to be present', () => {
        const {
            indexedDbRequestCount: _omitted,
            ...incompleteResourceAccounting
        } = validResourceAccounting();

        expect(() =>
            parseDesktopBrowserProofMeasurementRecord({
                ...validMeasurement(),
                resourceAccounting: incompleteResourceAccounting,
            }),
        ).toThrow(/exact fields/u);
    });

    it.each([
        {
            ...validMeasurement(),
            caseIdentifier: 'Ballot validity',
        },
        {
            ...validMeasurement(),
            durationMilliseconds: Number.NaN,
        },
        {
            ...validMeasurement(),
            finishedAtUnixMilliseconds: 999,
        },
        {
            ...validMeasurement(),
            javascriptHeapStartByteLength: undefined,
        },
        {
            ...validMeasurement(),
            canonicalInputSha512Hex: '12'.repeat(63),
        },
        {
            ...validMeasurement(),
            outputSha512Hex: 'AB'.repeat(64),
        },
        {
            ...validMeasurement(),
            suiteId: 'CD'.repeat(64),
        },
        {
            ...validMeasurement(),
            wasmSha256Hex: 'ef'.repeat(31),
        },
        {
            ...validMeasurement(),
            wasmLinearMemoryPeakByteLength: 65_536,
        },
        {
            ...validMeasurement(),
            wasmLinearMemoryPeakPageCount: 3,
        },
        {
            ...validMeasurement(),
            browserProcessResidentMemoryPeakByteLength: 999_999,
        },
        {
            ...validMeasurement(),
            executionKind: 'cancelled-generation',
        },
        {
            ...validMeasurement(),
            executionKind: 'deterministic-parity',
        },
        {
            ...validMeasurement(),
            executionKind: 'refused-generation',
        },
        {
            ...validMeasurement(),
            resourceAccounting: validResourceAccounting({
                javascriptToWasmCopyCount: 8,
            }),
        },
        {
            ...validMeasurement(),
            resourceAccounting: validResourceAccounting({
                physicalQuotaReservedByteLength: 40_000,
            }),
        },
        {
            ...validMeasurement(),
            externalScratchTransactionCount: 0,
        },
        {
            ...validMeasurement(),
            fullBufferCopyCount: 0,
        },
        {
            ...validMeasurement(),
            fullBufferCopiedByteLength: 1_048_575,
        },
    ])(
        'rejects malformed or internally inconsistent observations',
        (record) => {
            expect(() =>
                parseDesktopBrowserProofMeasurementRecord(record),
            ).toThrow();
        },
    );
});
