import { describe, expect, it, vi } from 'vitest';

import {
    beginDesktopBrowserProofMeasurement,
    parseDesktopBrowserProofMeasurementRecord,
} from '#tests/support/desktop-browser-proof-measurement';

const validMeasurement = () => ({
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
    outputSha512Hex: 'ab'.repeat(64),
    retainedResidentPeakByteLength: 8192,
    runOrdinal: 3,
    suiteId: 'cd'.repeat(64),
    startedAtUnixMilliseconds: 1_000,
    wasmSha256Hex: 'ef'.repeat(32),
    wasmLinearMemoryEndByteLength: 196_608,
    wasmLinearMemoryPeakByteLength: 262_144,
    wasmLinearMemoryStartByteLength: 131_072,
});

describe('Desktop-browser proof measurements', () => {
    it('accepts exact observations with an absent or complete JavaScript heap sample', () => {
        expect(
            parseDesktopBrowserProofMeasurementRecord(validMeasurement()),
        ).toEqual(validMeasurement());
        const withHeap = {
            ...validMeasurement(),
            javascriptHeapEndByteLength: 12_000,
            javascriptHeapPeakByteLength: 15_000,
            javascriptHeapStartByteLength: 10_000,
        };
        expect(parseDesktopBrowserProofMeasurementRecord(withHeap)).toEqual(
            withHeap,
        );
    });

    it('retains an exact transaction-derived scratch peak between memory samples', () => {
        const consoleInfo = vi
            .spyOn(console, 'info')
            .mockImplementation(() => undefined);
        const measurement = beginDesktopBrowserProofMeasurement({
            caseIdentifier: 'vss-share-linkage-generation-fresh',
            executionKind: 'fresh-generation',
            memoryReaders: {
                externalScratchByteLength: () => 0,
                wasmLinearMemoryByteLength: () => 65_536,
            },
            runOrdinal: 1,
            suiteId: 'cd'.repeat(64),
            wasmSha256Hex: 'ef'.repeat(32),
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
        });

        expect(record.externalScratchPeakByteLength).toBe(4_096);
        expect(consoleInfo).toHaveBeenCalledOnce();
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
            javascriptHeapPeakByteLength: 15_000,
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
