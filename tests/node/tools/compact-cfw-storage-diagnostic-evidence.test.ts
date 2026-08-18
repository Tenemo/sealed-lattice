import { describe, expect, it } from 'vitest';

import {
    validateCompactCfwStorageDiagnosticSchedule,
    validateDesktopBrowserCompactCfwStorageDiagnosticEvidence,
} from '#tools/ci/compact-cfw-storage-diagnostic-evidence';
import { parseDesktopBrowserCompactCfwStorageDiagnosticArguments } from '#tools/ci/run-desktop-browser-compact-cfw-storage-diagnostic';

const selectedSchedule = (): Record<string, unknown> => {
    const rounds = [];
    let outputElementCount = 4_194_304;
    let precedingOutputElementCount = 0;
    for (let roundOrdinal = 0; roundOrdinal < 23; roundOrdinal += 1) {
        rounds.push({
            appendChunkCountPerMatrix: Math.ceil(outputElementCount / 16_384),
            outputElementCount,
            outputObjectByteLength: outputElementCount * 40,
            precedingReadChunkCountPerMatrix:
                roundOrdinal === 0
                    ? 0
                    : Math.ceil(precedingOutputElementCount / 16_384),
            roundOrdinal,
        });
        precedingOutputElementCount = outputElementCount;
        outputElementCount /= 2;
    }
    return {
        appendTransactionCount: 1_575,
        createTransactionCount: 69,
        deleteTransactionCount: 69,
        deterministicSafeBoundaryCount: 2_657,
        extensionElementByteLength: 40,
        matrixCount: 3,
        maximumActiveObjectCount: 4,
        objectLifecycleCount: 69,
        peakStoredByteLength: 587_202_560,
        readTransactionCount: 3_144,
        r1csRowCount: 8_388_608,
        roundCount: 23,
        rounds,
        schemaVersion: 1,
        sealTransactionCount: 69,
        secretSealInvocationCount: 1_713,
        secretSealedPlaintextByteLength: 1_006_633_461,
        stepCount: 70,
        streamChunkByteLength: 655_360,
        streamChunkElementCount: 16_384,
        totalReadByteLength: 2_013_265_440,
        totalTransactionCount: 4_926,
        totalWrittenByteLength: 1_006_632_840,
        witnessElementCount: 4_194_304,
    };
};

const physicalAccounting = (cleanupCompleted: boolean) => ({
    ciphertextReadByteLength: 2_100_000_000,
    ciphertextReadCallCount: 4_000,
    ciphertextWriteByteLength: 1_100_000_000,
    ciphertextWriteCallCount: 2_000,
    cleanupCompleted,
    cleanupDurationMilliseconds: cleanupCompleted ? 1 : 0,
    commitReadbackByteLength: 1_010_000_000,
    commitReadbackCallCount: 1_713,
    deterministicRegeneratedByteLength: 0,
    deterministicRegenerationCallCount: 0,
    deletedByteLength: 1_010_000_000,
    deletionCount: 3_400,
    deletionDurationMilliseconds: 10,
    openCallCount: 3_144,
    openCiphertextByteLength: 2_020_000_000,
    openPlaintextByteLength: 2_013_265_440,
    physicalReadByteLength: 2_100_000_000,
    physicalReadCallCount: 4_000,
    physicalQuotaByteLength: 1_105_000_000,
    physicalQuotaHeadroomByteLength: 5_000_000,
    physicalQuotaReservedByteLength: 1_100_000_000,
    physicalStoredEndByteLength: 206,
    physicalStoredPeakByteLength: 588_000_000,
    physicalStoredStartByteLength: 206,
    physicalWriteByteLength: 1_100_000_000,
    physicalWriteCallCount: 2_000,
    plaintextReadByteLength: 2_013_265_440,
    plaintextReadCallCount: 3_144,
    plaintextWriteByteLength: 1_006_633_461,
    plaintextWriteCallCount: 1_713,
    repairHashCallCount: 10_000,
    repairHashedByteLength: 5_000_000_000,
    sealCallCount: 1_713,
    sealCiphertextByteLength: 1_010_000_000,
    sealPlaintextByteLength: 1_006_633_461,
    storageRequestCount: 5_000,
    storageTransactionCount: 4_900,
});

const primitiveCase = (caseIdentifier: 1 | 2) => ({
    record: {
        caseIdentifier,
        caseName:
            caseIdentifier === 1
                ? 'bounded-phase-lane-dft'
                : 'salted-phase-column-leaf',
        checksumHex: '0123456789abcdef',
        dimensions:
            caseIdentifier === 1
                ? [
                      { name: 'fullDomainSize', value: 16_777_216 },
                      { name: 'laneColumnCount', value: 524_288 },
                      { name: 'butterflyCount', value: 4_980_736 },
                      { name: 'pollCount', value: 83 },
                  ]
                : [
                      { name: 'logicalLeafWidth', value: 1_128 },
                      { name: 'saltByteLength', value: 128 },
                      { name: 'keccakPermutationCount', value: 34_816 },
                  ],
        elapsedNanoseconds: 1,
        executionTarget: 'wasm32-unknown-unknown',
        iterationCount: caseIdentifier === 1 ? 1 : 512,
        modeledPeakLiveByteLength: 1,
        schemaVersion: 2,
    },
    wallElapsedMilliseconds: 1,
    wasmMemoryByteLengthAfter: 65_536,
    wasmMemoryByteLengthBefore: 65_536,
});

const latencyDistribution = (count: number) => ({
    count,
    maximumMilliseconds: 1,
    meanMilliseconds: 1,
    minimumMilliseconds: 1,
    percentile50Milliseconds: 1,
    percentile90Milliseconds: 1,
    percentile95Milliseconds: 1,
    percentile99Milliseconds: 1,
    totalMilliseconds: count,
});

const selectedEvidence = (): Record<string, unknown> => ({
    browserEngine: 'chromium',
    browserUserAgent: 'Chromium test fixture',
    commitLatencyByTransactionKind: {
        append: latencyDistribution(1_575),
        create: latencyDistribution(69),
        delete: latencyDistribution(69),
        read: latencyDistribution(3_144),
        seal: latencyDistribution(69),
    },
    evidenceScope: 'nonqualifying-desktop-chromium-development-diagnostic',
    memoryAndStorageSamples: [
        'before-open',
        'after-open',
        ...Array.from(
            { length: 23 },
            (_unused, roundOrdinal) => `after-round-${String(roundOrdinal)}`,
        ),
        'after-final-deletes',
        'after-custody-cleanup',
    ].map((sampleLabel) => ({ sampleLabel, storageEstimate: {} })),
    observedReadByteLength: 2_013_265_440,
    observedReadChecksumHex: '51d46ff8bc9dd585',
    observedTransactionCount: 4_926,
    observedWrittenByteLength: 1_006_632_840,
    physicalStorageAccountingAfterCleanup: physicalAccounting(true),
    physicalStorageAccountingBeforeCleanup: physicalAccounting(false),
    primitiveCases: [primitiveCase(1), primitiveCase(2)],
    schedule: selectedSchedule(),
    schemaVersion: 1,
    totalElapsedMilliseconds: 5_000,
});

describe('Compact CFW storage diagnostic evidence', () => {
    it('independently reconciles the selected recursive schedule', () => {
        const schedule =
            validateCompactCfwStorageDiagnosticSchedule(selectedSchedule());

        expect(schedule.rounds).toHaveLength(23);
        expect(schedule.rounds[0]).toMatchObject({
            appendChunkCountPerMatrix: 256,
            outputObjectByteLength: 167_772_160,
            precedingReadChunkCountPerMatrix: 0,
        });
        expect(schedule.rounds[22]).toMatchObject({
            appendChunkCountPerMatrix: 1,
            outputElementCount: 1,
            outputObjectByteLength: 40,
            precedingReadChunkCountPerMatrix: 1,
        });
    });

    it('rejects changed totals, recursive geometry, ordinals, and schema fields', () => {
        const changedTotal = {
            ...selectedSchedule(),
            totalReadByteLength: 2_013_265_439,
        };
        expect(() =>
            validateCompactCfwStorageDiagnosticSchedule(changedTotal),
        ).toThrow(/totalReadByteLength/u);

        const changedGeometry = selectedSchedule();
        const changedGeometryRounds = structuredClone(
            changedGeometry.rounds,
        ) as Array<Record<string, unknown>>;
        changedGeometryRounds[11] = {
            ...changedGeometryRounds[11],
            appendChunkCountPerMatrix: 3,
        };
        expect(() =>
            validateCompactCfwStorageDiagnosticSchedule({
                ...changedGeometry,
                rounds: changedGeometryRounds,
            }),
        ).toThrow(/recursively derived geometry/u);

        const changedOrdinal = selectedSchedule();
        const changedOrdinalRounds = structuredClone(
            changedOrdinal.rounds,
        ) as Array<Record<string, unknown>>;
        changedOrdinalRounds[5] = {
            ...changedOrdinalRounds[5],
            roundOrdinal: 6,
        };
        expect(() =>
            validateCompactCfwStorageDiagnosticSchedule({
                ...changedOrdinal,
                rounds: changedOrdinalRounds,
            }),
        ).toThrow(/recursively derived geometry/u);

        expect(() =>
            validateCompactCfwStorageDiagnosticSchedule({
                ...selectedSchedule(),
                producerValidity: true,
            }),
        ).toThrow(/unknown or missing fields/u);
        expect(() =>
            validateCompactCfwStorageDiagnosticSchedule({
                ...selectedSchedule(),
                roundCount: 22.5,
            }),
        ).toThrow(/safe unsigned integer/u);
    });

    it('binds the complete diagnostic to physical custody and overlap evidence', () => {
        expect(
            validateDesktopBrowserCompactCfwStorageDiagnosticEvidence(
                selectedEvidence(),
            ),
        ).toMatchObject({
            observedReadChecksumHex: '51d46ff8bc9dd585',
            observedTransactionCount: 4_926,
        });

        const changedPhysicalAccounting = selectedEvidence();
        changedPhysicalAccounting.physicalStorageAccountingBeforeCleanup = {
            ...physicalAccounting(false),
            plaintextReadByteLength: 2_013_265_439,
        };
        expect(() =>
            validateDesktopBrowserCompactCfwStorageDiagnosticEvidence(
                changedPhysicalAccounting,
            ),
        ).toThrow(/physical custody does not reconcile/u);

        const changedSampleSequence = selectedEvidence();
        const samples = structuredClone(
            changedSampleSequence.memoryAndStorageSamples,
        ) as Array<Record<string, unknown>>;
        samples[12] = { ...samples[12], sampleLabel: 'after-round-99' };
        changedSampleSequence.memoryAndStorageSamples = samples;
        expect(() =>
            validateDesktopBrowserCompactCfwStorageDiagnosticEvidence(
                changedSampleSequence,
            ),
        ).toThrow(/exact storage-overlap sample sequence/u);

        expect(() =>
            validateDesktopBrowserCompactCfwStorageDiagnosticEvidence({
                ...selectedEvidence(),
                observedReadChecksumHex: '0000000000000000',
            }),
        ).toThrow(/compiler-derived schedule/u);
    });

    it('accepts only the explicit scalar-artifact reuse selector', () => {
        expect(
            parseDesktopBrowserCompactCfwStorageDiagnosticArguments([]),
        ).toEqual({ reuseWasm: false });
        expect(
            parseDesktopBrowserCompactCfwStorageDiagnosticArguments([
                '--',
                'reuse-wasm',
            ]),
        ).toEqual({ reuseWasm: true });
        expect(() =>
            parseDesktopBrowserCompactCfwStorageDiagnosticArguments([
                'firefox',
            ]),
        ).toThrow(/only an optional reuse-wasm/u);
        expect(() =>
            parseDesktopBrowserCompactCfwStorageDiagnosticArguments([
                'reuse-wasm',
                'extra',
            ]),
        ).toThrow(/only an optional reuse-wasm/u);
    });
});
