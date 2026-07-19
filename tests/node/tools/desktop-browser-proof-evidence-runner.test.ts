import { describe, expect, it } from 'vitest';

import { validateDesktopBrowserProofMeasurementEvents } from '#tools/ci/run-desktop-browser-proof-evidence';

const exactCaseExecutionKinds = Object.freeze({
    'aggregate-threshold-share-generation': 'fresh-generation',
    'aggregate-threshold-share-verification': 'verification',
    'ballot-validity-generation': 'fresh-generation',
    'ballot-validity-verification': 'verification',
    'evaluator-key-aggregate-generation': 'fresh-generation',
    'evaluator-key-aggregate-verification': 'verification',
    'evaluator-replay-maximum-stream': 'replay',
    'galois-key-share-batch-generation-fresh': 'fresh-generation',
    'galois-key-share-batch-generation-resumed': 'resumed-generation',
    'galois-key-share-batch-verification': 'verification',
    'vss-share-linkage-generation-fresh': 'fresh-generation',
    'vss-share-linkage-generation-resumed': 'resumed-generation',
    'vss-share-linkage-verification': 'verification',
} as const);

const createMeasurementEvent = (
    caseIdentifier: keyof typeof exactCaseExecutionKinds,
) => {
    const executionKind = exactCaseExecutionKinds[caseIdentifier];
    return {
        browser: true,
        canonicalInputByteLength: 11,
        canonicalInputSha512Hex: '12'.repeat(64),
        canonicalOutputByteLength: executionKind === 'verification' ? 0 : 17,
        caseIdentifier,
        copiedBufferPeakByteLength: 1024,
        durationMilliseconds: 12.5,
        event: 'desktop-browser-proof-measurement',
        executionKind,
        externalScratchPeakByteLength: 2048,
        externalScratchReadByteLength: 4096,
        externalScratchTransactionCount: 2,
        externalScratchWriteByteLength: 2048,
        finishedAtUnixMilliseconds: 1_020,
        fullBufferCopiedByteLength: 2048,
        fullBufferCopyCount: 2,
        observedHostAllocationVolumeByteLength: 4096,
        outputSha512Hex: 'ab'.repeat(64),
        retainedResidentPeakByteLength: 4096,
        runOrdinal: 1,
        startedAtUnixMilliseconds: 1_000,
        suiteId: 'cd'.repeat(64),
        wasmLinearMemoryEndByteLength: 196_608,
        wasmLinearMemoryPeakByteLength: 262_144,
        wasmLinearMemoryStartByteLength: 131_072,
        wasmSha256Hex: 'ef'.repeat(32),
    };
};

const createExactMeasurementEvents = () =>
    Object.keys(exactCaseExecutionKinds).map((caseIdentifier) =>
        createMeasurementEvent(
            caseIdentifier as keyof typeof exactCaseExecutionKinds,
        ),
    );

describe('Desktop-browser proof-evidence runner', () => {
    it('accepts exact contiguous repetitions for one suite and one Wasm module', () => {
        const exactEvents = createExactMeasurementEvents();
        const repeatedCase = {
            ...exactEvents[0],
            finishedAtUnixMilliseconds: 1_040,
            runOrdinal: 2,
            startedAtUnixMilliseconds: 1_021,
        };
        expect(
            validateDesktopBrowserProofMeasurementEvents(
                [...exactEvents, repeatedCase],
                {
                    wasmSha256Hex: 'ef'.repeat(32),
                },
            ),
        ).toHaveLength(Object.keys(exactCaseExecutionKinds).length + 1);
    });

    it('accepts exact zero copy, allocation, and scratch observations', () => {
        const exactEvents = createExactMeasurementEvents().map(
            (event, eventIndex) =>
                eventIndex === 0
                    ? {
                          ...event,
                          copiedBufferPeakByteLength: 0,
                          externalScratchPeakByteLength: 0,
                          externalScratchReadByteLength: 0,
                          externalScratchTransactionCount: 0,
                          externalScratchWriteByteLength: 0,
                          fullBufferCopiedByteLength: 0,
                          fullBufferCopyCount: 0,
                          observedHostAllocationVolumeByteLength: 0,
                      }
                    : event,
        );

        expect(
            validateDesktopBrowserProofMeasurementEvents(exactEvents),
        ).toHaveLength(Object.keys(exactCaseExecutionKinds).length);
    });

    it('rejects missing, duplicate, unexpected, or wrongly classified cases', () => {
        const exactEvents = createExactMeasurementEvents();
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(exactEvents.slice(1)),
        ).toThrow(/omitted required cases/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents([
                ...exactEvents,
                exactEvents[0],
            ]),
        ).toThrow(/more than once/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents([
                ...exactEvents,
                { ...exactEvents[0], runOrdinal: 3 },
            ]),
        ).toThrow(/contiguous from one/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents([
                ...exactEvents,
                {
                    ...exactEvents[0],
                    caseIdentifier: 'unregistered-proof-case',
                },
            ]),
        ).toThrow(/unexpected case/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? { ...event, executionKind: 'verification' }
                        : event,
                ),
            ),
        ).toThrow(/expected fresh-generation/u);
    });

    it('rejects non-browser records and mixed suite or Wasm bindings', () => {
        const exactEvents = createExactMeasurementEvents();
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0 ? { ...event, browser: false } : event,
                ),
            ),
        ).toThrow(/non-browser measurement/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? { ...event, suiteId: '12'.repeat(64) }
                        : event,
                ),
            ),
        ).toThrow(/one exact suite/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? { ...event, wasmSha256Hex: '34'.repeat(32) }
                        : event,
                ),
            ),
        ).toThrow(/one exact suite/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(exactEvents, {
                wasmSha256Hex: '34'.repeat(32),
            }),
        ).toThrow(/module produced by this build/u);
    });

    it('rejects placeholder byte accounting and absolute-bound overruns', () => {
        const exactEvents = createExactMeasurementEvents();
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? { ...event, canonicalInputByteLength: 0 }
                        : event,
                ),
            ),
        ).toThrow(/zero canonical input/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? {
                              ...event,
                              wasmLinearMemoryPeakByteLength: 671_088_641,
                          }
                        : event,
                ),
            ),
        ).toThrow(/absolute WebAssembly linear-memory peak bound/u);
        expect(() =>
            validateDesktopBrowserProofMeasurementEvents(
                exactEvents.map((event, eventIndex) =>
                    eventIndex === 0
                        ? {
                              ...event,
                              copiedBufferPeakByteLength: 8_388_609,
                              fullBufferCopiedByteLength: 8_388_609,
                          }
                        : event,
                ),
            ),
        ).toThrow(/absolute single copied-buffer bound/u);
    });
});
