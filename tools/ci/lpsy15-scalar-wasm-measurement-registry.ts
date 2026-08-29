import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const completionLpsy15ScalarKernels = Object.freeze({
    evidenceClassification:
        'completion-profile scalar WebAssembly LPSY15 kernel development measurement',
    measurementId: 'lpsy15-completion-scalar-kernels',
    expected: Object.freeze({
        fieldAdditionCount: 75_493_932,
        fieldMultiplicationCount: 76_451_296,
        fieldScratchByteLength: 1_376_256,
        prfCallCount: 1_894_200,
        prfMessageByteLength: 452,
        prfPermutationCountPerCall: 6,
        sampleWorkStepCount: 4,
        workBatchOperationCount: 4_096,
    }),
    limits: Object.freeze({
        maximumCheckpointMilliseconds: 5_000,
        maximumColdRestoreMilliseconds: 30_000,
        maximumCompleteParticipantProcessingMilliseconds: 120 * 60 * 1_000,
        maximumCopiedBufferByteLength:
            foundationProfile.maximumCopiedBufferByteLength,
        maximumUninterruptedWorkMilliseconds: 5_000,
        maximumWasmMemoryByteLength:
            foundationProfile.maximumWasmMemoryByteLength,
    }),
});

export type Lpsy15ScalarWasmMeasurement = typeof completionLpsy15ScalarKernels;

const lpsy15ScalarWasmMeasurementRegistry = Object.freeze({
    [completionLpsy15ScalarKernels.measurementId]:
        completionLpsy15ScalarKernels,
});

export const resolveLpsy15ScalarWasmMeasurement = (
    measurementId: string,
): Lpsy15ScalarWasmMeasurement => {
    const registeredMeasurementIds = Object.keys(
        lpsy15ScalarWasmMeasurementRegistry,
    );
    if (registeredMeasurementIds.length === 0) {
        throw new Error(
            'The LPSY15 scalar WebAssembly measurement registry is empty.',
        );
    }
    const measurement = (
        lpsy15ScalarWasmMeasurementRegistry as Readonly<
            Record<string, Lpsy15ScalarWasmMeasurement>
        >
    )[measurementId];
    if (measurement === undefined) {
        throw new Error(
            `No LPSY15 scalar WebAssembly measurement matches "${measurementId}". Registered measurements: ${registeredMeasurementIds.join(', ')}.`,
        );
    }
    return measurement;
};
