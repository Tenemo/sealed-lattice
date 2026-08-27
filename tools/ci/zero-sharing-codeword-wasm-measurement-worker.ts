import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { buildOptimizedWasmKernelArtifact } from './build-wasm-kernel.js';
import {
    resolveZeroSharingCodewordWasmMeasurement,
    type ZeroSharingCodewordWasmMeasurement,
} from './zero-sharing-codeword-wasm-measurement-registry.js';
import {
    copySecretOutput,
    distribution,
    executeCursor,
    instantiateMeasurement,
    numberFromUnsigned64,
    parseZeroSharingWasmMeasurementWorkerArguments,
    requireEqual,
    type MeasurementExports,
} from './zero-sharing-wasm-measurement-worker.js';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const repositoryRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const measurementTemporaryRoot = path.resolve(
    repositoryRoot,
    'temp',
    'build-scratch',
    'zero-sharing-codeword-wasm-measurements',
);
const measurementCargoTargetDirectory = path.resolve(
    repositoryRoot,
    'target',
    'wasm-zero-sharing-measurement',
);
const fieldElementByteLength = 40;
const measurementError = 0xffff_ffff;
const invalidCodeword = 1;

const unsignedStatus = (value: number): number => value >>> 0;

type ProcessMemoryExtrema = {
    arrayBufferByteLength: number;
    externalByteLength: number;
    heapUsedByteLength: number;
    residentSetByteLength: number;
};

const restoreSourceCheckpoint = (
    exports: MeasurementExports,
    participantPosition: number,
    checkpoint: Uint8Array,
): void => {
    const checkpointPointer = exports.allocate(checkpoint.byteLength);
    if (checkpointPointer === 0) {
        throw new Error(
            'The diagnostic kernel could not allocate checkpoint input.',
        );
    }
    new Uint8Array(
        exports.memory.buffer,
        checkpointPointer,
        checkpoint.byteLength,
    ).set(checkpoint);
    const result = unsignedStatus(
        exports.restoreSource(
            participantPosition,
            checkpointPointer,
            checkpoint.byteLength,
        ),
    );
    exports.deallocateSecret(checkpointPointer, checkpoint.byteLength);
    if (result !== 0) {
        throw new Error(
            `Diagnostic source checkpoint restoration failed with ${result}.`,
        );
    }
};

const executeSourceCursor = (input: {
    readonly captureCheckpointAtWorkStep?: number;
    readonly expectedOutputChunkByteLengths: readonly number[];
    readonly expectedWorkStepCount: number;
    readonly exports: MeasurementExports;
    readonly outputLengthPointer: number;
}) => executeCursor({ ...input, retainCompletedOutputs: true });

const invokeCodewordVerification = (
    exports: MeasurementExports,
    block: Uint8Array,
): Readonly<{ elapsedMilliseconds: number; result: number }> => {
    const inputPointer = exports.allocate(block.byteLength);
    if (inputPointer === 0) {
        throw new Error(
            'The diagnostic kernel could not allocate a codeword block.',
        );
    }
    new Uint8Array(exports.memory.buffer, inputPointer, block.byteLength).set(
        block,
    );
    const start = performance.now();
    const result = unsignedStatus(
        exports.verifyCodewordBlock(inputPointer, block.byteLength),
    );
    const elapsedMilliseconds = performance.now() - start;
    exports.deallocateSecret(inputPointer, block.byteLength);
    return Object.freeze({ elapsedMilliseconds, result });
};

const sourceFieldBytes = (
    participantOutputs: readonly Uint8Array[],
    outputChunkByteLengths: readonly number[],
    fieldOrdinal: number,
): Uint8Array => {
    let remainingFieldOrdinal = fieldOrdinal;
    for (
        let chunkPosition = 0;
        chunkPosition < outputChunkByteLengths.length;
        chunkPosition += 1
    ) {
        const chunkByteLength = outputChunkByteLengths[chunkPosition];
        const chunk = participantOutputs[chunkPosition];
        if (chunkByteLength === undefined || chunk === undefined) {
            throw new Error('The participant source chunk set is incomplete.');
        }
        const chunkFieldCount = chunkByteLength / fieldElementByteLength;
        if (remainingFieldOrdinal < chunkFieldCount) {
            const byteOffset = remainingFieldOrdinal * fieldElementByteLength;
            return chunk.subarray(
                byteOffset,
                byteOffset + fieldElementByteLength,
            );
        }
        remainingFieldOrdinal -= chunkFieldCount;
    }
    throw new Error(`Source field ordinal ${fieldOrdinal} is out of range.`);
};

const buildFieldMajorBlock = (input: {
    readonly codewordCount: number;
    readonly firstCodewordOrdinal: number;
    readonly outputChunkByteLengths: readonly number[];
    readonly participantOutputs: readonly (readonly Uint8Array[])[];
}): Uint8Array => {
    const participantCount = input.participantOutputs.length;
    const block = new Uint8Array(
        input.codewordCount * participantCount * fieldElementByteLength,
    );
    for (
        let codewordOffset = 0;
        codewordOffset < input.codewordCount;
        codewordOffset += 1
    ) {
        const fieldOrdinal = input.firstCodewordOrdinal + codewordOffset;
        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            const participantOutput =
                input.participantOutputs[participantPosition];
            if (participantOutput === undefined) {
                throw new Error(
                    `Source output for participant ${participantPosition} is absent.`,
                );
            }
            const destinationOffset =
                (codewordOffset * participantCount + participantPosition) *
                fieldElementByteLength;
            block.set(
                sourceFieldBytes(
                    participantOutput,
                    input.outputChunkByteLengths,
                    fieldOrdinal,
                ),
                destinationOffset,
            );
        }
    }
    return block;
};

const fieldMask = (1n << 320n) - 1n;
const reductionLow = (1n << 117n) | (1n << 86n) | (1n << 21n) | 1n;

const multiplyBinaryField320 = (left: bigint, right: bigint): bigint => {
    let product = 0n;
    let shiftedMultiplicand = left;
    let remainingMultiplier = right;
    for (let bitPosition = 0; bitPosition < 320; bitPosition += 1) {
        if ((remainingMultiplier & 1n) === 1n) {
            product ^= shiftedMultiplicand;
        }
        remainingMultiplier >>= 1n;
        const reductionBit = shiftedMultiplicand >> 319n;
        shiftedMultiplicand = (shiftedMultiplicand << 1n) & fieldMask;
        if (reductionBit === 1n) {
            shiftedMultiplicand ^= reductionLow;
        }
    }
    return product;
};

const invertBinaryField320 = (value: bigint): bigint => {
    if (value === 0n) {
        throw new Error('The independent field oracle cannot invert zero.');
    }
    let accumulatedPower = value;
    for (let fixedPowerStep = 0; fixedPowerStep < 318; fixedPowerStep += 1) {
        accumulatedPower = multiplyBinaryField320(
            multiplyBinaryField320(accumulatedPower, accumulatedPower),
            value,
        );
    }
    return multiplyBinaryField320(accumulatedPower, accumulatedPower);
};

const fieldFromCanonicalBytes = (bytes: Uint8Array): bigint => {
    if (bytes.byteLength !== fieldElementByteLength) {
        throw new Error('The independent field oracle requires 40 bytes.');
    }
    let value = 0n;
    for (
        let bytePosition = bytes.length - 1;
        bytePosition >= 0;
        bytePosition -= 1
    ) {
        value = (value << 8n) | BigInt(bytes[bytePosition] ?? 0);
    }
    return value;
};

const deriveInterpolationCoefficients = (): readonly (readonly bigint[])[] => {
    const basisPoints = Object.freeze(
        Array.from({ length: 7 }, (_, position) => BigInt(position + 1)),
    );
    const inverseDenominators = basisPoints.map(
        (selectedPoint, selectedPosition) => {
            let denominator = 1n;
            for (
                let otherPosition = 0;
                otherPosition < basisPoints.length;
                otherPosition += 1
            ) {
                if (otherPosition === selectedPosition) continue;
                denominator = multiplyBinaryField320(
                    denominator,
                    selectedPoint ^ (basisPoints[otherPosition] ?? 0n),
                );
            }
            return invertBinaryField320(denominator);
        },
    );
    return Object.freeze(
        [0n, 8n, 9n, 10n].map((evaluationPoint) =>
            Object.freeze(
                basisPoints.map((_, selectedPosition) => {
                    let numerator = 1n;
                    for (
                        let otherPosition = 0;
                        otherPosition < basisPoints.length;
                        otherPosition += 1
                    ) {
                        if (otherPosition === selectedPosition) continue;
                        numerator = multiplyBinaryField320(
                            numerator,
                            evaluationPoint ^
                                (basisPoints[otherPosition] ?? 0n),
                        );
                    }
                    return multiplyBinaryField320(
                        numerator,
                        inverseDenominators[selectedPosition] ?? 0n,
                    );
                }),
            ),
        ),
    );
};

const independentlyVerifyCodeword = (
    values: readonly bigint[],
    interpolationCoefficients: readonly (readonly bigint[])[],
): boolean => {
    if (values.length !== 10 || interpolationCoefficients.length !== 4) {
        throw new Error('The independent codeword oracle geometry is invalid.');
    }
    const expectedTargets = [
        0n,
        values[7] ?? 0n,
        values[8] ?? 0n,
        values[9] ?? 0n,
    ];
    return interpolationCoefficients.every((coefficients, targetPosition) => {
        let interpolated = 0n;
        for (
            let basisPosition = 0;
            basisPosition < coefficients.length;
            basisPosition += 1
        ) {
            interpolated ^= multiplyBinaryField320(
                values[basisPosition] ?? 0n,
                coefficients[basisPosition] ?? 0n,
            );
        }
        return interpolated === expectedTargets[targetPosition];
    });
};

const verifyIndependentOracleSamples = (input: {
    readonly codewordOrdinals: readonly number[];
    readonly interpolationCoefficients: readonly (readonly bigint[])[];
    readonly outputChunkByteLengths: readonly number[];
    readonly participantOutputs: readonly (readonly Uint8Array[])[];
}): number => {
    const start = performance.now();
    for (const codewordOrdinal of input.codewordOrdinals) {
        const values = input.participantOutputs.map((participantOutput) =>
            fieldFromCanonicalBytes(
                sourceFieldBytes(
                    participantOutput,
                    input.outputChunkByteLengths,
                    codewordOrdinal,
                ),
            ),
        );
        if (
            !independentlyVerifyCodeword(
                values,
                input.interpolationCoefficients,
            )
        ) {
            throw new Error(
                `The independent interpolation oracle rejected source codeword ${codewordOrdinal}.`,
            );
        }
    }
    const firstOrdinal = input.codewordOrdinals[0];
    if (firstOrdinal === undefined) {
        throw new Error('The independent interpolation sample is empty.');
    }
    const firstValues = input.participantOutputs.map((participantOutput) =>
        fieldFromCanonicalBytes(
            sourceFieldBytes(
                participantOutput,
                input.outputChunkByteLengths,
                firstOrdinal,
            ),
        ),
    );
    for (
        let participantPosition = 0;
        participantPosition < firstValues.length;
        participantPosition += 1
    ) {
        const invalidValues = [...firstValues];
        invalidValues[participantPosition] =
            (invalidValues[participantPosition] ?? 0n) ^ 1n;
        if (
            independentlyVerifyCodeword(
                invalidValues,
                input.interpolationCoefficients,
            )
        ) {
            throw new Error(
                `The independent interpolation oracle accepted a mutation at participant ${participantPosition}.`,
            );
        }
    }
    return performance.now() - start;
};

const verifyRustResourceModel = (
    exports: MeasurementExports,
    measurement: ZeroSharingCodewordWasmMeasurement,
) => {
    const actual = Object.freeze({
        absoluteCodewordCountPerBlock: numberFromUnsigned64(
            exports.codewordMaximumBlockCount(),
            'absolute codeword count per block',
        ),
        basisStreamCountPerParticipant: numberFromUnsigned64(
            exports.basisStreamCount(),
            'basis stream count per participant',
        ),
        codewordByteLength: numberFromUnsigned64(
            exports.codewordByteLength(),
            'codeword byte length',
        ),
        comparisonCountPerCodeword: numberFromUnsigned64(
            exports.codewordComparisonCount(),
            'comparison count per codeword',
        ),
        fieldAdditionCountPerCodeword: numberFromUnsigned64(
            exports.codewordAdditionCount(),
            'field addition count per codeword',
        ),
        fieldMultiplicationCountPerCodeword: numberFromUnsigned64(
            exports.codewordMultiplicationCount(),
            'field multiplication count per codeword',
        ),
        outputChunkCountPerParticipant: numberFromUnsigned64(
            exports.outputChunkCount(),
            'output chunk count per participant',
        ),
        workCheckpointCountPerParticipant: numberFromUnsigned64(
            exports.workCheckpointCount(),
            'work checkpoint count per participant',
        ),
        zeroSharingCount: numberFromUnsigned64(
            exports.zeroSharingCount(),
            'zero-sharing count',
        ),
    });
    for (const [field, actualValue] of Object.entries(actual)) {
        const expectedValue =
            measurement.expected[field as keyof typeof measurement.expected];
        if (typeof expectedValue !== 'number') {
            throw new Error(`The independent model omits ${field}.`);
        }
        requireEqual(actualValue, expectedValue, field);
    }
    return actual;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((byte, position) => byte === right[position]);

const updateProcessMemoryExtrema = (extrema: ProcessMemoryExtrema): void => {
    const memory = process.memoryUsage();
    extrema.arrayBufferByteLength = Math.max(
        extrema.arrayBufferByteLength,
        memory.arrayBuffers,
    );
    extrema.externalByteLength = Math.max(
        extrema.externalByteLength,
        memory.external,
    );
    extrema.heapUsedByteLength = Math.max(
        extrema.heapUsedByteLength,
        memory.heapUsed,
    );
    extrema.residentSetByteLength = Math.max(
        extrema.residentSetByteLength,
        memory.rss,
    );
};

export const runZeroSharingCodewordWasmMeasurementWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments =
        parseZeroSharingWasmMeasurementWorkerArguments(rawArguments);
    const measurement = resolveZeroSharingCodewordWasmMeasurement(
        parsedArguments.measurementId,
    );
    await mkdir(measurementTemporaryRoot, { recursive: true });
    const temporaryDirectoryPath = await mkdtemp(
        path.join(measurementTemporaryRoot, 'run-'),
    );
    try {
        const wasmOutputFilePath = path.join(
            temporaryDirectoryPath,
            'kernel.wasm',
        );
        const builtArtifact = await buildOptimizedWasmKernelArtifact({
            artifactLabel: 'All-roster zero-codeword measurement kernel',
            cargoFeatures: ['preparation-zero-sharing-measurement'],
            outputFilePath: wasmOutputFilePath,
            scratchDirectoryPrefix: 'zero-sharing-codeword-measurement-',
            targetDirectoryPath: measurementCargoTargetDirectory,
        });
        const wasmBytes = await readFile(wasmOutputFilePath);

        const warmup = await instantiateMeasurement(wasmBytes);
        if (
            warmup.exports.openSource(0) !== 0 ||
            unsignedStatus(warmup.exports.step()) === measurementError
        ) {
            throw new Error('The scalar WebAssembly source warmup failed.');
        }
        const warmupLengthPointer = warmup.exports.allocate(4);
        const warmupCheckpoint = copySecretOutput(
            warmup.exports,
            warmup.exports.checkpoint,
            warmupLengthPointer,
        );
        warmupCheckpoint.fill(0);
        warmup.exports.deallocate(warmupLengthPointer, 4);
        if (warmup.exports.close() !== 0) {
            throw new Error(
                'The scalar WebAssembly source warmup did not close.',
            );
        }
        const zeroCodeword = new Uint8Array(
            measurement.expected.codewordByteLength,
        );
        const warmupVerification = invokeCodewordVerification(
            warmup.exports,
            zeroCodeword,
        );
        zeroCodeword.fill(0);
        if (warmupVerification.result !== 0) {
            throw new Error(
                'The scalar WebAssembly codeword verifier warmup failed.',
            );
        }
        const warmupMisalignedBlock = new Uint8Array(
            measurement.expected.codewordByteLength - 1,
        );
        const warmupMisalignedVerification = invokeCodewordVerification(
            warmup.exports,
            warmupMisalignedBlock,
        );
        warmupMisalignedBlock.fill(0);
        if (
            warmupMisalignedVerification.result !== measurementError ||
            unsignedStatus(warmup.exports.verifyCodewordBlock(0, 0)) !==
                measurementError
        ) {
            throw new Error(
                'The scalar WebAssembly verifier did not reject malformed block boundaries.',
            );
        }

        const instantiated = await instantiateMeasurement(wasmBytes);
        const exports = instantiated.exports;
        const linearMemoryByteLengthBeforeOpen =
            exports.memory.buffer.byteLength;
        const processMemoryExtrema: ProcessMemoryExtrema = {
            arrayBufferByteLength: 0,
            externalByteLength: 0,
            heapUsedByteLength: 0,
            residentSetByteLength: 0,
        };
        updateProcessMemoryExtrema(processMemoryExtrema);
        const participantOutputs: Uint8Array[][] = [];
        const participantOutputDigests: string[][] = [];
        const sourceOpenDurationsMilliseconds: number[] = [];
        const sourceStepDurationsMilliseconds: number[] = [];
        const sourceCheckpointDurationsMilliseconds: number[] = [];
        const sourceParticipantDurationsMilliseconds: number[] = [];
        let baselineCheckpointCopiedByteLength = 0;
        let baselineWorkStepCount = 0;
        let maximumLinearMemoryByteLength = linearMemoryByteLengthBeforeOpen;
        let rustResourceModel:
            | ReturnType<typeof verifyRustResourceModel>
            | undefined;
        let restoration:
            | Readonly<{
                  captureCheckpointAtWorkStep: number;
                  checkpointByteLength: number;
                  coldRestoreElapsedMilliseconds: number;
                  maximumLinearMemoryByteLength: number;
                  remainingCheckpointCopiedByteLength: number;
                  remainingTotalElapsedMilliseconds: number;
                  remainingWorkStepCount: number;
              }>
            | undefined;

        for (
            let participantPosition = 0;
            participantPosition < measurement.expected.participantCount;
            participantPosition += 1
        ) {
            const openStart = performance.now();
            if (exports.openSource(participantPosition) !== 0) {
                throw new Error(
                    `Completion source cursor ${participantPosition} did not open.`,
                );
            }
            sourceOpenDurationsMilliseconds.push(performance.now() - openStart);
            rustResourceModel ??= verifyRustResourceModel(exports, measurement);
            const outputLengthPointer = exports.allocate(4);
            if (outputLengthPointer === 0) {
                throw new Error(
                    'The source measurement length slot could not be allocated.',
                );
            }
            const captureCheckpointAtWorkStep =
                participantPosition === 0
                    ? Math.floor(
                          measurement.expected
                              .workCheckpointCountPerParticipant / 4,
                      )
                    : undefined;
            const execution = executeSourceCursor({
                ...(captureCheckpointAtWorkStep === undefined
                    ? {}
                    : { captureCheckpointAtWorkStep }),
                expectedOutputChunkByteLengths:
                    measurement.expected.outputChunkByteLengths,
                expectedWorkStepCount:
                    measurement.expected.workCheckpointCountPerParticipant,
                exports,
                outputLengthPointer,
            });
            const completedOutputs = execution.completedOutputs;
            if (completedOutputs === undefined) {
                throw new Error(
                    'The source cursor did not retain its completed outputs.',
                );
            }
            exports.deallocate(outputLengthPointer, 4);
            baselineCheckpointCopiedByteLength +=
                execution.checkpointCopiedByteLength;
            baselineWorkStepCount += execution.workStepCount;
            sourceStepDurationsMilliseconds.push(
                ...execution.stepDurationsMilliseconds,
            );
            sourceCheckpointDurationsMilliseconds.push(
                ...execution.checkpointDurationsMilliseconds,
            );
            sourceParticipantDurationsMilliseconds.push(
                execution.totalElapsedMilliseconds,
            );
            participantOutputs.push([...completedOutputs]);
            participantOutputDigests.push([
                ...execution.completedOutputDigests,
            ]);
            maximumLinearMemoryByteLength = Math.max(
                maximumLinearMemoryByteLength,
                execution.maximumLinearMemoryByteLength,
                exports.memory.buffer.byteLength,
            );
            if (exports.close() !== 0) {
                throw new Error(
                    `Completion source cursor ${participantPosition} did not close.`,
                );
            }

            if (participantPosition === 0) {
                const checkpoint = execution.capturedCheckpoint;
                if (
                    checkpoint === undefined ||
                    captureCheckpointAtWorkStep === undefined
                ) {
                    throw new Error(
                        'The deterministic source restoration checkpoint is absent.',
                    );
                }
                const restoreStart = performance.now();
                restoreSourceCheckpoint(
                    exports,
                    participantPosition,
                    checkpoint,
                );
                const coldRestoreElapsedMilliseconds =
                    performance.now() - restoreStart;
                checkpoint.fill(0);
                const restoredLengthPointer = exports.allocate(4);
                const restoredExecution = executeSourceCursor({
                    expectedOutputChunkByteLengths:
                        measurement.expected.outputChunkByteLengths,
                    expectedWorkStepCount:
                        measurement.expected.workCheckpointCountPerParticipant -
                        captureCheckpointAtWorkStep,
                    exports,
                    outputLengthPointer: restoredLengthPointer,
                });
                const restoredCompletedOutputs =
                    restoredExecution.completedOutputs;
                if (restoredCompletedOutputs === undefined) {
                    throw new Error(
                        'The restored source cursor did not retain its completed outputs.',
                    );
                }
                exports.deallocate(restoredLengthPointer, 4);
                if (
                    restoredCompletedOutputs.length !== completedOutputs.length
                ) {
                    throw new Error(
                        'Cold restoration changed the source output chunk count.',
                    );
                }
                for (
                    let chunkPosition = 0;
                    chunkPosition < completedOutputs.length;
                    chunkPosition += 1
                ) {
                    const baselineOutput = completedOutputs[chunkPosition];
                    const restoredOutput =
                        restoredCompletedOutputs[chunkPosition];
                    if (
                        baselineOutput === undefined ||
                        restoredOutput === undefined ||
                        !bytesEqual(baselineOutput, restoredOutput)
                    ) {
                        throw new Error(
                            `Cold restoration changed source output chunk ${chunkPosition}.`,
                        );
                    }
                    restoredOutput.fill(0);
                }
                if (exports.close() !== 0) {
                    throw new Error(
                        'The restored completion source cursor did not close.',
                    );
                }
                restoration = Object.freeze({
                    captureCheckpointAtWorkStep,
                    checkpointByteLength:
                        execution.checkpointByteLengths[
                            captureCheckpointAtWorkStep - 1
                        ] ?? 0,
                    coldRestoreElapsedMilliseconds,
                    maximumLinearMemoryByteLength:
                        restoredExecution.maximumLinearMemoryByteLength,
                    remainingCheckpointCopiedByteLength:
                        restoredExecution.checkpointCopiedByteLength,
                    remainingTotalElapsedMilliseconds:
                        restoredExecution.totalElapsedMilliseconds,
                    remainingWorkStepCount: restoredExecution.workStepCount,
                });
                maximumLinearMemoryByteLength = Math.max(
                    maximumLinearMemoryByteLength,
                    restoredExecution.maximumLinearMemoryByteLength,
                    exports.memory.buffer.byteLength,
                );
            }
            updateProcessMemoryExtrema(processMemoryExtrema);
        }

        if (rustResourceModel === undefined || restoration === undefined) {
            throw new Error(
                'The source measurement did not produce its resource or restoration record.',
            );
        }
        requireEqual(
            baselineCheckpointCopiedByteLength,
            measurement.expected.cumulativeCheckpointByteLengthAllParticipants,
            'all-participant checkpoint copied byte length',
        );
        requireEqual(
            baselineWorkStepCount,
            measurement.expected.workCheckpointCountAllParticipants,
            'all-participant work checkpoint count',
        );
        const sourceOutputByteLength = participantOutputs.reduce(
            (allParticipantTotal, outputChunks) =>
                allParticipantTotal +
                outputChunks.reduce(
                    (participantTotal, chunk) =>
                        participantTotal + chunk.byteLength,
                    0,
                ),
            0,
        );
        requireEqual(
            sourceOutputByteLength,
            measurement.expected.sourceOutputByteLengthAllParticipants,
            'all-participant source output byte length',
        );

        const interpolationStart = performance.now();
        const interpolationCoefficients = deriveInterpolationCoefficients();
        const interpolationSetupElapsedMilliseconds =
            performance.now() - interpolationStart;
        const independentOracleElapsedMilliseconds =
            verifyIndependentOracleSamples({
                codewordOrdinals:
                    measurement.expected.independentlyCheckedCodewordOrdinals,
                interpolationCoefficients,
                outputChunkByteLengths:
                    measurement.expected.outputChunkByteLengths,
                participantOutputs,
            });

        const verificationDurationsMilliseconds: number[] = [];
        const transpositionDurationsMilliseconds: number[] = [];
        const observedVerificationBlockByteLengths: number[] = [];
        const fieldMajorDigest = createHash('sha3-512');
        let firstCodewordOrdinal = 0;
        for (const expectedBlockByteLength of measurement.expected
            .verificationBlockByteLengths) {
            const codewordCount =
                expectedBlockByteLength /
                measurement.expected.codewordByteLength;
            const transpositionStart = performance.now();
            const block = buildFieldMajorBlock({
                codewordCount,
                firstCodewordOrdinal,
                outputChunkByteLengths:
                    measurement.expected.outputChunkByteLengths,
                participantOutputs,
            });
            transpositionDurationsMilliseconds.push(
                performance.now() - transpositionStart,
            );
            observedVerificationBlockByteLengths.push(block.byteLength);
            requireEqual(
                block.byteLength,
                expectedBlockByteLength,
                'verification block byte length',
            );
            if (
                block.byteLength >
                measurement.expected.copiedBufferPlanningTargetByteLength
            ) {
                throw new Error(
                    'A verification block exceeds the copied-buffer planning target.',
                );
            }
            fieldMajorDigest.update(block);
            const verification = invokeCodewordVerification(exports, block);
            verificationDurationsMilliseconds.push(
                verification.elapsedMilliseconds,
            );
            if (verification.result !== 0) {
                throw new Error(
                    `The scalar WebAssembly verifier rejected block beginning at ${firstCodewordOrdinal}.`,
                );
            }
            firstCodewordOrdinal += codewordCount;
            block.fill(0);
            maximumLinearMemoryByteLength = Math.max(
                maximumLinearMemoryByteLength,
                exports.memory.buffer.byteLength,
            );
            updateProcessMemoryExtrema(processMemoryExtrema);
        }
        requireEqual(
            firstCodewordOrdinal,
            measurement.expected.zeroSharingCount,
            'verified codeword count',
        );
        if (
            JSON.stringify(observedVerificationBlockByteLengths) !==
            JSON.stringify(measurement.expected.verificationBlockByteLengths)
        ) {
            throw new Error(
                'Observed verification block geometry differs from the independent model.',
            );
        }

        const invalidVerificationDurationsMilliseconds: number[] = [];
        for (
            let participantPosition = 0;
            participantPosition < measurement.expected.participantCount;
            participantPosition += 1
        ) {
            const invalidBlock = buildFieldMajorBlock({
                codewordCount: 1,
                firstCodewordOrdinal: 0,
                outputChunkByteLengths:
                    measurement.expected.outputChunkByteLengths,
                participantOutputs,
            });
            invalidBlock[participantPosition * fieldElementByteLength] ^= 1;
            const invalidVerification = invokeCodewordVerification(
                exports,
                invalidBlock,
            );
            invalidVerificationDurationsMilliseconds.push(
                invalidVerification.elapsedMilliseconds,
            );
            invalidBlock.fill(0);
            if (invalidVerification.result !== invalidCodeword) {
                throw new Error(
                    `The scalar WebAssembly verifier accepted or malformed a participant-${participantPosition} mutation.`,
                );
            }
        }
        for (const outputChunks of participantOutputs) {
            for (const chunk of outputChunks) chunk.fill(0);
        }
        updateProcessMemoryExtrema(processMemoryExtrema);
        if (
            maximumLinearMemoryByteLength >
            foundationProfile.maximumWasmMemoryByteLength
        ) {
            throw new Error(
                `The scalar WebAssembly path used ${maximumLinearMemoryByteLength} bytes of linear memory; absolute maximum is ${foundationProfile.maximumWasmMemoryByteLength}.`,
            );
        }

        const result = Object.freeze({
            schemaVersion: 1,
            measurementId: measurement.measurementId,
            evidenceClassification: measurement.evidenceClassification,
            environment: Object.freeze({
                architecture: process.arch,
                nodeVersion: process.version,
                platform: process.platform,
                scalarBuild: true,
                simdRequired: false,
                singleWorker: true,
            }),
            build: Object.freeze({
                exports: instantiated.exportNames,
                normalizedSha256Hex: builtArtifact.normalizedSha256Hex,
                wasmByteLength: wasmBytes.byteLength,
            }),
            independentModel: measurement.expected,
            rustResourceModel,
            execution: Object.freeze({
                sourceGeneration: Object.freeze({
                    checkpointCopiedByteLength:
                        baselineCheckpointCopiedByteLength,
                    checkpointDurationMilliseconds: distribution(
                        sourceCheckpointDurationsMilliseconds,
                    ),
                    openDurationMilliseconds: distribution(
                        sourceOpenDurationsMilliseconds,
                    ),
                    outputByteLength: sourceOutputByteLength,
                    participantDurationMilliseconds: distribution(
                        sourceParticipantDurationsMilliseconds,
                    ),
                    participantOutputDigests,
                    stepDurationMilliseconds: distribution(
                        sourceStepDurationsMilliseconds,
                    ),
                    workStepCount: baselineWorkStepCount,
                }),
                restoration,
                independentInterpolationOracle: Object.freeze({
                    checkedCodewordOrdinals:
                        measurement.expected
                            .independentlyCheckedCodewordOrdinals,
                    interpolationSetupElapsedMilliseconds,
                    mutationCount: measurement.expected.participantCount,
                    verificationElapsedMilliseconds:
                        independentOracleElapsedMilliseconds,
                }),
                codewordVerification: Object.freeze({
                    fieldMajorSha3_512Hex: fieldMajorDigest.digest('hex'),
                    invalidMutationCount: measurement.expected.participantCount,
                    invalidVerificationDurationMilliseconds: distribution(
                        invalidVerificationDurationsMilliseconds,
                    ),
                    observedBlockByteLengths:
                        observedVerificationBlockByteLengths,
                    transpositionDurationMilliseconds: distribution(
                        transpositionDurationsMilliseconds,
                    ),
                    verificationDurationMilliseconds: distribution(
                        verificationDurationsMilliseconds,
                    ),
                    verifiedCodewordCount: firstCodewordOrdinal,
                }),
                memory: Object.freeze({
                    linearMemoryByteLengthBeforeOpen,
                    maximumLinearMemoryByteLength,
                    sampledProcessExtrema: Object.freeze({
                        ...processMemoryExtrema,
                    }),
                }),
            }),
            limitations: Object.freeze([
                'Node scalar WebAssembly development evidence only; not external Chrome or supported-phone evidence.',
                'Deterministic measurement masters exercise source correspondence but do not constitute seed establishment or malicious-security evidence.',
                'The all-roster verifier checks only the degree-six zero-codeword relation; it authenticates no source, opening, state transition, or continuation capability.',
                'The independent TypeScript interpolation oracle checks selected boundary-spanning rows and mutations; the scalar WebAssembly verifier checks every row.',
                'Checkpoint restoration covers authenticated inner custody only; encrypted persistence, rollback heads, quota admission, repair, and physical reclamation remain separate owners.',
                'The run retains the copied-buffer planning target separately from the larger absolute refusal bound and does not close the complete browser live set.',
            ]),
        });
        await mkdir(path.dirname(parsedArguments.outputFilePath), {
            recursive: true,
        });
        await writeFile(
            parsedArguments.outputFilePath,
            `${JSON.stringify(result, undefined, 4)}\n`,
            'utf8',
        );
        console.log(JSON.stringify(result));
    } finally {
        await rm(temporaryDirectoryPath, { force: true, recursive: true });
    }
};

if (import.meta.main) {
    await runZeroSharingCodewordWasmMeasurementWorker();
}
