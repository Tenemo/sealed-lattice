import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import {
    buildOptimizedWasmKernelArtifact,
    resolveWasmCargoExecutable,
} from './build-wasm-kernel.js';
import {
    resolveZeroSharingWasmMeasurement,
    type ZeroSharingWasmMeasurement,
} from './zero-sharing-wasm-measurement-registry.js';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const measurementTemporaryRoot = path.resolve(
    repoRoot,
    'temp',
    'build-scratch',
    'zero-sharing-wasm-measurements',
);
const measurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'wasm-zero-sharing-measurement',
);
const nativeMeasurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'native-zero-sharing-measurement',
);
const measurementError = 0xffff_ffff;
const processingState = 1;
const completedChunkReadyState = 2;
const finishedState = 3;

const unsignedStatus = (value: number): number => value >>> 0;

type ParsedArguments = Readonly<{
    measurementId: string;
    outputFilePath: string;
}>;

export type MeasurementExports = Readonly<{
    acknowledge: () => number;
    allocate: (byteLength: number) => number;
    basisPrecomputationCount: () => bigint;
    basisStreamCount: () => bigint;
    checkpoint: (outputLengthPointer: number) => number;
    checkpointTraffic: () => bigint;
    close: () => number;
    codewordAdditionCount: () => bigint;
    codewordByteLength: () => bigint;
    codewordComparisonCount: () => bigint;
    codewordMaximumBlockCount: () => bigint;
    codewordMultiplicationCount: () => bigint;
    combinationAdditionCount: () => bigint;
    combinationMultiplicationCount: () => bigint;
    completedChunk: (outputLengthPointer: number) => number;
    deallocate: (pointer: number, byteLength: number) => void;
    deallocateSecret: (pointer: number, byteLength: number) => void;
    fieldOutputCount: () => bigint;
    memory: WebAssembly.Memory;
    open: () => number;
    openSource: (participantPosition: number) => number;
    outputChunkCount: () => bigint;
    restore: (pointer: number, byteLength: number) => number;
    restoreSource: (
        participantPosition: number,
        pointer: number,
        byteLength: number,
    ) => number;
    state: () => number;
    step: () => number;
    verifyCodewordBlock: (pointer: number, byteLength: number) => number;
    workCheckpointCount: () => bigint;
    zeroSharingCount: () => bigint;
}>;

export type CursorExecution = Readonly<{
    checkpointByteLengths: readonly number[];
    checkpointCopiedByteLength: number;
    checkpointDurationsMilliseconds: readonly number[];
    completedOutputByteLength: number;
    completedOutputDigests: readonly string[];
    completedOutputLengths: readonly number[];
    completedOutputs?: readonly Uint8Array[];
    maximumLinearMemoryByteLength: number;
    stepDurationsMilliseconds: readonly number[];
    totalElapsedMilliseconds: number;
    workStepCount: number;
}>;

type NativeMeasurement = Readonly<{
    basisStreamCount: number;
    checkpointGeneratedByteLength: number;
    completedOutputLengths: readonly number[];
    completedOutputSha3_512Hex: readonly string[];
    elapsedMilliseconds: number;
    evidenceClassification: string;
    schemaVersion: number;
    workCheckpointCount: number;
    zeroSharingCount: number;
}>;

export const parseZeroSharingWasmMeasurementWorkerArguments = (
    commandArguments: readonly string[],
): ParsedArguments => {
    let measurementId: string | undefined;
    let outputFilePath: string | undefined;
    for (
        let argumentPosition = 0;
        argumentPosition < commandArguments.length;
    ) {
        const argument = commandArguments[argumentPosition];
        const value = commandArguments[argumentPosition + 1];
        if (argument === '--measurement' && value !== undefined) {
            measurementId = value;
            argumentPosition += 2;
            continue;
        }
        if (argument === '--output' && value !== undefined) {
            outputFilePath = value;
            argumentPosition += 2;
            continue;
        }
        throw new Error(
            `Unknown or incomplete zero-sharing measurement worker argument: ${argument ?? '<missing>'}.`,
        );
    }
    if (measurementId === undefined || measurementId.length === 0) {
        throw new Error('The measurement worker requires --measurement.');
    }
    if (outputFilePath === undefined || outputFilePath.length === 0) {
        throw new Error('The measurement worker requires --output.');
    }
    if (!path.isAbsolute(outputFilePath)) {
        throw new Error('The measurement worker output path must be absolute.');
    }
    return { measurementId, outputFilePath };
};

const resolveFunction = <FunctionType>(
    exports: WebAssembly.Exports,
    exportName: string,
): FunctionType => {
    const candidate = exports[exportName];
    if (typeof candidate !== 'function') {
        throw new Error(
            `The diagnostic WebAssembly build does not export ${exportName}.`,
        );
    }
    return candidate as unknown as FunctionType;
};

export const resolveMeasurementExports = (
    exports: WebAssembly.Exports,
): MeasurementExports => {
    const memory = exports.memory;
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error(
            'The diagnostic WebAssembly build does not export linear memory.',
        );
    }
    const resolved: MeasurementExports = {
        acknowledge: resolveFunction(
            exports,
            'sealed_lattice_acknowledge_zero_sharing_measurement_chunk_320',
        ),
        allocate: resolveFunction(exports, 'sealed_lattice_allocate'),
        basisPrecomputationCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_basis_precomputation_count_320',
        ),
        basisStreamCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_basis_stream_count_320',
        ),
        checkpoint: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_checkpoint_320_with_length',
        ),
        checkpointTraffic: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_expected_checkpoint_traffic_320',
        ),
        close: resolveFunction(
            exports,
            'sealed_lattice_close_zero_sharing_measurement_320',
        ),
        codewordAdditionCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_codeword_addition_count_320',
        ),
        codewordByteLength: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_codeword_byte_length_320',
        ),
        codewordComparisonCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_codeword_comparison_count_320',
        ),
        codewordMaximumBlockCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_codeword_maximum_block_count_320',
        ),
        codewordMultiplicationCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_codeword_multiplication_count_320',
        ),
        combinationAdditionCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_combination_addition_count_320',
        ),
        combinationMultiplicationCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_combination_multiplication_count_320',
        ),
        completedChunk: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_completed_chunk_320_with_length',
        ),
        deallocate: resolveFunction(exports, 'sealed_lattice_deallocate'),
        deallocateSecret: resolveFunction(
            exports,
            'sealed_lattice_deallocate_secret',
        ),
        fieldOutputCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_field_output_count_320',
        ),
        memory,
        open: resolveFunction(
            exports,
            'sealed_lattice_open_zero_sharing_measurement_320',
        ),
        openSource: resolveFunction(
            exports,
            'sealed_lattice_open_zero_sharing_codeword_source_measurement_320',
        ),
        outputChunkCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_output_chunk_count_320',
        ),
        restore: resolveFunction(
            exports,
            'sealed_lattice_restore_zero_sharing_measurement_320',
        ),
        restoreSource: resolveFunction(
            exports,
            'sealed_lattice_restore_zero_sharing_codeword_source_measurement_320',
        ),
        state: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_state_320',
        ),
        step: resolveFunction(
            exports,
            'sealed_lattice_step_zero_sharing_measurement_320',
        ),
        verifyCodewordBlock: resolveFunction(
            exports,
            'sealed_lattice_verify_zero_sharing_codeword_block_320',
        ),
        workCheckpointCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_work_checkpoint_count_320',
        ),
        zeroSharingCount: resolveFunction(
            exports,
            'sealed_lattice_zero_sharing_measurement_zero_sharing_count_320',
        ),
    };
    return Object.freeze(resolved);
};

export const instantiateMeasurement = async (
    wasmBytes: Uint8Array,
): Promise<{
    readonly exportNames: readonly string[];
    readonly exports: MeasurementExports;
}> => {
    const wasmCopy = new Uint8Array(wasmBytes.byteLength);
    wasmCopy.set(wasmBytes);
    const module = await WebAssembly.compile(wasmCopy.buffer);
    const instance = await WebAssembly.instantiate(module, {});
    return Object.freeze({
        exportNames: Object.keys(instance.exports).sort(),
        exports: resolveMeasurementExports(instance.exports),
    });
};

export const numberFromUnsigned64 = (value: bigint, field: string): number => {
    const converted = Number(value);
    if (!Number.isSafeInteger(converted) || converted < 0) {
        throw new Error(`${field} is not a nonnegative safe integer.`);
    }
    return converted;
};

export const requireEqual = (
    actual: number,
    expected: number,
    field: string,
): void => {
    if (actual !== expected) {
        throw new Error(
            `${field} mismatch: expected ${expected}, received ${actual}.`,
        );
    }
};

export const copySecretOutput = (
    exports: MeasurementExports,
    outputFunction: (outputLengthPointer: number) => number,
    outputLengthPointer: number,
): Uint8Array => {
    new DataView(exports.memory.buffer).setUint32(outputLengthPointer, 0, true);
    const outputPointer = outputFunction(outputLengthPointer);
    const outputByteLength = new DataView(exports.memory.buffer).getUint32(
        outputLengthPointer,
        true,
    );
    if (outputPointer === 0 || outputByteLength === 0) {
        throw new Error(
            'The diagnostic kernel returned an empty secret output.',
        );
    }
    const copied = new Uint8Array(
        exports.memory.buffer,
        outputPointer,
        outputByteLength,
    ).slice();
    exports.deallocateSecret(outputPointer, outputByteLength);
    return copied;
};

const restoreCheckpoint = (
    exports: MeasurementExports,
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
    const result = exports.restore(checkpointPointer, checkpoint.byteLength);
    exports.deallocateSecret(checkpointPointer, checkpoint.byteLength);
    if (result !== 0) {
        throw new Error(
            `Diagnostic checkpoint restoration failed with ${result}.`,
        );
    }
};

export const executeCursor = (input: {
    readonly captureCheckpointAtWorkStep?: number;
    readonly expectedOutputChunkByteLengths: readonly number[];
    readonly expectedWorkStepCount: number;
    readonly exports: MeasurementExports;
    readonly outputLengthPointer: number;
    readonly retainCompletedOutputs?: boolean;
}): CursorExecution & { readonly capturedCheckpoint?: Uint8Array } => {
    const checkpointByteLengths: number[] = [];
    const checkpointDurationsMilliseconds: number[] = [];
    const completedOutputDigests: string[] = [];
    const completedOutputLengths: number[] = [];
    const completedOutputs: Uint8Array[] = [];
    const stepDurationsMilliseconds: number[] = [];
    let capturedCheckpoint: Uint8Array | undefined;
    let checkpointCopiedByteLength = 0;
    let completedOutputByteLength = 0;
    let maximumLinearMemoryByteLength = input.exports.memory.buffer.byteLength;
    let workStepCount = 0;
    const startTimeMilliseconds = performance.now();

    while (input.exports.state() !== finishedState) {
        if (input.exports.state() !== processingState) {
            throw new Error(
                'The cursor reached an unexpected nonprocessing state.',
            );
        }
        const stepStart = performance.now();
        const stepResult = unsignedStatus(input.exports.step());
        const stepElapsed = performance.now() - stepStart;
        if (stepResult === measurementError) {
            throw new Error('The diagnostic zero-sharing step failed.');
        }
        stepDurationsMilliseconds.push(stepElapsed);
        workStepCount += 1;

        const checkpointStart = performance.now();
        const checkpoint = copySecretOutput(
            input.exports,
            input.exports.checkpoint,
            input.outputLengthPointer,
        );
        checkpointDurationsMilliseconds.push(
            performance.now() - checkpointStart,
        );
        checkpointByteLengths.push(checkpoint.byteLength);
        checkpointCopiedByteLength += checkpoint.byteLength;
        if (input.captureCheckpointAtWorkStep === workStepCount) {
            capturedCheckpoint = checkpoint;
        }

        maximumLinearMemoryByteLength = Math.max(
            maximumLinearMemoryByteLength,
            input.exports.memory.buffer.byteLength,
        );
        const stateAfterStep = input.exports.state();
        if (stateAfterStep === completedChunkReadyState) {
            if (stepResult !== 1) {
                throw new Error(
                    'The cursor did not report its completed chunk boundary.',
                );
            }
            const output = copySecretOutput(
                input.exports,
                input.exports.completedChunk,
                input.outputLengthPointer,
            );
            const expectedOutputByteLength =
                input.expectedOutputChunkByteLengths[
                    completedOutputDigests.length
                ];
            if (expectedOutputByteLength === undefined) {
                throw new Error('The cursor produced an extra output chunk.');
            }
            requireEqual(
                output.byteLength,
                expectedOutputByteLength,
                'completed output chunk byte length',
            );
            completedOutputLengths.push(output.byteLength);
            completedOutputByteLength += output.byteLength;
            completedOutputDigests.push(
                createHash('sha3-512').update(output).digest('hex'),
            );
            if (input.retainCompletedOutputs === true) {
                completedOutputs.push(output);
            } else {
                output.fill(0);
            }
            const acknowledgeResult = unsignedStatus(
                input.exports.acknowledge(),
            );
            if (acknowledgeResult === measurementError) {
                throw new Error(
                    'The diagnostic output acknowledgement failed.',
                );
            }
        } else if (stateAfterStep !== processingState || stepResult !== 0) {
            throw new Error('The cursor reported an invalid step transition.');
        }
    }
    requireEqual(
        workStepCount,
        input.expectedWorkStepCount,
        'work checkpoint count',
    );
    if (
        completedOutputDigests.length !==
        input.expectedOutputChunkByteLengths.length
    ) {
        throw new Error('The cursor produced an incomplete output chunk set.');
    }
    const base = Object.freeze({
        checkpointByteLengths: Object.freeze(checkpointByteLengths),
        checkpointCopiedByteLength,
        checkpointDurationsMilliseconds: Object.freeze(
            checkpointDurationsMilliseconds,
        ),
        completedOutputByteLength,
        completedOutputDigests: Object.freeze(completedOutputDigests),
        completedOutputLengths: Object.freeze(completedOutputLengths),
        ...(input.retainCompletedOutputs === true
            ? { completedOutputs: Object.freeze(completedOutputs) }
            : {}),
        maximumLinearMemoryByteLength,
        stepDurationsMilliseconds: Object.freeze(stepDurationsMilliseconds),
        totalElapsedMilliseconds: performance.now() - startTimeMilliseconds,
        workStepCount,
    });
    return capturedCheckpoint === undefined
        ? base
        : Object.freeze({ ...base, capturedCheckpoint });
};

export const distribution = (values: readonly number[]) => {
    if (values.length === 0) {
        throw new Error('A timing distribution cannot be empty.');
    }
    const sorted = [...values].sort((left, right) => left - right);
    const percentile = (fraction: number): number =>
        sorted[
            Math.min(
                sorted.length - 1,
                Math.max(0, Math.ceil(sorted.length * fraction) - 1),
            )
        ] ?? 0;
    return Object.freeze({
        maximum: sorted[sorted.length - 1] ?? 0,
        mean: values.reduce((sum, value) => sum + value, 0) / values.length,
        median: percentile(0.5),
        p95: percentile(0.95),
    });
};

const verifyRustResourceModel = (
    exports: MeasurementExports,
    measurement: ZeroSharingWasmMeasurement,
) => {
    const actual = Object.freeze({
        basisPrecomputationFieldMultiplicationCount: numberFromUnsigned64(
            exports.basisPrecomputationCount(),
            'basis precomputation count',
        ),
        basisStreamCount: numberFromUnsigned64(
            exports.basisStreamCount(),
            'basis stream count',
        ),
        combinationFieldAdditionCount: numberFromUnsigned64(
            exports.combinationAdditionCount(),
            'combination addition count',
        ),
        combinationFieldMultiplicationCount: numberFromUnsigned64(
            exports.combinationMultiplicationCount(),
            'combination multiplication count',
        ),
        cumulativeCheckpointByteLength: numberFromUnsigned64(
            exports.checkpointTraffic(),
            'checkpoint traffic',
        ),
        fieldOutputCount: numberFromUnsigned64(
            exports.fieldOutputCount(),
            'field output count',
        ),
        outputChunkCount: numberFromUnsigned64(
            exports.outputChunkCount(),
            'output chunk count',
        ),
        workCheckpointCount: numberFromUnsigned64(
            exports.workCheckpointCount(),
            'work checkpoint count',
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

const runNativeParityMeasurement = (): Readonly<{
    buildAndRunElapsedMilliseconds: number;
    result: NativeMeasurement;
}> => {
    const environment = { ...process.env };
    delete environment.CARGO_ENCODED_RUSTFLAGS;
    environment.CARGO_BUILD_JOBS = '1';
    environment.CARGO_INCREMENTAL = '0';
    environment.CARGO_TARGET_DIR = nativeMeasurementCargoTargetDirectory;
    const start = performance.now();
    const nativeProcess = spawnSync(
        resolveWasmCargoExecutable(environment),
        [
            'run',
            '--locked',
            '--release',
            '--quiet',
            '--package',
            'sealed-lattice-kernel',
            '--features',
            'preparation-zero-sharing-measurement',
            '--bin',
            'zero-sharing-native-measurement',
        ],
        {
            cwd: repoRoot,
            encoding: 'utf8',
            env: environment,
            maxBuffer: 10 * 1024 * 1024,
        },
    );
    if (nativeProcess.error !== undefined) {
        throw new Error(
            `Failed to start the native parity measurement: ${nativeProcess.error.message}`,
        );
    }
    if (nativeProcess.status !== 0) {
        throw new Error(
            `Native parity measurement failed with status ${nativeProcess.status ?? 'null'}: ${nativeProcess.stderr.trim()}`,
        );
    }
    const outputLines = nativeProcess.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    const finalLine = outputLines[outputLines.length - 1];
    if (finalLine === undefined) {
        throw new Error('The native parity measurement produced no result.');
    }
    const parsed = JSON.parse(finalLine) as Partial<NativeMeasurement>;
    if (
        parsed.schemaVersion !== 1 ||
        typeof parsed.zeroSharingCount !== 'number' ||
        typeof parsed.basisStreamCount !== 'number' ||
        typeof parsed.workCheckpointCount !== 'number' ||
        typeof parsed.checkpointGeneratedByteLength !== 'number' ||
        !Array.isArray(parsed.completedOutputLengths) ||
        !Array.isArray(parsed.completedOutputSha3_512Hex) ||
        typeof parsed.elapsedMilliseconds !== 'number' ||
        typeof parsed.evidenceClassification !== 'string'
    ) {
        throw new Error('The native parity result has an invalid shape.');
    }
    return Object.freeze({
        buildAndRunElapsedMilliseconds: performance.now() - start,
        result: parsed as NativeMeasurement,
    });
};

export const runZeroSharingWasmMeasurementWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments =
        parseZeroSharingWasmMeasurementWorkerArguments(rawArguments);
    const measurement = resolveZeroSharingWasmMeasurement(
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
            artifactLabel: 'Zero-sharing measurement kernel',
            cargoFeatures: ['preparation-zero-sharing-measurement'],
            outputFilePath: wasmOutputFilePath,
            scratchDirectoryPrefix: 'zero-sharing-measurement-',
            targetDirectoryPath: measurementCargoTargetDirectory,
        });
        const wasmBytes = await readFile(wasmOutputFilePath);
        const nativeParity = runNativeParityMeasurement();

        const warmup = await instantiateMeasurement(wasmBytes);
        if (
            warmup.exports.open() !== 0 ||
            warmup.exports.step() === measurementError
        ) {
            throw new Error('The scalar WebAssembly warmup cursor failed.');
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
                'The scalar WebAssembly warmup cursor did not close.',
            );
        }

        const instantiated = await instantiateMeasurement(wasmBytes);
        const exports = instantiated.exports;
        const linearMemoryByteLengthBeforeOpen =
            exports.memory.buffer.byteLength;
        const openStart = performance.now();
        if (exports.open() !== 0) {
            throw new Error('The completion zero-sharing cursor did not open.');
        }
        const coldOpenElapsedMilliseconds = performance.now() - openStart;
        const linearMemoryByteLengthAfterOpen =
            exports.memory.buffer.byteLength;
        const rustResourceModel = verifyRustResourceModel(exports, measurement);
        const outputLengthPointer = exports.allocate(4);
        if (outputLengthPointer === 0) {
            throw new Error(
                'The measurement length slot could not be allocated.',
            );
        }
        const captureCheckpointAtWorkStep = Math.floor(
            measurement.expected.workCheckpointCount / 4,
        );
        const baseline = executeCursor({
            captureCheckpointAtWorkStep,
            expectedOutputChunkByteLengths:
                measurement.expected.outputChunkByteLengths,
            expectedWorkStepCount: measurement.expected.workCheckpointCount,
            exports,
            outputLengthPointer,
        });
        requireEqual(
            baseline.checkpointCopiedByteLength,
            measurement.expected.cumulativeCheckpointByteLength,
            'observed cumulative checkpoint byte length',
        );
        requireEqual(
            Math.min(...baseline.checkpointByteLengths),
            measurement.expected.minimumCheckpointByteLength,
            'minimum checkpoint byte length',
        );
        requireEqual(
            Math.max(...baseline.checkpointByteLengths),
            measurement.expected.maximumCheckpointByteLength,
            'maximum checkpoint byte length',
        );
        if (baseline.capturedCheckpoint === undefined) {
            throw new Error(
                'The deterministic restoration checkpoint is absent.',
            );
        }
        const baselineOutputDigests = baseline.completedOutputDigests;
        const capturedCheckpoint = baseline.capturedCheckpoint;
        exports.deallocate(outputLengthPointer, 4);
        const closeStart = performance.now();
        if (exports.close() !== 0) {
            throw new Error(
                'The completion zero-sharing cursor did not close.',
            );
        }
        const closeElapsedMilliseconds = performance.now() - closeStart;
        const linearMemoryByteLengthAfterClose =
            exports.memory.buffer.byteLength;

        const restoreInputCopyStart = performance.now();
        restoreCheckpoint(exports, capturedCheckpoint);
        const coldRestoreElapsedMilliseconds =
            performance.now() - restoreInputCopyStart;
        capturedCheckpoint.fill(0);
        const restoredOutputLengthPointer = exports.allocate(4);
        const restored = executeCursor({
            expectedOutputChunkByteLengths:
                measurement.expected.outputChunkByteLengths,
            expectedWorkStepCount:
                measurement.expected.workCheckpointCount -
                captureCheckpointAtWorkStep,
            exports,
            outputLengthPointer: restoredOutputLengthPointer,
        });
        exports.deallocate(restoredOutputLengthPointer, 4);
        if (
            JSON.stringify(restored.completedOutputDigests) !==
            JSON.stringify(baselineOutputDigests)
        ) {
            throw new Error(
                'Cold restoration changed the completed zero-sharing bytes.',
            );
        }
        requireEqual(
            nativeParity.result.zeroSharingCount,
            measurement.expected.zeroSharingCount,
            'native zero-sharing count',
        );
        requireEqual(
            nativeParity.result.basisStreamCount,
            measurement.expected.basisStreamCount,
            'native basis stream count',
        );
        requireEqual(
            nativeParity.result.workCheckpointCount,
            measurement.expected.workCheckpointCount,
            'native work checkpoint count',
        );
        requireEqual(
            nativeParity.result.checkpointGeneratedByteLength,
            measurement.expected.cumulativeCheckpointByteLength,
            'native checkpoint traffic',
        );
        if (
            JSON.stringify(nativeParity.result.completedOutputLengths) !==
                JSON.stringify(baseline.completedOutputLengths) ||
            JSON.stringify(nativeParity.result.completedOutputSha3_512Hex) !==
                JSON.stringify(baselineOutputDigests)
        ) {
            throw new Error(
                'Native and scalar WebAssembly zero-sharing outputs differ.',
            );
        }
        if (exports.close() !== 0) {
            throw new Error('The restored zero-sharing cursor did not close.');
        }
        const linearMemoryByteLengthAfterRestoredClose =
            exports.memory.buffer.byteLength;
        const maximumLinearMemoryByteLength = Math.max(
            baseline.maximumLinearMemoryByteLength,
            restored.maximumLinearMemoryByteLength,
            linearMemoryByteLengthAfterOpen,
            linearMemoryByteLengthAfterRestoredClose,
        );
        if (
            maximumLinearMemoryByteLength >
            foundationProfile.maximumWasmMemoryByteLength
        ) {
            throw new Error(
                `The scalar WebAssembly cursor used ${maximumLinearMemoryByteLength} bytes of linear memory; absolute maximum is ${foundationProfile.maximumWasmMemoryByteLength}.`,
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
                nativeParity: Object.freeze({
                    ...nativeParity.result,
                    buildAndRunElapsedMilliseconds:
                        nativeParity.buildAndRunElapsedMilliseconds,
                    matchesScalarWebAssemblyBytes: true,
                }),
                baseline: Object.freeze({
                    checkpointCopiedByteLength:
                        baseline.checkpointCopiedByteLength,
                    checkpointDurationMilliseconds: distribution(
                        baseline.checkpointDurationsMilliseconds,
                    ),
                    coldOpenElapsedMilliseconds,
                    completedOutputByteLength:
                        baseline.completedOutputByteLength,
                    completedOutputDigests: baseline.completedOutputDigests,
                    completedOutputLengths: baseline.completedOutputLengths,
                    maximumLinearMemoryByteLength:
                        baseline.maximumLinearMemoryByteLength,
                    stepDurationMilliseconds: distribution(
                        baseline.stepDurationsMilliseconds,
                    ),
                    totalElapsedMilliseconds: baseline.totalElapsedMilliseconds,
                    workStepCount: baseline.workStepCount,
                }),
                restoration: Object.freeze({
                    captureCheckpointAtWorkStep,
                    coldRestoreElapsedMilliseconds,
                    completedOutputDigests: restored.completedOutputDigests,
                    completedOutputLengths: restored.completedOutputLengths,
                    maximumLinearMemoryByteLength:
                        restored.maximumLinearMemoryByteLength,
                    remainingCheckpointCopiedByteLength:
                        restored.checkpointCopiedByteLength,
                    remainingTotalElapsedMilliseconds:
                        restored.totalElapsedMilliseconds,
                    remainingWorkStepCount: restored.workStepCount,
                }),
                memory: Object.freeze({
                    closeElapsedMilliseconds,
                    linearMemoryByteLengthAfterClose,
                    linearMemoryByteLengthAfterOpen,
                    linearMemoryByteLengthAfterRestoredClose,
                    linearMemoryByteLengthBeforeOpen,
                    maximumLinearMemoryByteLength,
                    physicallyReclaimedByClose:
                        linearMemoryByteLengthAfterClose <
                        maximumLinearMemoryByteLength,
                }),
            }),
            limitations: Object.freeze([
                'Node scalar WebAssembly development evidence only; not external Chrome or supported-phone evidence.',
                'The deterministic measurement masters exercise the typed production cursor but do not constitute seed-establishment evidence.',
                'The checkpoint is authenticated inner custody; encrypted persistence, rollback heads, quota admission, repair, and physical reclamation remain separate owners.',
                'This run covers zero-source generation but not the all-ten degree-six codeword verifier or the seed-establishment theorem.',
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
    await runZeroSharingWasmMeasurementWorker();
}
