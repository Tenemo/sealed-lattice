import { spawn, spawnSync } from 'node:child_process';
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
    resolveDirectMpcWasmMeasurement,
    type DirectMpcWasmMeasurement,
} from './direct-mpc-wasm-measurement-registry.js';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const interruptionWorkerFilePath = fileURLToPath(
    new URL(
        './direct-mpc-wasm-measurement-interruption-worker.ts',
        import.meta.url,
    ),
);
const measurementTemporaryRoot = path.resolve(
    repoRoot,
    'temp',
    'build-scratch',
    'direct-mpc-wasm-measurements',
);
const measurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'wasm-direct-mpc-measurement',
);
const nativeMeasurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'native-direct-mpc-measurement',
);

export const directMpcSuccess = 0;
export const directMpcAlreadyOpen = 1;
export const directMpcNotOpen = 2;
export const directMpcCheckpointAuthenticationRefusal = 4;
export const directMpcProcessingState = 1;
export const directMpcFinishedState = 2;
export const directMpcErrorState = 0xffff_ffff;

type ParsedArguments = Readonly<{
    measurementId: string;
    outputFilePath: string;
}>;

export type DirectMpcMeasurementExports = Readonly<{
    accumulationAdditionCount: () => bigint;
    allocate: (byteLength: number) => number;
    authorizedSubsetCount: () => bigint;
    basisInverseCount: () => bigint;
    basisMultiplicationCount: () => bigint;
    canonicalAccumulatorByteLength: () => bigint;
    checkpoint: (outputLengthPointer: number) => number;
    checkpointByteLength: () => bigint;
    close: () => number;
    cumulativeCheckpointByteLength: () => bigint;
    deallocate: (pointer: number, byteLength: number) => void;
    deallocateSecret: (pointer: number, byteLength: number) => void;
    fieldOutputCount: () => bigint;
    internalAccumulatorByteLength: () => bigint;
    maximumXofAllocationByteLength: () => bigint;
    memory: WebAssembly.Memory;
    open: () => number;
    ordinaryFieldCount: () => bigint;
    ordinaryStreamCount: () => bigint;
    restore: (pointer: number, byteLength: number) => number;
    result: (outputLengthPointer: number) => number;
    resultByteLength: () => bigint;
    sourceByteLength: () => bigint;
    state: () => number;
    step: () => number;
    totalStreamCount: () => bigint;
    weightMultiplicationCount: () => bigint;
    zeroBasisStreamCount: () => bigint;
    zeroFieldCount: () => bigint;
}>;

export type DirectMpcCursorExecution = Readonly<{
    capturedCheckpoint?: Uint8Array;
    checkpointCopiedByteLength: number;
    checkpointDurationsMilliseconds: readonly number[];
    maximumLinearMemoryByteLength: number;
    resultByteLength: number;
    resultSha3_512Hex: string;
    stepDurationsMilliseconds: readonly number[];
    totalElapsedMilliseconds: number;
    workStepCount: number;
}>;

type NativeMeasurement = Readonly<{
    checkpointByteLength: number;
    checkpointGeneratedByteLength: number;
    checkpointMutationRefusalCode: number;
    elapsedMilliseconds: number;
    evidenceClassification: string;
    fieldOutputCount: number;
    participantPosition: number;
    restoredResultMatches: boolean;
    restoredResultSha3_512Hex: string;
    resultByteLength: number;
    resultSha3_512Hex: string;
    schemaVersion: number;
    sourceByteLength: number;
    totalStreamCount: number;
}>;

type ForcedRestoreResult = Readonly<{
    checkpointCopiedByteLength: number;
    checkpointDurationMaximumMilliseconds: number;
    coldRestoreElapsedMilliseconds: number;
    maximumLinearMemoryByteLength: number;
    remainingElapsedMilliseconds: number;
    remainingWorkStepCount: number;
    resultByteLength: number;
    resultSha3_512Hex: string;
}>;

export const parseDirectMpcWasmMeasurementWorkerArguments = (
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
            `Unknown or incomplete direct-MPC measurement worker argument: ${argument ?? '<missing>'}.`,
        );
    }
    if (measurementId === undefined || measurementId.length === 0) {
        throw new Error(
            'The direct-MPC measurement worker requires --measurement.',
        );
    }
    if (outputFilePath === undefined || outputFilePath.length === 0) {
        throw new Error('The direct-MPC measurement worker requires --output.');
    }
    if (!path.isAbsolute(outputFilePath)) {
        throw new Error(
            'The direct-MPC measurement worker output path must be absolute.',
        );
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
            `The direct-MPC diagnostic WebAssembly build does not export ${exportName}.`,
        );
    }
    return candidate as unknown as FunctionType;
};

export const resolveDirectMpcMeasurementExports = (
    exports: WebAssembly.Exports,
): DirectMpcMeasurementExports => {
    const memory = exports.memory;
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error(
            'The direct-MPC diagnostic WebAssembly build does not export linear memory.',
        );
    }
    const resolved: DirectMpcMeasurementExports = {
        accumulationAdditionCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_accumulation_addition_count',
        ),
        allocate: resolveFunction(exports, 'sealed_lattice_allocate'),
        authorizedSubsetCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_authorized_subset_count',
        ),
        basisInverseCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_basis_inverse_count',
        ),
        basisMultiplicationCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_basis_multiplication_count',
        ),
        canonicalAccumulatorByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_canonical_accumulator_byte_length',
        ),
        checkpoint: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_measurement_checkpoint_with_length',
        ),
        checkpointByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_checkpoint_byte_length',
        ),
        close: resolveFunction(
            exports,
            'sealed_lattice_close_direct_mpc_prss_measurement',
        ),
        cumulativeCheckpointByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_cumulative_checkpoint_byte_length',
        ),
        deallocate: resolveFunction(exports, 'sealed_lattice_deallocate'),
        deallocateSecret: resolveFunction(
            exports,
            'sealed_lattice_deallocate_secret',
        ),
        fieldOutputCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_field_output_count',
        ),
        internalAccumulatorByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_internal_accumulator_byte_length',
        ),
        maximumXofAllocationByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_maximum_xof_allocation_byte_length',
        ),
        memory,
        open: resolveFunction(
            exports,
            'sealed_lattice_open_direct_mpc_prss_measurement',
        ),
        ordinaryFieldCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_ordinary_field_count',
        ),
        ordinaryStreamCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_ordinary_stream_count',
        ),
        restore: resolveFunction(
            exports,
            'sealed_lattice_restore_direct_mpc_prss_measurement',
        ),
        result: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_measurement_result_with_length',
        ),
        resultByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_result_byte_length',
        ),
        sourceByteLength: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_source_byte_length',
        ),
        state: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_measurement_state',
        ),
        step: resolveFunction(
            exports,
            'sealed_lattice_step_direct_mpc_prss_measurement',
        ),
        totalStreamCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_total_stream_count',
        ),
        weightMultiplicationCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_weight_multiplication_count',
        ),
        zeroBasisStreamCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_zero_basis_stream_count',
        ),
        zeroFieldCount: resolveFunction(
            exports,
            'sealed_lattice_direct_mpc_prss_zero_field_count',
        ),
    };
    return Object.freeze(resolved);
};

export const instantiateDirectMpcMeasurement = async (
    wasmBytes: Uint8Array,
): Promise<{
    readonly exportNames: readonly string[];
    readonly exports: DirectMpcMeasurementExports;
}> => {
    const copiedBytes = new Uint8Array(wasmBytes.byteLength);
    copiedBytes.set(wasmBytes);
    const module = await WebAssembly.compile(copiedBytes.buffer);
    const instance = await WebAssembly.instantiate(module, {});
    return Object.freeze({
        exportNames: Object.keys(instance.exports).sort(),
        exports: resolveDirectMpcMeasurementExports(instance.exports),
    });
};

export const numberFromUnsigned64 = (value: bigint, field: string): number => {
    const converted = Number(value);
    if (!Number.isSafeInteger(converted) || converted < 0) {
        throw new Error(`${field} is not a nonnegative safe integer.`);
    }
    return converted;
};

export const copyOptionalSecretOutput = (
    exports: DirectMpcMeasurementExports,
    outputFunction: (outputLengthPointer: number) => number,
    outputLengthPointer: number,
): Uint8Array | undefined => {
    new DataView(exports.memory.buffer).setUint32(outputLengthPointer, 0, true);
    const outputPointer = outputFunction(outputLengthPointer);
    const outputByteLength = new DataView(exports.memory.buffer).getUint32(
        outputLengthPointer,
        true,
    );
    if (outputPointer === 0 || outputByteLength === 0) {
        if (outputPointer !== 0 || outputByteLength !== 0) {
            throw new Error(
                'The direct-MPC diagnostic returned an inconsistent empty output.',
            );
        }
        return undefined;
    }
    const copied = new Uint8Array(
        exports.memory.buffer,
        outputPointer,
        outputByteLength,
    ).slice();
    exports.deallocateSecret(outputPointer, outputByteLength);
    return copied;
};

export const copyRequiredSecretOutput = (
    exports: DirectMpcMeasurementExports,
    outputFunction: (outputLengthPointer: number) => number,
    outputLengthPointer: number,
): Uint8Array => {
    const output = copyOptionalSecretOutput(
        exports,
        outputFunction,
        outputLengthPointer,
    );
    if (output === undefined) {
        throw new Error('The direct-MPC diagnostic returned an empty output.');
    }
    return output;
};

export const restoreDirectMpcCheckpoint = (
    exports: DirectMpcMeasurementExports,
    checkpoint: Uint8Array,
): number => {
    const checkpointPointer = exports.allocate(checkpoint.byteLength);
    if (checkpointPointer === 0) {
        throw new Error(
            'The direct-MPC diagnostic could not allocate checkpoint input.',
        );
    }
    new Uint8Array(
        exports.memory.buffer,
        checkpointPointer,
        checkpoint.byteLength,
    ).set(checkpoint);
    const result = exports.restore(checkpointPointer, checkpoint.byteLength);
    exports.deallocateSecret(checkpointPointer, checkpoint.byteLength);
    return result;
};

export const executeDirectMpcCursor = (input: {
    readonly captureCheckpointAtWorkStep?: number;
    readonly expectedCheckpointByteLength: number;
    readonly expectedResultByteLength: number;
    readonly expectedWorkStepCount: number;
    readonly exports: DirectMpcMeasurementExports;
    readonly outputLengthPointer: number;
}): DirectMpcCursorExecution => {
    const checkpointDurationsMilliseconds: number[] = [];
    const stepDurationsMilliseconds: number[] = [];
    let capturedCheckpoint: Uint8Array | undefined;
    let checkpointCopiedByteLength = 0;
    let maximumLinearMemoryByteLength = input.exports.memory.buffer.byteLength;
    let workStepCount = 0;
    const start = performance.now();
    while (input.exports.state() !== directMpcFinishedState) {
        if (input.exports.state() !== directMpcProcessingState) {
            throw new Error(
                'The direct-MPC cursor reached an unexpected state.',
            );
        }
        const stepStart = performance.now();
        const stepResult = input.exports.step();
        stepDurationsMilliseconds.push(performance.now() - stepStart);
        if (stepResult !== directMpcSuccess) {
            throw new Error(
                `The direct-MPC scalar step refused with code ${stepResult}.`,
            );
        }
        workStepCount += 1;
        const checkpointStart = performance.now();
        const checkpoint = copyRequiredSecretOutput(
            input.exports,
            input.exports.checkpoint,
            input.outputLengthPointer,
        );
        checkpointDurationsMilliseconds.push(
            performance.now() - checkpointStart,
        );
        if (checkpoint.byteLength !== input.expectedCheckpointByteLength) {
            throw new Error(
                `Direct-MPC checkpoint length mismatch: expected ${input.expectedCheckpointByteLength}, received ${checkpoint.byteLength}.`,
            );
        }
        checkpointCopiedByteLength += checkpoint.byteLength;
        if (input.captureCheckpointAtWorkStep === workStepCount) {
            capturedCheckpoint = checkpoint;
        } else {
            checkpoint.fill(0);
        }
        maximumLinearMemoryByteLength = Math.max(
            maximumLinearMemoryByteLength,
            input.exports.memory.buffer.byteLength,
        );
    }
    if (workStepCount !== input.expectedWorkStepCount) {
        throw new Error(
            `Direct-MPC work-step mismatch: expected ${input.expectedWorkStepCount}, received ${workStepCount}.`,
        );
    }
    const result = copyRequiredSecretOutput(
        input.exports,
        input.exports.result,
        input.outputLengthPointer,
    );
    if (result.byteLength !== input.expectedResultByteLength) {
        throw new Error(
            `Direct-MPC result length mismatch: expected ${input.expectedResultByteLength}, received ${result.byteLength}.`,
        );
    }
    const resultSha3_512Hex = createHash('sha3-512')
        .update(result)
        .digest('hex');
    result.fill(0);
    return Object.freeze({
        ...(capturedCheckpoint === undefined ? {} : { capturedCheckpoint }),
        checkpointCopiedByteLength,
        checkpointDurationsMilliseconds: Object.freeze(
            checkpointDurationsMilliseconds,
        ),
        maximumLinearMemoryByteLength,
        resultByteLength: input.expectedResultByteLength,
        resultSha3_512Hex,
        stepDurationsMilliseconds: Object.freeze(stepDurationsMilliseconds),
        totalElapsedMilliseconds: performance.now() - start,
        workStepCount,
    });
};

const verifyRustResourceModel = (
    exports: DirectMpcMeasurementExports,
    measurement: DirectMpcWasmMeasurement,
) => {
    const actual = Object.freeze({
        accumulationFieldAdditionCount: numberFromUnsigned64(
            exports.accumulationAdditionCount(),
            'accumulation addition count',
        ),
        authorizedSubsetCountPerParticipant: numberFromUnsigned64(
            exports.authorizedSubsetCount(),
            'authorized subset count',
        ),
        basisPrecomputationFieldMultiplicationCount: numberFromUnsigned64(
            exports.basisMultiplicationCount(),
            'basis multiplication count',
        ),
        canonicalAccumulatorByteLength: numberFromUnsigned64(
            exports.canonicalAccumulatorByteLength(),
            'canonical accumulator byte length',
        ),
        checkpointByteLength: numberFromUnsigned64(
            exports.checkpointByteLength(),
            'checkpoint byte length',
        ),
        cumulativeCheckpointByteLength: numberFromUnsigned64(
            exports.cumulativeCheckpointByteLength(),
            'cumulative checkpoint byte length',
        ),
        fieldOutputCount: numberFromUnsigned64(
            exports.fieldOutputCount(),
            'field output count',
        ),
        internalAccumulatorByteLength: numberFromUnsigned64(
            exports.internalAccumulatorByteLength(),
            'internal accumulator byte length',
        ),
        maximumXofOutputAllocationByteLength: numberFromUnsigned64(
            exports.maximumXofAllocationByteLength(),
            'maximum XOF allocation byte length',
        ),
        ordinaryBasisModularInverseCount: numberFromUnsigned64(
            exports.basisInverseCount(),
            'basis inverse count',
        ),
        ordinaryFieldCount: numberFromUnsigned64(
            exports.ordinaryFieldCount(),
            'ordinary field count',
        ),
        ordinaryStreamCount: numberFromUnsigned64(
            exports.ordinaryStreamCount(),
            'ordinary stream count',
        ),
        resultByteLength: numberFromUnsigned64(
            exports.resultByteLength(),
            'result byte length',
        ),
        sourceByteLength: numberFromUnsigned64(
            exports.sourceByteLength(),
            'source byte length',
        ),
        totalStreamCount: numberFromUnsigned64(
            exports.totalStreamCount(),
            'total stream count',
        ),
        weightFieldMultiplicationCount: numberFromUnsigned64(
            exports.weightMultiplicationCount(),
            'weight multiplication count',
        ),
        zeroBasisStreamCount: numberFromUnsigned64(
            exports.zeroBasisStreamCount(),
            'zero-basis stream count',
        ),
        zeroFieldCount: numberFromUnsigned64(
            exports.zeroFieldCount(),
            'zero field count',
        ),
    });
    for (const [field, actualValue] of Object.entries(actual)) {
        const expectedValue =
            measurement.expected[field as keyof typeof measurement.expected];
        if (
            typeof expectedValue !== 'number' ||
            expectedValue !== actualValue
        ) {
            throw new Error(
                `Direct-MPC resource ${field} mismatch: expected ${String(expectedValue)}, received ${actualValue}.`,
            );
        }
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
            'direct-mpc-scalar-measurement',
            '--bin',
            'direct-mpc-native-measurement',
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
            `Failed to start the native direct-MPC measurement: ${nativeProcess.error.message}`,
        );
    }
    if (nativeProcess.status !== 0) {
        throw new Error(
            `Native direct-MPC measurement failed with status ${nativeProcess.status ?? 'null'}: ${nativeProcess.stderr.trim()}`,
        );
    }
    const outputLines = nativeProcess.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    const finalLine = outputLines[outputLines.length - 1];
    if (finalLine === undefined) {
        throw new Error(
            'The native direct-MPC measurement produced no result.',
        );
    }
    const parsed = JSON.parse(finalLine) as Partial<NativeMeasurement>;
    if (
        parsed.schemaVersion !== 1 ||
        typeof parsed.totalStreamCount !== 'number' ||
        typeof parsed.fieldOutputCount !== 'number' ||
        typeof parsed.sourceByteLength !== 'number' ||
        typeof parsed.checkpointGeneratedByteLength !== 'number' ||
        typeof parsed.checkpointByteLength !== 'number' ||
        typeof parsed.resultByteLength !== 'number' ||
        typeof parsed.resultSha3_512Hex !== 'string' ||
        typeof parsed.restoredResultSha3_512Hex !== 'string' ||
        typeof parsed.restoredResultMatches !== 'boolean' ||
        typeof parsed.checkpointMutationRefusalCode !== 'number'
    ) {
        throw new Error('The native direct-MPC result has an invalid shape.');
    }
    return Object.freeze({
        buildAndRunElapsedMilliseconds: performance.now() - start,
        result: parsed as NativeMeasurement,
    });
};

const distribution = (values: readonly number[]) => {
    if (values.length === 0) {
        throw new Error('Cannot summarize an empty duration distribution.');
    }
    const sorted = [...values].sort((left, right) => left - right);
    const percentile = (fraction: number): number => {
        const position = Math.min(
            sorted.length - 1,
            Math.floor(fraction * sorted.length),
        );
        const value = sorted[position];
        if (value === undefined) throw new Error('Duration sample is absent.');
        return value;
    };
    return Object.freeze({
        count: values.length,
        maximum: sorted[sorted.length - 1],
        minimum: sorted[0],
        p50: percentile(0.5),
        p95: percentile(0.95),
        total: values.reduce((sum, value) => sum + value, 0),
    });
};

const runForcedTerminationCheckpoint = async (input: {
    readonly captureWorkStep: number;
    readonly checkpointFilePath: string;
    readonly measurementId: string;
    readonly wasmFilePath: string;
}): Promise<
    Readonly<{
        checkpointSha256Hex: string;
        exitCode: number | null;
        terminationRequested: boolean;
    }>
> =>
    await new Promise((resolve, reject) => {
        const child = spawn(
            process.execPath,
            [
                '--import',
                'tsx',
                interruptionWorkerFilePath,
                '--mode',
                'checkpoint',
                '--measurement',
                input.measurementId,
                '--wasm',
                input.wasmFilePath,
                '--checkpoint',
                input.checkpointFilePath,
                '--capture-work-step',
                String(input.captureWorkStep),
            ],
            {
                cwd: repoRoot,
                env: process.env,
                stdio: ['ignore', 'pipe', 'pipe'],
            },
        );
        let stdoutBuffer = '';
        let stderr = '';
        let readyDigest: string | undefined;
        let terminationRequested = false;
        const timeout = setTimeout(() => {
            child.kill();
            reject(
                new Error(
                    'The forced-termination child did not publish a checkpoint within 60 seconds.',
                ),
            );
        }, 60_000);
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (chunk: string) => {
            stdoutBuffer += chunk;
            let newlinePosition = stdoutBuffer.indexOf('\n');
            while (newlinePosition >= 0) {
                const line = stdoutBuffer.slice(0, newlinePosition).trim();
                stdoutBuffer = stdoutBuffer.slice(newlinePosition + 1);
                if (line.startsWith('{')) {
                    const parsed = JSON.parse(line) as {
                        checkpointReady?: boolean;
                        checkpointSha256Hex?: string;
                    };
                    if (
                        parsed.checkpointReady === true &&
                        typeof parsed.checkpointSha256Hex === 'string'
                    ) {
                        readyDigest = parsed.checkpointSha256Hex;
                        terminationRequested = child.kill();
                    }
                }
                newlinePosition = stdoutBuffer.indexOf('\n');
            }
        });
        child.stderr.on('data', (chunk: string) => {
            stderr += chunk;
        });
        child.once('error', (error) => {
            clearTimeout(timeout);
            reject(error);
        });
        child.once('exit', (exitCode) => {
            clearTimeout(timeout);
            if (readyDigest === undefined || !terminationRequested) {
                reject(
                    new Error(
                        `The forced-termination child exited before checkpoint publication with ${exitCode}: ${stderr.trim()}`,
                    ),
                );
                return;
            }
            resolve(
                Object.freeze({
                    checkpointSha256Hex: readyDigest,
                    exitCode,
                    terminationRequested,
                }),
            );
        });
    });

const runForcedColdRestore = (input: {
    readonly checkpointFilePath: string;
    readonly measurementId: string;
    readonly wasmFilePath: string;
}): ForcedRestoreResult => {
    const child = spawnSync(
        process.execPath,
        [
            '--import',
            'tsx',
            interruptionWorkerFilePath,
            '--mode',
            'restore',
            '--measurement',
            input.measurementId,
            '--wasm',
            input.wasmFilePath,
            '--checkpoint',
            input.checkpointFilePath,
        ],
        {
            cwd: repoRoot,
            encoding: 'utf8',
            env: process.env,
            maxBuffer: 10 * 1024 * 1024,
        },
    );
    if (child.error !== undefined || child.status !== 0) {
        throw new Error(
            `The forced cold-restore child failed: ${child.error?.message ?? child.stderr.trim()}`,
        );
    }
    const outputLines = child.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.startsWith('{'));
    const finalLine = outputLines[outputLines.length - 1];
    if (finalLine === undefined) {
        throw new Error('The forced cold-restore child produced no result.');
    }
    return JSON.parse(finalLine) as ForcedRestoreResult;
};

export const runDirectMpcWasmMeasurementWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments =
        parseDirectMpcWasmMeasurementWorkerArguments(rawArguments);
    const measurement = resolveDirectMpcWasmMeasurement(
        parsedArguments.measurementId,
    );
    await mkdir(measurementTemporaryRoot, { recursive: true });
    const temporaryDirectoryPath = await mkdtemp(
        path.join(measurementTemporaryRoot, 'run-'),
    );
    try {
        const wasmFilePath = path.join(temporaryDirectoryPath, 'kernel.wasm');
        const checkpointFilePath = path.join(
            temporaryDirectoryPath,
            'forced-termination-checkpoint.bin',
        );
        const builtArtifact = await buildOptimizedWasmKernelArtifact({
            artifactLabel: 'Direct-MPC measurement kernel',
            cargoFeatures: ['direct-mpc-scalar-measurement'],
            outputFilePath: wasmFilePath,
            scratchDirectoryPrefix: 'direct-mpc-measurement-',
            targetDirectoryPath: measurementCargoTargetDirectory,
        });
        const wasmBytes = await readFile(wasmFilePath);
        const nativeParity = runNativeParityMeasurement();

        const warmup = await instantiateDirectMpcMeasurement(wasmBytes);
        const stepBeforeOpen = warmup.exports.step();
        const stateBeforeOpen = warmup.exports.state() >>> 0;
        const firstOpen = warmup.exports.open();
        const secondOpen = warmup.exports.open();
        if (
            stepBeforeOpen !== directMpcNotOpen ||
            stateBeforeOpen !== directMpcErrorState ||
            firstOpen !== directMpcSuccess ||
            secondOpen !== directMpcAlreadyOpen
        ) {
            throw new Error(
                `The direct-MPC diagnostic refusal boundary changed: step-before-open=${stepBeforeOpen}, state-before-open=${stateBeforeOpen}, first-open=${firstOpen}, second-open=${secondOpen}.`,
            );
        }
        const warmupLengthPointer = warmup.exports.allocate(4);
        if (
            copyOptionalSecretOutput(
                warmup.exports,
                warmup.exports.result,
                warmupLengthPointer,
            ) !== undefined ||
            warmup.exports.step() !== directMpcSuccess
        ) {
            throw new Error('The direct-MPC diagnostic warmup failed.');
        }
        const warmupCheckpoint = copyRequiredSecretOutput(
            warmup.exports,
            warmup.exports.checkpoint,
            warmupLengthPointer,
        );
        warmupCheckpoint.fill(0);
        warmup.exports.deallocate(warmupLengthPointer, 4);
        if (warmup.exports.close() !== directMpcSuccess) {
            throw new Error('The direct-MPC warmup cursor did not close.');
        }

        const instantiated = await instantiateDirectMpcMeasurement(wasmBytes);
        const exports = instantiated.exports;
        const linearMemoryByteLengthBeforeOpen =
            exports.memory.buffer.byteLength;
        const openStart = performance.now();
        if (exports.open() !== directMpcSuccess) {
            throw new Error('The completion direct-MPC cursor did not open.');
        }
        const coldOpenElapsedMilliseconds = performance.now() - openStart;
        const linearMemoryByteLengthAfterOpen =
            exports.memory.buffer.byteLength;
        const rustResourceModel = verifyRustResourceModel(exports, measurement);
        const outputLengthPointer = exports.allocate(4);
        if (outputLengthPointer === 0) {
            throw new Error(
                'The direct-MPC output-length slot was not allocated.',
            );
        }
        const captureCheckpointAtWorkStep =
            measurement.expected.ordinaryStreamCount;
        const baseline = executeDirectMpcCursor({
            captureCheckpointAtWorkStep,
            expectedCheckpointByteLength:
                measurement.expected.checkpointByteLength,
            expectedResultByteLength: measurement.expected.resultByteLength,
            expectedWorkStepCount: measurement.expected.totalStreamCount,
            exports,
            outputLengthPointer,
        });
        if (baseline.capturedCheckpoint === undefined) {
            throw new Error('The direct-MPC restoration checkpoint is absent.');
        }
        if (
            baseline.checkpointCopiedByteLength !==
            measurement.expected.cumulativeCheckpointByteLength
        ) {
            throw new Error(
                'Observed direct-MPC checkpoint traffic differs from the independent model.',
            );
        }
        const maximumCheckpointDuration = Math.max(
            ...baseline.checkpointDurationsMilliseconds,
        );
        const maximumWorkStepDuration = Math.max(
            ...baseline.stepDurationsMilliseconds,
        );
        if (
            maximumWorkStepDuration >
            measurement.expected.workStepForegroundTargetMilliseconds
        ) {
            throw new Error(
                `One direct-MPC work step took ${maximumWorkStepDuration} ms; target is ${measurement.expected.workStepForegroundTargetMilliseconds} ms.`,
            );
        }
        if (
            maximumCheckpointDuration >
            measurement.expected.checkpointForegroundTargetMilliseconds
        ) {
            throw new Error(
                `One direct-MPC checkpoint took ${maximumCheckpointDuration} ms; target is ${measurement.expected.checkpointForegroundTargetMilliseconds} ms.`,
            );
        }
        if (
            baseline.totalElapsedMilliseconds >
            measurement.expected.completeContributionTargetMilliseconds
        ) {
            throw new Error(
                `The direct-MPC scalar cursor took ${baseline.totalElapsedMilliseconds} ms; target is ${measurement.expected.completeContributionTargetMilliseconds} ms.`,
            );
        }
        exports.deallocate(outputLengthPointer, 4);
        if (exports.close() !== directMpcSuccess) {
            throw new Error('The direct-MPC baseline cursor did not close.');
        }
        const linearMemoryByteLengthAfterClose =
            exports.memory.buffer.byteLength;

        const mutationInstance =
            await instantiateDirectMpcMeasurement(wasmBytes);
        const changedCheckpoint = baseline.capturedCheckpoint.slice();
        changedCheckpoint[Math.floor(changedCheckpoint.byteLength / 2)] ^= 0x80;
        const checkpointMutationRefusalCode = restoreDirectMpcCheckpoint(
            mutationInstance.exports,
            changedCheckpoint,
        );
        changedCheckpoint.fill(0);
        if (
            checkpointMutationRefusalCode !==
            directMpcCheckpointAuthenticationRefusal
        ) {
            throw new Error(
                `A mutated direct-MPC checkpoint refused with ${checkpointMutationRefusalCode}; expected ${directMpcCheckpointAuthenticationRefusal}.`,
            );
        }
        if (mutationInstance.exports.close() !== directMpcNotOpen) {
            throw new Error(
                'A refused direct-MPC restoration left an open cursor.',
            );
        }

        const forcedTermination = await runForcedTerminationCheckpoint({
            captureWorkStep: captureCheckpointAtWorkStep,
            checkpointFilePath,
            measurementId: measurement.measurementId,
            wasmFilePath,
        });
        const terminatedCheckpoint = await readFile(checkpointFilePath);
        const terminatedCheckpointDigest = createHash('sha256')
            .update(terminatedCheckpoint)
            .digest('hex');
        if (
            forcedTermination.checkpointSha256Hex !==
                terminatedCheckpointDigest ||
            !terminatedCheckpoint.equals(
                Buffer.from(baseline.capturedCheckpoint),
            )
        ) {
            throw new Error(
                'The process-termination checkpoint differs from the baseline safe-boundary bytes.',
            );
        }
        const forcedRestore = runForcedColdRestore({
            checkpointFilePath,
            measurementId: measurement.measurementId,
            wasmFilePath,
        });
        terminatedCheckpoint.fill(0);
        baseline.capturedCheckpoint.fill(0);
        if (forcedRestore.resultSha3_512Hex !== baseline.resultSha3_512Hex) {
            throw new Error(
                'Forced process loss and cold restoration changed the direct-MPC result.',
            );
        }
        if (
            forcedRestore.coldRestoreElapsedMilliseconds >
            measurement.expected.coldRestoreTargetMilliseconds
        ) {
            throw new Error(
                `Direct-MPC cold restoration took ${forcedRestore.coldRestoreElapsedMilliseconds} ms; target is ${measurement.expected.coldRestoreTargetMilliseconds} ms.`,
            );
        }

        const native = nativeParity.result;
        if (
            native.totalStreamCount !== measurement.expected.totalStreamCount ||
            native.fieldOutputCount !== measurement.expected.fieldOutputCount ||
            native.sourceByteLength !== measurement.expected.sourceByteLength ||
            native.checkpointGeneratedByteLength !==
                measurement.expected.cumulativeCheckpointByteLength ||
            native.checkpointByteLength !==
                measurement.expected.checkpointByteLength ||
            native.resultByteLength !== measurement.expected.resultByteLength ||
            native.resultSha3_512Hex !== baseline.resultSha3_512Hex ||
            native.restoredResultSha3_512Hex !== baseline.resultSha3_512Hex ||
            native.restoredResultMatches !== true ||
            native.checkpointMutationRefusalCode !==
                checkpointMutationRefusalCode
        ) {
            throw new Error(
                'Native and scalar WebAssembly direct-MPC results, counts, restoration, or refusals differ.',
            );
        }

        const maximumLinearMemoryByteLength = Math.max(
            baseline.maximumLinearMemoryByteLength,
            forcedRestore.maximumLinearMemoryByteLength,
            linearMemoryByteLengthAfterOpen,
            linearMemoryByteLengthAfterClose,
        );
        if (
            maximumLinearMemoryByteLength >
            foundationProfile.maximumWasmMemoryByteLength
        ) {
            throw new Error(
                `The scalar direct-MPC cursor used ${maximumLinearMemoryByteLength} bytes of linear memory; absolute maximum is ${foundationProfile.maximumWasmMemoryByteLength}.`,
            );
        }
        if (
            measurement.expected.maximumXofOutputAllocationByteLength >
            foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new Error(
                'The direct-MPC XOF allocation exceeds the copied-buffer bound.',
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
                activeWorkerCount: 1,
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
                    ...native,
                    buildAndRunElapsedMilliseconds:
                        nativeParity.buildAndRunElapsedMilliseconds,
                    matchesScalarWebAssemblyBytes: true,
                    matchesScalarWebAssemblyRefusal: true,
                }),
                baseline: Object.freeze({
                    checkpointCopiedByteLength:
                        baseline.checkpointCopiedByteLength,
                    checkpointDurationMilliseconds: distribution(
                        baseline.checkpointDurationsMilliseconds,
                    ),
                    coldOpenElapsedMilliseconds,
                    maximumLinearMemoryByteLength:
                        baseline.maximumLinearMemoryByteLength,
                    resultByteLength: baseline.resultByteLength,
                    resultSha3_512Hex: baseline.resultSha3_512Hex,
                    stepDurationMilliseconds: distribution(
                        baseline.stepDurationsMilliseconds,
                    ),
                    totalElapsedMilliseconds: baseline.totalElapsedMilliseconds,
                    workStepCount: baseline.workStepCount,
                }),
                forcedTerminationAndColdRestore: Object.freeze({
                    captureCheckpointAtWorkStep,
                    checkpointByteLength:
                        measurement.expected.checkpointByteLength,
                    checkpointSha256Hex: terminatedCheckpointDigest,
                    terminatedProcessExitCode: forcedTermination.exitCode,
                    terminationRequested:
                        forcedTermination.terminationRequested,
                    ...forcedRestore,
                    resultMatchesBaseline:
                        forcedRestore.resultSha3_512Hex ===
                        baseline.resultSha3_512Hex,
                }),
                refusals: Object.freeze({
                    checkpointMutationRefusalCode,
                    cursorAlreadyOpenRefusalCode: directMpcAlreadyOpen,
                    cursorNotOpenRefusalCode: directMpcNotOpen,
                }),
                memory: Object.freeze({
                    linearMemoryByteLengthAfterClose,
                    linearMemoryByteLengthAfterOpen,
                    linearMemoryByteLengthBeforeOpen,
                    maximumLinearMemoryByteLength,
                    baselineLinearMemoryPhysicallyReclaimedByClose:
                        linearMemoryByteLengthAfterClose <
                        baseline.maximumLinearMemoryByteLength,
                }),
            }),
            limitations: Object.freeze([
                'Node scalar WebAssembly development evidence only; not external Chrome or supported-phone evidence.',
                'Deterministic measurement masters exercise the exact framed PRSS cursor but do not establish the malicious all-ten seed terminal.',
                'The authenticated inner checkpoint does not replace encrypted persistence, rollback witnessing, quota admission, repair, or browser reclamation.',
                'This kill test covers dominant PRSS generation, field reduction, basis weighting, checkpointing, and cold restoration; it does not prove the complete direct-MPC theorem or positive verifier.',
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
    await runDirectMpcWasmMeasurementWorker();
}
