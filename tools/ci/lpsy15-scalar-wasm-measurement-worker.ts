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
    resolveLpsy15ScalarWasmMeasurement,
    type Lpsy15ScalarWasmMeasurement,
} from './lpsy15-scalar-wasm-measurement-registry.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const measurementTemporaryRoot = path.resolve(
    repoRoot,
    'temp',
    'build-scratch',
    'lpsy15-scalar-wasm-measurements',
);
const measurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'wasm-lpsy15-scalar-measurement',
);
const nativeMeasurementCargoTargetDirectory = path.resolve(
    repoRoot,
    'target',
    'native-lpsy15-scalar-measurement',
);
const measurementError = 0xffff_ffff;
const primeFieldKind = 1;
const bmrPrfKind = 2;
const processingState = 1;

type ParsedArguments = Readonly<{
    measurementId: string;
    outputFilePath: string;
}>;

type MeasurementExports = Readonly<{
    allocate: (byteLength: number) => number;
    checkpoint: (outputLengthPointer: number) => number;
    close: () => number;
    completedOperationCount: () => bigint;
    deallocate: (pointer: number, byteLength: number) => void;
    deallocateSecret: (pointer: number, byteLength: number) => void;
    fieldScratchByteLength: () => bigint;
    memory: WebAssembly.Memory;
    open: (kind: number) => number;
    prfMessageByteLength: () => bigint;
    prfPermutationCountPerCall: () => bigint;
    restore: (kind: number, pointer: number, byteLength: number) => number;
    snapshot: (outputLengthPointer: number) => number;
    state: () => number;
    step: () => number;
    totalFieldAdditionCount: () => bigint;
    totalOperationCount: () => bigint;
    workBatchOperationCount: () => bigint;
}>;

type NativeKindResult = Readonly<{
    baselineSnapshotSha3_512Hex: string;
    checkpointByteLengths: readonly number[];
    checkpointSha3_512Hex: readonly string[];
    kind: 'prime-field' | 'bmr-prf';
    restoredSnapshotSha3_512Hex: string;
    totalOperationCount: number;
    workBatchOperationCount: number;
}>;

type NativeMeasurement = Readonly<{
    evidenceClassification: string;
    fieldAdditionCount: number;
    fieldMultiplicationCount: number;
    fieldScratchByteLength: number;
    prfCallCount: number;
    prfMessageByteLength: number;
    prfPermutationCountPerCall: number;
    results: readonly NativeKindResult[];
    schemaVersion: number;
}>;

type StepExecution = Readonly<{
    capturedCheckpoint?: Uint8Array;
    checkpointByteLengths: readonly number[];
    checkpointDurationsMilliseconds: readonly number[];
    checkpointSha3_512Hex: readonly string[];
    maximumLinearMemoryByteLength: number;
    stepDurationsMilliseconds: readonly number[];
}>;

type KernelMeasurement = Readonly<{
    baselineSnapshotSha3_512Hex: string;
    checkpointByteLengths: readonly number[];
    checkpointDurationsMilliseconds: readonly number[];
    checkpointSha3_512Hex: readonly string[];
    coldOpenMilliseconds: number;
    coldRestoreMilliseconds: number;
    forcedTerminationAtAuthenticatedBoundary: true;
    kind: 'prime-field' | 'bmr-prf';
    maximumLinearMemoryByteLength: number;
    maximumLostWorkOperationCount: number;
    projectedFullWorkloadMilliseconds: number;
    restoredSnapshotSha3_512Hex: string;
    restartTrafficByteLength: number;
    stepDurationsMilliseconds: readonly number[];
    totalOperationCount: number;
    workBatchOperationCount: number;
}>;

const isNativeKindResult = (value: unknown): value is NativeKindResult => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    const candidate = value as Record<string, unknown>;
    return (
        (candidate.kind === 'prime-field' || candidate.kind === 'bmr-prf') &&
        typeof candidate.baselineSnapshotSha3_512Hex === 'string' &&
        typeof candidate.restoredSnapshotSha3_512Hex === 'string' &&
        typeof candidate.totalOperationCount === 'number' &&
        typeof candidate.workBatchOperationCount === 'number' &&
        Array.isArray(candidate.checkpointByteLengths) &&
        candidate.checkpointByteLengths.every(
            (byteLength: unknown) => typeof byteLength === 'number',
        ) &&
        Array.isArray(candidate.checkpointSha3_512Hex) &&
        candidate.checkpointSha3_512Hex.every(
            (digest: unknown) => typeof digest === 'string',
        )
    );
};

export const parseLpsy15ScalarWasmMeasurementWorkerArguments = (
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
            `Unknown or incomplete LPSY15 measurement worker argument: ${argument ?? '<missing>'}.`,
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

const resolveMeasurementExports = (
    exports: WebAssembly.Exports,
): MeasurementExports => {
    const memory = exports.memory;
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error(
            'The diagnostic WebAssembly build does not export linear memory.',
        );
    }
    const resolved: MeasurementExports = {
        allocate: resolveFunction<MeasurementExports['allocate']>(
            exports,
            'sealed_lattice_allocate',
        ),
        checkpoint: resolveFunction<MeasurementExports['checkpoint']>(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_checkpoint_with_length',
        ),
        close: resolveFunction<MeasurementExports['close']>(
            exports,
            'sealed_lattice_close_lpsy15_scalar_measurement',
        ),
        completedOperationCount: resolveFunction<
            MeasurementExports['completedOperationCount']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_completed_operation_count',
        ),
        deallocate: resolveFunction<MeasurementExports['deallocate']>(
            exports,
            'sealed_lattice_deallocate',
        ),
        deallocateSecret: resolveFunction<
            MeasurementExports['deallocateSecret']
        >(exports, 'sealed_lattice_deallocate_secret'),
        fieldScratchByteLength: resolveFunction<
            MeasurementExports['fieldScratchByteLength']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_field_scratch_byte_length',
        ),
        memory,
        open: resolveFunction<MeasurementExports['open']>(
            exports,
            'sealed_lattice_open_lpsy15_scalar_measurement',
        ),
        prfMessageByteLength: resolveFunction<
            MeasurementExports['prfMessageByteLength']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_prf_message_byte_length',
        ),
        prfPermutationCountPerCall: resolveFunction<
            MeasurementExports['prfPermutationCountPerCall']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_prf_permutation_count_per_call',
        ),
        restore: resolveFunction<MeasurementExports['restore']>(
            exports,
            'sealed_lattice_restore_lpsy15_scalar_measurement',
        ),
        snapshot: resolveFunction<MeasurementExports['snapshot']>(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_snapshot_with_length',
        ),
        state: resolveFunction<MeasurementExports['state']>(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_state',
        ),
        step: resolveFunction<MeasurementExports['step']>(
            exports,
            'sealed_lattice_step_lpsy15_scalar_measurement',
        ),
        totalFieldAdditionCount: resolveFunction<
            MeasurementExports['totalFieldAdditionCount']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_total_field_addition_count',
        ),
        totalOperationCount: resolveFunction<
            MeasurementExports['totalOperationCount']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_total_operation_count',
        ),
        workBatchOperationCount: resolveFunction<
            MeasurementExports['workBatchOperationCount']
        >(
            exports,
            'sealed_lattice_lpsy15_scalar_measurement_work_batch_operation_count',
        ),
    };
    return Object.freeze(resolved);
};

const instantiateMeasurement = async (
    wasmBytes: Uint8Array,
): Promise<{
    readonly exportNames: readonly string[];
    readonly exports: MeasurementExports;
}> => {
    const ownedBytes = new Uint8Array(wasmBytes.byteLength);
    ownedBytes.set(wasmBytes);
    const module = await WebAssembly.compile(ownedBytes.buffer);
    const instance = await WebAssembly.instantiate(module, {});
    return Object.freeze({
        exportNames: Object.keys(instance.exports).sort(),
        exports: resolveMeasurementExports(instance.exports),
    });
};

const numberFromUnsigned64 = (value: bigint, field: string): number => {
    const converted = Number(value);
    if (!Number.isSafeInteger(converted) || converted < 0) {
        throw new Error(`${field} does not fit a nonnegative safe integer.`);
    }
    return converted;
};

const requireEqual = (
    actual: number,
    expected: number,
    field: string,
): void => {
    if (actual !== expected) {
        throw new Error(
            `LPSY15 scalar ${field} mismatch: expected ${expected}, received ${actual}.`,
        );
    }
};

const copySecretOutput = (
    exports: MeasurementExports,
    outputFunction: (outputLengthPointer: number) => number,
    outputLengthPointer: number,
): Uint8Array => {
    const outputPointer = outputFunction(outputLengthPointer) >>> 0;
    const outputLength = new DataView(exports.memory.buffer).getUint32(
        outputLengthPointer,
        true,
    );
    if (outputPointer === 0 || outputLength === 0) {
        throw new Error('The scalar measurement produced no output bytes.');
    }
    const output = new Uint8Array(outputLength);
    output.set(
        new Uint8Array(exports.memory.buffer, outputPointer, outputLength),
    );
    exports.deallocateSecret(outputPointer, outputLength);
    return output;
};

const restoreCheckpoint = (
    exports: MeasurementExports,
    kindCode: number,
    checkpoint: Uint8Array,
): void => {
    const inputPointer = exports.allocate(checkpoint.byteLength) >>> 0;
    if (inputPointer === 0) {
        throw new Error('The checkpoint input allocation failed.');
    }
    new Uint8Array(
        exports.memory.buffer,
        inputPointer,
        checkpoint.byteLength,
    ).set(checkpoint);
    const status = exports.restore(
        kindCode,
        inputPointer,
        checkpoint.byteLength,
    );
    exports.deallocateSecret(inputPointer, checkpoint.byteLength);
    if (status >>> 0 !== 0) {
        throw new Error('The authenticated scalar checkpoint was refused.');
    }
};

const executeSteps = (
    exports: MeasurementExports,
    workStepCount: number,
    captureFinalCheckpoint: boolean,
): StepExecution => {
    const outputLengthPointer = exports.allocate(4) >>> 0;
    if (outputLengthPointer === 0) {
        throw new Error('The output-length allocation failed.');
    }
    const stepDurationsMilliseconds: number[] = [];
    const checkpointDurationsMilliseconds: number[] = [];
    const checkpointByteLengths: number[] = [];
    const checkpointSha3_512Hex: string[] = [];
    let capturedCheckpoint: Uint8Array | undefined;
    let maximumLinearMemoryByteLength = exports.memory.buffer.byteLength;
    for (let workStep = 0; workStep < workStepCount; workStep += 1) {
        const stepStart = performance.now();
        const stepStatus = exports.step() >>> 0;
        stepDurationsMilliseconds.push(performance.now() - stepStart);
        if (stepStatus !== 0) {
            throw new Error(
                `A sampled scalar work step returned status ${stepStatus}.`,
            );
        }
        const checkpointStart = performance.now();
        const checkpoint = copySecretOutput(
            exports,
            exports.checkpoint,
            outputLengthPointer,
        );
        checkpointDurationsMilliseconds.push(
            performance.now() - checkpointStart,
        );
        checkpointByteLengths.push(checkpoint.byteLength);
        checkpointSha3_512Hex.push(sha3_512Hex(checkpoint));
        if (captureFinalCheckpoint && workStep + 1 === workStepCount) {
            capturedCheckpoint = checkpoint;
        } else {
            checkpoint.fill(0);
        }
        maximumLinearMemoryByteLength = Math.max(
            maximumLinearMemoryByteLength,
            exports.memory.buffer.byteLength,
        );
    }
    exports.deallocate(outputLengthPointer, 4);
    return Object.freeze({
        capturedCheckpoint,
        checkpointByteLengths,
        checkpointDurationsMilliseconds,
        checkpointSha3_512Hex,
        maximumLinearMemoryByteLength,
        stepDurationsMilliseconds,
    });
};

const snapshot = (exports: MeasurementExports): Uint8Array => {
    const outputLengthPointer = exports.allocate(4) >>> 0;
    if (outputLengthPointer === 0) {
        throw new Error('The snapshot length allocation failed.');
    }
    const bytes = copySecretOutput(
        exports,
        exports.snapshot,
        outputLengthPointer,
    );
    exports.deallocate(outputLengthPointer, 4);
    return bytes;
};

const sha3_512Hex = (bytes: Uint8Array): string =>
    createHash('sha3-512').update(bytes).digest('hex');

const verifyCompilerCounts = (
    exports: MeasurementExports,
    measurement: Lpsy15ScalarWasmMeasurement,
    kindCode: number,
): Readonly<{
    totalOperationCount: number;
    workBatchOperationCount: number;
}> => {
    const expected = measurement.expected;
    const totalOperationCount = numberFromUnsigned64(
        exports.totalOperationCount(),
        'total operation count',
    );
    requireEqual(
        totalOperationCount,
        kindCode === primeFieldKind
            ? expected.fieldMultiplicationCount
            : expected.prfCallCount,
        'total operation count',
    );
    requireEqual(
        numberFromUnsigned64(
            exports.totalFieldAdditionCount(),
            'field addition count',
        ),
        expected.fieldAdditionCount,
        'field addition count',
    );
    requireEqual(
        numberFromUnsigned64(
            exports.fieldScratchByteLength(),
            'field scratch byte length',
        ),
        expected.fieldScratchByteLength,
        'field scratch byte length',
    );
    requireEqual(
        numberFromUnsigned64(
            exports.prfMessageByteLength(),
            'PRF message byte length',
        ),
        expected.prfMessageByteLength,
        'PRF message byte length',
    );
    requireEqual(
        numberFromUnsigned64(
            exports.prfPermutationCountPerCall(),
            'PRF permutation count',
        ),
        expected.prfPermutationCountPerCall,
        'PRF permutation count',
    );
    const workBatchOperationCount = numberFromUnsigned64(
        exports.workBatchOperationCount(),
        'work batch operation count',
    );
    requireEqual(
        workBatchOperationCount,
        expected.workBatchOperationCount,
        'work batch operation count',
    );
    if (exports.state() >>> 0 !== processingState) {
        throw new Error('The opened scalar cursor is not processing.');
    }
    return Object.freeze({ totalOperationCount, workBatchOperationCount });
};

const warmUp = async (
    wasmBytes: Uint8Array,
    kindCode: number,
): Promise<void> => {
    const instantiated = await instantiateMeasurement(wasmBytes);
    if (instantiated.exports.open(kindCode) >>> 0 !== 0) {
        throw new Error('The scalar warmup cursor failed to open.');
    }
    executeSteps(instantiated.exports, 1, false);
    const warmupSnapshot = snapshot(instantiated.exports);
    warmupSnapshot.fill(0);
    if (instantiated.exports.close() >>> 0 !== 0) {
        throw new Error('The scalar warmup cursor failed to close.');
    }
};

const createInterruptedCheckpoint = async (
    wasmBytes: Uint8Array,
    kindCode: number,
    workStepCount: number,
): Promise<{
    readonly checkpoint: Uint8Array;
    readonly checkpointByteLengths: readonly number[];
    readonly checkpointDurationsMilliseconds: readonly number[];
    readonly checkpointSha3_512Hex: readonly string[];
    readonly maximumLinearMemoryByteLength: number;
    readonly stepDurationsMilliseconds: readonly number[];
}> => {
    const interrupted = await instantiateMeasurement(wasmBytes);
    if (interrupted.exports.open(kindCode) >>> 0 !== 0) {
        throw new Error('The interruption cursor failed to open.');
    }
    const execution = executeSteps(interrupted.exports, workStepCount, true);
    if (execution.capturedCheckpoint === undefined) {
        throw new Error('The interruption checkpoint is absent.');
    }
    // Deliberately omit close: the complete module instance and Rust-owned
    // cursor become unreachable here, modeling worker loss at a durable safe
    // boundary.
    return Object.freeze({
        checkpoint: execution.capturedCheckpoint,
        checkpointByteLengths: execution.checkpointByteLengths,
        checkpointDurationsMilliseconds:
            execution.checkpointDurationsMilliseconds,
        checkpointSha3_512Hex: execution.checkpointSha3_512Hex,
        maximumLinearMemoryByteLength: execution.maximumLinearMemoryByteLength,
        stepDurationsMilliseconds: execution.stepDurationsMilliseconds,
    });
};

const assertCheckpointMutationRefused = async (
    wasmBytes: Uint8Array,
    kindCode: number,
    checkpoint: Uint8Array,
): Promise<void> => {
    const mutated = checkpoint.slice();
    mutated[Math.floor(mutated.byteLength / 2)] ^= 1;
    const instantiated = await instantiateMeasurement(wasmBytes);
    const inputPointer =
        instantiated.exports.allocate(mutated.byteLength) >>> 0;
    if (inputPointer === 0) {
        throw new Error('The hostile checkpoint input allocation failed.');
    }
    new Uint8Array(
        instantiated.exports.memory.buffer,
        inputPointer,
        mutated.byteLength,
    ).set(mutated);
    const status =
        instantiated.exports.restore(
            kindCode,
            inputPointer,
            mutated.byteLength,
        ) >>> 0;
    instantiated.exports.deallocateSecret(inputPointer, mutated.byteLength);
    mutated.fill(0);
    if (status !== measurementError) {
        throw new Error(
            `A mutated authenticated checkpoint returned status ${status}.`,
        );
    }
};

const measureKernel = async (input: {
    readonly kind: 'prime-field' | 'bmr-prf';
    readonly kindCode: number;
    readonly measurement: Lpsy15ScalarWasmMeasurement;
    readonly nativeResult: NativeKindResult;
    readonly wasmBytes: Uint8Array;
}): Promise<KernelMeasurement> => {
    await warmUp(input.wasmBytes, input.kindCode);

    const baseline = await instantiateMeasurement(input.wasmBytes);
    const coldOpenStart = performance.now();
    if (baseline.exports.open(input.kindCode) >>> 0 !== 0) {
        throw new Error(`The ${input.kind} scalar cursor failed to open.`);
    }
    const coldOpenMilliseconds = performance.now() - coldOpenStart;
    const counts = verifyCompilerCounts(
        baseline.exports,
        input.measurement,
        input.kindCode,
    );
    const baselineExecution = executeSteps(
        baseline.exports,
        input.measurement.expected.sampleWorkStepCount,
        false,
    );
    requireEqual(
        numberFromUnsigned64(
            baseline.exports.completedOperationCount(),
            'completed operation count',
        ),
        input.measurement.expected.sampleWorkStepCount *
            counts.workBatchOperationCount,
        'completed operation count',
    );
    const baselineSnapshot = snapshot(baseline.exports);
    const baselineSnapshotSha3_512Hex = sha3_512Hex(baselineSnapshot);
    if (baseline.exports.close() >>> 0 !== 0) {
        throw new Error(`The ${input.kind} baseline cursor failed to close.`);
    }

    const checkpointWorkStepCount =
        input.measurement.expected.sampleWorkStepCount / 2;
    const interrupted = await createInterruptedCheckpoint(
        input.wasmBytes,
        input.kindCode,
        checkpointWorkStepCount,
    );
    await assertCheckpointMutationRefused(
        input.wasmBytes,
        input.kindCode,
        interrupted.checkpoint,
    );

    const coldRestoreStart = performance.now();
    const restored = await instantiateMeasurement(input.wasmBytes);
    restoreCheckpoint(restored.exports, input.kindCode, interrupted.checkpoint);
    const coldRestoreMilliseconds = performance.now() - coldRestoreStart;
    interrupted.checkpoint.fill(0);
    const restoredExecution = executeSteps(
        restored.exports,
        input.measurement.expected.sampleWorkStepCount -
            checkpointWorkStepCount,
        false,
    );
    const restoredSnapshot = snapshot(restored.exports);
    const restoredSnapshotSha3_512Hex = sha3_512Hex(restoredSnapshot);
    if (
        baselineSnapshot.byteLength !== restoredSnapshot.byteLength ||
        !baselineSnapshot.every(
            (byte, bytePosition) => byte === restoredSnapshot[bytePosition],
        )
    ) {
        throw new Error(
            `Cold restoration changed the ${input.kind} scalar bytes.`,
        );
    }
    baselineSnapshot.fill(0);
    restoredSnapshot.fill(0);
    if (restored.exports.close() >>> 0 !== 0) {
        throw new Error(`The restored ${input.kind} cursor failed to close.`);
    }

    if (
        baselineSnapshotSha3_512Hex !==
            input.nativeResult.baselineSnapshotSha3_512Hex ||
        restoredSnapshotSha3_512Hex !==
            input.nativeResult.restoredSnapshotSha3_512Hex
    ) {
        throw new Error(
            `Native and scalar WebAssembly ${input.kind} snapshots differ.`,
        );
    }
    if (
        JSON.stringify(baselineExecution.checkpointByteLengths) !==
        JSON.stringify(input.nativeResult.checkpointByteLengths)
    ) {
        throw new Error(
            `Native and scalar WebAssembly ${input.kind} checkpoint sizes differ.`,
        );
    }
    if (
        JSON.stringify(baselineExecution.checkpointSha3_512Hex) !==
        JSON.stringify(input.nativeResult.checkpointSha3_512Hex)
    ) {
        throw new Error(
            `Native and scalar WebAssembly ${input.kind} checkpoint bytes differ.`,
        );
    }

    const maximumStepMilliseconds = Math.max(
        ...baselineExecution.stepDurationsMilliseconds,
        ...interrupted.stepDurationsMilliseconds,
        ...restoredExecution.stepDurationsMilliseconds,
    );
    const projectedFullWorkloadMilliseconds =
        (maximumStepMilliseconds / counts.workBatchOperationCount) *
        counts.totalOperationCount;
    return Object.freeze({
        baselineSnapshotSha3_512Hex,
        checkpointByteLengths: [
            ...baselineExecution.checkpointByteLengths,
            ...interrupted.checkpointByteLengths,
            ...restoredExecution.checkpointByteLengths,
        ],
        checkpointDurationsMilliseconds: [
            ...baselineExecution.checkpointDurationsMilliseconds,
            ...interrupted.checkpointDurationsMilliseconds,
            ...restoredExecution.checkpointDurationsMilliseconds,
        ],
        checkpointSha3_512Hex: [
            ...baselineExecution.checkpointSha3_512Hex,
            ...interrupted.checkpointSha3_512Hex,
            ...restoredExecution.checkpointSha3_512Hex,
        ],
        coldOpenMilliseconds,
        coldRestoreMilliseconds,
        forcedTerminationAtAuthenticatedBoundary: true,
        kind: input.kind,
        maximumLinearMemoryByteLength: Math.max(
            baselineExecution.maximumLinearMemoryByteLength,
            interrupted.maximumLinearMemoryByteLength,
            restoredExecution.maximumLinearMemoryByteLength,
        ),
        maximumLostWorkOperationCount: counts.workBatchOperationCount,
        projectedFullWorkloadMilliseconds,
        restoredSnapshotSha3_512Hex,
        restartTrafficByteLength: Math.max(
            ...baselineExecution.checkpointByteLengths,
            ...interrupted.checkpointByteLengths,
            ...restoredExecution.checkpointByteLengths,
        ),
        stepDurationsMilliseconds: [
            ...baselineExecution.stepDurationsMilliseconds,
            ...interrupted.stepDurationsMilliseconds,
            ...restoredExecution.stepDurationsMilliseconds,
        ],
        totalOperationCount: counts.totalOperationCount,
        workBatchOperationCount: counts.workBatchOperationCount,
    });
};

const runNativeParityMeasurement = (): Readonly<{
    buildAndRunMilliseconds: number;
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
            'lpsy15-scalar-measurement',
            '--bin',
            'lpsy15-scalar-native-measurement',
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
            `Failed to start native LPSY15 parity: ${nativeProcess.error.message}`,
        );
    }
    if (nativeProcess.status !== 0) {
        throw new Error(
            `Native LPSY15 parity failed with status ${nativeProcess.status ?? 'null'}: ${nativeProcess.stderr.trim()}`,
        );
    }
    const outputLines = nativeProcess.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    const finalLine = outputLines[outputLines.length - 1];
    if (finalLine === undefined) {
        throw new Error('Native LPSY15 parity produced no result.');
    }
    const parsed = JSON.parse(finalLine) as Partial<NativeMeasurement>;
    if (
        parsed.schemaVersion !== 1 ||
        typeof parsed.evidenceClassification !== 'string' ||
        typeof parsed.fieldMultiplicationCount !== 'number' ||
        typeof parsed.fieldAdditionCount !== 'number' ||
        typeof parsed.prfCallCount !== 'number' ||
        typeof parsed.prfMessageByteLength !== 'number' ||
        typeof parsed.prfPermutationCountPerCall !== 'number' ||
        typeof parsed.fieldScratchByteLength !== 'number' ||
        !Array.isArray(parsed.results) ||
        parsed.results.length !== 2 ||
        parsed.results.some((result: unknown) => !isNativeKindResult(result))
    ) {
        throw new Error('Native LPSY15 parity has an invalid shape.');
    }
    return Object.freeze({
        buildAndRunMilliseconds: performance.now() - start,
        result: parsed as NativeMeasurement,
    });
};

const verifyNativeCounts = (
    native: NativeMeasurement,
    measurement: Lpsy15ScalarWasmMeasurement,
): void => {
    const fields = [
        [
            'field multiplication',
            native.fieldMultiplicationCount,
            measurement.expected.fieldMultiplicationCount,
        ],
        [
            'field addition',
            native.fieldAdditionCount,
            measurement.expected.fieldAdditionCount,
        ],
        ['PRF call', native.prfCallCount, measurement.expected.prfCallCount],
        [
            'PRF message byte length',
            native.prfMessageByteLength,
            measurement.expected.prfMessageByteLength,
        ],
        [
            'PRF permutation',
            native.prfPermutationCountPerCall,
            measurement.expected.prfPermutationCountPerCall,
        ],
        [
            'field scratch byte length',
            native.fieldScratchByteLength,
            measurement.expected.fieldScratchByteLength,
        ],
    ] as const;
    for (const [field, actual, expected] of fields) {
        requireEqual(actual, expected, `native ${field}`);
    }
};

export const runLpsy15ScalarWasmMeasurementWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments =
        parseLpsy15ScalarWasmMeasurementWorkerArguments(rawArguments);
    const measurement = resolveLpsy15ScalarWasmMeasurement(
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
            artifactLabel: 'LPSY15 scalar measurement kernel',
            cargoFeatures: ['lpsy15-scalar-measurement'],
            outputFilePath: wasmOutputFilePath,
            scratchDirectoryPrefix: 'lpsy15-scalar-measurement-',
            targetDirectoryPath: measurementCargoTargetDirectory,
        });
        const wasmBytes = await readFile(wasmOutputFilePath);
        const nativeParity = runNativeParityMeasurement();
        verifyNativeCounts(nativeParity.result, measurement);
        const primeFieldNative = nativeParity.result.results.find(
            (result) => result.kind === 'prime-field',
        );
        const bmrPrfNative = nativeParity.result.results.find(
            (result) => result.kind === 'bmr-prf',
        );
        if (primeFieldNative === undefined || bmrPrfNative === undefined) {
            throw new Error('Native LPSY15 parity omitted a kernel result.');
        }

        const primeField = await measureKernel({
            kind: 'prime-field',
            kindCode: primeFieldKind,
            measurement,
            nativeResult: primeFieldNative,
            wasmBytes,
        });
        const bmrPrf = await measureKernel({
            kind: 'bmr-prf',
            kindCode: bmrPrfKind,
            measurement,
            nativeResult: bmrPrfNative,
            wasmBytes,
        });
        const maximumUninterruptedWorkMilliseconds = Math.max(
            ...primeField.stepDurationsMilliseconds,
            ...bmrPrf.stepDurationsMilliseconds,
        );
        const maximumCheckpointMilliseconds = Math.max(
            ...primeField.checkpointDurationsMilliseconds,
            ...bmrPrf.checkpointDurationsMilliseconds,
        );
        const maximumColdRestoreMilliseconds = Math.max(
            primeField.coldRestoreMilliseconds,
            bmrPrf.coldRestoreMilliseconds,
        );
        const maximumLinearMemoryByteLength = Math.max(
            primeField.maximumLinearMemoryByteLength,
            bmrPrf.maximumLinearMemoryByteLength,
        );
        const maximumCheckpointByteLength = Math.max(
            ...primeField.checkpointByteLengths,
            ...bmrPrf.checkpointByteLengths,
        );
        const projectedCompleteKernelWorkloadMilliseconds =
            primeField.projectedFullWorkloadMilliseconds +
            bmrPrf.projectedFullWorkloadMilliseconds;
        const absoluteBounds = Object.freeze({
            checkpoint: Object.freeze({
                actual: maximumCheckpointMilliseconds,
                limit: measurement.limits.maximumCheckpointMilliseconds,
                passed:
                    maximumCheckpointMilliseconds <=
                    measurement.limits.maximumCheckpointMilliseconds,
            }),
            coldRestore: Object.freeze({
                actual: maximumColdRestoreMilliseconds,
                limit: measurement.limits.maximumColdRestoreMilliseconds,
                passed:
                    maximumColdRestoreMilliseconds <=
                    measurement.limits.maximumColdRestoreMilliseconds,
            }),
            contiguousCopy: Object.freeze({
                actual: Math.max(
                    maximumCheckpointByteLength,
                    measurement.expected.fieldScratchByteLength,
                ),
                limit: measurement.limits.maximumCopiedBufferByteLength,
                passed:
                    Math.max(
                        maximumCheckpointByteLength,
                        measurement.expected.fieldScratchByteLength,
                    ) <= measurement.limits.maximumCopiedBufferByteLength,
            }),
            projectedCompleteKernelWorkload: Object.freeze({
                actual: projectedCompleteKernelWorkloadMilliseconds,
                limit: measurement.limits
                    .maximumCompleteParticipantProcessingMilliseconds,
                passed:
                    projectedCompleteKernelWorkloadMilliseconds <=
                    measurement.limits
                        .maximumCompleteParticipantProcessingMilliseconds,
            }),
            uninterruptedWork: Object.freeze({
                actual: maximumUninterruptedWorkMilliseconds,
                limit: measurement.limits.maximumUninterruptedWorkMilliseconds,
                passed:
                    maximumUninterruptedWorkMilliseconds <=
                    measurement.limits.maximumUninterruptedWorkMilliseconds,
            }),
            wasmMemory: Object.freeze({
                actual: maximumLinearMemoryByteLength,
                limit: measurement.limits.maximumWasmMemoryByteLength,
                passed:
                    maximumLinearMemoryByteLength <=
                    measurement.limits.maximumWasmMemoryByteLength,
            }),
        });
        const allAbsoluteBoundsPassed = Object.values(absoluteBounds).every(
            (bound) => bound.passed,
        );
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
                exports: (await instantiateMeasurement(wasmBytes)).exportNames,
                normalizedSha256Hex: builtArtifact.normalizedSha256Hex,
                wasmByteLength: wasmBytes.byteLength,
            }),
            compilerCounts: measurement.expected,
            kernels: Object.freeze({ primeField, bmrPrf }),
            nativeParity: Object.freeze({
                buildAndRunMilliseconds: nativeParity.buildAndRunMilliseconds,
                evidenceClassification:
                    nativeParity.result.evidenceClassification,
                matched: true,
            }),
            observed: Object.freeze({
                maximumCheckpointByteLength,
                maximumCheckpointMilliseconds,
                maximumColdRestoreMilliseconds,
                maximumLinearMemoryByteLength,
                maximumUninterruptedWorkMilliseconds,
                projectedCompleteKernelWorkloadMilliseconds,
            }),
            absoluteBounds,
            allAbsoluteBoundsPassed,
            limitation:
                'Scalar Node/WebAssembly development evidence only. The full-workload duration is a maximum-observed-batch linear projection, not browser or selected-phone evidence, and no suite or continuation capability is admitted.',
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
        if (!allAbsoluteBoundsPassed) {
            throw new Error(
                'The LPSY15 scalar candidate exceeded at least one absolute development bound.',
            );
        }
    } finally {
        await rm(temporaryDirectoryPath, { force: true, recursive: true });
    }
};

if (import.meta.main) {
    await runLpsy15ScalarWasmMeasurementWorker();
}
