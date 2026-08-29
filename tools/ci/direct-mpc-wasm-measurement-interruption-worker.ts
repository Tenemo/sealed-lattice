import { createHash } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { resolveDirectMpcWasmMeasurement } from './direct-mpc-wasm-measurement-registry.js';
import {
    copyRequiredSecretOutput,
    directMpcSuccess,
    executeDirectMpcCursor,
    instantiateDirectMpcMeasurement,
    restoreDirectMpcCheckpoint,
} from './direct-mpc-wasm-measurement-worker.js';

type ParsedArguments = Readonly<{
    captureWorkStep?: number;
    checkpointFilePath: string;
    measurementId: string;
    mode: 'checkpoint' | 'restore';
    wasmFilePath: string;
}>;

const parseArguments = (
    commandArguments: readonly string[],
): ParsedArguments => {
    const values = new Map<string, string>();
    for (
        let argumentPosition = 0;
        argumentPosition < commandArguments.length;
        argumentPosition += 2
    ) {
        const key = commandArguments[argumentPosition];
        const value = commandArguments[argumentPosition + 1];
        if (key === undefined || value === undefined || !key.startsWith('--')) {
            throw new Error(
                `Malformed direct-MPC interruption worker argument: ${key ?? '<missing>'}.`,
            );
        }
        values.set(key, value);
    }
    const mode = values.get('--mode');
    const measurementId = values.get('--measurement');
    const wasmFilePath = values.get('--wasm');
    const checkpointFilePath = values.get('--checkpoint');
    if (mode !== 'checkpoint' && mode !== 'restore') {
        throw new Error('The interruption worker requires a known --mode.');
    }
    if (
        measurementId === undefined ||
        wasmFilePath === undefined ||
        checkpointFilePath === undefined ||
        !path.isAbsolute(wasmFilePath) ||
        !path.isAbsolute(checkpointFilePath)
    ) {
        throw new Error(
            'The interruption worker requires an identifier and absolute WebAssembly and checkpoint paths.',
        );
    }
    const captureWorkStepText = values.get('--capture-work-step');
    const captureWorkStep =
        captureWorkStepText === undefined
            ? undefined
            : Number.parseInt(captureWorkStepText, 10);
    if (
        mode === 'checkpoint' &&
        (!Number.isSafeInteger(captureWorkStep) || (captureWorkStep ?? 0) <= 0)
    ) {
        throw new Error(
            'Checkpoint mode requires a positive safe --capture-work-step.',
        );
    }
    return Object.freeze({
        ...(captureWorkStep === undefined ? {} : { captureWorkStep }),
        checkpointFilePath,
        measurementId,
        mode,
        wasmFilePath,
    });
};

const writeJsonLine = async (value: unknown): Promise<void> =>
    await new Promise((resolve, reject) => {
        process.stdout.write(`${JSON.stringify(value)}\n`, (error) => {
            if (error === null || error === undefined) resolve();
            else reject(error);
        });
    });

const runCheckpointMode = async (parsed: ParsedArguments): Promise<never> => {
    const measurement = resolveDirectMpcWasmMeasurement(parsed.measurementId);
    const captureWorkStep = parsed.captureWorkStep;
    if (captureWorkStep === undefined) {
        throw new Error('The checkpoint work step is absent.');
    }
    const wasmBytes = await readFile(parsed.wasmFilePath);
    const instantiated = await instantiateDirectMpcMeasurement(wasmBytes);
    if (instantiated.exports.open() !== directMpcSuccess) {
        throw new Error('The forced-termination cursor did not open.');
    }
    const outputLengthPointer = instantiated.exports.allocate(4);
    if (outputLengthPointer === 0) {
        throw new Error(
            'The forced-termination output-length slot was not allocated.',
        );
    }
    let checkpoint: Uint8Array | undefined;
    for (let workStep = 1; workStep <= captureWorkStep; workStep += 1) {
        if (instantiated.exports.step() !== directMpcSuccess) {
            throw new Error(
                `The forced-termination cursor failed at work step ${workStep}.`,
            );
        }
        const currentCheckpoint = copyRequiredSecretOutput(
            instantiated.exports,
            instantiated.exports.checkpoint,
            outputLengthPointer,
        );
        if (
            currentCheckpoint.byteLength !==
            measurement.expected.checkpointByteLength
        ) {
            throw new Error(
                'The forced-termination checkpoint has the wrong byte length.',
            );
        }
        checkpoint?.fill(0);
        checkpoint = currentCheckpoint;
    }
    if (checkpoint === undefined) {
        throw new Error('The forced-termination checkpoint is absent.');
    }
    const checkpointFile = await open(parsed.checkpointFilePath, 'w');
    try {
        await checkpointFile.writeFile(checkpoint);
        await checkpointFile.sync();
    } finally {
        await checkpointFile.close();
    }
    const checkpointSha256Hex = createHash('sha256')
        .update(checkpoint)
        .digest('hex');
    checkpoint.fill(0);
    await writeJsonLine(
        Object.freeze({
            checkpointReady: true,
            checkpointSha256Hex,
            captureWorkStep,
        }),
    );
    return await new Promise<never>(() => {
        // The parent deliberately terminates this process after synced checkpoint publication.
    });
};

const runRestoreMode = async (parsed: ParsedArguments): Promise<void> => {
    const measurement = resolveDirectMpcWasmMeasurement(parsed.measurementId);
    const wasmBytes = await readFile(parsed.wasmFilePath);
    const checkpoint = await readFile(parsed.checkpointFilePath);
    const coldRestoreStart = performance.now();
    const instantiated = await instantiateDirectMpcMeasurement(wasmBytes);
    const restoreResult = restoreDirectMpcCheckpoint(
        instantiated.exports,
        checkpoint,
    );
    checkpoint.fill(0);
    if (restoreResult !== directMpcSuccess) {
        throw new Error(
            `The forced cold restoration refused with code ${restoreResult}.`,
        );
    }
    const coldRestoreElapsedMilliseconds = performance.now() - coldRestoreStart;
    const outputLengthPointer = instantiated.exports.allocate(4);
    if (outputLengthPointer === 0) {
        throw new Error(
            'The cold-restore output-length slot was not allocated.',
        );
    }
    const execution = executeDirectMpcCursor({
        expectedCheckpointByteLength: measurement.expected.checkpointByteLength,
        expectedResultByteLength: measurement.expected.resultByteLength,
        expectedWorkStepCount:
            measurement.expected.totalStreamCount -
            measurement.expected.ordinaryStreamCount,
        exports: instantiated.exports,
        outputLengthPointer,
    });
    instantiated.exports.deallocate(outputLengthPointer, 4);
    if (instantiated.exports.close() !== directMpcSuccess) {
        throw new Error('The forced cold-restore cursor did not close.');
    }
    await writeJsonLine(
        Object.freeze({
            checkpointCopiedByteLength: execution.checkpointCopiedByteLength,
            checkpointDurationMaximumMilliseconds: Math.max(
                ...execution.checkpointDurationsMilliseconds,
            ),
            coldRestoreElapsedMilliseconds,
            maximumLinearMemoryByteLength:
                execution.maximumLinearMemoryByteLength,
            remainingElapsedMilliseconds: execution.totalElapsedMilliseconds,
            remainingWorkStepCount: execution.workStepCount,
            resultByteLength: execution.resultByteLength,
            resultSha3_512Hex: execution.resultSha3_512Hex,
        }),
    );
};

export const runDirectMpcInterruptionWorker = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsed = parseArguments(rawArguments);
    if (parsed.mode === 'checkpoint') {
        await runCheckpointMode(parsed);
    } else {
        await runRestoreMode(parsed);
    }
};

if (import.meta.main) {
    await runDirectMpcInterruptionWorker();
}
