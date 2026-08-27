import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import {
    allRosterZeroSharingCodewordMeasurementId,
    resolveZeroSharingCodewordWasmMeasurement,
} from './zero-sharing-codeword-wasm-measurement-registry.js';
import { resolveZeroSharingWasmMeasurement } from './zero-sharing-wasm-measurement-registry.js';

const workerFilePath = fileURLToPath(
    new URL('./zero-sharing-wasm-measurement-worker.ts', import.meta.url),
);
const codewordWorkerFilePath = fileURLToPath(
    new URL(
        './zero-sharing-codeword-wasm-measurement-worker.ts',
        import.meta.url,
    ),
);
const usage =
    'Usage: run-zero-sharing-wasm-measurement.ts <registered measurement id>.';

type ParsedArguments = Readonly<{ measurementId: string }>;

let zeroSharingProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getZeroSharingProcessMemoryGuard = (): ProcessMemoryGuard => {
    zeroSharingProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'Zero-sharing scalar WebAssembly measurements',
        memoryLimitEnvironmentVariable:
            'SEALED_LATTICE_ZERO_SHARING_MEMORY_LIMIT_GIB',
    });
    return zeroSharingProcessMemoryGuard;
};

export const parseZeroSharingWasmMeasurementArguments = (
    commandArguments: readonly string[],
): ParsedArguments => {
    const positionalArguments = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        positionalArguments.some((argument) => argument.startsWith('-')) ||
        positionalArguments.length !== 1
    ) {
        throw new Error(
            `Zero-sharing WebAssembly measurements require one exact registered identifier. ${usage}`,
        );
    }
    const measurementId = positionalArguments[0]?.trim() ?? '';
    if (measurementId.length === 0) {
        throw new Error(
            `Zero-sharing WebAssembly measurements require a nonempty identifier. ${usage}`,
        );
    }
    if (measurementId === allRosterZeroSharingCodewordMeasurementId) {
        resolveZeroSharingCodewordWasmMeasurement(measurementId);
    } else {
        resolveZeroSharingWasmMeasurement(measurementId);
    }
    return { measurementId };
};

const buildWorkerCommand = (
    parsedArguments: ParsedArguments,
    outputFilePath: string,
    diagnosticsPath: string,
): CommandInvocation => {
    const processMemoryGuard = getZeroSharingProcessMemoryGuard();
    const environment = { ...process.env };
    delete environment.CARGO_ENCODED_RUSTFLAGS;
    return processMemoryGuard.guardCommand(
        {
            args: [
                '--import',
                'tsx',
                parsedArguments.measurementId ===
                allRosterZeroSharingCodewordMeasurementId
                    ? codewordWorkerFilePath
                    : workerFilePath,
                '--measurement',
                parsedArguments.measurementId,
                '--output',
                outputFilePath,
            ],
            command: process.execPath,
            description: `scalar WebAssembly zero-sharing measurement (${parsedArguments.measurementId})`,
            env: {
                ...environment,
                CARGO_BUILD_JOBS: '1',
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: '1',
                RUST_BACKTRACE: 'full',
            },
            logFileSlug: 'zero-sharing-wasm-measurement',
        },
        {
            diagnosticsPath,
            resourceSampleIntervalMilliseconds: 100,
        },
    );
};

export const runZeroSharingWasmMeasurement = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Zero sharing scalar WebAssembly measurement'],
            scriptName: 'test:wasm:zero-sharing',
        },
        async (runLog) => {
            const parsedArguments =
                parseZeroSharingWasmMeasurementArguments(rawArguments);
            const resultFilePath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'zero-sharing-wasm-measurement.json',
            );
            const command = buildWorkerCommand(
                parsedArguments,
                resultFilePath,
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    'process-memory-guard-zero-sharing-wasm.jsonl',
                ),
            );
            const processMemoryGuard = getZeroSharingProcessMemoryGuard();
            const setupMessage =
                `Zero-sharing scalar WebAssembly measurement: ${parsedArguments.measurementId}; ` +
                `one worker; hard inherited process-memory ceiling ${processMemoryGuard.memoryLimitGigabytes} GiB.`;
            console.log(setupMessage);
            runLog.writeCombinedOutput(`${setupMessage}\n`);

            process.exitCode = await withLocalHeavyLaneLease({
                action: async () => {
                    let exitCode = await runCommandsInSeries(
                        [processMemoryGuard.buildVerificationCommand()],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) return exitCode;
                    exitCode = await runCommandsInSeries([command], {
                        outputMode: 'inherit',
                        runLog,
                    });
                    return exitCode;
                },
                laneLabel: 'Zero sharing scalar WebAssembly measurement',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    await runZeroSharingWasmMeasurement();
}
