import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import { resolveLpsy15ScalarWasmMeasurement } from './lpsy15-scalar-wasm-measurement-registry.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

const workerFilePath = fileURLToPath(
    new URL('./lpsy15-scalar-wasm-measurement-worker.ts', import.meta.url),
);
const usage =
    'Usage: run-lpsy15-scalar-wasm-measurement.ts <registered measurement id>.';

type ParsedArguments = Readonly<{ measurementId: string }>;

let lpsy15ProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getLpsy15ProcessMemoryGuard = (): ProcessMemoryGuard => {
    lpsy15ProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'LPSY15 scalar WebAssembly measurements',
        memoryLimitEnvironmentVariable:
            'SEALED_LATTICE_LPSY15_SCALAR_MEMORY_LIMIT_GIB',
    });
    return lpsy15ProcessMemoryGuard;
};

export const parseLpsy15ScalarWasmMeasurementArguments = (
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
            `LPSY15 scalar WebAssembly measurements require one exact registered identifier. ${usage}`,
        );
    }
    const measurementId = positionalArguments[0]?.trim() ?? '';
    if (measurementId.length === 0) {
        throw new Error(
            `LPSY15 scalar WebAssembly measurements require a nonempty identifier. ${usage}`,
        );
    }
    resolveLpsy15ScalarWasmMeasurement(measurementId);
    return { measurementId };
};

const buildWorkerCommand = (
    parsedArguments: ParsedArguments,
    outputFilePath: string,
    diagnosticsPath: string,
): CommandInvocation => {
    const processMemoryGuard = getLpsy15ProcessMemoryGuard();
    const environment = { ...process.env };
    delete environment.CARGO_ENCODED_RUSTFLAGS;
    return processMemoryGuard.guardCommand(
        {
            args: [
                '--import',
                'tsx',
                workerFilePath,
                '--measurement',
                parsedArguments.measurementId,
                '--output',
                outputFilePath,
            ],
            command: process.execPath,
            description: `scalar WebAssembly LPSY15 measurement (${parsedArguments.measurementId})`,
            env: {
                ...environment,
                CARGO_BUILD_JOBS: '1',
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: '1',
                RUST_BACKTRACE: 'full',
            },
            logFileSlug: 'lpsy15-scalar-wasm-measurement',
        },
        {
            diagnosticsPath,
            resourceSampleIntervalMilliseconds: 100,
        },
    );
};

export const runLpsy15ScalarWasmMeasurement = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['LPSY15 scalar WebAssembly measurement'],
            scriptName: 'test:wasm:lpsy15-scalar',
        },
        async (runLog) => {
            const parsedArguments =
                parseLpsy15ScalarWasmMeasurementArguments(rawArguments);
            const resultFilePath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'lpsy15-scalar-wasm-measurement.json',
            );
            const processMemoryGuard = getLpsy15ProcessMemoryGuard();
            const command = buildWorkerCommand(
                parsedArguments,
                resultFilePath,
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    'process-memory-guard-lpsy15-scalar-wasm.jsonl',
                ),
            );
            const setupMessage =
                `LPSY15 scalar WebAssembly measurement: ${parsedArguments.measurementId}; ` +
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
                laneLabel: 'LPSY15 scalar WebAssembly measurement',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    await runLpsy15ScalarWasmMeasurement();
}
