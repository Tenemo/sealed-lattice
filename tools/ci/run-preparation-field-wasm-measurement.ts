import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import { resolvePreparationFieldWasmMeasurement } from './preparation-field-wasm-measurement-registry.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

const workerFilePath = fileURLToPath(
    new URL('./preparation-field-wasm-measurement-worker.ts', import.meta.url),
);
const usage =
    'Usage: run-preparation-field-wasm-measurement.ts <registered measurement id>.';

export type ParsedPreparationFieldWasmMeasurementArguments = Readonly<{
    measurementId: string;
}>;

let preparationFieldProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getPreparationFieldProcessMemoryGuard = (): ProcessMemoryGuard => {
    preparationFieldProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'Preparation-field scalar WebAssembly measurements',
        memoryLimitEnvironmentVariable:
            'SEALED_LATTICE_PREPARATION_FIELD_MEMORY_LIMIT_GIB',
    });
    return preparationFieldProcessMemoryGuard;
};

export const parsePreparationFieldWasmMeasurementArguments = (
    commandArguments: readonly string[],
): ParsedPreparationFieldWasmMeasurementArguments => {
    const positionalArguments = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        positionalArguments.some((argument) => argument.startsWith('-')) ||
        positionalArguments.length !== 1
    ) {
        throw new Error(
            `Preparation-field WebAssembly measurements require one exact registered identifier. ${usage}`,
        );
    }
    const measurementId = positionalArguments[0]?.trim() ?? '';
    if (measurementId.length === 0) {
        throw new Error(
            `Preparation-field WebAssembly measurements require a nonempty identifier. ${usage}`,
        );
    }

    resolvePreparationFieldWasmMeasurement(measurementId);
    return { measurementId };
};

const buildMeasurementWorkerCommand = (
    parsedArguments: ParsedPreparationFieldWasmMeasurementArguments,
    outputFilePath: string,
    diagnosticsPath: string,
): CommandInvocation => {
    const processMemoryGuard = getPreparationFieldProcessMemoryGuard();
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
            description: `scalar WebAssembly preparation-field measurement (${parsedArguments.measurementId})`,
            env: {
                ...environment,
                CARGO_BUILD_JOBS: '1',
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: '1',
                RUST_BACKTRACE: 'full',
            },
            logFileSlug: 'preparation-field-wasm-measurement',
        },
        {
            diagnosticsPath,
            resourceSampleIntervalMilliseconds: 100,
        },
    );
};

export const runPreparationFieldWasmMeasurement = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Preparation field scalar WebAssembly measurement'],
            scriptName: 'test:wasm:preparation-field',
        },
        async (runLog) => {
            const parsedArguments =
                parsePreparationFieldWasmMeasurementArguments(rawArguments);
            const resultFilePath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'preparation-field-wasm-measurement.json',
            );
            const command = buildMeasurementWorkerCommand(
                parsedArguments,
                resultFilePath,
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    'process-memory-guard-preparation-field-wasm.jsonl',
                ),
            );
            const processMemoryGuard = getPreparationFieldProcessMemoryGuard();
            const setupMessage =
                `Preparation-field scalar WebAssembly measurement: ${parsedArguments.measurementId}; ` +
                `one worker; hard inherited process-memory ceiling ${processMemoryGuard.memoryLimitGigabytes} GiB.`;
            console.log(setupMessage);
            runLog.writeCombinedOutput(`${setupMessage}\n`);

            process.exitCode = await withLocalHeavyLaneLease({
                action: async () => {
                    let exitCode = await runCommandsInSeries(
                        [processMemoryGuard.buildVerificationCommand()],
                        {
                            outputMode: 'inherit',
                            runLog,
                        },
                    );
                    if (exitCode !== 0) return exitCode;
                    exitCode = await runCommandsInSeries([command], {
                        outputMode: 'inherit',
                        runLog,
                    });
                    return exitCode;
                },
                laneLabel: 'Preparation field scalar WebAssembly measurement',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    await runPreparationFieldWasmMeasurement();
}
