import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveDirectMpcWasmMeasurement } from './direct-mpc-wasm-measurement-registry.js';
import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

const workerFilePath = fileURLToPath(
    new URL('./direct-mpc-wasm-measurement-worker.ts', import.meta.url),
);
const usage =
    'Usage: run-direct-mpc-wasm-measurement.ts <registered measurement id>.';

type ParsedArguments = Readonly<{ measurementId: string }>;

let directMpcProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getDirectMpcProcessMemoryGuard = (): ProcessMemoryGuard => {
    directMpcProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'Direct-MPC scalar WebAssembly measurements',
        memoryLimitEnvironmentVariable:
            'SEALED_LATTICE_DIRECT_MPC_MEMORY_LIMIT_GIB',
    });
    return directMpcProcessMemoryGuard;
};

export const parseDirectMpcWasmMeasurementArguments = (
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
            `Direct-MPC WebAssembly measurements require one exact registered identifier. ${usage}`,
        );
    }
    const measurementId = positionalArguments[0]?.trim() ?? '';
    if (measurementId.length === 0) {
        throw new Error(
            `Direct-MPC WebAssembly measurements require a nonempty identifier. ${usage}`,
        );
    }
    resolveDirectMpcWasmMeasurement(measurementId);
    return { measurementId };
};

const buildWorkerCommand = (
    parsedArguments: ParsedArguments,
    outputFilePath: string,
    diagnosticsPath: string,
): CommandInvocation => {
    const processMemoryGuard = getDirectMpcProcessMemoryGuard();
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
            description: `scalar WebAssembly direct-MPC measurement (${parsedArguments.measurementId})`,
            env: {
                ...environment,
                CARGO_BUILD_JOBS: '1',
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: '1',
                RUST_BACKTRACE: 'full',
            },
            logFileSlug: 'direct-mpc-wasm-measurement',
        },
        {
            diagnosticsPath,
            resourceSampleIntervalMilliseconds: 100,
        },
    );
};

export const runDirectMpcWasmMeasurement = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Direct MPC scalar WebAssembly measurement'],
            scriptName: 'test:wasm:direct-mpc',
        },
        async (runLog) => {
            const parsedArguments =
                parseDirectMpcWasmMeasurementArguments(rawArguments);
            const resultFilePath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'direct-mpc-wasm-measurement.json',
            );
            const processMemoryGuard = getDirectMpcProcessMemoryGuard();
            const command = buildWorkerCommand(
                parsedArguments,
                resultFilePath,
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    'process-memory-guard-direct-mpc-wasm.jsonl',
                ),
            );
            const setupMessage =
                `Direct-MPC scalar WebAssembly measurement: ${parsedArguments.measurementId}; ` +
                `one active worker; hard inherited process-memory ceiling ${processMemoryGuard.memoryLimitGigabytes} GiB.`;
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
                laneLabel: 'Direct MPC scalar WebAssembly measurement',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    await runDirectMpcWasmMeasurement();
}
