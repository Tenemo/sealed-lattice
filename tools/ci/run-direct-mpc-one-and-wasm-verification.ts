import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveDirectMpcOneAndWasmVerification } from './direct-mpc-one-and-wasm-verification-registry.js';
import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

const workerFilePath = fileURLToPath(
    new URL(
        './direct-mpc-one-and-wasm-verification-worker.ts',
        import.meta.url,
    ),
);
const usage =
    'Usage: run-direct-mpc-one-and-wasm-verification.ts <registered verification id>.';

let processMemoryGuard: ProcessMemoryGuard | undefined;

const getProcessMemoryGuard = (): ProcessMemoryGuard => {
    processMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'Direct-MPC one-AND scalar WebAssembly verification',
        memoryLimitEnvironmentVariable:
            'SEALED_LATTICE_DIRECT_MPC_ONE_AND_MEMORY_LIMIT_GIB',
    });
    return processMemoryGuard;
};

const parseArguments = (
    commandArguments: readonly string[],
): Readonly<{ verificationId: string }> => {
    const positionalArguments = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        positionalArguments.some((argument) => argument.startsWith('-')) ||
        positionalArguments.length !== 1
    ) {
        throw new Error(
            `Direct-MPC one-AND WebAssembly verification requires one exact registered identifier. ${usage}`,
        );
    }
    const verificationId = positionalArguments[0]?.trim() ?? '';
    if (verificationId.length === 0) {
        throw new Error(
            `Direct-MPC one-AND WebAssembly verification requires a nonempty identifier. ${usage}`,
        );
    }
    resolveDirectMpcOneAndWasmVerification(verificationId);
    return { verificationId };
};

const buildWorkerCommand = (
    verificationId: string,
    outputFilePath: string,
    diagnosticsPath: string,
): CommandInvocation => {
    const memoryGuard = getProcessMemoryGuard();
    const environment = { ...process.env };
    delete environment.CARGO_ENCODED_RUSTFLAGS;
    return memoryGuard.guardCommand(
        {
            args: [
                '--import',
                'tsx',
                workerFilePath,
                '--verification',
                verificationId,
                '--output',
                outputFilePath,
            ],
            command: process.execPath,
            description: `scalar WebAssembly direct-MPC one-AND verification (${verificationId})`,
            env: {
                ...environment,
                CARGO_BUILD_JOBS: '1',
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: '1',
                RUST_BACKTRACE: 'full',
            },
            logFileSlug: 'direct-mpc-one-and-wasm-verification',
        },
        {
            diagnosticsPath,
            resourceSampleIntervalMilliseconds: 100,
        },
    );
};

export const runDirectMpcOneAndWasmVerification = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Direct MPC one-AND scalar WebAssembly verification'],
            scriptName: 'test:wasm:direct-mpc-one-and',
        },
        async (runLog) => {
            const parsedArguments = parseArguments(rawArguments);
            const resultFilePath = path.join(
                runLog.runDirectoryPath,
                'attachments',
                'direct-mpc-one-and-wasm-verification.json',
            );
            const memoryGuard = getProcessMemoryGuard();
            const command = buildWorkerCommand(
                parsedArguments.verificationId,
                resultFilePath,
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    'process-memory-guard-direct-mpc-one-and-wasm.jsonl',
                ),
            );
            const setupMessage =
                `Direct-MPC one-AND scalar WebAssembly verification: ${parsedArguments.verificationId}; ` +
                `one active worker; hard inherited process-memory ceiling ${memoryGuard.memoryLimitGigabytes} GiB.`;
            console.log(setupMessage);
            runLog.writeCombinedOutput(`${setupMessage}\n`);
            process.exitCode = await withLocalHeavyLaneLease({
                action: async () => {
                    let exitCode = await runCommandsInSeries(
                        [memoryGuard.buildVerificationCommand()],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) return exitCode;
                    exitCode = await runCommandsInSeries([command], {
                        outputMode: 'inherit',
                        runLog,
                    });
                    return exitCode;
                },
                laneLabel: 'Direct MPC one-AND scalar WebAssembly verification',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    await runDirectMpcOneAndWasmVerification();
}
