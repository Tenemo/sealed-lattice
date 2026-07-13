import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
    type CommandInvocation,
} from './run-command.js';
import { buildTestDiagnosticEnvironment } from './test-diagnostic-environment.js';

const nodeWasmVirtualAddressSpaceAllowanceBytes = 32 * 1024 ** 3;
let processMemoryGuard: ProcessMemoryGuard | undefined;

const getProcessMemoryGuard = (): ProcessMemoryGuard => {
    processMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription: 'Node kernel heavy tests',
        // Node and Vitest reserve large inaccessible mappings around wasm32
        // linear memory. Linux RLIMIT_AS counts those nonresident mappings, so
        // admit the measured Node 24 process shape separately while RLIMIT_DATA
        // retains the hard allocation limit.
        virtualAddressSpaceAllowanceBytes:
            nodeWasmVirtualAddressSpaceAllowanceBytes,
    });

    return processMemoryGuard;
};

export const buildNodeKernelHeavyTestCommand = (input: {
    readonly packageManagerRunner: PackageManagerRunner;
    readonly runDirectoryPath: string;
}): CommandInvocation => {
    const unguardedCommand = createPackageManagerCommand(
        'Run heavy kernel Node tests',
        ['exec', 'vitest', '--project', 'node-kernel-heavy', '--run'],
        {
            env: buildTestDiagnosticEnvironment({
                projectLabel: 'node-kernel-heavy',
                runDirectoryPath: input.runDirectoryPath,
            }),
            logFileSlug: 'node-kernel-heavy',
            packageManagerRunner: input.packageManagerRunner,
        },
    );
    const guard = getProcessMemoryGuard();

    return guard.guardCommand(unguardedCommand, {
        diagnosticsPath: path.join(
            input.runDirectoryPath,
            'resources',
            'process-memory-guard-node-kernel-heavy.jsonl',
        ),
    });
};

export const buildNodeKernelHeavyGuardVerificationCommand =
    (): CommandInvocation => getProcessMemoryGuard().buildVerificationCommand();

const parseArguments = (commandArguments: readonly string[]): void => {
    if (commandArguments.some((argument) => argument !== '--')) {
        throw new Error('Usage: run-node-kernel-heavy-tests.ts.');
    }
};

export const runNodeKernelHeavyTests = async (
    commandArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: commandArguments,
            lanes: ['Node kernel heavy'],
            scriptName: 'test:node:kernel:heavy',
        },
        async (runLog) => {
            parseArguments(commandArguments);
            const packageManagerRunner = resolvePackageManagerRunner();
            process.exitCode = await withLocalHeavyLaneLease({
                action: () =>
                    runCommandsInSeries(
                        [
                            buildNodeKernelHeavyGuardVerificationCommand(),
                            buildNodeKernelHeavyTestCommand({
                                packageManagerRunner,
                                runDirectoryPath: runLog.runDirectoryPath,
                            }),
                        ],
                        { outputMode: 'inherit', runLog },
                    ),
                laneLabel: 'Node kernel heavy',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runNodeKernelHeavyTests();
}
