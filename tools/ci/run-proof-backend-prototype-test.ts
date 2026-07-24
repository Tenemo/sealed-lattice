import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import {
    createHeavyTestProgressReporter,
    resolveFocusedRustTestRunResult,
} from './heavy-test-progress.js';
import { runWithLocalRunLog } from './local-run-log.js';
import { createProcessMemoryGuard } from './process-memory-guard.js';
import { runCommandsInSeries } from './run-command.js';
import {
    heavyRustKernelTestNamePrefix,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

const scriptName = 'test:rust:kernel:proof-backend-prototype';

const runProofBackendPrototypeTest = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const positionalArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (positionalArguments.length !== 1) {
        throw new Error(`${scriptName} requires exactly one heavy test filter.`);
    }
    const testFilter = normalizeRustTestFilter(positionalArguments[0] ?? '');
    if (!testFilter.startsWith(heavyRustKernelTestNamePrefix)) {
        throw new Error(
            `${scriptName} requires a ${heavyRustKernelTestNamePrefix} test.`,
        );
    }

    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Proof backend prototype'],
            scriptName,
        },
        async (runLog) => {
            const processMemoryGuard = createProcessMemoryGuard({
                insufficientFreeMemoryRunDescription:
                    'Proof backend prototype test',
                memoryLimitEnvironmentVariable:
                    'SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB',
            });
            const diagnosticsPath = path.join(
                runLog.runDirectoryPath,
                'resources',
                'process-memory-guard-proof-backend-prototype.jsonl',
            );
            const command = processMemoryGuard.guardCommand(
                {
                    args: [
                        'test',
                        '--locked',
                        '--release',
                        '-p',
                        'sealed-lattice-kernel',
                        '--features',
                        'proof-backend-bakeoff',
                        testFilter,
                        '--',
                        '--ignored',
                        '--nocapture',
                        '--test-threads',
                        '1',
                    ],
                    command: 'cargo',
                    description: `cargo test proof backend prototype (${testFilter})`,
                    env: {
                        ...process.env,
                        CARGO_BUILD_JOBS: '1',
                        CARGO_INCREMENTAL: '0',
                        RAYON_NUM_THREADS: '1',
                        RUST_BACKTRACE: 'full',
                    },
                    logFileSlug: 'cargo-test-proof-backend-prototype',
                },
                { diagnosticsPath },
            );
            const progressReporter = createHeavyTestProgressReporter({
                eventFilePath: path.join(
                    runLog.runDirectoryPath,
                    'tests',
                    'proof-backend-prototype.jsonl',
                ),
                label: 'proof-backend-prototype',
                threadCount: 1,
            });

            try {
                process.exitCode = await withLocalHeavyLaneLease({
                    action: async () => {
                        let exitCode = await runCommandsInSeries(
                            [processMemoryGuard.buildVerificationCommand()],
                            { outputMode: 'inherit', runLog },
                        );
                        if (exitCode !== 0) return exitCode;
                        exitCode = await runCommandsInSeries([command], {
                            observer: progressReporter.observer,
                            outputMode: 'inherit',
                            runLog,
                            terminalOutputFilter:
                                progressReporter.terminalOutputFilter,
                        });
                        return resolveFocusedRustTestRunResult({
                            commandExitCode: exitCode,
                            executedTestCount:
                                progressReporter.executedTestCount(),
                            runnerName: 'Proof backend prototype',
                            testFilter,
                        }).exitCode;
                    },
                    laneLabel: 'Proof backend prototype',
                    runLog,
                });
            } finally {
                progressReporter.stop();
            }
        },
    );
};

if (import.meta.main) {
    void runProofBackendPrototypeTest();
}
