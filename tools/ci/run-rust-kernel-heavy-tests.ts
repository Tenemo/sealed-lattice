import path from 'node:path';

import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from './focused-rust-test-match.js';
import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './run-command.js';
import { verifyFocusedRustLaneSelection } from './rust-focused-lane-selection.js';
import {
    cargoTestArgumentsForRustKernelHeavy,
    heavyRustKernelTestNamePrefix,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

export type ParsedRustKernelHeavyArguments = Readonly<{
    testFilter: string;
}>;

const usage = 'Usage: run-rust-kernel-heavy-tests.ts [<heavy Rust test name>].';
let rustKernelHeavyProcessMemoryGuard: ProcessMemoryGuard | undefined;

const combineObservers = (
    observers: readonly CommandRunObserver[],
): CommandRunObserver => ({
    onCommandExit: (event): void => {
        for (const observer of observers) observer.onCommandExit?.(event);
    },
    onCommandOutput: (event): void => {
        for (const observer of observers) observer.onCommandOutput?.(event);
    },
    onCommandStart: (event): void => {
        for (const observer of observers) observer.onCommandStart?.(event);
    },
});

const getRustKernelHeavyProcessMemoryGuard = (): ProcessMemoryGuard => {
    rustKernelHeavyProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription: 'Rust kernel heavy tests',
    });

    return rustKernelHeavyProcessMemoryGuard;
};

export const parseRustKernelHeavyArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelHeavyArguments => {
    const positionalArguments: string[] = [];
    for (const argument of commandArguments) {
        if (argument === '--') {
            continue;
        }
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument: ${argument}. ${usage}`);
        }
        positionalArguments.push(argument);
    }

    if (positionalArguments.length > 1) {
        throw new Error(`Heavy Rust kernel runs accept one filter. ${usage}`);
    }

    const positionalFilter = positionalArguments[0];
    const testFilter =
        positionalFilter === undefined
            ? heavyRustKernelTestNamePrefix
            : normalizeRustTestFilter(positionalFilter);
    return { testFilter };
};

export const buildRustKernelHeavyTestCommand = (
    parsedArguments: ParsedRustKernelHeavyArguments,
): CommandInvocation =>
    getRustKernelHeavyProcessMemoryGuard().guardCommand({
        args: cargoTestArgumentsForRustKernelHeavy(parsedArguments.testFilter),
        command: 'cargo',
        description: `cargo test Rust kernel heavy (${parsedArguments.testFilter})`,
        env: {
            ...process.env,
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            RAYON_NUM_THREADS: '1',
            RUST_BACKTRACE: 'full',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '1',
        },
        logFileSlug: 'cargo-test-rust-kernel-heavy',
    });

export const buildRustKernelHeavyProcessMemoryGuardVerificationCommand =
    (): CommandInvocation =>
        getRustKernelHeavyProcessMemoryGuard().buildVerificationCommand();

export const runRustKernelHeavyTests = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Rust kernel heavy'],
            scriptName: 'test:rust:kernel:heavy',
        },
        async (runLog) => {
            const parsedArguments = parseRustKernelHeavyArguments(rawArguments);
            const processMemoryGuard = getRustKernelHeavyProcessMemoryGuard();
            const command = processMemoryGuard.addDiagnostics(
                buildRustKernelHeavyTestCommand(parsedArguments),
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    'process-memory-guard-rust-kernel-heavy.jsonl',
                ),
            );
            if (rawArguments.some((argument) => argument !== '--')) {
                await verifyFocusedRustLaneSelection({
                    environment: command.env,
                    lane: 'rust-kernel-heavy',
                    runLog,
                    testFilter: parsedArguments.testFilter,
                });
            }
            const testMatchTracker = createFocusedRustTestMatchTracker();
            const progressReporter = createHeavyTestProgressReporter({
                eventFilePath: path.join(
                    runLog.runDirectoryPath,
                    'tests',
                    'rust-kernel-heavy.jsonl',
                ),
                label: 'rust-kernel-heavy',
                threadCount: 1,
            });

            try {
                process.exitCode = await withLocalHeavyLaneLease({
                    action: async () => {
                        let exitCode = await runCommandsInSeries(
                            [
                                buildRustKernelHeavyProcessMemoryGuardVerificationCommand(),
                            ],
                            {
                                outputMode: 'inherit',
                                runLog,
                            },
                        );
                        if (exitCode !== 0) return exitCode;

                        exitCode = await runCommandsInSeries([command], {
                            observer: combineObservers([
                                progressReporter.observer,
                                testMatchTracker.observer,
                            ]),
                            outputMode: 'inherit',
                            runLog,
                            terminalOutputFilter:
                                progressReporter.terminalOutputFilter,
                        });
                        const runResult = resolveFocusedRustTestRunResult({
                            commandExitCode: exitCode,
                            matchedTestCount:
                                testMatchTracker.matchedTestCount(),
                            runnerName: 'Rust kernel heavy',
                            testFilter: parsedArguments.testFilter,
                        });
                        if (runResult.failureMessage !== undefined) {
                            console.error(runResult.failureMessage);
                            runLog.writeCombinedOutput(
                                `${runResult.failureMessage}\n`,
                            );
                        }
                        return runResult.exitCode;
                    },
                    laneLabel: 'Rust kernel heavy',
                    runLog,
                });
            } finally {
                progressReporter.stop();
            }
        },
    );
};

if (import.meta.main) {
    void runRustKernelHeavyTests();
}
