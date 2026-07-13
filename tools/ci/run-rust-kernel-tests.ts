import path from 'node:path';

import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from './focused-rust-test-match.js';
import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './run-command.js';
import { verifyFocusedRustLaneSelection } from './rust-focused-lane-selection.js';
import {
    cargoTestArgumentsForRustKernelFast,
    heavyRustKernelTestNamePrefix,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

export type ParsedRustKernelArguments = {
    readonly testFilter?: string;
};

const usage =
    'Usage: run-rust-kernel-tests.ts [<test name, module name, or Rust file filter>].';

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

export const parseRustKernelArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelArguments => {
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
        throw new Error(`Rust kernel test runs accept one filter. ${usage}`);
    }

    const positionalFilter = positionalArguments[0];
    const normalizedFilter =
        positionalFilter !== undefined
            ? normalizeRustTestFilter(positionalFilter)
            : undefined;
    if (normalizedFilter === '') {
        throw new Error(
            `Rust kernel test runs require a non-empty filter. ${usage}`,
        );
    }
    if (normalizedFilter?.startsWith(heavyRustKernelTestNamePrefix) === true) {
        throw new Error(
            `Heavy Rust kernel tests must use "pnpm run test:rust:kernel:heavy -- ${normalizedFilter}".`,
        );
    }

    return {
        testFilter: normalizedFilter,
    };
};

export const buildRustKernelTestCommand = (
    parsedArguments: ParsedRustKernelArguments,
): CommandInvocation => ({
    args: cargoTestArgumentsForRustKernelFast(parsedArguments.testFilter),
    command: 'cargo',
    description:
        parsedArguments.testFilter === undefined
            ? 'cargo test Rust kernel fast'
            : `cargo test Rust kernel fast (${parsedArguments.testFilter})`,
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        RUST_BACKTRACE: '1',
    },
    logFileSlug: 'cargo-test-rust-kernel-fast',
});

export const runRustKernelTests = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Rust kernel fast'],
            scriptName: 'test:rust:kernel',
        },
        async (runLog) => {
            const parsedArguments = parseRustKernelArguments(rawArguments);
            const command = buildRustKernelTestCommand(parsedArguments);
            if (parsedArguments.testFilter !== undefined) {
                await verifyFocusedRustLaneSelection({
                    environment: command.env,
                    lane: 'rust-kernel-fast',
                    runLog,
                    testFilter: parsedArguments.testFilter,
                });
            }
            const focusedTestMatchTracker =
                parsedArguments.testFilter === undefined
                    ? undefined
                    : createFocusedRustTestMatchTracker();
            const progressReporter = createHeavyTestProgressReporter({
                eventFilePath: path.join(
                    runLog.runDirectoryPath,
                    'tests',
                    'rust-kernel-fast.jsonl',
                ),
                label: 'rust-kernel-fast',
                threadCount: 1,
            });

            try {
                let exitCode = await runCommandsInSeries([command], {
                    observer:
                        focusedTestMatchTracker === undefined
                            ? progressReporter.observer
                            : combineObservers([
                                  progressReporter.observer,
                                  focusedTestMatchTracker.observer,
                              ]),
                    outputMode: 'inherit',
                    runLog,
                    terminalOutputFilter: progressReporter.terminalOutputFilter,
                });
                if (
                    focusedTestMatchTracker !== undefined &&
                    parsedArguments.testFilter !== undefined
                ) {
                    const focusedRunResult = resolveFocusedRustTestRunResult({
                        commandExitCode: exitCode,
                        matchedTestCount:
                            focusedTestMatchTracker.matchedTestCount(),
                        runnerName: 'Rust kernel fast',
                        testFilter: parsedArguments.testFilter,
                    });
                    exitCode = focusedRunResult.exitCode;
                    if (focusedRunResult.failureMessage !== undefined) {
                        console.error(focusedRunResult.failureMessage);
                        runLog.writeCombinedOutput(
                            `${focusedRunResult.failureMessage}\n`,
                        );
                    }
                }
                process.exitCode = exitCode;
            } finally {
                progressReporter.stop();
            }
        },
    );
};

if (import.meta.main) {
    void runRustKernelTests();
}
