import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from './focused-rust-test-match.js';
import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import { verifyFocusedRustLaneSelection } from './rust-focused-lane-selection.js';
import {
    cargoTestArgumentsForRustKernelFast,
    heavyRustKernelTestNamePrefix,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

export type ParsedRustKernelArguments = {
    readonly testFilter?: string;
};

const usage =
    'Usage: run-rust-kernel-tests.ts [<test name, module name, or Rust file filter>].';

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
    },
    logFileSlug: 'cargo-test-rust-kernel-fast',
});

export const runRustKernelTests = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments = parseRustKernelArguments(rawArguments);
    const command = buildRustKernelTestCommand(parsedArguments);
    if (parsedArguments.testFilter !== undefined) {
        verifyFocusedRustLaneSelection({
            environment: command.env,
            lane: 'rust-kernel-fast',
            testFilter: parsedArguments.testFilter,
        });
    }
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: ['Rust kernel fast'],
        scriptName: 'test:rust:kernel',
    });
    let exitCode: number | undefined;
    const focusedTestMatchTracker =
        parsedArguments.testFilter === undefined
            ? undefined
            : createFocusedRustTestMatchTracker();

    try {
        exitCode = await runCommandsInSeries([command], {
            observer: focusedTestMatchTracker?.observer,
            outputMode: 'inherit',
            runLog,
        });
        if (
            focusedTestMatchTracker !== undefined &&
            parsedArguments.testFilter !== undefined
        ) {
            const focusedRunResult = resolveFocusedRustTestRunResult({
                commandExitCode: exitCode,
                matchedTestCount: focusedTestMatchTracker.matchedTestCount(),
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
        await runLog?.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runRustKernelTests();
}
