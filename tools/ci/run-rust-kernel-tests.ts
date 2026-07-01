import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import {
    cargoTestArgumentsForRustKernelFast,
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

    const normalizedFilter =
        positionalArguments.length === 1
            ? normalizeRustTestFilter(positionalArguments[0] ?? '')
            : undefined;
    if (normalizedFilter === '') {
        throw new Error(
            `Rust kernel test runs require a non-empty filter. ${usage}`,
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
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: ['Rust kernel fast'],
        scriptName: 'test:rust:kernel',
    });
    let exitCode: number | undefined;

    try {
        exitCode = await runCommandsInSeries(
            [buildRustKernelTestCommand(parsedArguments)],
            {
                outputMode: 'inherit',
                runLog,
            },
        );
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
