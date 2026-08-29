import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CommandInvocation,
} from './run-command.js';

export type ParsedRustKernelArguments = {
    readonly testFilter?: string;
};

const usage =
    'Usage: run-rust-kernel-tests.ts [<test name, module name, or Rust file filter>].';

const normalizeRustTestFilter = (filter: string): string => {
    const pathParts = filter.replace(/\\/gu, '/').split('/');
    const fileName = pathParts[pathParts.length - 1] ?? filter;
    return fileName.endsWith('.rs')
        ? fileName.slice(0, -'.rs'.length)
        : fileName;
};

export const parseRustKernelArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelArguments => {
    const positionalArguments = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        positionalArguments.length > 1 ||
        positionalArguments.some((argument) => argument.startsWith('-'))
    ) {
        throw new Error(
            `Rust kernel tests accept one optional filter. ${usage}`,
        );
    }

    const rawFilter = positionalArguments[0];
    if (rawFilter === undefined) {
        return {};
    }
    const testFilter = normalizeRustTestFilter(rawFilter);
    if (testFilter.length === 0) {
        throw new Error(`Rust kernel test filters must not be empty. ${usage}`);
    }
    return { testFilter };
};

const commonCargoArguments = [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
] as const;

export const buildRustKernelTestCommand = (
    parsedArguments: ParsedRustKernelArguments,
): CommandInvocation => ({
    args: [
        ...commonCargoArguments,
        ...(parsedArguments.testFilter === undefined
            ? []
            : [parsedArguments.testFilter]),
        '--',
        '--test-threads',
        '1',
        '--show-output',
    ],
    command: 'cargo',
    description:
        parsedArguments.testFilter === undefined
            ? 'cargo test Rust kernel'
            : `cargo test Rust kernel (${parsedArguments.testFilter})`,
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        RUST_BACKTRACE: '1',
    },
    logFileSlug: 'cargo-test-rust-kernel',
});

const requireFocusedTestMatch = async (
    testFilter: string,
    runLog: ActiveLocalRunLog,
    environment: NodeJS.ProcessEnv | undefined,
): Promise<void> => {
    const result = await runCommandAndCaptureOutput(
        {
            args: [
                ...commonCargoArguments,
                testFilter,
                '--',
                '--list',
                '--format',
                'terse',
            ],
            command: 'cargo',
            description: `list Rust kernel tests matching ${testFilter}`,
            env: environment,
            logFileSlug: 'cargo-test-rust-kernel-inventory',
        },
        { runLog },
    );
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `Unable to list Rust kernel tests matching ${testFilter}.`,
        );
    }
    const matchedTests = result.stdout
        .split(/\r?\n/gu)
        .filter((line) => line.trim().endsWith(': test'));
    if (matchedTests.length === 0) {
        throw new Error(
            `test:rust:kernel filter ${testFilter} selects zero tests.`,
        );
    }
};

export const runRustKernelTests = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Rust kernel'],
            scriptName: 'test:rust:kernel',
        },
        async (runLog) => {
            const parsedArguments = parseRustKernelArguments(rawArguments);
            const command = buildRustKernelTestCommand(parsedArguments);
            if (parsedArguments.testFilter !== undefined) {
                await requireFocusedTestMatch(
                    parsedArguments.testFilter,
                    runLog,
                    command.env,
                );
            }
            process.exitCode = await runCommandsInSeries([command], {
                outputMode: 'inherit',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runRustKernelTests();
}
