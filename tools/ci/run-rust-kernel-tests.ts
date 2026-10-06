import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CommandInvocation,
} from './run-command.js';

const usage =
    'Usage: run-rust-kernel-tests.ts [<test name, module name, or Rust file filter>].';
// The participant module's crates build in their own workspace with its
// pinned compiler and locked offline dependencies.
const workspace = fileURLToPath(
    new URL('../../crates/protocol-research/', import.meta.url),
);

export const rustKernelCommand = (
    description: string,
    args: readonly string[],
    logFileSlug: string,
): CommandInvocation => ({
    args: ['+1.95.0', ...args],
    command: 'cargo',
    description,
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR: path.join(workspace, 'target'),
        RUSTFLAGS: '',
        RUST_BACKTRACE: '1',
    },
    logFileSlug,
    workingDirectoryPath: workspace,
});

// Credential conformance and the small transcript integration target. The
// explicit latter target keeps heavy proof-generation unit tests in their
// guarded lane.
const rustKernelTestSuites = [
    {
        name: 'registration-credentials',
        arguments: [
            'test',
            '--offline',
            '--locked',
            '-p',
            'registration-credentials',
        ],
    },
    {
        name: 'continuation-transcript',
        arguments: [
            'test',
            '--offline',
            '--locked',
            '-p',
            'word-proof',
            '--test',
            'continuation-transcript',
        ],
    },
] as const;

export const rustKernelTestCommands = (filter?: string): CommandInvocation[] =>
    rustKernelTestSuites.map((suite) =>
        rustKernelCommand(
            `cargo test ${suite.name}${filter === undefined ? '' : ` (${filter})`}`,
            [
                ...suite.arguments,
                ...(filter === undefined || filter === suite.name
                    ? []
                    : [filter]),
                '--',
                '--test-threads',
                '1',
                '--show-output',
            ],
            `cargo-test-${suite.name}`,
        ),
    );

const parseFilter = (rawArguments: readonly string[]): string | undefined => {
    const arguments_ = rawArguments.filter((argument) => argument !== '--');
    if (
        arguments_.length > 1 ||
        arguments_.some((argument) => argument.startsWith('-'))
    ) {
        throw new Error(
            `Rust kernel tests accept one optional filter. ${usage}`,
        );
    }
    const rawFilter = arguments_[0];
    if (rawFilter === undefined) return undefined;
    const pathParts = rawFilter.replace(/\\/gu, '/').split('/');
    const fileName = pathParts[pathParts.length - 1] ?? '';
    const filter = fileName.endsWith('.rs')
        ? fileName.slice(0, -'.rs'.length)
        : fileName;
    if (filter.length === 0) {
        throw new Error(`Rust kernel test filters must not be empty. ${usage}`);
    }
    return filter;
};

const requireTestMatch = async (
    filter: string,
    runLog: ActiveLocalRunLog,
): Promise<CommandInvocation[]> => {
    const commands = rustKernelTestCommands(filter);
    const matched: CommandInvocation[] = [];
    for (const [index, suite] of rustKernelTestSuites.entries()) {
        const result = await runCommandAndCaptureOutput(
            rustKernelCommand(
                `list ${suite.name} tests matching ${filter}`,
                [
                    ...suite.arguments,
                    ...(filter === suite.name ? [] : [filter]),
                    '--',
                    '--list',
                    '--format',
                    'terse',
                ],
                `cargo-test-${suite.name}-inventory`,
            ),
            { runLog },
        );
        if (result.exitCode !== 0 || result.terminationSignal !== null)
            throw new Error(
                `Unable to list Rust kernel tests matching ${filter}.`,
            );
        if (
            result.stdout
                .split(/\r?\n/gu)
                .some((line) => line.trim().endsWith(': test'))
        )
            matched.push(commands[index]);
    }
    if (matched.length === 0) {
        throw new Error(
            `test:rust:kernel filter ${filter} selects zero tests.`,
        );
    }
    return matched;
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Rust kernel'],
            scriptName: 'test:rust:kernel',
        },
        async (runLog) => {
            const filter = parseFilter(rawArguments);
            const commands =
                filter === undefined
                    ? rustKernelTestCommands()
                    : await requireTestMatch(filter, runLog);
            process.exitCode = await runCommandsInSeries(commands, {
                outputMode: 'inherit',
                runLog,
            });
        },
    );
};

if (import.meta.main) void main();
