import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CommandInvocation,
} from './command-runner.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';

const usage =
    'Usage: run-rust-fast-tests.ts [<test name, module name, or Rust file filter>].';
// The participant module's crates build in their own workspace with its
// pinned compiler and locked offline dependencies.
const workspace = fileURLToPath(
    new URL('../../crates/protocol-research/', import.meta.url),
);

export const rustWorkspaceCommand = (
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

// Every member's unit and integration tests except the ballot and release
// provers', whose proof-generation tests run in the guarded research check.
const rustFastTestSuites = [
    {
        name: 'workspace',
        arguments: [
            'test',
            '--offline',
            '--locked',
            '--workspace',
            '--exclude',
            'ballot-proof',
            '--exclude',
            'linked-release-proof',
            '--lib',
            '--bins',
            '--test',
            '*',
        ],
    },
] as const;

export const rustFastTestCommands = (filter?: string): CommandInvocation[] =>
    rustFastTestSuites.map((suite) =>
        rustWorkspaceCommand(
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
    const commandLineArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        commandLineArguments.length > 1 ||
        commandLineArguments.some((argument) => argument.startsWith('-'))
    ) {
        throw new Error(`Fast Rust tests accept one optional filter. ${usage}`);
    }
    const rawFilter = commandLineArguments[0];
    if (rawFilter === undefined) return undefined;
    const pathParts = rawFilter.replace(/\\/gu, '/').split('/');
    const fileName = pathParts[pathParts.length - 1] ?? '';
    const filter = fileName.endsWith('.rs')
        ? fileName.slice(0, -'.rs'.length)
        : fileName;
    if (filter.length === 0) {
        throw new Error(`Fast Rust test filters must not be empty. ${usage}`);
    }
    return filter;
};

const requireTestMatch = async (
    filter: string,
    runLog: ActiveLocalRunLog,
): Promise<CommandInvocation[]> => {
    const commands = rustFastTestCommands(filter);
    const matched: CommandInvocation[] = [];
    for (const [index, suite] of rustFastTestSuites.entries()) {
        const result = await runCommandAndCaptureOutput(
            rustWorkspaceCommand(
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
                `Unable to list fast Rust tests matching ${filter}.`,
            );
        if (
            result.stdout
                .split(/\r?\n/gu)
                .some((line) => line.trim().endsWith(': test'))
        )
            matched.push(commands[index]);
    }
    if (matched.length === 0) {
        throw new Error(`test:rust:fast filter ${filter} selects zero tests.`);
    }
    return matched;
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Fast Rust tests'],
            scriptName: 'test:rust:fast',
        },
        async (runLog) => {
            const filter = parseFilter(rawArguments);
            const commands =
                filter === undefined
                    ? rustFastTestCommands()
                    : await requireTestMatch(filter, runLog);
            process.exitCode = await runCommandsInSeries(commands, {
                outputMode: 'inherit',
                runLog,
            });
        },
    );
};

if (import.meta.main) void main();
