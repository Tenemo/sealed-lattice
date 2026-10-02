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

// The canonical encoding, hashing and registration credentials that the
// participant module signs and verifies with, and their ML-DSA-65
// conformance vectors.
export const rustKernelTestArguments = [
    'test',
    '--offline',
    '--locked',
    '-p',
    'registration-credentials',
] as const;

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
): Promise<void> => {
    const result = await runCommandAndCaptureOutput(
        rustKernelCommand(
            `list Rust kernel tests matching ${filter}`,
            [
                ...rustKernelTestArguments,
                filter,
                '--',
                '--list',
                '--format',
                'terse',
            ],
            'cargo-test-rust-kernel-inventory',
        ),
        { runLog },
    );
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(`Unable to list Rust kernel tests matching ${filter}.`);
    }
    if (
        !result.stdout
            .split(/\r?\n/gu)
            .some((line) => line.trim().endsWith(': test'))
    ) {
        throw new Error(
            `test:rust:kernel filter ${filter} selects zero tests.`,
        );
    }
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
            if (filter !== undefined) await requireTestMatch(filter, runLog);
            process.exitCode = await runCommandsInSeries(
                [
                    rustKernelCommand(
                        filter === undefined
                            ? 'cargo test Rust kernel'
                            : `cargo test Rust kernel (${filter})`,
                        [
                            ...rustKernelTestArguments,
                            ...(filter === undefined ? [] : [filter]),
                            '--',
                            '--test-threads',
                            '1',
                            '--show-output',
                        ],
                        'cargo-test-rust-kernel',
                    ),
                ],
                { outputMode: 'inherit', runLog },
            );
        },
    );
};

if (import.meta.main) void main();
