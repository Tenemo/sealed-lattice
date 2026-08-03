import { fileURLToPath } from 'node:url';

import type { ActiveLocalRunLog } from './local-run-log.js';
import {
    runCommandAndCaptureOutput,
    type CommandInvocation,
} from './run-command.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

export type RustTestInventoryEntry = {
    readonly ignored: boolean;
    readonly testName: string;
};

export const parseLibtestListOutput = (output: string): readonly string[] =>
    [
        ...new Set(
            output
                .split(/\r?\n/u)
                .map((line) => line.trim())
                .flatMap((line) =>
                    line.endsWith(': test')
                        ? [line.slice(0, -': test'.length)]
                        : [],
                ),
        ),
    ].sort((left, right) => left.localeCompare(right));

export const classifyRustTestInventory = (input: {
    readonly allTests: readonly string[];
    readonly ignoredTests: readonly string[];
}): readonly RustTestInventoryEntry[] => {
    const ignoredTestSet = new Set(input.ignoredTests);

    return input.allTests.map((testName) => ({
        ignored: ignoredTestSet.has(testName),
        testName,
    }));
};

export const buildRustTestInventoryArguments = (input: {
    readonly cargoFeatures?: readonly string[];
    readonly ignoredOnly: boolean;
    readonly useReleaseProfile?: boolean;
}): readonly string[] => [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
    ...(input.useReleaseProfile === true ? ['--release'] : []),
    ...(input.cargoFeatures === undefined || input.cargoFeatures.length === 0
        ? []
        : ['--features', input.cargoFeatures.join(',')]),
    '--',
    ...(input.ignoredOnly ? ['--ignored'] : ['--include-ignored']),
    '--list',
    '--format',
    'terse',
];

const listRustTests = async (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly ignoredOnly: boolean;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly runLog?: ActiveLocalRunLog;
    readonly useReleaseProfile?: boolean;
}): Promise<readonly string[]> => {
    const arguments_ = buildRustTestInventoryArguments(input);
    const command: CommandInvocation = {
        args: arguments_,
        command: 'cargo',
        description: 'list complete Rust test inventory',
        env: input.environment,
        logFileSlug: 'cargo-test-inventory',
        workingDirectoryPath: repositoryRoot,
    };
    const result = await runCommandAndCaptureOutput(
        input.inventoryCommandTransform?.(command) ?? command,
        { runLog: input.runLog },
    );
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `Unable to list focused Rust tests: cargo ${arguments_.join(' ')} exited with ${result.exitCode}, signal ${result.terminationSignal ?? 'none'}.\n${result.stderr}${result.stdout}`,
        );
    }

    return parseLibtestListOutput(result.stdout);
};

export const collectRustKernelTestInventory = async (input: {
    readonly cargoFeatures?: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly inventoryCommandTransform?: (
        command: CommandInvocation,
    ) => CommandInvocation;
    readonly runLog?: ActiveLocalRunLog;
    readonly useReleaseProfile?: boolean;
}): Promise<readonly RustTestInventoryEntry[]> => {
    const allTests = await listRustTests({
        ...input,
        ignoredOnly: false,
    });
    const ignoredTests = await listRustTests({
        ...input,
        ignoredOnly: true,
    });

    return classifyRustTestInventory({ allTests, ignoredTests });
};
