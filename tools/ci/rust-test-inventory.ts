import { fileURLToPath } from 'node:url';

import type { ActiveLocalRunLog } from './local-run-log.js';
import { runCommandAndCaptureOutput } from './run-command.js';

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

const listFocusedTests = async (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly ignoredOnly: boolean;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
}): Promise<readonly string[]> => {
    const arguments_ = [
        'test',
        '--locked',
        '-p',
        'sealed-lattice-kernel',
        input.testFilter,
        '--',
        ...(input.ignoredOnly ? ['--ignored'] : ['--include-ignored']),
        '--list',
        '--format',
        'terse',
    ];
    const result = await runCommandAndCaptureOutput(
        {
            args: arguments_,
            command: 'cargo',
            description: `list focused Rust tests (${input.testFilter})`,
            env: input.environment,
            logFileSlug: 'cargo-test-inventory',
            workingDirectoryPath: repositoryRoot,
        },
        { runLog: input.runLog },
    );
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `Unable to list focused Rust tests: cargo ${arguments_.join(' ')} exited with ${result.exitCode}, signal ${result.terminationSignal ?? 'none'}.\n${result.stderr}${result.stdout}`,
        );
    }

    return parseLibtestListOutput(result.stdout);
};

export const collectFocusedRustKernelTestInventory = async (input: {
    readonly environment?: NodeJS.ProcessEnv;
    readonly runLog?: ActiveLocalRunLog;
    readonly testFilter: string;
}): Promise<readonly RustTestInventoryEntry[]> => {
    const allTests = await listFocusedTests({
        ...input,
        ignoredOnly: false,
    });
    const ignoredTests = await listFocusedTests({
        ...input,
        ignoredOnly: true,
    });

    return classifyRustTestInventory({ allTests, ignoredTests });
};
