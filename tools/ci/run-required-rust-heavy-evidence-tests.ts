import os from 'node:os';
import path from 'node:path';

import {
    requiredRustHeavyEvidenceTests,
    type RequiredRustHeavyEvidenceTest,
} from './heavy-evidence-tests.js';
import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const listRequiredTestsArgument = '--list';
const approximateGigabytesPerHeavyTest = 15;
const heavyTestMemoryBudgetFraction = 0.7;
const gigabyte = 1024 ** 3;
const availableGigabytes = os.freemem() / gigabyte;
const memoryBoundedHeavyTestThreadCount = Math.max(
    1,
    Math.floor(
        (availableGigabytes * heavyTestMemoryBudgetFraction) /
            approximateGigabytesPerHeavyTest,
    ),
);
const heavyAcceptedSetupTestThreadCount = Math.min(
    os.cpus().length,
    memoryBoundedHeavyTestThreadCount,
);

export const heavyRequiredEvidenceTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'heavy-required-evidence',
);

export type RequiredRustHeavyEvidenceCommandInput = {
    readonly baseEnvironment?: NodeJS.ProcessEnv;
    readonly targetDirectory?: string;
    readonly testThreadCount?: number;
};

const requiredRustHeavyEvidenceTestsByName: ReadonlyMap<
    string,
    RequiredRustHeavyEvidenceTest
> = new Map(
    requiredRustHeavyEvidenceTests.map((test) => [test.testName, test]),
);

export const shouldListRequiredRustHeavyEvidenceTests = (
    commandArguments: readonly string[],
): boolean => commandArguments.includes(listRequiredTestsArgument);

export const unknownRequiredRustHeavyEvidenceOptions = (
    commandArguments: readonly string[],
): readonly string[] =>
    commandArguments.filter(
        (argument) =>
            argument.startsWith('-') && argument !== listRequiredTestsArgument,
    );

const assertKnownOptions = (commandArguments: readonly string[]): void => {
    const unknownOptions =
        unknownRequiredRustHeavyEvidenceOptions(commandArguments);
    if (unknownOptions.length > 0) {
        throw new Error(
            `Unknown required Rust heavy evidence option(s): ${unknownOptions.join(
                ', ',
            )}. Use --list to print valid test names.`,
        );
    }
};

export const selectedRequiredRustHeavyEvidenceTests = (
    commandArguments: readonly string[],
): readonly RequiredRustHeavyEvidenceTest[] => {
    assertKnownOptions(commandArguments);

    const requestedTestNames = commandArguments.filter(
        (argument) => !argument.startsWith('-'),
    );
    if (requestedTestNames.length === 0) {
        return requiredRustHeavyEvidenceTests;
    }

    const unknownTestNames = requestedTestNames.filter(
        (testName) => !requiredRustHeavyEvidenceTestsByName.has(testName),
    );
    if (unknownTestNames.length > 0) {
        throw new Error(
            `Unknown required Rust heavy evidence test(s): ${unknownTestNames.join(
                ', ',
            )}. Use --list to print valid test names.`,
        );
    }

    return requestedTestNames.map((testName) => {
        const requiredTest = requiredRustHeavyEvidenceTestsByName.get(testName);
        if (requiredTest === undefined) {
            throw new Error(
                `Missing required Rust heavy evidence test: ${testName}.`,
            );
        }

        return requiredTest;
    });
};

export const formatRequiredRustHeavyEvidenceTestList = (
    tests: readonly RequiredRustHeavyEvidenceTest[] = requiredRustHeavyEvidenceTests,
): string =>
    [
        `Required Rust heavy evidence tests (${tests.length}):`,
        ...tests.map(
            (test, testIndex) =>
                `${testIndex + 1}. ${test.testName}\n` +
                `   Evidence: ${test.claimEvidence}\n` +
                `   Source: ${test.relativePath}`,
        ),
    ].join('\n');

export const createRequiredRustHeavyEvidenceCargoCommands = (
    selectedTests: readonly RequiredRustHeavyEvidenceTest[],
    input: RequiredRustHeavyEvidenceCommandInput = {},
): readonly CommandInvocation[] => {
    const targetDirectory =
        input.targetDirectory ?? heavyRequiredEvidenceTargetDirectory;
    const testThreadCount =
        input.testThreadCount ?? heavyAcceptedSetupTestThreadCount;
    const baseEnvironment = input.baseEnvironment ?? process.env;

    return selectedTests.map((test) => ({
        args: [
            'test',
            '-p',
            'sealed-lattice-kernel',
            test.testName,
            '--',
            '--ignored',
            '--nocapture',
            '--test-threads',
            String(testThreadCount),
        ],
        command: 'cargo',
        description: `cargo test ${test.testName} (required heavy evidence)`,
        env: {
            ...baseEnvironment,
            CARGO_INCREMENTAL: '1',
            CARGO_TARGET_DIR: targetDirectory,
            SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
        },
        logFileSlug: `cargo-test-required-heavy-evidence-${test.testName}`,
    }));
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    assertKnownOptions(commandArguments);

    if (shouldListRequiredRustHeavyEvidenceTests(commandArguments)) {
        console.log(formatRequiredRustHeavyEvidenceTestList());
        return;
    }

    const selectedTests =
        selectedRequiredRustHeavyEvidenceTests(commandArguments);
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: ['Rust kernel required heavy evidence'],
              scriptName: 'test:rust:kernel:heavy:required',
          });

    console.log(
        `Rust kernel required heavy evidence lane: ${selectedTests.length} test(s), ` +
            `${heavyAcceptedSetupTestThreadCount} test thread(s) ` +
            `(${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB budgeted per test).`,
    );
    console.log(
        `Pinned target directory: ${heavyRequiredEvidenceTargetDirectory}. ` +
            `Incremental compilation: on. Checkpoint resume: on. Manual lane only.`,
    );

    const progressReporter = createHeavyTestProgressReporter({
        label: 'heavy:required',
        threadCount: heavyAcceptedSetupTestThreadCount,
    });

    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries(
            createRequiredRustHeavyEvidenceCargoCommands(selectedTests),
            {
                observer: progressReporter.observer,
                outputMode: 'inherit',
                runLog,
                terminalOutputFilter: progressReporter.terminalOutputFilter,
            },
        );
        process.exitCode = exitCode;
    } finally {
        progressReporter.stop();
        await runLog?.finish({
            details: {
                requiredRustHeavyEvidenceTests: selectedTests.map(
                    (test) => test.testName,
                ),
            },
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
