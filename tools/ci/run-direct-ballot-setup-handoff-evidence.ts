import {
    requiredRustHeavyEvidenceTests,
    type RequiredRustHeavyEvidenceTest,
} from './heavy-evidence-tests.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
    type CommandInvocation,
} from './run-command.js';
import { createRequiredRustHeavyEvidenceCargoCommands } from './run-required-rust-heavy-evidence-tests.js';
import { buildWorkspaceBuildCommand } from './run-vitest-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const listEvidenceCommandsArgument = '--list';

export const directBallotSetupHandoffPublicParityTestPaths = [
    'packages/sdk/tests/node/direct-encrypted-ballot-public-api.test.ts',
    'packages/wasm/tests/node/transcript-core-kernel/kernel-memory-and-loader.kernel.test.ts',
] as const;

export type DirectBallotSetupHandoffEvidenceCommandInput = {
    readonly baseEnvironment?: NodeJS.ProcessEnv;
    readonly packageManagerRunner?: PackageManagerRunner;
    readonly requiredRustHeavyEvidenceTests?: readonly RequiredRustHeavyEvidenceTest[];
    readonly targetDirectory?: string;
    readonly testThreadCount?: number;
};

export const shouldListDirectBallotSetupHandoffEvidenceCommands = (
    commandArguments: readonly string[],
): boolean => commandArguments.includes(listEvidenceCommandsArgument);

export const unknownDirectBallotSetupHandoffEvidenceOptions = (
    commandArguments: readonly string[],
): readonly string[] =>
    commandArguments.filter(
        (argument) =>
            argument.startsWith('-') &&
            argument !== listEvidenceCommandsArgument,
    );

const assertKnownOptions = (commandArguments: readonly string[]): void => {
    const unknownOptions =
        unknownDirectBallotSetupHandoffEvidenceOptions(commandArguments);
    if (unknownOptions.length > 0) {
        throw new Error(
            `Unknown direct ballot setup handoff evidence option(s): ${unknownOptions.join(
                ', ',
            )}. Use --list to print the manual evidence command plan.`,
        );
    }
};

export const createDirectBallotSetupHandoffEvidenceCommands = (
    input: DirectBallotSetupHandoffEvidenceCommandInput = {},
): readonly CommandInvocation[] => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();
    const heavyEvidenceCommands = createRequiredRustHeavyEvidenceCargoCommands(
        input.requiredRustHeavyEvidenceTests ?? requiredRustHeavyEvidenceTests,
        {
            baseEnvironment: input.baseEnvironment,
            targetDirectory: input.targetDirectory,
            testThreadCount: input.testThreadCount,
        },
    );

    return [
        buildWorkspaceBuildCommand(packageManagerRunner),
        ...heavyEvidenceCommands,
        createPackageManagerCommand(
            'Run direct ballot setup handoff SDK/WASM public package parity tests',
            [
                'exec',
                'vitest',
                'run',
                ...directBallotSetupHandoffPublicParityTestPaths,
            ],
            {
                logFileSlug: 'direct-ballot-setup-handoff-public-parity',
                packageManagerRunner,
            },
        ),
        createPackageManagerCommand(
            'Verify test lane coverage and manual heavy evidence registry',
            ['exec', 'tsx', 'tools/ci/verify-test-lane-coverage.ts'],
            {
                logFileSlug: 'verify-test-lane-coverage',
                packageManagerRunner,
            },
        ),
    ];
};

export const formatDirectBallotSetupHandoffEvidenceCommandPlan = (
    commands: readonly CommandInvocation[] = createDirectBallotSetupHandoffEvidenceCommands(),
): string =>
    [
        'Direct ballot setup handoff evidence lane:',
        'Manual lane only. This combines the required full-profile Rust heavy setup evidence with SDK/WASM public package boundary tests; it is not part of default check.',
        ...commands.map(
            (command, commandIndex) =>
                `${commandIndex + 1}. ${command.description}\n` +
                `   Command: ${[command.command, ...command.args].join(' ')}`,
        ),
    ].join('\n');

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    assertKnownOptions(commandArguments);

    const commands = createDirectBallotSetupHandoffEvidenceCommands();
    if (shouldListDirectBallotSetupHandoffEvidenceCommands(commandArguments)) {
        console.log(
            formatDirectBallotSetupHandoffEvidenceCommandPlan(commands),
        );
        return;
    }

    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: ['Direct ballot setup handoff evidence'],
              scriptName: 'test:direct-ballot:setup-handoff:evidence',
          });

    console.log(
        'Direct ballot setup handoff evidence lane: manual lane only. ' +
            'Runs the required Rust heavy evidence set, then SDK/WASM public package boundary tests.',
    );

    try {
        process.exitCode = await runCommandsInSeries(commands, {
            outputMode: 'inherit',
            runLog,
        });
    } finally {
        await runLog?.finish({ exitCode: currentProcessExitCode() });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
