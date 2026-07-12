import path from 'node:path';

import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from './focused-rust-test-match.js';
import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import {
    runWithLocalRunLog,
    safeLogSlug,
    type ActiveLocalRunLog,
} from './local-run-log.js';
import {
    createProcessMemoryGuard,
    deriveProcessMemoryLimitGigabytes,
    resolveProcessMemoryLimitGigabytes,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './run-command.js';
import { verifyFocusedRustLaneSelection } from './rust-focused-lane-selection.js';
import {
    acceptedSetupTestModulePattern,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// One implementation for the Rust accepted-setup proof-test runs. The heavy
// accepted-setup suite contains every test in the accepted-setup test module,
// including ignored proof tests, and shares one memoized package fixture. The
// entrypoint also accepts a single positional test or file-stem filter for a
// focused local run. The default mode is
// accelerated local execution. GitHub CI passes `--ci` to request the
// conservative prove-fresh run:
//
//   default (no positional filter): accelerated local runs. They build the
//     accepted-setup test module in a pinned warm target directory
//     (`target/accepted-setup-accelerated/`), keep incremental compilation on,
//     resume deterministic proof checkpoints from `temp/test-checkpoints/`, and
//     run under a hard process-memory ceiling with serialized libtest, prover,
//     and Rayon execution. Run logs stay under `logs/`; proof checkpoints stay
//     under `temp/test-checkpoints/`.
//
//   --ci: authoritative CI-style runs. They build the accepted-setup test
//     module cleanly in the shared `target/` (CARGO_INCREMENTAL=0), prove every
//     proof family fresh (no checkpoint resume), under the same hard memory
//     ceiling and serialized execution used by local runs.
//
//   <filter>: the fast developer inner loop. It runs only the filtered test or
//     module in a separate pinned `target/accepted-setup-focused/`
//     (CARGO_INCREMENTAL=1) so an edit recompiles incrementally (measured ~16s
//     versus ~44s for a full rebuild) without contending for the gate's build
//     lock, and resumes the
//     on-disk proof checkpoints so each family's corpus loads from
//     `temp/test-checkpoints/` instead of being re-proved. That trades the
//     authoritative prove-fresh guarantee for speed.

export { acceptedSetupTestModulePattern };

export type RustKernelAcceptedSetupRunMode = 'accelerated' | 'ci';

export type ParsedRustKernelAcceptedSetupArguments = {
    readonly focused: boolean;
    readonly mode: RustKernelAcceptedSetupRunMode;
    readonly testFilters: readonly string[];
};

const memoryLimitEnvironmentVariable =
    'SEALED_LATTICE_ACCEPTED_SETUP_MEMORY_LIMIT_GIB';

export const deriveAcceptedSetupMemoryLimitGigabytes = (input: {
    readonly freeMemoryGigabytes: number;
    readonly totalMemoryGigabytes: number;
}): number =>
    deriveProcessMemoryLimitGigabytes({
        ...input,
        insufficientFreeMemoryRunDescription: 'Accepted-setup tests',
    });

export const resolveAcceptedSetupMemoryLimitGigabytes = (input: {
    readonly automaticLimitGigabytes: number;
    readonly environment?: NodeJS.ProcessEnv;
}): number =>
    resolveProcessMemoryLimitGigabytes({
        ...input,
        memoryLimitEnvironmentVariable,
    });

let acceptedSetupProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getAcceptedSetupProcessMemoryGuard = (): ProcessMemoryGuard => {
    acceptedSetupProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription: 'Accepted-setup tests',
        memoryLimitEnvironmentVariable,
    });

    return acceptedSetupProcessMemoryGuard;
};

// The pinned focused target directory. It lives under `target/` (already
// git-ignored) but is distinct from the default `target/` the gate uses, so a
// focused run never blocks, and is never blocked by, a running gate.
const acceptedSetupFocusedTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'accepted-setup-focused',
);
const acceptedSetupAcceleratedTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'accepted-setup-accelerated',
);
const acceptedSetupCheckpointRootDirectory = path.resolve(
    process.cwd(),
    'temp',
    'test-checkpoints',
);
const acceptedSetupCheckpointDirectory = path.join(
    acceptedSetupCheckpointRootDirectory,
    'accepted-setup-final-package-material-store',
);

export type ResolvedKnob = {
    readonly value: string;
    readonly source: string;
};

export type ResolvedRunKnobs = {
    readonly rayonThreadCount: ResolvedKnob;
    readonly testThreads: ResolvedKnob;
    readonly trusteeProofBatchSize: ResolvedKnob;
    readonly trusteeProofLimbBatchSize: ResolvedKnob;
};

export type BuiltRustKernelAcceptedSetupCommand = {
    readonly command: CommandInvocation;
    readonly progressLabel: string;
    readonly setupMessages: readonly string[];
    readonly testThreadCount: number;
};

export type GuardedRustKernelCommand = {
    readonly builtCommand: BuiltRustKernelAcceptedSetupCommand;
    readonly expectedTestFilter?: string;
};

export const cargoTestArgumentsForAcceptedSetupTests = (
    testThreadCount: string,
): readonly string[] => [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
    acceptedSetupTestModulePattern,
    '--',
    '--include-ignored',
    '--nocapture',
    '--test-threads',
    testThreadCount,
];

const acceptedSetupRunName = 'Rust accepted setup';
const acceptedSetupScriptName = 'test:rust:kernel:accepted-setup';

// Keep every nested scheduling layer serial until its peak memory has been
// measured inside the hard ceiling. Environment overrides cannot weaken this
// containment policy.
export const resolveRunKnobs = (): ResolvedRunKnobs => ({
    testThreads: { value: '1', source: 'serialized' },
    trusteeProofBatchSize: { value: '1', source: 'serialized' },
    trusteeProofLimbBatchSize: { value: '1', source: 'serialized' },
    rayonThreadCount: { value: '1', source: 'serialized' },
});

export const buildAcceptedSetupEnvironment = (input: {
    readonly baseEnvironment?: NodeJS.ProcessEnv;
    readonly cargoIncremental: '0' | '1';
    readonly knobs: ResolvedRunKnobs;
    readonly resumeCheckpoints: boolean;
    readonly targetDirectoryPath?: string;
}): NodeJS.ProcessEnv => {
    const environment = {
        ...(input.baseEnvironment ?? process.env),
    };
    delete environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS;
    delete environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT;
    delete environment.CARGO_TARGET_DIR;

    return {
        ...environment,
        CARGO_BUILD_JOBS: '1',
        CARGO_INCREMENTAL: input.cargoIncremental,
        ...(input.targetDirectoryPath === undefined
            ? {}
            : { CARGO_TARGET_DIR: input.targetDirectoryPath }),
        ...(input.resumeCheckpoints
            ? {
                  SEALED_LATTICE_TEST_CHECKPOINT_ROOT:
                      acceptedSetupCheckpointRootDirectory,
                  SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
              }
            : {}),
        RAYON_NUM_THREADS: input.knobs.rayonThreadCount.value,
        RUST_BACKTRACE: 'full',
        SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
            input.knobs.trusteeProofBatchSize.value,
        SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
            input.knobs.trusteeProofLimbBatchSize.value,
    };
};

export const verifyProcessMemoryGuardCommand = (): CommandInvocation =>
    getAcceptedSetupProcessMemoryGuard().buildVerificationCommand();

export const guardAcceptedSetupCommand = (
    command: CommandInvocation,
    memoryLimitBytes?: number,
): CommandInvocation => {
    const processMemoryGuard = getAcceptedSetupProcessMemoryGuard();
    return processMemoryGuard.guardCommand(
        command,
        memoryLimitBytes ?? processMemoryGuard.memoryLimitBytes,
    );
};

const buildAcceptedSetupCommand = (
    mode: RustKernelAcceptedSetupRunMode,
): BuiltRustKernelAcceptedSetupCommand => {
    const memoryLimitGigabytes =
        getAcceptedSetupProcessMemoryGuard().memoryLimitGigabytes;
    const knobs = resolveRunKnobs();
    const modeLabel =
        mode === 'accelerated' ? 'accelerated local' : 'CI prove-fresh';
    const setupMessages = [
        `${acceptedSetupRunName} (${modeLabel}): hard inherited process-memory ceiling ${memoryLimitGigabytes} GiB.`,
        `${acceptedSetupRunName} (${modeLabel}): serialized libtest, cargo build, trustee proof, RNS-limb proof, and Rayon execution.`,
    ];
    if (mode === 'accelerated') {
        setupMessages.push(
            `${acceptedSetupRunName} (${modeLabel}): incremental compilation on; ` +
                `target directory ${acceptedSetupAcceleratedTargetDirectory}; proof checkpoints ${acceptedSetupCheckpointDirectory}; run logs stay under logs/.`,
        );
    }

    return {
        command: guardAcceptedSetupCommand({
            args: cargoTestArgumentsForAcceptedSetupTests(
                knobs.testThreads.value,
            ),
            command: 'cargo',
            description: `cargo test Rust accepted setup${
                mode === 'accelerated' ? ' (accelerated local)' : ''
            }`,
            env: buildAcceptedSetupEnvironment({
                cargoIncremental: mode === 'accelerated' ? '1' : '0',
                knobs,
                resumeCheckpoints: mode === 'accelerated',
                targetDirectoryPath:
                    mode === 'accelerated'
                        ? acceptedSetupAcceleratedTargetDirectory
                        : undefined,
            }),
            logFileSlug:
                mode === 'accelerated'
                    ? 'cargo-test-rust-accepted-setup-accelerated'
                    : 'cargo-test-rust-accepted-setup',
        }),
        progressLabel: 'accepted-setup',
        setupMessages,
        testThreadCount: Number.parseInt(knobs.testThreads.value, 10),
    };
};

export const normalizeFocusedTestFilter = (filter: string): string => {
    return normalizeRustTestFilter(filter);
};

export const cargoTestArgumentsForFocusedFilter = (
    testFilter: string,
    testThreadCount: string,
): readonly string[] => [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
    testFilter,
    '--',
    '--include-ignored',
    '--nocapture',
    '--test-threads',
    testThreadCount,
];

export const buildFocusedCommand = (
    testFilter: string,
    mode: RustKernelAcceptedSetupRunMode,
    customization: {
        readonly logFileSlug?: string;
        readonly progressLabel?: string;
        readonly runName?: string;
        readonly targetDirectoryPath?: string;
    } = {},
): BuiltRustKernelAcceptedSetupCommand => {
    const memoryLimitGigabytes =
        getAcceptedSetupProcessMemoryGuard().memoryLimitGigabytes;
    const knobs = resolveRunKnobs();
    const isAccelerated = mode === 'accelerated';
    const modeLabel = isAccelerated ? 'accelerated local' : 'CI prove-fresh';
    const runName = customization.runName ?? 'Rust accepted setup focused';
    const targetDirectoryPath =
        customization.targetDirectoryPath ??
        acceptedSetupFocusedTargetDirectory;
    const setupMessages = [
        `${runName} (${modeLabel}): filter [${testFilter}], ` +
            `${knobs.testThreads.value} serialized test thread; hard inherited process-memory ceiling ` +
            `${memoryLimitGigabytes} GiB.`,
        ...(isAccelerated
            ? [
                  `Pinned target directory: ${targetDirectoryPath}. ` +
                      `Incremental compilation: on. Proof checkpoint resume: on. Proof checkpoints ${acceptedSetupCheckpointDirectory}; run logs stay under logs/.`,
              ]
            : [
                  'Incremental compilation: off. Proof checkpoint resume: off. Run logs stay under logs/.',
              ]),
    ];

    return {
        command: guardAcceptedSetupCommand({
            args: cargoTestArgumentsForFocusedFilter(
                testFilter,
                knobs.testThreads.value,
            ),
            command: 'cargo',
            description: `cargo test ${testFilter} (${modeLabel} focused)`,
            env: buildAcceptedSetupEnvironment({
                cargoIncremental: isAccelerated ? '1' : '0',
                knobs,
                resumeCheckpoints: isAccelerated,
                targetDirectoryPath: isAccelerated
                    ? targetDirectoryPath
                    : undefined,
            }),
            logFileSlug:
                customization.logFileSlug ??
                (isAccelerated
                    ? 'cargo-test-rust-accepted-setup-focused'
                    : 'cargo-test-rust-accepted-setup-focused-ci'),
        }),
        progressLabel: customization.progressLabel ?? 'accepted-setup:focused',
        setupMessages,
        testThreadCount: Number.parseInt(knobs.testThreads.value, 10),
    };
};

const writeRunnerSetupMessages = (
    runLog: ActiveLocalRunLog,
    setupMessages: readonly string[],
): void => {
    for (const message of setupMessages) {
        console.log(message);
        runLog.writeCombinedOutput(`${message}\n`);
    }
};

const combineCommandRunObservers = (
    observers: readonly CommandRunObserver[],
): CommandRunObserver => ({
    onCommandExit: (event): void => {
        for (const observer of observers) {
            observer.onCommandExit?.(event);
        }
    },
    onCommandOutput: (event): void => {
        for (const observer of observers) {
            observer.onCommandOutput?.(event);
        }
    },
    onCommandStart: (event): void => {
        for (const observer of observers) {
            observer.onCommandStart?.(event);
        }
    },
});

export const buildGuardedRustKernelDiagnosticFileNames = (input: {
    readonly commandIndex: number;
    readonly progressLabel: string;
}): Readonly<{
    processMemoryGuard: string;
    testEvents: string;
}> => {
    if (!Number.isSafeInteger(input.commandIndex) || input.commandIndex < 0) {
        throw new Error(
            'Guarded Rust kernel diagnostic command index must be a non-negative safe integer.',
        );
    }
    const commandOrdinal = String(input.commandIndex + 1).padStart(2, '0');
    const diagnosticSlug = safeLogSlug(input.progressLabel);

    return {
        processMemoryGuard: `process-memory-guard-${commandOrdinal}-${diagnosticSlug}.jsonl`,
        testEvents: `${commandOrdinal}-${diagnosticSlug}.jsonl`,
    };
};

export const runGuardedRustKernelCommands = async (input: {
    readonly commands: readonly GuardedRustKernelCommand[];
    readonly laneLabel: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<void> => {
    const { runLog } = input;
    for (const command of input.commands) {
        writeRunnerSetupMessages(runLog, command.builtCommand.setupMessages);
    }
    let exitCode = await runCommandsInSeries(
        [verifyProcessMemoryGuardCommand()],
        { outputMode: 'inherit', runLog },
    );
    if (exitCode !== 0) {
        process.exitCode = exitCode;
        return;
    }

    for (const [commandIndex, command] of input.commands.entries()) {
        const testMatchTracker =
            command.expectedTestFilter === undefined
                ? undefined
                : createFocusedRustTestMatchTracker();
        const diagnosticFileNames = buildGuardedRustKernelDiagnosticFileNames({
            commandIndex,
            progressLabel: command.builtCommand.progressLabel,
        });
        const guardedCommand =
            getAcceptedSetupProcessMemoryGuard().addDiagnostics(
                command.builtCommand.command,
                path.join(
                    runLog.runDirectoryPath,
                    'resources',
                    diagnosticFileNames.processMemoryGuard,
                ),
            );
        const progressReporter = createHeavyTestProgressReporter({
            eventFilePath: path.join(
                runLog.runDirectoryPath,
                'tests',
                diagnosticFileNames.testEvents,
            ),
            label: command.builtCommand.progressLabel,
            threadCount: command.builtCommand.testThreadCount,
        });
        try {
            exitCode = await runCommandsInSeries([guardedCommand], {
                observer:
                    testMatchTracker === undefined
                        ? progressReporter.observer
                        : combineCommandRunObservers([
                              progressReporter.observer,
                              testMatchTracker.observer,
                          ]),
                outputMode: 'inherit',
                runLog,
                terminalOutputFilter: progressReporter.terminalOutputFilter,
            });
        } finally {
            progressReporter.stop();
        }
        if (
            testMatchTracker !== undefined &&
            command.expectedTestFilter !== undefined
        ) {
            const focusedRunResult = resolveFocusedRustTestRunResult({
                commandExitCode: exitCode,
                matchedTestCount: testMatchTracker.matchedTestCount(),
                runnerName: input.laneLabel,
                testFilter: command.expectedTestFilter,
            });
            exitCode = focusedRunResult.exitCode;
            if (focusedRunResult.failureMessage !== undefined) {
                console.error(focusedRunResult.failureMessage);
                runLog.writeCombinedOutput(
                    `${focusedRunResult.failureMessage}\n`,
                );
            }
        }
        if (exitCode !== 0) {
            break;
        }
    }
    process.exitCode = exitCode;
};

const usage =
    'Usage: run-rust-kernel-accepted-setup-tests.ts [--ci] [<test name, module name, or Rust file filter>]. ' +
    'Default mode is accelerated local execution with checkpoint resume. Pass --ci for the conservative prove-fresh run.';

export const parseRustKernelAcceptedSetupArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelAcceptedSetupArguments => {
    const positionalArguments: string[] = [];
    let mode: RustKernelAcceptedSetupRunMode = 'accelerated';

    for (const argument of commandArguments) {
        if (argument === undefined) {
            continue;
        }
        if (argument === '--') {
            continue;
        }
        if (argument === '--ci') {
            mode = 'ci';
            continue;
        }
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument: ${argument}. ${usage}`);
        }

        positionalArguments.push(argument);
    }

    if (positionalArguments.length > 1) {
        throw new Error(
            `Focused accepted-setup runs accept one test or file filter. ${usage}`,
        );
    }

    const focused = positionalArguments.length === 1;
    const normalizedFocusedFilter = focused
        ? normalizeFocusedTestFilter(positionalArguments[0] ?? '')
        : undefined;
    if (normalizedFocusedFilter === '') {
        throw new Error(
            `Focused accepted-setup runs require a non-empty filter. ${usage}`,
        );
    }

    return {
        focused,
        mode,
        testFilters:
            normalizedFocusedFilter !== undefined
                ? [normalizedFocusedFilter]
                : [acceptedSetupTestModulePattern],
    };
};

export const runRustKernelAcceptedSetupTests = async (input: {
    readonly rawArguments?: readonly string[];
    readonly scriptName?: string;
}): Promise<void> => {
    const rawArguments = input.rawArguments ?? process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [acceptedSetupRunName],
            scriptName: input.scriptName ?? acceptedSetupScriptName,
        },
        async (runLog) => {
            const parsedArguments =
                parseRustKernelAcceptedSetupArguments(rawArguments);
            const builtCommand = parsedArguments.focused
                ? buildFocusedCommand(
                      parsedArguments.testFilters[0] ?? '',
                      parsedArguments.mode,
                  )
                : buildAcceptedSetupCommand(parsedArguments.mode);
            const focusedTestFilter = parsedArguments.focused
                ? parsedArguments.testFilters[0]
                : undefined;
            if (focusedTestFilter !== undefined) {
                await verifyFocusedRustLaneSelection({
                    environment: builtCommand.command.env,
                    lane: 'rust-accepted-setup',
                    runLog,
                    testFilter: focusedTestFilter,
                });
            }

            await runGuardedRustKernelCommands({
                commands: [
                    { builtCommand, expectedTestFilter: focusedTestFilter },
                ],
                laneLabel: parsedArguments.focused
                    ? `Rust accepted setup focused (${parsedArguments.mode})`
                    : `${acceptedSetupRunName} (${parsedArguments.mode})`,
                runLog,
            });
        },
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runRustKernelAcceptedSetupTests({});
}
