import os from 'node:os';
import path from 'node:path';

import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from './focused-rust-test-match.js';
import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import {
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './run-command.js';
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

const gigabyte = 1024 ** 3;
const defaultHardMemoryLimitGigabytes = 32;
const maximumHostMemoryFraction = 0.7;
const reservedHostMemoryGigabytes = 2;
const memoryLimitEnvironmentVariable =
    'SEALED_LATTICE_ACCEPTED_SETUP_MEMORY_LIMIT_GIB';

// Thirty-two GiB is the workstation ceiling. Smaller hosts receive a lower
// ceiling, and every host retains at least two GiB of currently free memory for
// the runner and operating system. This is a hard OS limit, not a scheduling
// estimate.
export const deriveAcceptedSetupMemoryLimitGigabytes = (input: {
    readonly freeMemoryGigabytes: number;
    readonly totalMemoryGigabytes: number;
}): number => {
    if (
        !Number.isFinite(input.totalMemoryGigabytes) ||
        input.totalMemoryGigabytes <= 0 ||
        !Number.isFinite(input.freeMemoryGigabytes) ||
        input.freeMemoryGigabytes <= 0
    ) {
        throw new Error('Host memory values must be positive finite numbers.');
    }
    const freeMemoryAfterReserve = Math.floor(
        input.freeMemoryGigabytes - reservedHostMemoryGigabytes,
    );
    if (freeMemoryAfterReserve < 1) {
        throw new Error(
            `Accepted-setup tests require at least ${reservedHostMemoryGigabytes + 1} GiB of free host memory.`,
        );
    }

    return Math.min(
        defaultHardMemoryLimitGigabytes,
        Math.max(
            1,
            Math.floor(input.totalMemoryGigabytes * maximumHostMemoryFraction),
        ),
        freeMemoryAfterReserve,
    );
};

export const resolveAcceptedSetupMemoryLimitGigabytes = (input: {
    readonly automaticLimitGigabytes: number;
    readonly environment?: NodeJS.ProcessEnv;
}): number => {
    const override = (input.environment ?? process.env)[
        memoryLimitEnvironmentVariable
    ];
    if (override === undefined) {
        return input.automaticLimitGigabytes;
    }
    if (!/^[1-9][0-9]*$/u.test(override)) {
        throw new Error(
            `${memoryLimitEnvironmentVariable} must be a positive integer.`,
        );
    }
    const overrideGigabytes = Number.parseInt(override, 10);
    if (overrideGigabytes > input.automaticLimitGigabytes) {
        throw new Error(
            `${memoryLimitEnvironmentVariable} cannot exceed the automatic safe ceiling of ${input.automaticLimitGigabytes} GiB.`,
        );
    }

    return overrideGigabytes;
};

const automaticAcceptedSetupMemoryLimitGigabytes =
    deriveAcceptedSetupMemoryLimitGigabytes({
        freeMemoryGigabytes: os.freemem() / gigabyte,
        totalMemoryGigabytes: os.totalmem() / gigabyte,
    });
const acceptedSetupMemoryLimitGigabytes =
    resolveAcceptedSetupMemoryLimitGigabytes({
        automaticLimitGigabytes: automaticAcceptedSetupMemoryLimitGigabytes,
    });
const acceptedSetupMemoryLimitBytes =
    acceptedSetupMemoryLimitGigabytes * gigabyte;

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
const processMemoryGuardTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'process-memory-guard',
);
const processMemoryGuardExecutablePath = path.join(
    processMemoryGuardTargetDirectory,
    'debug',
    process.platform === 'win32'
        ? 'sealed-lattice-process-memory-guard.exe'
        : 'sealed-lattice-process-memory-guard',
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

export const cargoTestArgumentsForAcceptedSetupTests = (
    testThreadCount: string,
): readonly string[] => [
    'test',
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
        SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
            input.knobs.trusteeProofBatchSize.value,
        SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
            input.knobs.trusteeProofLimbBatchSize.value,
    };
};

export const verifyProcessMemoryGuardCommand = (): CommandInvocation => {
    const environment = { ...process.env };
    delete environment.CARGO_TARGET_DIR;

    return {
        args: [
            'test',
            '--locked',
            '-p',
            'sealed-lattice-process-memory-guard',
            '--target-dir',
            processMemoryGuardTargetDirectory,
        ],
        command: 'cargo',
        description: 'verify process memory guard',
        env: environment,
        logFileSlug: 'cargo-test-process-memory-guard',
    };
};

export const guardAcceptedSetupCommand = (
    command: CommandInvocation,
    memoryLimitBytes = acceptedSetupMemoryLimitBytes,
): CommandInvocation => ({
    ...command,
    args: [
        '--memory-limit-bytes',
        String(memoryLimitBytes),
        '--',
        command.command,
        ...command.args,
    ],
    command: processMemoryGuardExecutablePath,
});

const buildAcceptedSetupCommand = (
    mode: RustKernelAcceptedSetupRunMode,
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveRunKnobs();
    const modeLabel =
        mode === 'accelerated' ? 'accelerated local' : 'CI prove-fresh';
    const setupMessages = [
        `${acceptedSetupRunName} (${modeLabel}): hard inherited process-memory ceiling ${acceptedSetupMemoryLimitGigabytes} GiB.`,
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
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveRunKnobs();
    const isAccelerated = mode === 'accelerated';
    const modeLabel = isAccelerated ? 'accelerated local' : 'CI prove-fresh';
    const setupMessages = [
        `Rust accepted setup focused run (${modeLabel}): filter [${testFilter}], ` +
            `${knobs.testThreads.value} serialized test thread; hard inherited process-memory ceiling ` +
            `${acceptedSetupMemoryLimitGigabytes} GiB.`,
        ...(isAccelerated
            ? [
                  `Pinned target directory: ${acceptedSetupFocusedTargetDirectory}. ` +
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
                    ? acceptedSetupFocusedTargetDirectory
                    : undefined,
            }),
            logFileSlug: isAccelerated
                ? 'cargo-test-rust-accepted-setup-focused'
                : 'cargo-test-rust-accepted-setup-focused-ci',
        }),
        progressLabel: 'accepted-setup:focused',
        setupMessages,
        testThreadCount: Number.parseInt(knobs.testThreads.value, 10),
    };
};

const writeRunnerSetupMessages = (
    runLog: Awaited<ReturnType<typeof createLocalRunLog>>,
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
    const parsedArguments = parseRustKernelAcceptedSetupArguments(rawArguments);

    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: [
            parsedArguments.focused
                ? `Rust accepted setup focused (${parsedArguments.mode})`
                : `${acceptedSetupRunName} (${parsedArguments.mode})`,
        ],
        scriptName: input.scriptName ?? acceptedSetupScriptName,
    });

    const builtCommand = parsedArguments.focused
        ? buildFocusedCommand(
              parsedArguments.testFilters[0] ?? '',
              parsedArguments.mode,
          )
        : buildAcceptedSetupCommand(parsedArguments.mode);
    const focusedTestFilter = parsedArguments.focused
        ? parsedArguments.testFilters[0]
        : undefined;
    const focusedTestMatchTracker =
        focusedTestFilter === undefined
            ? undefined
            : createFocusedRustTestMatchTracker();

    let exitCode: number | undefined;
    try {
        writeRunnerSetupMessages(runLog, builtCommand.setupMessages);
        exitCode = await runCommandsInSeries(
            [verifyProcessMemoryGuardCommand()],
            {
                outputMode: 'inherit',
                runLog,
            },
        );
        if (exitCode !== 0) {
            process.exitCode = exitCode;
            return;
        }

        const progressReporter = createHeavyTestProgressReporter({
            label: builtCommand.progressLabel,
            threadCount: builtCommand.testThreadCount,
        });

        try {
            exitCode = await runCommandsInSeries([builtCommand.command], {
                observer:
                    focusedTestMatchTracker === undefined
                        ? progressReporter.observer
                        : combineCommandRunObservers([
                              progressReporter.observer,
                              focusedTestMatchTracker.observer,
                          ]),
                outputMode: 'inherit',
                runLog,
                terminalOutputFilter: progressReporter.terminalOutputFilter,
            });
        } finally {
            progressReporter.stop();
        }
        if (
            focusedTestMatchTracker !== undefined &&
            focusedTestFilter !== undefined
        ) {
            const focusedRunResult = resolveFocusedRustTestRunResult({
                commandExitCode: exitCode,
                matchedTestCount: focusedTestMatchTracker.matchedTestCount(),
                runnerName: 'Rust accepted setup focused',
                testFilter: focusedTestFilter,
            });
            exitCode = focusedRunResult.exitCode;
            if (focusedRunResult.failureMessage !== undefined) {
                console.error(focusedRunResult.failureMessage);
                runLog.writeCombinedOutput(
                    `${focusedRunResult.failureMessage}\n`,
                );
            }
        }
        process.exitCode = exitCode;
    } finally {
        await runLog?.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runRustKernelAcceptedSetupTests({});
}
