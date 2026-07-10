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
//     size libtest/prover/Rayon concurrency from available memory. Run logs stay
//     under `logs/`; proof checkpoints stay under `temp/test-checkpoints/`.
//
//   --ci: authoritative CI-style runs. They build the accepted-setup test
//     module cleanly in the shared `target/` (CARGO_INCREMENTAL=0), prove every
//     proof family fresh (no checkpoint resume), and size libtest/prover/rayon
//     concurrency from available memory so a constrained runner does not
//     exhaust RAM.
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

// Shared libtest-thread budget. The heavy suite uses transported
// proof/key material, but package construction and verification still have a
// transient working set large enough that libtest concurrency must be
// memory-bound, and most of that working set is the shared memoized fixture
// that concurrent tests reuse rather than a per-test cost multiplied by the
// thread count. Size the thread pool from currently available memory, capped
// by core count, so a constrained runner stays serial while a workstation runs
// several tests; a single focused filter simply runs one thread.
const approximateGigabytesPerHeavyTest = 15;
const heavyTestMemoryBudgetFraction = 0.7;
const gigabyte = 1024 ** 3;
const availableGigabytes = os.freemem() / gigabyte;
const logicalProcessorCount = os.cpus().length;

// Per-prover RAM budgets. Each trustee evaluation-key prover, the rayon
// par_iter phases (public-key share succinct proofs, relinearization and
// Galois records, same-secret bridge proofs), and the per-prover RNS-limb proving
// all draw large working sets, so each concurrency knob is sized from available
// memory below.
const approximateGigabytesPerTrusteeProver = 10;
const approximateGigabytesPerRayonThread = 2;
const approximateGigabytesPerTrusteeProofLimb = 5;

export type AutomaticAcceptedSetupConcurrency = {
    readonly rayonThreadCount: number;
    readonly testThreadCount: number;
    readonly trusteeProofBatchSize: number;
    readonly trusteeProofLimbBatchSize: number;
};

// The trustee, limb, and Rayon layers are nested during proof construction, so
// they must share one memory budget. Sizing every layer independently lets each
// consume the full host budget and was enough to terminate a 14 GiB CI runner.
// Reserve one Rayon worker, then choose the trustee and per-trustee limb batches
// from the remaining budget before assigning any remaining capacity to Rayon.
// When even the minimum serial working-set estimate exceeds the budget, the
// only executable configuration is one worker at every layer.
export const deriveAutomaticAcceptedSetupConcurrency = (input: {
    readonly availableGigabytes: number;
    readonly logicalProcessorCount: number;
}): AutomaticAcceptedSetupConcurrency => {
    const memoryBudgetGigabytes =
        input.availableGigabytes * heavyTestMemoryBudgetFraction;
    const boundedProcessorCount = Math.max(1, input.logicalProcessorCount);
    const testThreadCount = Math.min(
        boundedProcessorCount,
        Math.max(
            1,
            Math.floor(
                memoryBudgetGigabytes / approximateGigabytesPerHeavyTest,
            ),
        ),
    );

    const memoryAfterMinimumRayon = Math.max(
        0,
        memoryBudgetGigabytes - approximateGigabytesPerRayonThread,
    );
    const minimumGigabytesPerTrustee =
        approximateGigabytesPerTrusteeProver +
        approximateGigabytesPerTrusteeProofLimb;
    const coreDerivedTrusteeProverConcurrency = Math.max(
        1,
        Math.floor(boundedProcessorCount / 4),
    );
    const trusteeProofBatchSize = Math.min(
        coreDerivedTrusteeProverConcurrency,
        Math.max(
            1,
            Math.floor(memoryAfterMinimumRayon / minimumGigabytesPerTrustee),
        ),
    );

    const memoryPerTrustee = memoryAfterMinimumRayon / trusteeProofBatchSize;
    const trusteeProofLimbBatchSize = Math.min(
        Math.max(1, Math.floor(boundedProcessorCount / trusteeProofBatchSize)),
        Math.max(
            1,
            Math.floor(
                Math.max(
                    0,
                    memoryPerTrustee - approximateGigabytesPerTrusteeProver,
                ) / approximateGigabytesPerTrusteeProofLimb,
            ),
        ),
    );

    const reservedProofMemoryGigabytes =
        trusteeProofBatchSize *
        (approximateGigabytesPerTrusteeProver +
            trusteeProofLimbBatchSize *
                approximateGigabytesPerTrusteeProofLimb);
    const rayonThreadCount = Math.min(
        boundedProcessorCount,
        Math.max(
            1,
            Math.floor(
                Math.max(
                    0,
                    memoryBudgetGigabytes - reservedProofMemoryGigabytes,
                ) / approximateGigabytesPerRayonThread,
            ),
        ),
    );

    return {
        rayonThreadCount,
        testThreadCount,
        trusteeProofBatchSize,
        trusteeProofLimbBatchSize,
    };
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

const resolveKnob = (
    automaticValue: number,
    automaticSource: string,
    override: string | undefined,
): ResolvedKnob =>
    override === undefined
        ? { value: String(automaticValue), source: automaticSource }
        : { value: override, source: 'environment override' };

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

// Resolve the concurrency knobs. The core-derived caps mirror the kernel's
// package proving concurrency; the kernel treats the exported values as
// authoritative, so on a high-core but low-memory runner the RAM bound (not the
// core count) wins.
export const resolveRunKnobs = (
    mode: RustKernelAcceptedSetupRunMode,
    environment: NodeJS.ProcessEnv = process.env,
): ResolvedRunKnobs => {
    const automaticConcurrency = deriveAutomaticAcceptedSetupConcurrency({
        availableGigabytes,
        logicalProcessorCount,
    });
    const localOverride = (value: string | undefined): string | undefined =>
        mode === 'accelerated' ? value : undefined;

    return {
        testThreads: {
            value: String(automaticConcurrency.testThreadCount),
            source: 'memory-bounded',
        },
        trusteeProofBatchSize: resolveKnob(
            automaticConcurrency.trusteeProofBatchSize,
            'shared-memory-bounded',
            localOverride(environment.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE),
        ),
        trusteeProofLimbBatchSize: resolveKnob(
            automaticConcurrency.trusteeProofLimbBatchSize,
            'shared-memory-bounded',
            localOverride(
                environment.SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE,
            ),
        ),
        rayonThreadCount: resolveKnob(
            automaticConcurrency.rayonThreadCount,
            'shared-memory-bounded',
            localOverride(environment.RAYON_NUM_THREADS),
        ),
    };
};

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

const buildAcceptedSetupCommand = (
    mode: RustKernelAcceptedSetupRunMode,
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveRunKnobs(mode);
    const modeLabel =
        mode === 'accelerated' ? 'accelerated local' : 'CI prove-fresh';
    const setupMessages = [
        `${acceptedSetupRunName} (${modeLabel}): running with ${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB automatically budgeted per test).`,
        `${acceptedSetupRunName} (${modeLabel}): proving up to ${knobs.trusteeProofBatchSize.value} trustee evaluation-key ` +
            `proof(s) concurrently (${knobs.trusteeProofBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProver} GiB per prover).`,
        `${acceptedSetupRunName} (${modeLabel}): proving up to ${knobs.trusteeProofLimbBatchSize.value} RNS limb(s) per ` +
            `trustee evaluation-key prover (${knobs.trusteeProofLimbBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProofLimb} GiB per limb).`,
        `${acceptedSetupRunName} (${modeLabel}): bounding the rayon pool to ${knobs.rayonThreadCount.value} thread(s) ` +
            `(${knobs.rayonThreadCount.source}; automatic budget uses ` +
            `${approximateGigabytesPerRayonThread} GiB per rayon thread).`,
    ];
    if (mode === 'accelerated') {
        setupMessages.push(
            `${acceptedSetupRunName} (${modeLabel}): incremental compilation on; ` +
                `target directory ${acceptedSetupAcceleratedTargetDirectory}; proof checkpoints ${acceptedSetupCheckpointDirectory}; run logs stay under logs/.`,
        );
    }

    return {
        command: {
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
        },
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
    '--show-output',
    '--test-threads',
    testThreadCount,
];

export const buildFocusedCommand = (
    testFilter: string,
    mode: RustKernelAcceptedSetupRunMode,
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveRunKnobs(mode);
    const isAccelerated = mode === 'accelerated';
    const modeLabel = isAccelerated ? 'accelerated local' : 'CI prove-fresh';
    const setupMessages = [
        `Rust accepted setup focused run (${modeLabel}): filter [${testFilter}], ` +
            `${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available).`,
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
        command: {
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
        },
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
