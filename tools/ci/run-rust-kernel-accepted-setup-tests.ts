import os from 'node:os';
import path from 'node:path';

import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import {
    heavyAcceptedSetupTestPattern,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// One implementation for the Rust accepted-setup proof-test runs. The heavy
// accepted-setup suite is one set of `heavy_accepted_setup` tests sharing one
// memoized package fixture; the entrypoint also accepts a single positional
// test or file-stem filter for a focused local run. The default mode is
// accelerated local execution. GitHub CI passes `--ci` to request the
// conservative prove-fresh run:
//
//   default (no positional filter): accelerated local runs. They build the
//     `heavy_accepted_setup` suite in a pinned warm target directory
//     (`target/accepted-setup-accelerated/`), keep incremental compilation on,
//     resume deterministic proof checkpoints from `temp/test-checkpoints/`, and
//     size libtest/prover/Rayon concurrency from available memory. Run logs stay
//     under `logs/`; proof checkpoints stay under `temp/test-checkpoints/`.
//
//   --ci: authoritative CI-style runs. They build the `heavy_accepted_setup`
//     suite cleanly in the shared `target/` (CARGO_INCREMENTAL=0), prove every
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

export { heavyAcceptedSetupTestPattern };

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

const automaticTestThreadCount = (): number =>
    Math.min(
        logicalProcessorCount,
        Math.max(
            1,
            Math.floor(
                (availableGigabytes * heavyTestMemoryBudgetFraction) /
                    approximateGigabytesPerHeavyTest,
            ),
        ),
    );

// Per-prover RAM budgets. Each trustee evaluation-key prover, the rayon
// par_iter phases (public-key share succinct proofs, relinearization and
// Galois records, same-secret anchors), and the per-prover RNS-limb proving
// all draw large working sets, so each concurrency knob is sized from available
// memory below.
const approximateGigabytesPerTrusteeProver = 10;
const approximateGigabytesPerRayonThread = 2;
const approximateGigabytesPerTrusteeProofLimb = 5;

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

type ResolvedRunKnobs = {
    readonly rayonThreadCount: ResolvedKnob;
    readonly testThreads: ResolvedKnob;
    readonly trusteeProofBatchSize: ResolvedKnob;
    readonly trusteeProofLimbBatchSize: ResolvedKnob;
};

type BuiltRustKernelAcceptedSetupCommand = {
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
    heavyAcceptedSetupTestPattern,
    '--',
    '--ignored',
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
const resolveRunKnobs = (): ResolvedRunKnobs => {
    const coreDerivedTrusteeProverConcurrency = Math.max(
        1,
        Math.floor(logicalProcessorCount / 4),
    );
    const memoryBoundedTrusteeProofBatchSize = Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                approximateGigabytesPerTrusteeProver,
        ),
    );
    const trusteeProofBatchSize = Math.min(
        coreDerivedTrusteeProverConcurrency,
        memoryBoundedTrusteeProofBatchSize,
    );
    const memoryBoundedRayonThreadCount = Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                approximateGigabytesPerRayonThread,
        ),
    );
    const rayonThreadCount = Math.min(
        logicalProcessorCount,
        memoryBoundedRayonThreadCount,
    );
    const memoryBoundedTrusteeProofLimbBatchSize = Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                approximateGigabytesPerTrusteeProofLimb,
        ),
    );
    const trusteeProofLimbBatchSize = Math.min(
        rayonThreadCount,
        memoryBoundedTrusteeProofLimbBatchSize,
    );

    return {
        testThreads: {
            value: String(automaticTestThreadCount()),
            source: 'memory-bounded',
        },
        trusteeProofBatchSize: resolveKnob(
            trusteeProofBatchSize,
            'memory-bounded',
            process.env.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE,
        ),
        trusteeProofLimbBatchSize: resolveKnob(
            trusteeProofLimbBatchSize,
            'memory-bounded',
            process.env.SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE,
        ),
        rayonThreadCount: resolveKnob(
            rayonThreadCount,
            'memory-bounded',
            process.env.RAYON_NUM_THREADS,
        ),
    };
};

const buildAcceptedSetupEnvironment = (input: {
    readonly cargoIncremental: '0' | '1';
    readonly knobs: ResolvedRunKnobs;
    readonly resumeCheckpoints: boolean;
    readonly targetDirectoryPath?: string;
}): NodeJS.ProcessEnv => ({
    ...process.env,
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
});

const buildAcceptedSetupCommand = (
    mode: RustKernelAcceptedSetupRunMode,
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveRunKnobs();
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
            description: `cargo test Rust accepted setup proofs${
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
    '--ignored',
    '--show-output',
    '--test-threads',
    testThreadCount,
];

const buildFocusedCommand = (
    testFilter: string,
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveRunKnobs();
    const setupMessages = [
        `Rust accepted setup focused run: filter [${testFilter}], ` +
            `${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available).`,
        `Pinned target directory: ${acceptedSetupFocusedTargetDirectory}. ` +
            `Incremental compilation: on. Proof checkpoint resume: on. Proof checkpoints ${acceptedSetupCheckpointDirectory}; run logs stay under logs/.`,
    ];

    return {
        command: {
            args: cargoTestArgumentsForFocusedFilter(
                testFilter,
                knobs.testThreads.value,
            ),
            command: 'cargo',
            description: `cargo test ${testFilter} (warm focused)`,
            env: buildAcceptedSetupEnvironment({
                cargoIncremental: '1',
                knobs,
                resumeCheckpoints: true,
                targetDirectoryPath: acceptedSetupFocusedTargetDirectory,
            }),
            logFileSlug: 'cargo-test-rust-accepted-setup-focused',
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
                : [heavyAcceptedSetupTestPattern],
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
        ? buildFocusedCommand(parsedArguments.testFilters[0] ?? '')
        : buildAcceptedSetupCommand(parsedArguments.mode);

    let exitCode: number | undefined;
    try {
        writeRunnerSetupMessages(runLog, builtCommand.setupMessages);
        const progressReporter = createHeavyTestProgressReporter({
            label: builtCommand.progressLabel,
            threadCount: builtCommand.testThreadCount,
        });

        try {
            exitCode = await runCommandsInSeries([builtCommand.command], {
                observer: progressReporter.observer,
                outputMode: 'inherit',
                runLog,
                terminalOutputFilter: progressReporter.terminalOutputFilter,
            });
        } finally {
            progressReporter.stop();
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
