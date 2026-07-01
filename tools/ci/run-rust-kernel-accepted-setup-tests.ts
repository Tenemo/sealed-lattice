import os from 'node:os';
import path from 'node:path';

import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import {
    heavyAcceptedSetupFinalPackageTestPattern,
    heavyAcceptedSetupTestPattern,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// One shared implementation for the Rust accepted-setup proof-test lanes.
// Authoritative lanes are selected by the package-script entrypoint; the main
// accepted-setup entrypoint also accepts a single positional test or file-stem
// filter for focused local mode. Keeping those modes mutually exclusive
// prevents a half-and-half state, for example checkpoint resume in the gate's
// shared target:
//
//   default (no positional filter): authoritative CI-style runs. They build the selected
//     `heavy_accepted_setup` lane cleanly in the shared `target/`
//     (CARGO_INCREMENTAL=0), prove every proof family fresh (no checkpoint
//     resume), and size libtest/prover/rayon concurrency from available memory
//     so a constrained runner does not exhaust RAM. The selected lane defines
//     coverage.
//
//   <filter>: the fast developer inner loop. It runs only the filtered test or
//     module in a separate pinned `target/accepted-setup-focused/`
//     (CARGO_INCREMENTAL=1) so an edit recompiles incrementally (measured ~16s
//     versus ~44s for a full rebuild) without contending for the gate's build
//     lock, and resumes the
//     on-disk proof checkpoints so each family's corpus loads from
//     `temp/test-checkpoints/` instead of being re-proved. That trades the
//     authoritative prove-fresh guarantee for speed.

export {
    heavyAcceptedSetupFinalPackageTestPattern,
    heavyAcceptedSetupTestPattern,
};

export type RustKernelAcceptedSetupLane = 'all' | 'fast' | 'final-package';
type RustKernelAcceptedSetupCommandLane = Exclude<
    RustKernelAcceptedSetupLane,
    'all'
>;

export type ParsedRustKernelAcceptedSetupArguments = {
    readonly focused: boolean;
    readonly testFilters: readonly string[];
};

// Shared libtest-thread budget. The heavy lane uses compact transported
// proof/key material, but full-profile package construction and verification
// still have a transient working set large enough that libtest concurrency must
// be memory-bound: a single package-inflating test was measured near 57 GiB
// resident, most of it the shared fixture that concurrent tests reuse rather
// than a per-test cost multiplied by the thread count. Size the thread pool from
// currently available memory, capped by core count, so a constrained runner
// stays serial while a workstation runs several tests; a single focused filter
// simply runs one thread.
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
// Final-package tests inflate the full accepted-setup package and then run
// trustee evaluation-key proving with their own Rayon/prover concurrency. Letting
// libtest start multiple such tests multiplies the fixture working set and can
// overcommit even a 128 GiB workstation; the full-ring trustee prover is also
// already parallelized across limbs, so this lane serializes trustees and leaves
// parallelism to the inner prover.
const finalPackageMaximumLibtestThreadCount = 1;
const finalPackageMaximumTrusteeProofBatchSize = 1;

// Authoritative-mode per-prover RAM budgets. Each trustee evaluation-key prover,
// the rayon par_iter phases (public-key share succinct proofs, relinearization
// and Galois records, same-secret anchors), and the per-prover RNS-limb proving
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

export type ResolvedKnob = {
    readonly value: string;
    readonly source: string;
};

type BuiltRustKernelAcceptedSetupCommand = {
    readonly command: CommandInvocation;
    readonly progressLabel: string;
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

export const automaticTestThreadKnobForLane = (
    lane: RustKernelAcceptedSetupLane,
    memoryBoundedTestThreadCount: number,
): ResolvedKnob => {
    if (
        lane === 'final-package' &&
        memoryBoundedTestThreadCount > finalPackageMaximumLibtestThreadCount
    ) {
        return {
            value: String(finalPackageMaximumLibtestThreadCount),
            source: 'final-package fixture cap',
        };
    }

    return {
        value: String(memoryBoundedTestThreadCount),
        source: 'memory-bounded',
    };
};

export const automaticTrusteeProofBatchKnobForLane = (
    lane: RustKernelAcceptedSetupLane,
    memoryBoundedTrusteeProofBatchSize: number,
): ResolvedKnob => {
    if (
        lane === 'final-package' &&
        memoryBoundedTrusteeProofBatchSize >
            finalPackageMaximumTrusteeProofBatchSize
    ) {
        return {
            value: String(finalPackageMaximumTrusteeProofBatchSize),
            source: 'final-package prover cap',
        };
    }

    return {
        value: String(memoryBoundedTrusteeProofBatchSize),
        source: 'memory-bounded',
    };
};

export const cargoTestArgumentsForLane = (
    lane: RustKernelAcceptedSetupLane,
    testThreadCount: string,
): readonly string[] => {
    const testFilter =
        lane === 'final-package'
            ? heavyAcceptedSetupFinalPackageTestPattern
            : heavyAcceptedSetupTestPattern;
    const skippedTests =
        lane === 'fast'
            ? ['--skip', heavyAcceptedSetupFinalPackageTestPattern]
            : [];

    return [
        'test',
        '-p',
        'sealed-lattice-kernel',
        testFilter,
        '--',
        '--ignored',
        '--nocapture',
        ...skippedTests,
        '--test-threads',
        testThreadCount,
    ];
};

const testFiltersForLane = (
    lane: RustKernelAcceptedSetupLane,
): readonly string[] =>
    lane === 'final-package'
        ? [heavyAcceptedSetupFinalPackageTestPattern]
        : [heavyAcceptedSetupTestPattern];

const laneNameForLane = (lane: RustKernelAcceptedSetupLane): string => {
    if (lane === 'fast') {
        return 'Rust accepted setup fast';
    }
    if (lane === 'final-package') {
        return 'Rust accepted setup final package';
    }

    return 'Rust accepted setup';
};

const scriptNameForLane = (lane: RustKernelAcceptedSetupLane): string => {
    if (lane === 'fast') {
        return 'test:rust:kernel:accepted-setup:fast';
    }
    if (lane === 'final-package') {
        return 'test:rust:kernel:accepted-setup:final-package';
    }

    return 'test:rust:kernel:accepted-setup';
};

const progressLabelForLane = (lane: RustKernelAcceptedSetupLane): string => {
    if (lane === 'fast') {
        return 'accepted-setup:fast';
    }
    if (lane === 'final-package') {
        return 'accepted-setup:final-package';
    }

    return 'accepted-setup';
};

const logFileSlugForLane = (lane: RustKernelAcceptedSetupLane): string => {
    if (lane === 'fast') {
        return 'cargo-test-rust-accepted-setup-fast';
    }
    if (lane === 'final-package') {
        return 'cargo-test-rust-accepted-setup-final-package';
    }

    return 'cargo-test-rust-accepted-setup';
};

const commandDescriptionForLane = (
    lane: RustKernelAcceptedSetupLane,
): string => {
    if (lane === 'fast') {
        return 'cargo test Rust accepted setup fast proof checks';
    }
    if (lane === 'final-package') {
        return 'cargo test Rust accepted setup final package';
    }

    return 'cargo test Rust accepted setup proofs';
};

// Resolve the authoritative-lane concurrency knobs only for authoritative runs,
// so a focused run neither validates nor depends on these overrides. The
// core-derived caps mirror the kernel's final-package proving concurrency; the
// kernel treats the exported values as authoritative, so on a high-core but
// low-memory runner the RAM bound (not the core count) wins.
const resolveAuthoritativeKnobs = (
    lane: RustKernelAcceptedSetupCommandLane,
): {
    readonly testThreads: ResolvedKnob;
    readonly trusteeProofBatchSize: ResolvedKnob;
    readonly trusteeProofLimbBatchSize: ResolvedKnob;
    readonly rayonThreadCount: ResolvedKnob;
} => {
    const automaticTestThreads = automaticTestThreadKnobForLane(
        lane,
        heavyAcceptedSetupTestThreadCount,
    );
    const coreDerivedTrusteeProverConcurrency = Math.max(
        1,
        Math.floor(os.cpus().length / 4),
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
    const automaticTrusteeProofBatchSize =
        automaticTrusteeProofBatchKnobForLane(lane, trusteeProofBatchSize);
    const memoryBoundedRayonThreadCount = Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                approximateGigabytesPerRayonThread,
        ),
    );
    const rayonThreadCount = Math.min(
        os.cpus().length,
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
        testThreads: automaticTestThreads,
        trusteeProofBatchSize: resolveKnob(
            Number.parseInt(automaticTrusteeProofBatchSize.value, 10),
            automaticTrusteeProofBatchSize.source,
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

const buildAuthoritativeCommand = (
    lane: RustKernelAcceptedSetupCommandLane,
): BuiltRustKernelAcceptedSetupCommand => {
    const knobs = resolveAuthoritativeKnobs(lane);
    console.log(
        `${laneNameForLane(lane)} lane: running with ${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB automatically budgeted per test).`,
    );
    console.log(
        `${laneNameForLane(lane)} lane: proving up to ${knobs.trusteeProofBatchSize.value} trustee evaluation-key ` +
            `proof(s) concurrently (${knobs.trusteeProofBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProver} GiB per prover).`,
    );
    console.log(
        `${laneNameForLane(lane)} lane: proving up to ${knobs.trusteeProofLimbBatchSize.value} RNS limb(s) per ` +
            `trustee evaluation-key prover (${knobs.trusteeProofLimbBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProofLimb} GiB per limb).`,
    );
    console.log(
        `${laneNameForLane(lane)} lane: bounding the rayon pool to ${knobs.rayonThreadCount.value} thread(s) ` +
            `(${knobs.rayonThreadCount.source}; automatic budget uses ` +
            `${approximateGigabytesPerRayonThread} GiB per rayon thread).`,
    );

    return {
        command: {
            args: cargoTestArgumentsForLane(lane, knobs.testThreads.value),
            command: 'cargo',
            description: commandDescriptionForLane(lane),
            env: {
                ...process.env,
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: knobs.rayonThreadCount.value,
                SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
                    knobs.trusteeProofBatchSize.value,
                SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
                    knobs.trusteeProofLimbBatchSize.value,
                ...(lane === 'final-package'
                    ? { SEALED_LATTICE_TRUSTEE_PROOF_VERIFY_PROGRESS: '1' }
                    : {}),
            },
            logFileSlug: logFileSlugForLane(lane),
        },
        progressLabel: progressLabelForLane(lane),
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
    console.log(
        `Rust accepted setup focused run: filter [${testFilter}], ` +
            `${heavyAcceptedSetupTestThreadCount} test thread(s) ` +
            `(${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB budgeted per test).`,
    );
    console.log(
        `Pinned target directory: ${acceptedSetupFocusedTargetDirectory}. ` +
            `Incremental compilation: on. Checkpoint resume: on.`,
    );

    return {
        command: {
            args: cargoTestArgumentsForFocusedFilter(
                testFilter,
                String(heavyAcceptedSetupTestThreadCount),
            ),
            command: 'cargo',
            description: `cargo test ${testFilter} (warm focused)`,
            env: {
                ...process.env,
                CARGO_TARGET_DIR: acceptedSetupFocusedTargetDirectory,
                // Force incremental compilation on (this mode's central per-edit
                // saving) rather than relying on the cargo default, which an
                // inherited environment or a cargo config could otherwise disable.
                CARGO_INCREMENTAL: '1',
                // Resume each proof family's corpus from on-disk checkpoints instead
                // of re-running the prover from a cold in-process fixture cache.
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            },
            logFileSlug: 'cargo-test-rust-accepted-setup-focused',
        },
        progressLabel: 'accepted-setup:focused',
        testThreadCount: heavyAcceptedSetupTestThreadCount,
    };
};

export const authoritativeCommandLanesForLane = (
    lane: RustKernelAcceptedSetupLane,
): readonly RustKernelAcceptedSetupCommandLane[] =>
    lane === 'all' ? ['fast', 'final-package'] : [lane];

const buildAuthoritativeCommands = (
    lane: RustKernelAcceptedSetupLane,
): readonly BuiltRustKernelAcceptedSetupCommand[] =>
    authoritativeCommandLanesForLane(lane).map((commandLane) =>
        buildAuthoritativeCommand(commandLane),
    );

const usage =
    'Usage: run-rust-kernel-accepted-setup-tests.ts [<test name, module name, or Rust file filter>]. ' +
    'Use one positional filter for a focused local run, or no filter for the full authoritative accepted-setup lane.';

export const parseRustKernelAcceptedSetupArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelAcceptedSetupArguments => {
    const positionalArguments: string[] = [];

    for (const argument of commandArguments) {
        if (argument === '--') {
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
        testFilters:
            normalizedFocusedFilter !== undefined
                ? [normalizedFocusedFilter]
                : testFiltersForLane('all'),
    };
};

export const runRustKernelAcceptedSetupTests = async (input: {
    readonly lane: RustKernelAcceptedSetupLane;
    readonly rawArguments?: readonly string[];
    readonly scriptName?: string;
}): Promise<void> => {
    const rawArguments = input.rawArguments ?? process.argv.slice(2);
    const parsedArguments = parseRustKernelAcceptedSetupArguments(rawArguments);

    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: parsedArguments.focused
            ? ['Rust accepted setup focused']
            : authoritativeCommandLanesForLane(input.lane).map((lane) =>
                  laneNameForLane(lane),
              ),
        scriptName: input.scriptName ?? scriptNameForLane(input.lane),
    });

    const builtCommands = parsedArguments.focused
        ? [buildFocusedCommand(parsedArguments.testFilters[0] ?? '')]
        : buildAuthoritativeCommands(input.lane);

    let exitCode: number | undefined;
    try {
        for (const builtCommand of builtCommands) {
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

            if (exitCode !== 0) {
                break;
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
    void runRustKernelAcceptedSetupTests({ lane: 'all' });
}
