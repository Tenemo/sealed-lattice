import os from 'node:os';
import path from 'node:path';

import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// One runner for the heavy accepted-setup tests in two modes, selected by the
// `--iterate` flag. The flag is the ONLY mode switch, so the two configurations
// stay mutually exclusive and a half-and-half state (for example checkpoint
// resume in the gate's shared target) cannot be assembled:
//
//   default (no flag): the authoritative full lane CI runs. It builds the whole
//     `heavy_accepted_setup` suite cleanly in the shared `target/`
//     (CARGO_INCREMENTAL=0), proves every proof family fresh (no checkpoint
//     resume), and sizes libtest/prover/rayon concurrency from available memory
//     so a constrained runner does not exhaust RAM. It rejects test-name
//     filters: the authoritative run always covers the whole suite.
//
//   --iterate [<filter>...]: the fast developer inner loop. It runs only the
//     filtered tests in a separate pinned `target/heavy-iteration/`
//     (CARGO_INCREMENTAL=1) so an edit recompiles incrementally (measured ~16s
//     versus ~44s for a full rebuild) without contending for the gate's build
//     lock, and resumes the on-disk proof checkpoints so each family's corpus
//     loads from `temp/test-checkpoints/` instead of being re-proved. That
//     trades the authoritative prove-fresh guarantee for speed, which is why it
//     is a separate, explicitly named mode rather than the default.

const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';

// Shared libtest-thread budget. The heavy lane uses compact transported
// proof/key material, but full-profile package construction and verification
// still have a transient working set large enough that libtest concurrency must
// be memory-bound: a single package-inflating test was measured near 57 GiB
// resident, most of it the shared fixture that concurrent tests reuse rather
// than a per-test cost multiplied by the thread count. Size the thread pool from
// currently available memory, capped by core count, so a constrained runner
// stays serial while a workstation runs several tests; a single-test `--iterate`
// filter simply runs one thread.
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

// Authoritative-mode per-prover RAM budgets. Each trustee evaluation-key prover,
// the rayon par_iter phases (public-key share succinct proofs, relinearization
// and Galois records, same-secret anchors), and the per-prover RNS-limb proving
// all draw large working sets, so each concurrency knob is sized from available
// memory below.
const approximateGigabytesPerTrusteeProver = 10;
const approximateGigabytesPerRayonThread = 2;
const approximateGigabytesPerTrusteeProofLimb = 5;

// The pinned `--iterate` target directory. It lives under `target/` (already
// git-ignored) but is distinct from the default `target/` the gate uses, so
// iterating never blocks, and is never blocked by, a running gate.
const heavyIterationTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'heavy-iteration',
);

const parsePositiveIntegerEnvironmentOverride = (
    variableName: string,
    variableValue: string | undefined,
): number | undefined => {
    if (variableValue === undefined) {
        return undefined;
    }
    if (!/^[1-9]\d*$/.test(variableValue)) {
        throw new Error(`${variableName} must be a positive integer.`);
    }
    const parsedValue = Number.parseInt(variableValue, 10);
    if (!Number.isSafeInteger(parsedValue)) {
        throw new Error(`${variableName} must fit a safe integer.`);
    }
    return parsedValue;
};

type ResolvedKnob = {
    readonly value: string;
    readonly source: 'memory-bounded' | 'environment override';
};

const resolveKnob = (
    memoryBoundedValue: number,
    override: string | undefined,
): ResolvedKnob =>
    override === undefined
        ? { value: String(memoryBoundedValue), source: 'memory-bounded' }
        : { value: override, source: 'environment override' };

// Resolve the authoritative-lane concurrency knobs only when the full lane runs,
// so an `--iterate` run neither validates nor depends on these overrides. The
// core-derived caps mirror the kernel's terminal proving concurrency; the kernel
// treats the exported values as authoritative, so on a high-core but low-memory
// runner the RAM bound (not the core count) wins.
const resolveAuthoritativeKnobs = (): {
    readonly testThreads: ResolvedKnob;
    readonly trusteeProofBatchSize: ResolvedKnob;
    readonly trusteeProofLimbBatchSize: ResolvedKnob;
    readonly rayonThreadCount: ResolvedKnob;
} => {
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
        testThreads: resolveKnob(
            heavyAcceptedSetupTestThreadCount,
            parsePositiveIntegerEnvironmentOverride(
                'SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT',
                process.env.SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT,
            )?.toString(),
        ),
        trusteeProofBatchSize: resolveKnob(
            trusteeProofBatchSize,
            process.env.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE,
        ),
        trusteeProofLimbBatchSize: resolveKnob(
            trusteeProofLimbBatchSize,
            process.env.SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE,
        ),
        rayonThreadCount: resolveKnob(
            rayonThreadCount,
            process.env.RAYON_NUM_THREADS,
        ),
    };
};

const buildAuthoritativeCommand = (): CommandInvocation => {
    const knobs = resolveAuthoritativeKnobs();
    console.log(
        `Rust kernel heavy lane: running with ${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB automatically budgeted per test).`,
    );
    console.log(
        `Rust kernel heavy lane: proving up to ${knobs.trusteeProofBatchSize.value} trustee evaluation-key ` +
            `proof(s) concurrently (${knobs.trusteeProofBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProver} GiB per prover).`,
    );
    console.log(
        `Rust kernel heavy lane: proving up to ${knobs.trusteeProofLimbBatchSize.value} RNS limb(s) per ` +
            `trustee evaluation-key prover (${knobs.trusteeProofLimbBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProofLimb} GiB per limb).`,
    );
    console.log(
        `Rust kernel heavy lane: bounding the rayon pool to ${knobs.rayonThreadCount.value} thread(s) ` +
            `(${knobs.rayonThreadCount.source}; automatic budget uses ` +
            `${approximateGigabytesPerRayonThread} GiB per rayon thread).`,
    );

    return {
        args: [
            'test',
            '-p',
            'sealed-lattice-kernel',
            heavyAcceptedSetupTestPattern,
            '--',
            '--ignored',
            '--nocapture',
            '--test-threads',
            knobs.testThreads.value,
        ],
        command: 'cargo',
        description: 'cargo test heavy accepted setup tests',
        env: {
            ...process.env,
            CARGO_INCREMENTAL: '0',
            RAYON_NUM_THREADS: knobs.rayonThreadCount.value,
            SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
                knobs.trusteeProofBatchSize.value,
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
                knobs.trusteeProofLimbBatchSize.value,
        },
        logFileSlug: 'cargo-test-heavy-accepted-setup',
    };
};

const buildIterationCommand = (
    testFilters: readonly string[],
): CommandInvocation => {
    console.log(
        `Rust kernel heavy iteration: filters [${testFilters.join(', ')}], ` +
            `${heavyAcceptedSetupTestThreadCount} test thread(s) ` +
            `(${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB budgeted per test).`,
    );
    console.log(
        `Pinned target directory: ${heavyIterationTargetDirectory}. ` +
            `Incremental compilation: on. Checkpoint resume: on.`,
    );

    return {
        args: [
            'test',
            '-p',
            'sealed-lattice-kernel',
            ...testFilters,
            '--',
            '--ignored',
            '--show-output',
            '--test-threads',
            String(heavyAcceptedSetupTestThreadCount),
        ],
        command: 'cargo',
        description: `cargo test ${testFilters.join(' ')} (warm iteration)`,
        env: {
            ...process.env,
            CARGO_TARGET_DIR: heavyIterationTargetDirectory,
            // Force incremental compilation on (this mode's central per-edit
            // saving) rather than relying on the cargo default, which an
            // inherited environment or a cargo config could otherwise disable.
            CARGO_INCREMENTAL: '1',
            // Resume each proof family's corpus from on-disk checkpoints instead
            // of re-running the prover from a cold in-process fixture cache.
            SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
        },
        logFileSlug: 'cargo-test-heavy-accepted-setup-iteration',
    };
};

const usage =
    'Usage: run-rust-kernel-heavy-tests.ts [--iterate [<test name filter>...]] [--no-run-log]. ' +
    'Test-name filters require --iterate; the full heavy lane always runs the whole suite.';

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const argumentsWithoutRunLog = removeRunLogArguments(rawArguments);
    const iterate = argumentsWithoutRunLog.includes('--iterate');
    const positionalArguments = argumentsWithoutRunLog.filter(
        (argument) => argument !== '--iterate',
    );
    const unknownFlags = positionalArguments.filter((argument) =>
        argument.startsWith('-'),
    );
    if (unknownFlags.length > 0) {
        throw new Error(
            `Unknown argument(s): ${unknownFlags.join(', ')}. ${usage}`,
        );
    }
    if (!iterate && positionalArguments.length > 0) {
        throw new Error(usage);
    }
    const testFilters =
        positionalArguments.length > 0
            ? positionalArguments
            : [heavyAcceptedSetupTestPattern];

    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: [
                  iterate ? 'Rust kernel heavy iteration' : 'Rust kernel heavy',
              ],
              scriptName: iterate
                  ? 'test:rust:kernel:heavy:iterate'
                  : 'test:rust:kernel:heavy',
          });

    const cargoCommand = iterate
        ? buildIterationCommand(testFilters)
        : buildAuthoritativeCommand();

    const progressReporter = createHeavyTestProgressReporter({
        label: iterate ? 'heavy:iterate' : 'heavy',
        threadCount: heavyAcceptedSetupTestThreadCount,
    });

    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries([cargoCommand], {
            observer: progressReporter.observer,
            outputMode: 'inherit',
            runLog,
            terminalOutputFilter: progressReporter.terminalOutputFilter,
        });
        process.exitCode = exitCode;
    } finally {
        progressReporter.stop();
        await runLog?.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
