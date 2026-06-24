import os from 'node:os';

import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
} from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';

// The heavy accepted-setup lane uses compact transported proof/key material, but
// full-profile package construction and verification still have a large enough
// transient working set that libtest concurrency must be memory-bound. A
// free-runner-knob local simulation on 2026-06-21 completed the full lane with
// one libtest thread, one trustee prover, two RNS limbs per trustee prover, and
// a four-thread rayon pool at 9.97 GiB peak process-tree RSS. Keep the automatic
// per-test budget conservative so the free runner stays serial while larger
// workstations can still run multiple independent heavy tests.
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

// Each trustee evaluation-key prover now regenerates limb commitments in
// bounded chunks instead of retaining the whole phase-one commitment set. The
// remaining prover working set is still large enough that concurrent trustees
// must be sized from memory. Keep this budget conservative: a free CI runner
// should prove one trustee at a time, while a workstation can run several.
const approximateGigabytesPerTrusteeProver = 10;
// Match the kernel's core-derived terminal concurrency (a quarter of the cores;
// each prover saturates a few cores through the shared work pool) so a
// workstation proves as many trustees at once as it has memory for, while a
// memory-constrained runner is bounded by the per-prover RAM budget instead. The
// kernel treats this exported value as authoritative for terminal proving, so on
// a high-core but low-memory runner the RAM bound (not the core count) wins.
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

// The setup build also runs several rayon par_iter phases that the trustee proof
// batch does not bound: the public-key share succinct proofs prove every trustee
// at once, the relinearization/Galois records, same-secret anchors, and each
// prover's internal parallelism all draw from the global rayon pool. That pool
// defaults to the reported core count, so a runner that reports more cores than
// its memory supports (a containerized CI host) over-parallelizes those phases
// and exhausts memory regardless of the trustee batch. Bound the pool from
// available RAM the same way: a workstation still uses every core, while a
// memory-constrained host caps concurrency to what fits. The kernel inherits this
// through RAYON_NUM_THREADS.
const approximateGigabytesPerRayonThread = 2;
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

// Inside one trustee prover, the Rust kernel proves only this many RNS limbs at
// once after all witness roots are transcript-bound. After the limb witness
// builder stopped materializing the full residue/error-square witness copy, the
// measured full-ring limb peak is about 4.5 GiB, so a free 14.4 GiB runner can
// prove two limbs at a time with headroom while still keeping one trustee prover
// active at a time.
const approximateGigabytesPerTrusteeProofLimb = 5;
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

const heavyAcceptedSetupTestThreadCountOverride =
    parsePositiveIntegerEnvironmentOverride(
        'SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT',
        process.env.SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT,
    );
const effectiveHeavyAcceptedSetupTestThreadCount =
    heavyAcceptedSetupTestThreadCountOverride ??
    heavyAcceptedSetupTestThreadCount;
const heavyAcceptedSetupTestThreadCountSource =
    heavyAcceptedSetupTestThreadCountOverride === undefined
        ? 'memory-bounded'
        : 'environment override';

const rayonThreadCountOverride = process.env.RAYON_NUM_THREADS;
const effectiveRayonThreadCount =
    rayonThreadCountOverride ?? String(rayonThreadCount);
const rayonThreadCountSource =
    rayonThreadCountOverride === undefined
        ? 'memory-bounded'
        : 'environment override';

const trusteeProofBatchSizeOverride =
    process.env.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE;
const effectiveTrusteeProofBatchSize =
    trusteeProofBatchSizeOverride ?? String(trusteeProofBatchSize);
const trusteeProofBatchSizeSource =
    trusteeProofBatchSizeOverride === undefined
        ? 'memory-bounded'
        : 'environment override';

const trusteeProofLimbBatchSizeOverride =
    process.env.SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE;
const effectiveTrusteeProofLimbBatchSize =
    trusteeProofLimbBatchSizeOverride ?? String(trusteeProofLimbBatchSize);
const trusteeProofLimbBatchSizeSource =
    trusteeProofLimbBatchSizeOverride === undefined
        ? 'memory-bounded'
        : 'environment override';

const rustKernelHeavyTestCommand: CommandInvocation = {
    args: [
        'test',
        '-p',
        'sealed-lattice-kernel',
        heavyAcceptedSetupTestPattern,
        '--',
        '--ignored',
        '--nocapture',
        '--test-threads',
        String(effectiveHeavyAcceptedSetupTestThreadCount),
    ],
    command: 'cargo',
    description: 'cargo test heavy accepted setup tests',
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        RAYON_NUM_THREADS: effectiveRayonThreadCount,
        SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE: effectiveTrusteeProofBatchSize,
        SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
            effectiveTrusteeProofLimbBatchSize,
    },
    logFileSlug: 'cargo-test-heavy-accepted-setup',
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    if (commandArguments.length > 0) {
        throw new Error(
            'Usage: run-rust-kernel-heavy-tests.ts [--no-run-log].',
        );
    }
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: ['Rust kernel heavy'],
              scriptName: 'test:rust:kernel:heavy',
          });

    console.log(
        `Rust kernel heavy lane: running with ${effectiveHeavyAcceptedSetupTestThreadCount} test thread(s) ` +
            `(${heavyAcceptedSetupTestThreadCountSource}; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB automatically budgeted per test).`,
    );
    console.log(
        `Rust kernel heavy lane: proving up to ${effectiveTrusteeProofBatchSize} trustee evaluation-key ` +
            `proof(s) concurrently (${trusteeProofBatchSizeSource}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProver} GiB per prover).`,
    );
    console.log(
        `Rust kernel heavy lane: proving up to ${effectiveTrusteeProofLimbBatchSize} RNS limb(s) per ` +
            `trustee evaluation-key prover (${trusteeProofLimbBatchSizeSource}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProofLimb} GiB per limb).`,
    );
    console.log(
        `Rust kernel heavy lane: bounding the rayon pool to ${effectiveRayonThreadCount} thread(s) ` +
            `(${rayonThreadCountSource}; automatic budget uses ` +
            `${approximateGigabytesPerRayonThread} GiB per rayon thread).`,
    );

    const progressReporter = createHeavyTestProgressReporter({
        label: 'heavy',
        threadCount: effectiveHeavyAcceptedSetupTestThreadCount,
    });

    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries([rustKernelHeavyTestCommand], {
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
