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

// Each mutating heavy accepted-setup test clones the full first-profile
// evaluation-key proof container package fixture, which embeds every trustee's
// evaluation-key proof as inline hex, so a clone is several gigabytes resident.
// The cargo default of one thread per core would hold enough concurrent clones
// to exhaust system memory and abort the process. Size the libtest pool from
// currently free memory with a per-test budget, capped by core count. The budget
// is set from the worst case rather than the steady-state average: a single
// package-inflating test (the extra/duplicate refusals, which add proofs to
// their clone) was measured at roughly 57 GiB resident, most of it the shared
// fixture that concurrent tests reuse, so the bound must keep that worst case
// plus a few normal clones (about seven gigabytes marginal each) inside free
// memory. At this budget a typical 88 GiB-free machine runs four threads, up
// from three; pushing higher needs an empirical peak measurement, and the real
// lever for using all cores is moving the container off inline hex onto the
// transported-material representation, which would shrink the per-clone cost.
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

// Each trustee evaluation-key prover holds a several-gigabyte working set while
// the first-profile package fixture is assembled, so the number of provers
// running at once must also fit available memory. The kernel proves the trustees
// in batches; size that batch from free memory the same way as the libtest
// thread pool, capped so a workstation keeps proving three trustees at a time
// while a 16 GiB CI runner proves one and the build is no longer killed
// mid-proving. The kernel reads this through SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE.
const approximateGigabytesPerTrusteeProver = 8;
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

const rustKernelHeavyTestCommand: CommandInvocation = {
    args: [
        'test',
        '-p',
        'sealed-lattice-kernel',
        heavyAcceptedSetupTestPattern,
        '--',
        '--ignored',
        '--show-output',
        '--test-threads',
        String(heavyAcceptedSetupTestThreadCount),
    ],
    command: 'cargo',
    description: 'cargo test heavy accepted setup tests',
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        RAYON_NUM_THREADS:
            process.env.RAYON_NUM_THREADS ?? String(rayonThreadCount),
        SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
            process.env.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE ??
            String(trusteeProofBatchSize),
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
        `Rust kernel heavy lane: running with ${heavyAcceptedSetupTestThreadCount} test thread(s) ` +
            `(memory-bounded; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB budgeted per test).`,
    );
    console.log(
        `Rust kernel heavy lane: proving up to ${trusteeProofBatchSize} trustee evaluation-key ` +
            `proof(s) concurrently (memory-bounded; ${approximateGigabytesPerTrusteeProver} GiB ` +
            `budgeted per prover).`,
    );
    console.log(
        `Rust kernel heavy lane: bounding the rayon pool to ${rayonThreadCount} thread(s) ` +
            `(memory-bounded; ${approximateGigabytesPerRayonThread} GiB budgeted per rayon thread).`,
    );

    const progressReporter = createHeavyTestProgressReporter({
        label: 'heavy',
        threadCount: heavyAcceptedSetupTestThreadCount,
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
