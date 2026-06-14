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
