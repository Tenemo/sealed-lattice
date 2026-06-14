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

// Each mutating heavy accepted-setup test holds a multi-gigabyte clone of the
// first-profile evaluation-key proof container package fixture while it runs, so
// the cargo default of one test thread per core would hold enough concurrent
// clones to exhaust system memory and abort the process. Size the libtest thread
// pool from a fixed fraction of TOTAL system memory, capped by core count, with
// a per-test budget set above the measured ~12.7 GiB peak. Total memory is used
// rather than os.freemem() because on Windows the latter reports only
// immediately-free physical memory (excluding reclaimable cache) and swings with
// unrelated activity, which previously collapsed the pool to far fewer threads
// than the machine could sustain. The headroom fraction leaves room for the OS
// and light concurrent work; a heavy concurrent run (for example a second
// clone's heavy lane) should be sequenced separately, and the launch banner
// warns when currently-available memory is below the projected peak.
const approximateGigabytesPerHeavyTest = 14;
const heavyTestMemoryHeadroomFraction = 0.6;
const gigabyte = 1024 ** 3;
const totalGigabytes = os.totalmem() / gigabyte;
const availableGigabytes = os.freemem() / gigabyte;
const memoryBoundedHeavyTestThreadCount = Math.max(
    1,
    Math.floor(
        (totalGigabytes * heavyTestMemoryHeadroomFraction) /
            approximateGigabytesPerHeavyTest,
    ),
);
const heavyAcceptedSetupTestThreadCount = Math.min(
    os.cpus().length,
    memoryBoundedHeavyTestThreadCount,
);
const projectedPeakGigabytes =
    heavyAcceptedSetupTestThreadCount * approximateGigabytesPerHeavyTest;

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
            `(sized from ${totalGigabytes.toFixed(1)} GiB total RAM at ` +
            `${approximateGigabytesPerHeavyTest} GiB/test, ~${projectedPeakGigabytes} GiB projected peak).`,
    );
    if (availableGigabytes < projectedPeakGigabytes) {
        console.warn(
            `  Warning: only ${availableGigabytes.toFixed(1)} GiB is currently available, ` +
                `below the ~${projectedPeakGigabytes} GiB projected peak. Close other ` +
                `memory-heavy work (such as a second clone's heavy run) to avoid swapping.`,
        );
    }

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
