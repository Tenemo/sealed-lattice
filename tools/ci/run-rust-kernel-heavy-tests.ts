import os from 'node:os';

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
// evaluation-key proof container package fixture. That fixture embeds every
// trustee's evaluation-key proof as hex, and each proof is several hundred
// megabytes of bytes (roughly twice that as hex), so a single clone is many
// gigabytes and the cargo default of one test thread per core holds enough
// concurrent clones to exhaust system memory and abort the process. Size the
// libtest thread pool from currently available memory with a conservative
// per-test budget, capped by core count, so the suite still runs as parallel as
// the machine can sustain without thrashing or aborting.
const approximateGigabytesPerHeavyTest = 20;
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

    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries([rustKernelHeavyTestCommand], {
            outputMode: 'inherit',
            runLog,
        });
        process.exitCode = exitCode;
    } finally {
        await runLog?.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
