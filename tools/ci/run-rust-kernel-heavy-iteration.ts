import { spawnSync } from 'node:child_process';
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

// Fast inner-loop runner for the heavy accepted-setup tests. It exists so a
// developer iterating on one or a few of these tests does not pay the two taxes
// that make the default `cargo test` cycle slow:
//
//   1. A throwaway `--target-dir` forces a full optimized rebuild of the whole
//      dependency graph every run. This runner pins one persistent target
//      directory so only the edited crate recompiles after the first build, and
//      it keeps that directory separate from `target/` so it never contends with
//      a concurrently running gate for the cargo build lock.
//   2. A fresh process re-runs the prover for the entire proof corpus because
//      the in-process `OnceLock` fixture cache starts cold. This runner enables
//      the deterministic on-disk proof checkpoints so each family's corpus loads
//      from `temp/test-checkpoints/` instead of being re-proved, and it runs the
//      selected tests in a single cargo invocation so they share one warm corpus.
//
// When `sccache` is installed it is wired in as the compiler cache so even the
// first build in the pinned directory reuses dependency compilations shared with
// every other target directory on the machine.

const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';

// The pinned iteration target directory. It lives under `target/` (already
// ignored by git) but is distinct from the default `target/` the gate uses, so
// iterating here never blocks, and is never blocked by, a running gate.
const heavyIterationTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'heavy-iteration',
);

// Each mutating heavy accepted-setup test holds a clone of the evaluation-key
// proof container package fixture while it runs. Size the libtest thread pool
// from currently available memory with a conservative per-test budget, capped by
// core count, so a full-filter run stays as parallel as the machine can sustain
// without thrashing or aborting. A single-test filter simply runs one thread.
// This is lower than the gate runner's budget because the package-hash rebinder
// no longer clones the whole package; tune it down further once a warm run has
// confirmed the measured per-test peak.
const approximateGigabytesPerHeavyTest = 12;
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

const sccacheIsAvailable = (): boolean => {
    try {
        const probe = spawnSync('sccache', ['--version'], {
            shell: true,
            stdio: 'ignore',
        });

        return probe.status === 0;
    } catch {
        return false;
    }
};

const parseTestFilters = (commandArguments: readonly string[]): string[] => {
    const filters = commandArguments.filter(
        (argument) => !argument.startsWith('-'),
    );

    return filters.length > 0 ? filters : [heavyAcceptedSetupTestPattern];
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    const testFilters = parseTestFilters(commandArguments);
    const useSccache = sccacheIsAvailable();

    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: ['Rust kernel heavy iteration'],
              scriptName: 'test:rust:kernel:heavy:iterate',
          });

    const cargoCommand: CommandInvocation = {
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
            // sccache cannot cache incremental artifacts, and the pinned target
            // directory makes incremental rebuilds redundant with the cache, so
            // disabling it keeps the compiler-cache path clean.
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: heavyIterationTargetDirectory,
            // Resume each proof family's corpus from on-disk checkpoints instead
            // of re-running the prover from a cold in-process fixture cache.
            SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            ...(useSccache ? { RUSTC_WRAPPER: 'sccache' } : {}),
        },
        logFileSlug: 'cargo-test-heavy-accepted-setup-iteration',
    };

    console.log(
        `Rust kernel heavy iteration: filters [${testFilters.join(', ')}], ` +
            `${heavyAcceptedSetupTestThreadCount} test thread(s) ` +
            `(${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB budgeted per test).`,
    );
    console.log(
        `Pinned target directory: ${heavyIterationTargetDirectory}. ` +
            `Checkpoint resume: on. Compiler cache: ${
                useSccache ? 'sccache' : 'off (sccache not found)'
            }.`,
    );

    const progressReporter = createHeavyTestProgressReporter({
        label: 'heavy:iterate',
        threadCount: heavyAcceptedSetupTestThreadCount,
    });

    let exitCode: number | undefined;
    try {
        exitCode = await runCommandsInSeries([cargoCommand], {
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
