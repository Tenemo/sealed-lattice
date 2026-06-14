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
//      dependency graph every run (~44s here). This runner pins one persistent
//      target directory, kept separate from `target/` so it never contends with
//      a concurrently running gate for the cargo build lock. The first build is
//      full; after that, re-running an unchanged test recompiles nothing, and an
//      edit recompiles incrementally (measured ~16s versus ~44s for a full
//      rebuild). Incremental compilation is deliberately left enabled: it is the
//      single biggest per-edit saving, and a compiler cache such as sccache does
//      not help here because the dominant cost is the one large kernel crate,
//      which an edit always invalidates and which does not cache across target
//      directories anyway.
//   2. A fresh process re-runs the prover for the entire proof corpus because
//      the in-process `OnceLock` fixture cache starts cold. This runner enables
//      the deterministic on-disk proof checkpoints so each family's corpus loads
//      from `temp/test-checkpoints/` instead of being re-proved, and it runs the
//      selected tests in a single cargo invocation so they share one warm corpus.
//      This only helps generation-bound tests (the trustee family); the heavy
//      tests are otherwise dominated by proof verification, which nothing here
//      changes.

const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';

// The pinned iteration target directory. It lives under `target/` (already
// ignored by git) but is distinct from the default `target/` the gate uses, so
// iterating here never blocks, and is never blocked by, a running gate.
const heavyIterationTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'heavy-iteration',
);

// Each mutating heavy accepted-setup test clones the full evaluation-key proof
// container package fixture while it runs. That container embeds the proof and
// key-switch material as inline hex, so a clone is several gigabytes resident,
// and the package-inflating tests (extra/duplicate refusals) peak highest: a
// single such test was measured at roughly 57 GiB resident, most of it the shared
// fixture that concurrent tests reuse rather than a per-test cost multiplied by
// the thread count. Size the libtest thread pool from currently available memory
// with the same per-test budget as the gate runner, capped by core count, so a
// multi-test filter keeps that worst case plus a few normal clones inside memory.
// A single-test filter simply runs one thread. Raising parallelism safely needs
// the container moved off inline hex onto the transported-material representation.
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
            CARGO_TARGET_DIR: heavyIterationTargetDirectory,
            // Force incremental compilation on (this runner's central per-edit
            // saving) rather than relying on the cargo default, which an inherited
            // environment or a cargo config could otherwise have disabled. This is
            // what the "Incremental compilation: on" log line below promises.
            CARGO_INCREMENTAL: '1',
            // Resume each proof family's corpus from on-disk checkpoints instead
            // of re-running the prover from a cold in-process fixture cache.
            SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
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
            `Incremental compilation: on. Checkpoint resume: on.`,
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
