import os from 'node:os';
import path from 'node:path';

import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// One runner for the heavy accepted-setup tests in two modes, selected by the
// `--iterate` flag. The flag is the mode switch, so the two configurations stay
// mutually exclusive and a half-and-half state (for example checkpoint resume in
// the gate's shared target) cannot be assembled:
//
//   default (no --iterate): authoritative CI-style runs. They build the selected
//     `heavy_accepted_setup` scope cleanly in the shared `target/`
//     (CARGO_INCREMENTAL=0), prove every proof family fresh (no checkpoint
//     resume), and size libtest/prover/rayon concurrency from available memory
//     so a constrained runner does not exhaust RAM. Test-name filters are
//     rejected here; the selected scope defines coverage.
//
//   --iterate [<filter>...]: the fast developer inner loop. It runs only the
//     filtered tests in a separate pinned `target/heavy-iteration/`
//     (CARGO_INCREMENTAL=1) so an edit recompiles incrementally (measured ~16s
//     versus ~44s for a full rebuild) without contending for the gate's build
//     lock, and resumes the on-disk proof checkpoints so each family's corpus
//     loads from `temp/test-checkpoints/` instead of being re-proved. That
//     trades the authoritative prove-fresh guarantee for speed, which is why it
//     is a separate, explicitly named mode rather than the default.

export const heavyAcceptedSetupTestPattern = 'heavy_accepted_setup';
export const heavyAcceptedSetupFinalPackageTestPattern =
    'heavy_accepted_setup_final_package';

const rustKernelHeavyScopeValues = ['all', 'checks', 'final-package'] as const;

export type RustKernelHeavyScope = (typeof rustKernelHeavyScopeValues)[number];
type RustKernelHeavyCommandScope = Exclude<RustKernelHeavyScope, 'all'>;

export type ParsedRustKernelHeavyArguments = {
    readonly iterate: boolean;
    readonly scope: RustKernelHeavyScope;
    readonly testFilters: readonly string[];
};

const isRustKernelHeavyScope = (scope: string): scope is RustKernelHeavyScope =>
    rustKernelHeavyScopeValues.some(
        (supportedScope) => supportedScope === scope,
    );

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
// Final-package tests inflate the full accepted-setup package and then run
// trustee evaluation-key proving with their own Rayon/prover concurrency. Letting
// libtest start multiple such tests multiplies the fixture working set and can
// overcommit even a 128 GiB workstation.
const finalPackageMaximumLibtestThreadCount = 1;
const finalPackageMaximumTrusteeProofBatchSize = 2;

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

export type ResolvedKnob = {
    readonly value: string;
    readonly source: string;
};

type BuiltRustKernelHeavyCommand = {
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

export const automaticTestThreadKnobForScope = (
    scope: RustKernelHeavyScope,
    memoryBoundedTestThreadCount: number,
): ResolvedKnob => {
    if (
        scope === 'final-package' &&
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

export const automaticTrusteeProofBatchKnobForScope = (
    scope: RustKernelHeavyScope,
    memoryBoundedTrusteeProofBatchSize: number,
): ResolvedKnob => {
    if (
        scope === 'final-package' &&
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

export const cargoTestArgumentsForScope = (
    scope: RustKernelHeavyScope,
    testThreadCount: string,
): readonly string[] => {
    const testFilter =
        scope === 'final-package'
            ? heavyAcceptedSetupFinalPackageTestPattern
            : heavyAcceptedSetupTestPattern;
    const skippedTests =
        scope === 'checks'
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

const testFiltersForScope = (scope: RustKernelHeavyScope): readonly string[] =>
    scope === 'final-package'
        ? [heavyAcceptedSetupFinalPackageTestPattern]
        : [heavyAcceptedSetupTestPattern];

const laneNameForScope = (scope: RustKernelHeavyScope): string => {
    if (scope === 'checks') {
        return 'Rust accepted setup checks';
    }
    if (scope === 'final-package') {
        return 'Rust accepted setup final package';
    }

    return 'Rust kernel heavy';
};

const scriptNameForScope = (scope: RustKernelHeavyScope): string => {
    if (scope === 'checks') {
        return 'test:rust:kernel:heavy:checks';
    }
    if (scope === 'final-package') {
        return 'test:rust:kernel:heavy:final-package';
    }

    return 'test:rust:kernel:heavy';
};

const progressLabelForScope = (scope: RustKernelHeavyScope): string => {
    if (scope === 'checks') {
        return 'heavy:checks';
    }
    if (scope === 'final-package') {
        return 'heavy:final-package';
    }

    return 'heavy';
};

const logFileSlugForScope = (scope: RustKernelHeavyScope): string => {
    if (scope === 'checks') {
        return 'cargo-test-heavy-accepted-setup-checks';
    }
    if (scope === 'final-package') {
        return 'cargo-test-heavy-accepted-setup-final-package';
    }

    return 'cargo-test-heavy-accepted-setup';
};

const commandDescriptionForScope = (scope: RustKernelHeavyScope): string => {
    if (scope === 'checks') {
        return 'cargo test heavy accepted setup checks';
    }
    if (scope === 'final-package') {
        return 'cargo test heavy accepted setup final package';
    }

    return 'cargo test heavy accepted setup tests';
};

// Resolve the authoritative-lane concurrency knobs only for authoritative runs,
// so an `--iterate` run neither validates nor depends on these overrides. The
// core-derived caps mirror the kernel's final-package proving concurrency; the
// kernel treats the exported values as authoritative, so on a high-core but
// low-memory runner the RAM bound (not the core count) wins.
const resolveAuthoritativeKnobs = (
    scope: RustKernelHeavyCommandScope,
): {
    readonly testThreads: ResolvedKnob;
    readonly trusteeProofBatchSize: ResolvedKnob;
    readonly trusteeProofLimbBatchSize: ResolvedKnob;
    readonly rayonThreadCount: ResolvedKnob;
} => {
    const automaticTestThreads = automaticTestThreadKnobForScope(
        scope,
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
        automaticTrusteeProofBatchKnobForScope(scope, trusteeProofBatchSize);
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
            Number.parseInt(automaticTestThreads.value, 10),
            automaticTestThreads.source,
            parsePositiveIntegerEnvironmentOverride(
                'SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT',
                process.env.SEALED_LATTICE_HEAVY_TEST_THREAD_COUNT,
            )?.toString(),
        ),
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
    scope: RustKernelHeavyCommandScope,
): BuiltRustKernelHeavyCommand => {
    const knobs = resolveAuthoritativeKnobs(scope);
    console.log(
        `${laneNameForScope(scope)} lane: running with ${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerHeavyTest} GiB automatically budgeted per test).`,
    );
    console.log(
        `${laneNameForScope(scope)} lane: proving up to ${knobs.trusteeProofBatchSize.value} trustee evaluation-key ` +
            `proof(s) concurrently (${knobs.trusteeProofBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProver} GiB per prover).`,
    );
    console.log(
        `${laneNameForScope(scope)} lane: proving up to ${knobs.trusteeProofLimbBatchSize.value} RNS limb(s) per ` +
            `trustee evaluation-key prover (${knobs.trusteeProofLimbBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProofLimb} GiB per limb).`,
    );
    console.log(
        `${laneNameForScope(scope)} lane: bounding the rayon pool to ${knobs.rayonThreadCount.value} thread(s) ` +
            `(${knobs.rayonThreadCount.source}; automatic budget uses ` +
            `${approximateGigabytesPerRayonThread} GiB per rayon thread).`,
    );

    return {
        command: {
            args: cargoTestArgumentsForScope(scope, knobs.testThreads.value),
            command: 'cargo',
            description: commandDescriptionForScope(scope),
            env: {
                ...process.env,
                CARGO_INCREMENTAL: '0',
                RAYON_NUM_THREADS: knobs.rayonThreadCount.value,
                SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
                    knobs.trusteeProofBatchSize.value,
                SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
                    knobs.trusteeProofLimbBatchSize.value,
            },
            logFileSlug: logFileSlugForScope(scope),
        },
        progressLabel: progressLabelForScope(scope),
        testThreadCount: Number.parseInt(knobs.testThreads.value, 10),
    };
};

const buildIterationCommand = (
    testFilters: readonly string[],
): BuiltRustKernelHeavyCommand => {
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
        command: {
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
        },
        progressLabel: 'heavy:iterate',
        testThreadCount: heavyAcceptedSetupTestThreadCount,
    };
};

export const authoritativeCommandScopesForScope = (
    scope: RustKernelHeavyScope,
): readonly RustKernelHeavyCommandScope[] =>
    scope === 'all' ? ['checks', 'final-package'] : [scope];

const buildAuthoritativeCommands = (
    scope: RustKernelHeavyScope,
): readonly BuiltRustKernelHeavyCommand[] =>
    authoritativeCommandScopesForScope(scope).map((commandScope) =>
        buildAuthoritativeCommand(commandScope),
    );

const usage =
    'Usage: run-rust-kernel-heavy-tests.ts [--scope all|checks|final-package] [--iterate [<test name filter>...]]. ' +
    'Test-name filters require --iterate; authoritative runs use the selected scope.';

export const parseRustKernelHeavyArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelHeavyArguments => {
    let iterate = false;
    let scope: RustKernelHeavyScope = 'all';
    let scopeWasSet = false;
    const positionalArguments: string[] = [];

    for (let index = 0; index < commandArguments.length; index += 1) {
        const argument = commandArguments[index];
        if (argument === undefined) {
            continue;
        }

        if (argument === '--iterate') {
            iterate = true;
            continue;
        }
        if (argument === '--scope') {
            const scopeValue = commandArguments[index + 1];
            if (
                scopeValue === undefined ||
                !isRustKernelHeavyScope(scopeValue)
            ) {
                throw new Error(usage);
            }
            scope = scopeValue;
            scopeWasSet = true;
            index += 1;
            continue;
        }
        if (argument.startsWith('--scope=')) {
            const scopeValue = argument.slice('--scope='.length);
            if (!isRustKernelHeavyScope(scopeValue)) {
                throw new Error(usage);
            }
            scope = scopeValue;
            scopeWasSet = true;
            continue;
        }
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument: ${argument}. ${usage}`);
        }

        positionalArguments.push(argument);
    }

    if (!iterate && positionalArguments.length > 0) {
        throw new Error(usage);
    }
    if (iterate && scopeWasSet) {
        throw new Error(
            'Use explicit test-name filters with --iterate; --scope is for authoritative runs.',
        );
    }

    return {
        iterate,
        scope,
        testFilters:
            positionalArguments.length > 0
                ? positionalArguments
                : testFiltersForScope(scope),
    };
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const parsedArguments = parseRustKernelHeavyArguments(rawArguments);

    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: parsedArguments.iterate
            ? ['Rust kernel heavy iteration']
            : authoritativeCommandScopesForScope(parsedArguments.scope).map(
                  (scope) => laneNameForScope(scope),
              ),
        scriptName: parsedArguments.iterate
            ? 'test:rust:kernel:heavy:iterate'
            : scriptNameForScope(parsedArguments.scope),
    });

    const builtCommands = parsedArguments.iterate
        ? [buildIterationCommand(parsedArguments.testFilters)]
        : buildAuthoritativeCommands(parsedArguments.scope);

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
    void main();
}
