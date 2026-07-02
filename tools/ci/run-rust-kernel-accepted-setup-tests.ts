import fs, { type Dirent } from 'node:fs';
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
// Lanes are selected by the package-script entrypoint; the main accepted-setup
// entrypoint also accepts a single positional test or file-stem filter for a
// focused local run. The default mode is accelerated local execution. GitHub CI
// passes `--ci` to request the conservative prove-fresh lane:
//
//   default (no positional filter): accelerated local runs. They build the
//     selected `heavy_accepted_setup` lane in a pinned warm target directory
//     (`target/accepted-setup-accelerated/`), keep incremental compilation on,
//     resume deterministic proof checkpoints from `temp/test-checkpoints/`, and
//     size libtest/prover/Rayon concurrency from available memory. Run logs stay
//     under `logs/`; proof checkpoints stay under `temp/test-checkpoints/`.
//
//   --ci: authoritative CI-style runs. They build the selected
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
export type RustKernelAcceptedSetupRunMode = 'accelerated' | 'ci';

export type ParsedRustKernelAcceptedSetupArguments = {
    readonly focused: boolean;
    readonly lane: RustKernelAcceptedSetupLane;
    readonly mode: RustKernelAcceptedSetupRunMode;
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
const approximateGigabytesPerFinalPackageTest = 57;
const heavyTestMemoryBudgetFraction = 0.7;
const gigabyte = 1024 ** 3;
const availableGigabytes = os.freemem() / gigabyte;
const logicalProcessorCount = os.cpus().length;

const approximateGigabytesPerTestForLane = (
    lane: RustKernelAcceptedSetupCommandLane,
    mode: RustKernelAcceptedSetupRunMode,
    warmFinalPackageCheckpointStore: boolean,
): number => {
    if (
        lane === 'final-package' &&
        mode === 'accelerated' &&
        !warmFinalPackageCheckpointStore
    ) {
        return approximateGigabytesPerFinalPackageTest;
    }

    return approximateGigabytesPerHeavyTest;
};

const memoryBoundedTestThreadCount = (
    lane: RustKernelAcceptedSetupCommandLane,
    mode: RustKernelAcceptedSetupRunMode,
    warmFinalPackageCheckpointStore: boolean,
): number =>
    Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                approximateGigabytesPerTestForLane(
                    lane,
                    mode,
                    warmFinalPackageCheckpointStore,
                ),
        ),
    );

const automaticTestThreadCountForLane = (
    lane: RustKernelAcceptedSetupCommandLane,
    mode: RustKernelAcceptedSetupRunMode,
    warmFinalPackageCheckpointStore: boolean,
): number =>
    Math.min(
        logicalProcessorCount,
        memoryBoundedTestThreadCount(
            lane,
            mode,
            warmFinalPackageCheckpointStore,
        ),
    );

// CI final-package tests inflate the full accepted-setup package and then run
// trustee evaluation-key proving with their own Rayon/prover concurrency. Letting
// libtest start multiple cold prove-fresh tests multiplies the fixture working
// set, so CI keeps the lane serial. Accelerated local runs can loosen libtest
// concurrency once the checkpoint store is warm because the expensive prover
// corpus is loaded instead of regenerated.
const finalPackageMaximumLibtestThreadCount = 1;
const finalPackageMaximumTrusteeProofBatchSize = 1;
const acceleratedFinalPackageMaximumTrusteeProofBatchSize = 3;

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
const acceptedSetupAcceleratedTargetDirectory = path.resolve(
    process.cwd(),
    'target',
    'accepted-setup-accelerated',
);
const acceptedSetupCheckpointRootDirectory = path.resolve(
    process.cwd(),
    'temp',
    'test-checkpoints',
);
const acceptedSetupCheckpointDirectory = path.join(
    acceptedSetupCheckpointRootDirectory,
    'accepted-setup-final-package-material-store',
);
const acceptedSetupFinalPackageCompletionManifestPath = path.join(
    acceptedSetupCheckpointDirectory,
    'accelerated-final-package-completion.json',
);

const checkpointProofFamilyDirectories = [
    'same-secret-anchor-proof-material',
    'public-key-share-proof-material',
    'trustee-evaluation-key-anchor-proof-material',
] as const;

const checkpointFamilyProofMaterialCount = (
    familyDirectory: string,
): number => {
    const directory = path.join(
        acceptedSetupCheckpointDirectory,
        familyDirectory,
    );
    try {
        return fs
            .readdirSync(directory, { withFileTypes: true })
            .filter((entry) => entry.isFile() && entry.name.endsWith('.bin'))
            .length;
    } catch {
        return 0;
    }
};

const checkpointFamilyProofMaterialCounts = (): ReadonlyMap<string, number> =>
    new Map(
        checkpointProofFamilyDirectories.map((familyDirectory) => [
            familyDirectory,
            checkpointFamilyProofMaterialCount(familyDirectory),
        ]),
    );

const checkpointFamilyProofMaterialCountSummary = (
    counts: ReadonlyMap<string, number>,
): string =>
    checkpointProofFamilyDirectories
        .map(
            (familyDirectory) =>
                `${familyDirectory}: ${counts.get(familyDirectory) ?? 0}`,
        )
        .join(', ');

const newestModificationTimeMillisecondsUnder = (
    directoryPath: string,
): number => {
    let newestModificationTimeMilliseconds = 0;

    const visit = (currentDirectoryPath: string): void => {
        let entries: readonly Dirent[];
        try {
            entries = fs.readdirSync(currentDirectoryPath, {
                withFileTypes: true,
            });
        } catch {
            return;
        }

        for (const entry of entries) {
            const entryPath = path.join(currentDirectoryPath, entry.name);
            if (entry.isDirectory()) {
                visit(entryPath);
                continue;
            }
            if (!entry.isFile()) {
                continue;
            }

            newestModificationTimeMilliseconds = Math.max(
                newestModificationTimeMilliseconds,
                fs.statSync(entryPath).mtimeMs,
            );
        }
    };

    visit(directoryPath);

    return newestModificationTimeMilliseconds;
};

const acceptedSetupSourceNewestModificationTimeMilliseconds = (): number =>
    newestModificationTimeMillisecondsUnder(
        path.resolve(
            process.cwd(),
            'crates',
            'sealed-lattice-kernel',
            'src',
            'bgv',
            'setup',
        ),
    );

export type FinalPackageCheckpointStoreWarmInputs = {
    readonly completionManifestModifiedAtMilliseconds: number | undefined;
    readonly proofFamilyCounts: ReadonlyMap<string, number>;
    readonly sourceNewestModificationTimeMilliseconds: number;
};

export const finalPackageCheckpointStoreIsWarmForInputs = (
    input: FinalPackageCheckpointStoreWarmInputs,
): boolean =>
    checkpointProofFamilyDirectories.every(
        (familyDirectory) =>
            (input.proofFamilyCounts.get(familyDirectory) ?? 0) > 0,
    ) &&
    input.completionManifestModifiedAtMilliseconds !== undefined &&
    input.completionManifestModifiedAtMilliseconds >=
        input.sourceNewestModificationTimeMilliseconds;

const finalPackageCompletionManifestModifiedAtMilliseconds = ():
    | number
    | undefined => {
    try {
        return fs.statSync(acceptedSetupFinalPackageCompletionManifestPath)
            .mtimeMs;
    } catch {
        return undefined;
    }
};

const finalPackageCheckpointStoreIsWarm = (): boolean =>
    finalPackageCheckpointStoreIsWarmForInputs({
        completionManifestModifiedAtMilliseconds:
            finalPackageCompletionManifestModifiedAtMilliseconds(),
        proofFamilyCounts: checkpointFamilyProofMaterialCounts(),
        sourceNewestModificationTimeMilliseconds:
            acceptedSetupSourceNewestModificationTimeMilliseconds(),
    });

const writeFinalPackageCompletionManifest = (): void => {
    fs.mkdirSync(acceptedSetupCheckpointDirectory, { recursive: true });
    const proofFamilyCounts = Object.fromEntries(
        checkpointFamilyProofMaterialCounts(),
    );
    fs.writeFileSync(
        acceptedSetupFinalPackageCompletionManifestPath,
        `${JSON.stringify(
            {
                checkpointDirectory: acceptedSetupCheckpointDirectory,
                completedAt: new Date().toISOString(),
                proofFamilyCounts,
            },
            undefined,
            2,
        )}\n`,
    );
};

export type ResolvedKnob = {
    readonly value: string;
    readonly source: string;
};

type ResolvedRunKnobs = {
    readonly rayonThreadCount: ResolvedKnob;
    readonly testThreads: ResolvedKnob;
    readonly trusteeProofBatchSize: ResolvedKnob;
    readonly trusteeProofLimbBatchSize: ResolvedKnob;
};

type BuiltRustKernelAcceptedSetupCommand = {
    readonly command: CommandInvocation;
    readonly marksFinalPackageCheckpointStoreComplete: boolean;
    readonly progressLabel: string;
    readonly setupMessages: readonly string[];
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
    memoryBoundedThreadCount: number,
    mode: RustKernelAcceptedSetupRunMode = 'ci',
): ResolvedKnob => {
    if (
        mode === 'ci' &&
        lane === 'final-package' &&
        memoryBoundedThreadCount > finalPackageMaximumLibtestThreadCount
    ) {
        return {
            value: String(finalPackageMaximumLibtestThreadCount),
            source: 'final-package fixture cap',
        };
    }

    return {
        value: String(memoryBoundedThreadCount),
        source: 'memory-bounded',
    };
};

export const automaticTrusteeProofBatchKnobForLane = (
    lane: RustKernelAcceptedSetupLane,
    memoryBoundedTrusteeProofBatchSize: number,
    mode: RustKernelAcceptedSetupRunMode = 'ci',
): ResolvedKnob => {
    if (
        mode === 'ci' &&
        lane === 'final-package' &&
        memoryBoundedTrusteeProofBatchSize >
            finalPackageMaximumTrusteeProofBatchSize
    ) {
        return {
            value: String(finalPackageMaximumTrusteeProofBatchSize),
            source: 'final-package prover cap',
        };
    }
    if (
        mode === 'accelerated' &&
        lane === 'final-package' &&
        memoryBoundedTrusteeProofBatchSize >
            acceleratedFinalPackageMaximumTrusteeProofBatchSize
    ) {
        return {
            value: String(acceleratedFinalPackageMaximumTrusteeProofBatchSize),
            source: 'local final-package workstation cap',
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

type AcceptedSetupLaneMetadata = {
    readonly commandDescription: string;
    readonly laneName: string;
    readonly logFileSlug: string;
    readonly progressLabel: string;
    readonly scriptName: string;
};

const acceptedSetupLaneMetadata = {
    all: {
        commandDescription: 'cargo test Rust accepted setup proofs',
        laneName: 'Rust accepted setup',
        logFileSlug: 'cargo-test-rust-accepted-setup',
        progressLabel: 'accepted-setup',
        scriptName: 'test:rust:kernel:accepted-setup',
    },
    fast: {
        commandDescription: 'cargo test Rust accepted setup fast proof checks',
        laneName: 'Rust accepted setup fast',
        logFileSlug: 'cargo-test-rust-accepted-setup-fast',
        progressLabel: 'accepted-setup:fast',
        scriptName: 'test:rust:kernel:accepted-setup:fast',
    },
    'final-package': {
        commandDescription: 'cargo test Rust accepted setup final package',
        laneName: 'Rust accepted setup final package',
        logFileSlug: 'cargo-test-rust-accepted-setup-final-package',
        progressLabel: 'accepted-setup:final-package',
        scriptName: 'test:rust:kernel:accepted-setup:final-package',
    },
} as const satisfies Record<
    RustKernelAcceptedSetupLane,
    AcceptedSetupLaneMetadata
>;

const laneMetadata = (
    lane: RustKernelAcceptedSetupLane,
): AcceptedSetupLaneMetadata => acceptedSetupLaneMetadata[lane];

const laneNameForLane = (lane: RustKernelAcceptedSetupLane): string =>
    laneMetadata(lane).laneName;

const scriptNameForLane = (lane: RustKernelAcceptedSetupLane): string =>
    laneMetadata(lane).scriptName;

const commandDescriptionForLane = (
    lane: RustKernelAcceptedSetupLane,
    mode: RustKernelAcceptedSetupRunMode,
): string =>
    `${laneMetadata(lane).commandDescription}${
        mode === 'accelerated' ? ' (accelerated local)' : ''
    }`;

// Resolve per-lane concurrency knobs. The core-derived caps mirror the kernel's
// final-package proving concurrency; the kernel treats the exported values as
// authoritative, so on a high-core but low-memory runner the RAM bound (not the
// core count) wins.
const resolveRunKnobs = (
    lane: RustKernelAcceptedSetupCommandLane,
    mode: RustKernelAcceptedSetupRunMode,
): ResolvedRunKnobs => {
    const finalPackageWarmCheckpointStore =
        lane === 'final-package' &&
        mode === 'accelerated' &&
        finalPackageCheckpointStoreIsWarm();
    const automaticTestThreads = automaticTestThreadKnobForLane(
        lane,
        automaticTestThreadCountForLane(
            lane,
            mode,
            finalPackageWarmCheckpointStore,
        ),
        mode,
    );
    const coreDerivedTrusteeProverConcurrency = Math.max(
        1,
        Math.floor(logicalProcessorCount / 4),
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
        automaticTrusteeProofBatchKnobForLane(
            lane,
            trusteeProofBatchSize,
            mode,
        );
    const resolvedTrusteeProofBatchSize = resolveKnob(
        Number.parseInt(automaticTrusteeProofBatchSize.value, 10),
        automaticTrusteeProofBatchSize.source,
        process.env.SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE,
    );
    const limbMemoryBudgetDivisor =
        lane === 'final-package' && mode === 'accelerated'
            ? Math.max(
                  1,
                  Number.parseInt(resolvedTrusteeProofBatchSize.value, 10),
              )
            : 1;
    const memoryBoundedRayonThreadCount = Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                approximateGigabytesPerRayonThread,
        ),
    );
    const rayonThreadCount = Math.min(
        logicalProcessorCount,
        memoryBoundedRayonThreadCount,
    );
    const memoryBoundedTrusteeProofLimbBatchSize = Math.max(
        1,
        Math.floor(
            (availableGigabytes * heavyTestMemoryBudgetFraction) /
                (approximateGigabytesPerTrusteeProofLimb *
                    limbMemoryBudgetDivisor),
        ),
    );
    const trusteeProofLimbBatchSize = Math.min(
        rayonThreadCount,
        memoryBoundedTrusteeProofLimbBatchSize,
    );

    return {
        testThreads: automaticTestThreads,
        trusteeProofBatchSize: resolvedTrusteeProofBatchSize,
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

const buildAcceptedSetupEnvironment = (input: {
    readonly cargoIncremental: '0' | '1';
    readonly knobs: ResolvedRunKnobs;
    readonly lane: RustKernelAcceptedSetupCommandLane;
    readonly resumeCheckpoints: boolean;
    readonly targetDirectoryPath?: string;
}): NodeJS.ProcessEnv => ({
    ...process.env,
    CARGO_INCREMENTAL: input.cargoIncremental,
    ...(input.targetDirectoryPath === undefined
        ? {}
        : { CARGO_TARGET_DIR: input.targetDirectoryPath }),
    ...(input.resumeCheckpoints
        ? {
              SEALED_LATTICE_TEST_CHECKPOINT_ROOT:
                  acceptedSetupCheckpointRootDirectory,
              SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
          }
        : {}),
    RAYON_NUM_THREADS: input.knobs.rayonThreadCount.value,
    SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE:
        input.knobs.trusteeProofBatchSize.value,
    SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE:
        input.knobs.trusteeProofLimbBatchSize.value,
    ...(input.lane === 'final-package'
        ? { SEALED_LATTICE_TRUSTEE_PROOF_VERIFY_PROGRESS: '1' }
        : {}),
});

const buildLaneCommand = (
    lane: RustKernelAcceptedSetupCommandLane,
    mode: RustKernelAcceptedSetupRunMode,
): BuiltRustKernelAcceptedSetupCommand => {
    const metadata = laneMetadata(lane);
    const knobs = resolveRunKnobs(lane, mode);
    const modeLabel =
        mode === 'accelerated' ? 'accelerated local' : 'CI prove-fresh';
    const finalPackageWarmCheckpointStore =
        lane === 'final-package' &&
        mode === 'accelerated' &&
        finalPackageCheckpointStoreIsWarm();
    const approximateGigabytesPerTest = approximateGigabytesPerTestForLane(
        lane,
        mode,
        finalPackageWarmCheckpointStore,
    );
    const setupMessages = [
        `${laneNameForLane(lane)} lane (${modeLabel}): running with ${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available, ` +
            `${approximateGigabytesPerTest} GiB automatically budgeted per test` +
            `${finalPackageWarmCheckpointStore ? ', warm checkpoint store detected' : ''}).`,
        `${laneNameForLane(lane)} lane (${modeLabel}): proving up to ${knobs.trusteeProofBatchSize.value} trustee evaluation-key ` +
            `proof(s) concurrently (${knobs.trusteeProofBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProver} GiB per prover).`,
        `${laneNameForLane(lane)} lane (${modeLabel}): proving up to ${knobs.trusteeProofLimbBatchSize.value} RNS limb(s) per ` +
            `trustee evaluation-key prover (${knobs.trusteeProofLimbBatchSize.source}; automatic budget uses ` +
            `${approximateGigabytesPerTrusteeProofLimb} GiB per limb).`,
        `${laneNameForLane(lane)} lane (${modeLabel}): bounding the rayon pool to ${knobs.rayonThreadCount.value} thread(s) ` +
            `(${knobs.rayonThreadCount.source}; automatic budget uses ` +
            `${approximateGigabytesPerRayonThread} GiB per rayon thread).`,
    ];
    if (mode === 'accelerated') {
        setupMessages.push(
            `${laneNameForLane(lane)} lane (${modeLabel}): incremental compilation on; ` +
                `target directory ${acceptedSetupAcceleratedTargetDirectory}; proof checkpoints ${acceptedSetupCheckpointDirectory}; run logs stay under logs/.`,
        );
    }
    if (lane === 'final-package' && mode === 'accelerated') {
        const checkpointCounts = checkpointFamilyProofMaterialCounts();
        setupMessages.push(
            `${laneNameForLane(lane)} lane (${modeLabel}): checkpoint family counts: ` +
                `${checkpointFamilyProofMaterialCountSummary(checkpointCounts)}.`,
        );
        if (!finalPackageWarmCheckpointStore) {
            setupMessages.push(
                `${laneNameForLane(lane)} lane (${modeLabel}): checkpoint resume is enabled, ` +
                    `but warm-store parallelism waits for ${acceptedSetupFinalPackageCompletionManifestPath}.`,
            );
        }
    }

    return {
        command: {
            args: cargoTestArgumentsForLane(lane, knobs.testThreads.value),
            command: 'cargo',
            description: commandDescriptionForLane(lane, mode),
            env: buildAcceptedSetupEnvironment({
                cargoIncremental: mode === 'accelerated' ? '1' : '0',
                knobs,
                lane,
                resumeCheckpoints: mode === 'accelerated',
                targetDirectoryPath:
                    mode === 'accelerated'
                        ? acceptedSetupAcceleratedTargetDirectory
                        : undefined,
            }),
            logFileSlug:
                mode === 'accelerated'
                    ? `${metadata.logFileSlug}-accelerated`
                    : metadata.logFileSlug,
        },
        marksFinalPackageCheckpointStoreComplete:
            lane === 'final-package' && mode === 'accelerated',
        progressLabel: metadata.progressLabel,
        setupMessages,
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

const focusedLaneForFilter = (
    selectedLane: RustKernelAcceptedSetupLane,
    testFilter: string,
): RustKernelAcceptedSetupCommandLane => {
    if (
        selectedLane === 'final-package' ||
        testFilter.includes(heavyAcceptedSetupFinalPackageTestPattern)
    ) {
        return 'final-package';
    }

    return 'fast';
};

const buildFocusedCommand = (
    testFilter: string,
    selectedLane: RustKernelAcceptedSetupLane,
): BuiltRustKernelAcceptedSetupCommand => {
    const lane = focusedLaneForFilter(selectedLane, testFilter);
    const knobs = resolveRunKnobs(lane, 'accelerated');
    const setupMessages = [
        `Rust accepted setup focused run: filter [${testFilter}], ` +
            `${knobs.testThreads.value} test thread(s) ` +
            `(${knobs.testThreads.source}; ${availableGigabytes.toFixed(1)} GiB available).`,
        `Pinned target directory: ${acceptedSetupFocusedTargetDirectory}. ` +
            `Incremental compilation: on. Proof checkpoint resume: on. Proof checkpoints ${acceptedSetupCheckpointDirectory}; run logs stay under logs/.`,
    ];

    return {
        command: {
            args: cargoTestArgumentsForFocusedFilter(
                testFilter,
                knobs.testThreads.value,
            ),
            command: 'cargo',
            description: `cargo test ${testFilter} (warm focused)`,
            env: buildAcceptedSetupEnvironment({
                cargoIncremental: '1',
                knobs,
                lane,
                resumeCheckpoints: true,
                targetDirectoryPath: acceptedSetupFocusedTargetDirectory,
            }),
            logFileSlug: 'cargo-test-rust-accepted-setup-focused',
        },
        marksFinalPackageCheckpointStoreComplete: false,
        progressLabel: 'accepted-setup:focused',
        setupMessages,
        testThreadCount: Number.parseInt(knobs.testThreads.value, 10),
    };
};

export const authoritativeCommandLanesForLane = (
    lane: RustKernelAcceptedSetupLane,
): readonly RustKernelAcceptedSetupCommandLane[] =>
    lane === 'all' ? ['fast', 'final-package'] : [lane];

const buildAuthoritativeCommands = (
    lane: RustKernelAcceptedSetupLane,
    mode: RustKernelAcceptedSetupRunMode,
): readonly BuiltRustKernelAcceptedSetupCommand[] =>
    authoritativeCommandLanesForLane(lane).map((commandLane) =>
        buildLaneCommand(commandLane, mode),
    );

const writeRunnerSetupMessages = (
    runLog: Awaited<ReturnType<typeof createLocalRunLog>>,
    setupMessages: readonly string[],
): void => {
    for (const message of setupMessages) {
        console.log(message);
        runLog.writeCombinedOutput(`${message}\n`);
    }
};

const usage =
    'Usage: run-rust-kernel-accepted-setup-tests.ts [--ci] [--lane all|fast|final-package] [<test name, module name, or Rust file filter>]. ' +
    'Default mode is accelerated local execution with checkpoint resume. Pass --ci for the conservative prove-fresh CI lane.';

const isRustKernelAcceptedSetupLane = (
    value: string,
): value is RustKernelAcceptedSetupLane =>
    value === 'all' || value === 'fast' || value === 'final-package';

export const parseRustKernelAcceptedSetupArguments = (
    commandArguments: readonly string[],
    defaultLane: RustKernelAcceptedSetupLane = 'all',
): ParsedRustKernelAcceptedSetupArguments => {
    const positionalArguments: string[] = [];
    let lane = defaultLane;
    let mode: RustKernelAcceptedSetupRunMode = 'accelerated';

    for (let index = 0; index < commandArguments.length; index += 1) {
        const argument = commandArguments[index];
        if (argument === undefined) {
            continue;
        }
        if (argument === '--') {
            continue;
        }
        if (argument === '--ci') {
            mode = 'ci';
            continue;
        }
        if (argument === '--lane') {
            const value = commandArguments[index + 1];
            if (value === undefined || !isRustKernelAcceptedSetupLane(value)) {
                throw new Error(`Invalid accepted-setup lane. ${usage}`);
            }
            lane = value;
            index += 1;
            continue;
        }
        const lanePrefix = '--lane=';
        if (argument.startsWith(lanePrefix)) {
            const value = argument.slice(lanePrefix.length);
            if (!isRustKernelAcceptedSetupLane(value)) {
                throw new Error(`Invalid accepted-setup lane. ${usage}`);
            }
            lane = value;
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
        lane,
        mode,
        testFilters:
            normalizedFocusedFilter !== undefined
                ? [normalizedFocusedFilter]
                : testFiltersForLane(lane),
    };
};

export const runRustKernelAcceptedSetupTests = async (input: {
    readonly lane: RustKernelAcceptedSetupLane;
    readonly rawArguments?: readonly string[];
    readonly scriptName?: string;
}): Promise<void> => {
    const rawArguments = input.rawArguments ?? process.argv.slice(2);
    const parsedArguments = parseRustKernelAcceptedSetupArguments(
        rawArguments,
        input.lane,
    );

    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: parsedArguments.focused
            ? [`Rust accepted setup focused (${parsedArguments.mode})`]
            : authoritativeCommandLanesForLane(parsedArguments.lane).map(
                  (lane) =>
                      `${laneNameForLane(lane)} (${parsedArguments.mode})`,
              ),
        scriptName: input.scriptName ?? scriptNameForLane(parsedArguments.lane),
    });

    const builtCommands = parsedArguments.focused
        ? [
              buildFocusedCommand(
                  parsedArguments.testFilters[0] ?? '',
                  parsedArguments.lane,
              ),
          ]
        : buildAuthoritativeCommands(
              parsedArguments.lane,
              parsedArguments.mode,
          );

    let exitCode: number | undefined;
    try {
        for (const builtCommand of builtCommands) {
            writeRunnerSetupMessages(runLog, builtCommand.setupMessages);
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
            if (builtCommand.marksFinalPackageCheckpointStoreComplete) {
                writeFinalPackageCompletionManifest();
                const message =
                    `Rust accepted setup final package lane (accelerated local): ` +
                    `wrote checkpoint completion manifest ${acceptedSetupFinalPackageCompletionManifestPath}.\n`;
                console.log(message.trimEnd());
                runLog.writeCombinedOutput(message);
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
