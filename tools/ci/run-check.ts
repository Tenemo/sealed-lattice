import { performance } from 'node:perf_hooks';

import {
    CheckProgressReporter,
    checkCommandTimingKey,
    formatProgressDuration,
    readPreviousCheckTimingHistory,
    type CheckFailureDetail,
    type CheckProgressLanePlan,
    type CheckRunTimingDetails,
    type CheckTimingHistory,
} from './check-progress-reporter.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    removeRunLogArguments,
    runLogDisabledByArguments,
    type ActiveLocalRunLog,
} from './local-run-log.js';
import {
    createPackageManagerCommand,
    resolvePackageManagerRunner,
    runCommandsInSeries,
    type CommandInvocation,
    type PackageManagerRunner,
} from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// `passed` and `failed` are a lane's own result; `stopped` means a sibling lane
// failed first and this lane was killed before it could finish.
type LaneStatus = 'failed' | 'passed' | 'stopped';

// A validation lane is a named group of commands that run in series with one
// another. Lanes may run concurrently during the independent-check phase, and
// the isolated Rust lane keeps `cargo fmt`, `cargo clippy`, and `cargo test`
// sequential so they share one native `target/` build lock and reuse each
// other's dependency artifacts.
type ValidationLane = {
    readonly commands: readonly CommandInvocation[];
    readonly name: string;
};

type ValidationLaneResult = {
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly name: string;
    readonly status: LaneStatus;
};

export type CheckProgressMode = 'always' | 'auto' | 'never';

export type ParsedCheckArguments = {
    readonly progressMode: CheckProgressMode;
};

const checkUsage =
    'Usage: run-check.ts [--no-run-log] [--progress=auto|always|never].';
const rustKernelLaneName = 'Rust kernel (fmt, clippy, optimized test)';
const legacyRustKernelLaneName = 'Rust kernel (fmt, clippy, test)';

const isCheckProgressMode = (value: string): value is CheckProgressMode =>
    value === 'always' || value === 'auto' || value === 'never';

export const parseCheckArguments = (
    commandArguments: readonly string[],
): ParsedCheckArguments => {
    let progressMode: CheckProgressMode = 'auto';
    for (let index = 0; index < commandArguments.length; index += 1) {
        const argument = commandArguments[index];
        if (argument === undefined) {
            continue;
        }

        if (argument === '--progress') {
            const value = commandArguments[index + 1];
            if (value === undefined || !isCheckProgressMode(value)) {
                throw new Error(checkUsage);
            }
            progressMode = value;
            index += 1;
            continue;
        }

        const progressPrefix = '--progress=';
        if (argument.startsWith(progressPrefix)) {
            const value = argument.slice(progressPrefix.length);
            if (!isCheckProgressMode(value)) {
                throw new Error(checkUsage);
            }
            progressMode = value;
            continue;
        }

        throw new Error(checkUsage);
    }

    return { progressMode };
};

export const redrawEnabledForProgressMode = (
    progressMode: CheckProgressMode,
    standardOutputIsTerminal = process.stdout.isTTY === true,
): boolean | undefined => {
    if (progressMode === 'always') {
        return standardOutputIsTerminal;
    }
    if (progressMode === 'never') {
        return false;
    }

    return undefined;
};

const createCargoCommand = (
    description: string,
    commandArguments: readonly string[],
    logFileSlug: string,
): CommandInvocation => ({
    args: commandArguments,
    command: 'cargo',
    description,
    logFileSlug,
});

const createPackageManagerLane = (
    packageManagerRunner: PackageManagerRunner,
    name: string,
    logFileSlug: string,
    commandArguments: readonly string[],
): ValidationLane => ({
    commands: [
        createPackageManagerCommand(name, commandArguments, {
            logFileSlug,
            packageManagerRunner,
        }),
    ],
    name,
});

// The gating lanes run first, in series. The workspace build emits every
// `dist/` artifact and compiles the Rust kernel to WebAssembly (holding the
// cargo build lock); the type-check also emits declarations. Keeping both ahead
// of the parallel phase means no lane writes `dist/` while the test lanes import
// it, and no `cargo` lane competes with the WebAssembly build for `target/`. A
// failure here makes the rest pointless, so the run stops immediately.
const buildGatingLanes = (
    packageManagerRunner: PackageManagerRunner,
): readonly ValidationLane[] => [
    createPackageManagerLane(
        packageManagerRunner,
        'Build workspace packages',
        'build',
        ['run', 'build'],
    ),
    createPackageManagerLane(
        packageManagerRunner,
        'Type-check workspace',
        'tsc',
        ['run', 'tsc'],
    ),
];

// Independent checks run concurrently against the built output. The docs lane
// uses the same build script as standalone verification so TypeDoc generation
// and postprocessing stay in one package-script sequence on Windows. The pack
// smoke lane still calls its underlying tool directly because its package script
// rebuilds for standalone use. The Rust lane runs after this phase: the tests
// are memory-heavy on Windows and should not compete with docs rendering,
// linting, package smoke verification, and Node tests. The commit gate runs
// only the fast Node test project; the heavier protocol and kernel Node
// projects and the Playwright browser projects stay in `pnpm run test:node`
// and `pnpm run test:browser` for pre-push verification.
const buildParallelLanes = (
    packageManagerRunner: PackageManagerRunner,
): readonly ValidationLane[] => {
    const lane = (
        name: string,
        logFileSlug: string,
        commandArguments: readonly string[],
    ): ValidationLane =>
        createPackageManagerLane(
            packageManagerRunner,
            name,
            logFileSlug,
            commandArguments,
        );

    return [
        lane('Lint', 'lint', ['run', 'lint']),
        {
            commands: [
                createPackageManagerCommand(
                    'Build docs',
                    ['run', 'docs:build'],
                    {
                        logFileSlug: 'docs-build',
                        packageManagerRunner,
                    },
                ),
                createPackageManagerCommand(
                    'Verify docs links',
                    ['exec', 'tsx', './docs/typedoc/verify-docs.ts'],
                    {
                        logFileSlug: 'docs-link-verification',
                        packageManagerRunner,
                    },
                ),
                createPackageManagerCommand(
                    'Verify rendered docs',
                    ['exec', 'tsx', './tools/ci/verify-docs-render.ts'],
                    {
                        logFileSlug: 'docs-render-verification',
                        packageManagerRunner,
                    },
                ),
            ],
            name: 'Verify docs',
        },
        lane('Smoke npm package', 'smoke-pack-npm', [
            'exec',
            'tsx',
            './tools/ci/verify-packed-package.ts',
            '--package-manager',
            'npm',
        ]),
        lane('Verify public package policy', 'package-policy', [
            'exec',
            'tsx',
            './tools/ci/verify-public-package-policy.ts',
        ]),
        lane('Check package boundaries', 'package-boundaries', [
            'exec',
            'tsx',
            './tools/ci/check-package-boundaries.ts',
        ]),
        lane('Verify test vectors', 'test-vectors', ['run', 'vectors']),
        lane('Knip unused-code scan', 'knip', ['exec', 'knip']),
        lane('Node tests (fast)', 'vitest-node', [
            'exec',
            'vitest',
            '--project',
            'node',
            '--run',
            '--reporter',
            'default',
            '--reporter',
            './tools/ci/vitest-progress-reporter.ts',
        ]),
    ];
};

const buildRustKernelLane = (): ValidationLane => ({
    commands: [
        createCargoCommand(
            'cargo fmt --check',
            ['fmt', '--check', '-p', 'sealed-lattice-kernel'],
            'cargo-fmt',
        ),
        createCargoCommand(
            'cargo clippy',
            [
                'clippy',
                '--workspace',
                '--all-targets',
                '--all-features',
                '--',
                '-D',
                'warnings',
            ],
            'cargo-clippy',
        ),
        createCargoCommand(
            'cargo test (optimized test profile)',
            ['test', '-p', 'sealed-lattice-kernel', '--quiet'],
            'cargo-test',
        ),
    ],
    name: rustKernelLaneName,
});

const buildIsolatedLanes = (): readonly ValidationLane[] => [
    buildRustKernelLane(),
];

const buildProgressLanePlans = (
    lanes: readonly ValidationLane[],
    timingHistory: CheckTimingHistory,
): readonly CheckProgressLanePlan[] => {
    const progressSourceForLane = (
        lane: ValidationLane,
    ): CheckProgressLanePlan['progress'] => {
        const previousProgress =
            lane.name === rustKernelLaneName
                ? (timingHistory.laneProgress.get(rustKernelLaneName) ??
                  timingHistory.laneProgress.get(legacyRustKernelLaneName))
                : timingHistory.laneProgress.get(lane.name);
        if (lane.name === 'Build workspace packages') {
            return {
                primary:
                    previousProgress?.primary === undefined
                        ? undefined
                        : {
                              completed: 0,
                              total: previousProgress.primary.total,
                              unit: 'task seen',
                          },
                source: 'turbo',
            };
        }
        if (lane.name === 'Node tests (fast)') {
            return {
                primary:
                    previousProgress?.primary === undefined
                        ? undefined
                        : {
                              completed: 0,
                              total: previousProgress.primary.total,
                              unit: 'test file',
                          },
                secondary:
                    previousProgress?.secondary === undefined
                        ? undefined
                        : {
                              completed: 0,
                              total: previousProgress.secondary.total,
                              unit: 'test',
                          },
                source: 'vitest',
            };
        }
        if (lane.name === rustKernelLaneName) {
            return {
                secondary:
                    previousProgress?.secondary === undefined
                        ? undefined
                        : {
                              completed: 0,
                              total: previousProgress.secondary.total,
                              unit: 'test',
                          },
                source: 'libtest',
            };
        }
        if (lane.commands.length > 1) {
            return {
                source: 'commands',
            };
        }

        return {
            source: 'opaque',
        };
    };

    return lanes.map((lane) => ({
        commands: lane.commands.map((command) => ({
            description: command.description,
            expectedDurationMilliseconds:
                timingHistory.commandDurationMilliseconds.get(
                    checkCommandTimingKey(lane.name, command.description),
                ),
        })),
        expectedDurationMilliseconds:
            timingHistory.laneDurationMilliseconds.get(lane.name),
        name: lane.name,
        progress: progressSourceForLane(lane),
    }));
};

const runGatingLane = async (
    lane: ValidationLane,
    runLog: ActiveLocalRunLog | undefined,
    reporter: CheckProgressReporter,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, {
        observer: reporter.createCommandObserver(lane.name),
        outputMode: 'capture',
        runLog,
    });
    reporter.recordLaneResult(lane.name, exitCode === 0 ? 'passed' : 'failed');

    return {
        durationMilliseconds: Math.round(
            performance.now() - startedAtMilliseconds,
        ),
        exitCode,
        name: lane.name,
        status: exitCode === 0 ? 'passed' : 'failed',
    };
};

const runParallelLane = async (
    lane: ValidationLane,
    runLog: ActiveLocalRunLog | undefined,
    abortController: AbortController,
    reporter: CheckProgressReporter,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, {
        observer: reporter.createCommandObserver(lane.name),
        outputMode: 'capture',
        runLog,
        signal: abortController.signal,
    });
    const durationMilliseconds = Math.round(
        performance.now() - startedAtMilliseconds,
    );

    if (exitCode === 0) {
        reporter.recordLaneResult(lane.name, 'passed');

        return {
            durationMilliseconds,
            exitCode,
            name: lane.name,
            status: 'passed',
        };
    }
    if (abortController.signal.aborted) {
        reporter.recordLaneResult(lane.name, 'stopped');

        return {
            durationMilliseconds,
            exitCode,
            name: lane.name,
            status: 'stopped',
        };
    }

    // This lane failed on its own. Abort so every other still-running lane is
    // killed instead of grinding to completion behind a known failure.
    abortController.abort();
    reporter.recordLaneResult(lane.name, 'failed');

    return {
        durationMilliseconds,
        exitCode,
        name: lane.name,
        status: 'failed',
    };
};

const statusLabels: Readonly<Record<LaneStatus, string>> = {
    failed: 'FAIL',
    passed: 'PASS',
    stopped: 'STOP',
};

const formatDurationSeconds = (durationMilliseconds: number): string =>
    `${(durationMilliseconds / 1000).toFixed(1)}s`;

const printValidationSummary = (
    results: readonly ValidationLaneResult[],
    runLog: ActiveLocalRunLog | undefined,
    timingHistory: CheckTimingHistory,
    failureDetails: readonly CheckFailureDetail[],
): void => {
    console.log('\nValidation summary');
    for (const result of results) {
        const duration = formatDurationSeconds(
            result.durationMilliseconds,
        ).padStart(8);
        console.log(
            `  ${statusLabels[result.status]}  ${duration}  ${result.name}`,
        );
    }

    const failedResults = results.filter(
        (result) => result.status === 'failed',
    );
    const stoppedCount = results.filter(
        (result) => result.status === 'stopped',
    ).length;
    if (failedResults.length === 0) {
        console.log('\nAll validation lanes passed.');
        if (timingHistory.totalDurationMilliseconds !== undefined) {
            console.log(
                `Expected duration from previous successful check: ${formatProgressDuration(
                    timingHistory.totalDurationMilliseconds,
                )}.`,
            );
        }

        return;
    }

    const stoppedNote =
        stoppedCount > 0
            ? ` (${stoppedCount} other lane(s) stopped early)`
            : '';
    console.log(
        `\nFailed: ${failedResults
            .map((result) => result.name)
            .join(', ')}${stoppedNote}.`,
    );
    if (runLog !== undefined) {
        console.log(`Per-lane logs: ${runLog.runDirectoryPath}`);
    }
    for (const failureDetail of failureDetails) {
        console.log(`\nFailure detail: ${failureDetail.laneName}`);
        if (failureDetail.commandDescription !== undefined) {
            console.log(`Command: ${failureDetail.commandDescription}`);
        }
        if (failureDetail.exitCode !== undefined) {
            console.log(`Exit code: ${failureDetail.exitCode}`);
        }
        if (failureDetail.logPath !== undefined) {
            console.log(`Log: ${failureDetail.logPath}`);
        }
        if (failureDetail.recentOutputLines.length > 0) {
            console.log('Recent output:');
            for (const line of failureDetail.recentOutputLines) {
                console.log(`  ${line}`);
            }
        }
    }
};

const overallExitCode = (results: readonly ValidationLaneResult[]): number => {
    const failingResult =
        results.find((result) => result.status === 'failed') ??
        results.find((result) => result.status === 'stopped');

    return failingResult ? failingResult.exitCode || 1 : 0;
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const commandArguments = removeRunLogArguments(rawArguments);
    const parsedArguments = parseCheckArguments(commandArguments);
    const packageManagerRunner = resolvePackageManagerRunner();
    const gatingLanes = buildGatingLanes(packageManagerRunner);
    const parallelLanes = buildParallelLanes(packageManagerRunner);
    const isolatedLanes = buildIsolatedLanes();
    const validationLanes = [
        ...gatingLanes,
        ...parallelLanes,
        ...isolatedLanes,
    ];
    const timingHistory = await readPreviousCheckTimingHistory();
    const reporter = new CheckProgressReporter({
        history: timingHistory,
        lanes: buildProgressLanePlans(validationLanes, timingHistory),
        redrawEnabled: redrawEnabledForProgressMode(
            parsedArguments.progressMode,
        ),
    });
    const runLog = runLogDisabledByArguments(rawArguments)
        ? undefined
        : await createLocalRunLog({
              commandLineArguments: rawArguments,
              lanes: validationLanes.map((lane) => lane.name),
              scriptName: 'check',
          });
    let timingDetails: CheckRunTimingDetails | undefined;

    try {
        const results: ValidationLaneResult[] = [];
        reporter.start();

        for (const lane of gatingLanes) {
            const result = await runGatingLane(lane, runLog, reporter);
            results.push(result);
            if (result.exitCode !== 0) {
                reporter.stop();
                timingDetails = reporter.createTimingDetails();
                printValidationSummary(
                    results,
                    runLog,
                    timingHistory,
                    reporter.failureDetails(),
                );
                process.exitCode = result.exitCode;

                return;
            }
        }

        const abortController = new AbortController();
        const parallelResults = await Promise.all(
            parallelLanes.map((lane) =>
                runParallelLane(lane, runLog, abortController, reporter),
            ),
        );
        results.push(
            ...[...parallelResults].sort(
                (first, second) =>
                    second.durationMilliseconds - first.durationMilliseconds,
            ),
        );
        if (parallelResults.some((result) => result.exitCode !== 0)) {
            reporter.stop();
            timingDetails = reporter.createTimingDetails();
            printValidationSummary(
                results,
                runLog,
                timingHistory,
                reporter.failureDetails(),
            );
            process.exitCode = overallExitCode(results);

            return;
        }

        for (const lane of isolatedLanes) {
            const result = await runGatingLane(lane, runLog, reporter);
            results.push(result);
            if (result.exitCode !== 0) {
                break;
            }
        }

        reporter.stop();
        timingDetails = reporter.createTimingDetails();
        printValidationSummary(
            results,
            runLog,
            timingHistory,
            reporter.failureDetails(),
        );
        process.exitCode = overallExitCode(results);
    } finally {
        reporter.stop();
        await runLog?.finish({
            details: timingDetails,
            exitCode: currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
