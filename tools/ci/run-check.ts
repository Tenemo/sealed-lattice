import path from 'node:path';
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
import { createHeavyTestProgressReporter } from './heavy-test-progress.js';
import {
    createLocalRunLog,
    currentProcessExitCode,
    type ActiveLocalRunLog,
} from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './run-command.js';
import { buildVitestProjectCommand } from './run-vitest-lanes.js';
import { cargoTestArgumentsForRustKernelFast } from './rust-kernel-test-arguments.js';
import {
    canonicalTestLaneDefinitions,
    nodeTestLaneDefinitions,
} from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

// `passed` and `failed` are a lane's own result; `stopped` means a sibling lane
// failed first and this lane was killed before it could finish.
type LaneStatus = 'failed' | 'passed' | 'stopped';

// A validation lane is a named group of commands that run in series with one
// another. Lanes may run concurrently during the independent-check phase.
type ValidationLane = {
    readonly baselineDurationMilliseconds: number;
    readonly commands: readonly CommandInvocation[];
    readonly name: string;
};

export type ValidationLaneResult = {
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly name: string;
    readonly status: LaneStatus;
};

type ValidationSummaryContext = {
    readonly failureDetails: readonly CheckFailureDetail[];
    readonly previousSuccessfulDurationMilliseconds?: number;
    readonly runLogDirectoryPath?: string;
};

export type CheckProgressMode = 'always' | 'auto' | 'never';

export type ParsedCheckArguments = {
    readonly progressMode: CheckProgressMode;
};

const combineCommandRunObservers = (
    observers: readonly CommandRunObserver[],
): CommandRunObserver => ({
    onCommandExit: (event): void => {
        for (const observer of observers) observer.onCommandExit?.(event);
    },
    onCommandOutput: (event): void => {
        for (const observer of observers) observer.onCommandOutput?.(event);
    },
    onCommandStart: (event): void => {
        for (const observer of observers) observer.onCommandStart?.(event);
    },
});

const scopeCommandRunObserver = (
    commandDescription: string,
    observer: CommandRunObserver,
): CommandRunObserver => ({
    onCommandExit: (event): void => {
        if (event.invocation.description === commandDescription) {
            observer.onCommandExit?.(event);
        }
    },
    onCommandOutput: (event): void => {
        if (event.invocation.description === commandDescription) {
            observer.onCommandOutput?.(event);
        }
    },
    onCommandStart: (event): void => {
        if (event.invocation.description === commandDescription) {
            observer.onCommandStart?.(event);
        }
    },
});

const checkUsage = 'Usage: run-check.ts [--progress=auto|always|never].';
const rustKernelLaneName = 'Rust kernel (fmt, clippy, fast test)';
const checkRunLaneNames = [
    'Build workspace packages',
    'Type-check workspace',
    'Smoke npm package',
    'Lint',
    rustKernelLaneName,
    'Verify public package policy',
    'Verify test lane coverage',
    'Check package boundaries',
    'Knip unused-code scan',
    'Node tests (fast)',
    'Node tests (kernel fast)',
] as const;
const checkLaneBaselineDurationMilliseconds = {
    'Build workspace packages': 20_000,
    'Check package boundaries': 1_000,
    'Knip unused-code scan': 4_000,
    Lint: 30_000,
    'Smoke npm package': 5_000,
    'Type-check workspace': 8_000,
    'Verify public package policy': 1_000,
    'Verify test lane coverage': 3_000,
} as const;

const baselineDurationForCheckLane = (laneName: string): number =>
    checkLaneBaselineDurationMilliseconds[
        laneName as keyof typeof checkLaneBaselineDurationMilliseconds
    ] ?? 5_000;

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

        if (argument === '--') {
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
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        RUST_BACKTRACE: '1',
    },
    logFileSlug,
});

const createPackageManagerLane = (
    packageManagerRunner: PackageManagerRunner,
    name: string,
    logFileSlug: string,
    commandArguments: readonly string[],
): ValidationLane => ({
    baselineDurationMilliseconds: baselineDurationForCheckLane(name),
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
// cargo build lock); the type-check also emits declarations; the smoke package
// lane stages and hashes the built public package. Keeping these ahead of the
// parallel phase means no lane writes or stages `dist/` while test lanes import
// it, and no `cargo` lane competes with the WebAssembly build for `target/`. A
// failure here makes the rest pointless, so the run stops immediately.
export const buildCheckGatingLanes = (
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
    createPackageManagerLane(
        packageManagerRunner,
        'Smoke npm package',
        'smoke-pack-npm',
        ['exec', 'tsx', './tools/ci/verify-packed-package.ts'],
    ),
];

const buildRustKernelLane = (
    packageManagerRunner: PackageManagerRunner,
): ValidationLane => ({
    baselineDurationMilliseconds:
        canonicalTestLaneDefinitions['rust-kernel-fast']
            .baselineDurationMilliseconds,
    commands: [
        createCargoCommand(
            'cargo fmt --check',
            ['fmt', '--all', '--check'],
            'cargo-fmt',
        ),
        createCargoCommand(
            'cargo clippy',
            [
                'clippy',
                '--locked',
                '--workspace',
                '--all-targets',
                '--all-features',
                '--',
                '-D',
                'warnings',
            ],
            'cargo-clippy',
        ),
        createPackageManagerCommand(
            'Verify Rust test lane inventory',
            ['run', 'test:lanes:verify', '--', '--rust'],
            {
                logFileSlug: 'test-lane-coverage-rust',
                packageManagerRunner,
            },
        ),
        createPackageManagerCommand(
            'Test process memory guard',
            ['run', 'test:rust:process-memory-guard'],
            {
                logFileSlug: 'process-memory-guard',
                packageManagerRunner,
            },
        ),
        createCargoCommand(
            'cargo test (optimized test profile, fast)',
            cargoTestArgumentsForRustKernelFast(),
            'cargo-test',
        ),
    ],
    name: rustKernelLaneName,
});

// Independent checks run concurrently against the built output. The commit gate
// runs the fast Node test project, the kernel-fast Node project, and the fast
// Rust kernel tests. The heavier protocol, kernel-heavy Node project, ignored
// measured-heavy Rust proof and evaluator tests, Rust accepted-setup tests,
// including their ignored proof tests, and the Playwright browser projects
// stay in standalone lanes so local checks remain fast and CI can schedule the
// expensive work independently.
export const buildCheckParallelLanes = (
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
    const vitestLane = (
        name: string,
        laneName: 'fast' | 'kernel-fast',
    ): ValidationLane => ({
        baselineDurationMilliseconds:
            canonicalTestLaneDefinitions[
                laneName === 'fast' ? 'node-fast' : 'node-kernel-fast'
            ].baselineDurationMilliseconds,
        commands: [
            buildVitestProjectCommand({
                commandDescription: name,
                packageManagerRunner,
                projectName: nodeTestLaneDefinitions[laneName].projectName,
            }),
        ],
        name,
    });

    return [
        lane('Lint', 'lint', ['run', 'lint']),
        buildRustKernelLane(packageManagerRunner),
        lane('Verify public package policy', 'package-policy', [
            'exec',
            'tsx',
            './tools/ci/verify-public-package-policy.ts',
        ]),
        lane('Verify test lane coverage', 'test-lane-coverage', [
            'run',
            'test:lanes:verify',
            '--',
            '--static',
        ]),
        lane('Check package boundaries', 'package-boundaries', [
            'exec',
            'tsx',
            './tools/ci/check-package-boundaries.ts',
        ]),
        lane('Knip unused-code scan', 'knip', ['exec', 'knip']),
        vitestLane('Node tests (fast)', 'fast'),
        vitestLane('Node tests (kernel fast)', 'kernel-fast'),
    ];
};

export const buildProgressLanePlans = (
    lanes: readonly ValidationLane[],
    timingHistory: CheckTimingHistory,
): readonly CheckProgressLanePlan[] => {
    const progressSourceForLane = (
        lane: ValidationLane,
    ): CheckProgressLanePlan['progress'] => {
        const previousProgress =
            lane.name === rustKernelLaneName
                ? timingHistory.laneProgress.get(rustKernelLaneName)
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
        if (
            lane.name === 'Node tests (fast)' ||
            lane.name === 'Node tests (kernel fast)'
        ) {
            return {
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
            timingHistory.laneDurationMilliseconds.get(lane.name) ??
            lane.baselineDurationMilliseconds,
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
    additionalObserver?: CommandRunObserver,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, {
        observer:
            additionalObserver === undefined
                ? reporter.createCommandObserver(lane.name)
                : combineCommandRunObservers([
                      reporter.createCommandObserver(lane.name),
                      additionalObserver,
                  ]),
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
    abortController.abort({
        classification: 'sibling-abort',
        initiator: lane.name,
        objectVersion: 'sealed-lattice-command-abort-reason-v1',
    });
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

export const formatValidationSummary = (
    results: readonly ValidationLaneResult[],
    context: ValidationSummaryContext,
): readonly string[] => {
    const lines = ['', 'Validation summary'];
    for (const result of results) {
        const duration = formatDurationSeconds(
            result.durationMilliseconds,
        ).padStart(8);
        lines.push(
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
        lines.push('', 'All validation lanes passed.');
        if (context.previousSuccessfulDurationMilliseconds !== undefined) {
            lines.push(
                `Expected duration from previous successful check: ${formatProgressDuration(
                    context.previousSuccessfulDurationMilliseconds,
                )}.`,
            );
        }

        return lines;
    }

    const stoppedNote =
        stoppedCount > 0
            ? ` (${stoppedCount} other lane(s) stopped early)`
            : '';
    lines.push(
        '',
        `Failed: ${failedResults
            .map((result) => result.name)
            .join(', ')}${stoppedNote}.`,
    );
    if (context.runLogDirectoryPath !== undefined) {
        lines.push(`Per-lane logs: ${context.runLogDirectoryPath}`);
    }
    for (const failureDetail of context.failureDetails) {
        lines.push('', `Failure detail: ${failureDetail.laneName}`);
        if (failureDetail.commandDescription !== undefined) {
            lines.push(`Command: ${failureDetail.commandDescription}`);
        }
        if (failureDetail.exitCode !== undefined) {
            lines.push(`Exit code: ${failureDetail.exitCode}`);
        }
        if (failureDetail.logPath !== undefined) {
            lines.push(`Log: ${failureDetail.logPath}`);
        }
        if (failureDetail.recentOutputLines.length > 0) {
            lines.push('Recent output:');
            for (const line of failureDetail.recentOutputLines) {
                lines.push(`  ${line}`);
            }
        }
    }

    return lines;
};

const printValidationSummary = (
    results: readonly ValidationLaneResult[],
    runLog: ActiveLocalRunLog | undefined,
    timingHistory: CheckTimingHistory,
    failureDetails: readonly CheckFailureDetail[],
): void => {
    const lines = formatValidationSummary(results, {
        failureDetails,
        previousSuccessfulDurationMilliseconds:
            timingHistory.totalDurationMilliseconds,
        runLogDirectoryPath: runLog?.runDirectoryPath,
    });
    for (const line of lines) {
        console.log(line);
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
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: checkRunLaneNames,
        scriptName: 'check',
    });
    let timingDetails: CheckRunTimingDetails | undefined;
    let reporter: CheckProgressReporter | undefined;
    let rustTestProgressReporter:
        | ReturnType<typeof createHeavyTestProgressReporter>
        | undefined;
    let executionError: unknown;
    let logFinishingError: unknown;

    try {
        const parsedArguments = parseCheckArguments(rawArguments);
        const packageManagerRunner = resolvePackageManagerRunner();
        const gatingLanes = buildCheckGatingLanes(packageManagerRunner);
        const parallelLanes = buildCheckParallelLanes(packageManagerRunner);
        const validationLanes = [...gatingLanes, ...parallelLanes];
        const timingHistory = await readPreviousCheckTimingHistory();
        reporter = new CheckProgressReporter({
            history: timingHistory,
            lanes: buildProgressLanePlans(validationLanes, timingHistory),
            redrawEnabled: redrawEnabledForProgressMode(
                parsedArguments.progressMode,
            ),
        });
        rustTestProgressReporter = createHeavyTestProgressReporter({
            eventFilePath: path.join(
                runLog.runDirectoryPath,
                'tests',
                'rust-kernel-fast.jsonl',
            ),
            label: 'rust-kernel-fast',
            threadCount: 1,
        });
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
        const activeReporter = reporter;
        const rustTestObserver = scopeCommandRunObserver(
            'cargo test (optimized test profile, fast)',
            rustTestProgressReporter.observer,
        );
        const parallelResults = await Promise.all(
            parallelLanes.map((lane) =>
                runParallelLane(
                    lane,
                    runLog,
                    abortController,
                    activeReporter,
                    lane.name === rustKernelLaneName
                        ? rustTestObserver
                        : undefined,
                ),
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

        reporter.stop();
        timingDetails = reporter.createTimingDetails();
        printValidationSummary(
            results,
            runLog,
            timingHistory,
            reporter.failureDetails(),
        );
        process.exitCode = overallExitCode(results);
    } catch (error) {
        executionError = error;
        process.exitCode = currentProcessExitCode() || 1;
    } finally {
        reporter?.stop();
        rustTestProgressReporter?.stop();
        try {
            await runLog.finish({
                details: timingDetails,
                ...(executionError === undefined
                    ? {}
                    : { error: executionError }),
                exitCode: currentProcessExitCode(),
            });
        } catch (loggingError) {
            logFinishingError = loggingError;
            if (executionError !== undefined) {
                process.stderr.write(
                    `Failed to finish check diagnostics: ${String(loggingError)}\n`,
                );
            }
        }
    }

    const finalError = executionError ?? logFinishingError;
    if (finalError !== undefined) {
        throw finalError instanceof Error
            ? finalError
            : Object.assign(
                  new Error('Check runner threw a non-Error value.'),
                  {
                      cause: finalError,
                  },
              );
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
