import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { CheckReporter, type CheckFailureDetail } from './check-reporter.js';
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
import { cargoTestArgumentsForRustKernelFast } from './rust-kernel-test-arguments.js';

type LaneStatus = 'failed' | 'passed' | 'stopped';

type ValidationLane = {
    readonly commands: readonly CommandInvocation[];
    readonly name: string;
};

export type ParsedCheckArguments = {
    readonly includeDesktopBrowser: boolean;
};

export type ValidationLaneResult = {
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly name: string;
    readonly status: LaneStatus;
};

type ValidationSummaryContext = {
    readonly failureDetails: readonly CheckFailureDetail[];
    readonly runLogDirectoryPath?: string;
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

const rustKernelLaneName = 'Rust kernel (fmt, clippy, fast test)';
const includeDesktopBrowserArgument = '--include-desktop-browser';
const usage = `Usage: run-check.ts [${includeDesktopBrowserArgument}].`;

export const parseCheckArguments = (
    commandArguments: readonly string[],
): ParsedCheckArguments => {
    let includeDesktopBrowser = false;

    for (const argument of commandArguments) {
        if (argument !== includeDesktopBrowserArgument) {
            throw new Error(`Unknown argument: ${argument}. ${usage}`);
        }
        if (includeDesktopBrowser) {
            throw new Error(
                `${includeDesktopBrowserArgument} may be specified only once. ${usage}`,
            );
        }
        includeDesktopBrowser = true;
    }

    return { includeDesktopBrowser };
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
    commands: [
        createPackageManagerCommand(name, commandArguments, {
            logFileSlug,
            packageManagerRunner,
        }),
    ],
    name,
});

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

export const buildCheckDesktopBrowserLane = (
    packageManagerRunner: PackageManagerRunner,
): ValidationLane =>
    createPackageManagerLane(
        packageManagerRunner,
        'Desktop browser tests',
        'browser-desktop',
        ['run', 'test:browser:built'],
    );

const buildRustKernelLane = (
    packageManagerRunner: PackageManagerRunner,
): ValidationLane => ({
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
    return [
        lane('Lint', 'lint', ['run', 'lint']),
        buildRustKernelLane(packageManagerRunner),
        lane('Knip unused-code scan', 'knip', ['exec', 'knip']),
        lane('Node tests', 'node', [
            'run',
            'test:node:built',
            '--',
            '--maxWorkers',
            '50%',
        ]),
    ];
};

const runGatingLane = async (
    lane: ValidationLane,
    runLog: ActiveLocalRunLog,
    reporter: CheckReporter,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, {
        observer: reporter.createCommandObserver(lane.name),
        outputMode: 'capture',
        runLog,
    });

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
    runLog: ActiveLocalRunLog,
    abortController: AbortController,
    reporter: CheckReporter,
    additionalObserver?: CommandRunObserver,
): Promise<ValidationLaneResult> => {
    const startedAtMilliseconds = performance.now();
    const checkObserver = reporter.createCommandObserver(
        lane.name,
        abortController.signal,
    );
    const exitCode = await runCommandsInSeries(lane.commands, {
        observer:
            additionalObserver === undefined
                ? checkObserver
                : combineCommandRunObservers([
                      checkObserver,
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
        return {
            durationMilliseconds,
            exitCode,
            name: lane.name,
            status: 'passed',
        };
    }
    if (abortController.signal.aborted) {
        reporter.recordStoppedLane(lane.name, durationMilliseconds);
        return {
            durationMilliseconds,
            exitCode,
            name: lane.name,
            status: 'stopped',
        };
    }

    abortController.abort({
        classification: 'sibling-abort',
        initiator: lane.name,
    });
    return {
        durationMilliseconds,
        exitCode,
        name: lane.name,
        status: 'failed',
    };
};

const laneStatusText: Readonly<Record<LaneStatus, string>> = {
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
        lines.push(
            `  ${laneStatusText[result.status]}  ${formatDurationSeconds(result.durationMilliseconds).padStart(8)}  ${result.name}`,
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
        return lines;
    }

    const stoppedNote =
        stoppedCount > 0
            ? ` (${stoppedCount} other lane(s) stopped early)`
            : '';
    lines.push(
        '',
        `Failed: ${failedResults.map((result) => result.name).join(', ')}${stoppedNote}.`,
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
            lines.push(
                'Recent output:',
                ...failureDetail.recentOutputLines.map((line) => `  ${line}`),
            );
        }
    }

    return lines;
};

const printValidationSummary = (
    results: readonly ValidationLaneResult[],
    runLog: ActiveLocalRunLog,
    failureDetails: readonly CheckFailureDetail[],
): void => {
    for (const line of formatValidationSummary(results, {
        failureDetails,
        runLogDirectoryPath: runLog.runDirectoryPath,
    })) {
        process.stdout.write(`${line}\n`);
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
    const parsedArguments = parseCheckArguments(rawArguments);
    const packageManagerRunner = resolvePackageManagerRunner();
    const gatingLanes = buildCheckGatingLanes(packageManagerRunner);
    const parallelLanes = buildCheckParallelLanes(packageManagerRunner);
    const desktopBrowserLane = parsedArguments.includeDesktopBrowser
        ? buildCheckDesktopBrowserLane(packageManagerRunner)
        : undefined;
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: [
            ...gatingLanes,
            ...parallelLanes,
            ...(desktopBrowserLane === undefined ? [] : [desktopBrowserLane]),
        ].map((lane) => lane.name),
        scriptName:
            desktopBrowserLane === undefined ? 'check' : 'check:desktop',
    });
    const results: ValidationLaneResult[] = [];
    const reporter = new CheckReporter();
    let rustTestProgressReporter:
        | ReturnType<typeof createHeavyTestProgressReporter>
        | undefined;
    let executionError: unknown;
    let logFinishingError: unknown;

    try {
        rustTestProgressReporter = createHeavyTestProgressReporter({
            eventFilePath: path.join(
                runLog.runDirectoryPath,
                'tests',
                'rust-kernel-fast.jsonl',
            ),
            label: 'rust-kernel-fast',
            threadCount: 1,
        });

        for (const lane of gatingLanes) {
            const result = await runGatingLane(lane, runLog, reporter);
            results.push(result);
            if (result.exitCode !== 0) {
                printValidationSummary(
                    results,
                    runLog,
                    reporter.failureDetails(),
                );
                process.exitCode = result.exitCode;
                return;
            }
        }

        const abortController = new AbortController();
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
                    reporter,
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
        const routineExitCode = overallExitCode(results);
        if (routineExitCode !== 0) {
            printValidationSummary(results, runLog, reporter.failureDetails());
            process.exitCode = routineExitCode;
            return;
        }

        if (desktopBrowserLane !== undefined) {
            results.push(
                await runGatingLane(desktopBrowserLane, runLog, reporter),
            );
        }
        printValidationSummary(results, runLog, reporter.failureDetails());
        process.exitCode = overallExitCode(results);
    } catch (error) {
        executionError = error;
        process.exitCode = currentProcessExitCode() || 1;
    } finally {
        rustTestProgressReporter?.stop();
        try {
            await runLog.finish({
                details: { results },
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
                  { cause: finalError },
              );
    }
};

if (import.meta.main) {
    void main();
}
