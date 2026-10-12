import { appendFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { performance } from 'node:perf_hooks';
import { stripVTControlCharacters } from 'node:util';

import {
    createPackageManagerCommand,
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './command-runner.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import {
    rustFastTestCommands,
    rustWorkspaceCommand,
} from './run-rust-fast-tests.js';

export type Lane = {
    readonly commands: readonly CommandInvocation[];
    // The longest the lane may run under continuous integration, where a hung
    // lane then fails with its own name instead of exhausting the job.
    readonly limitMilliseconds: number;
    readonly name: string;
};
type LaneStatus = 'failed' | 'passed' | 'stopped';
type LaneResult = {
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly name: string;
    readonly status: LaneStatus;
    readonly timedOut: boolean;
};
type CommandState = {
    readonly description: string;
    exitCode?: number;
    readonly logPath?: string;
    readonly output: RecentOutput;
    status: LaneStatus | 'running';
};
// The gating lanes run in order and stop the check at the first failure. The
// parallel lanes then run together, and the first failure stops the others.
// The desktop browser lane runs last, only after every other lane passed.
export type CheckGraph = {
    readonly desktopBrowser?: Lane;
    readonly gating: readonly Lane[];
    readonly parallel: readonly Lane[];
};
type CheckOptions = {
    // GitHub Actions: lane limits, error annotations, grouped failure
    // details and a step summary.
    readonly continuousIntegration: boolean;
    readonly runLog: ActiveLocalRunLog;
    readonly stepSummaryPath?: string;
    readonly write: (text: string) => void;
};

const desktopBrowserArgument = '--include-desktop-browser';
const recentOutputLineLimit = 20;
const minute = 60_000;
// The parallel lanes leave most of a workstation to interactive work: the
// Node lane's longest test files, not its worker count, set its length, and
// the Rust lane finishes well before it. A machine with fewer logical
// processors keeps the counts the tools would choose themselves.
const parallelLaneProcessorLimit = 6;
const statusLabel: Readonly<Record<LaneStatus, string>> = {
    failed: 'FAIL',
    passed: 'PASS',
    stopped: 'STOP',
};
const summaryStatus: Readonly<Record<LaneStatus, string>> = {
    failed: 'Failed',
    passed: 'Passed',
    stopped: 'Stopped',
};
const formatDuration = (milliseconds: number): string =>
    `${(milliseconds / 1_000).toFixed(1)}s`;

// Workflow command values escape their line breaks and percent signs, and a
// property also its separators.
const escapeCommandData = (value: string): string =>
    value.replace(/%/gu, '%25').replace(/\r/gu, '%0D').replace(/\n/gu, '%0A');
const escapeCommandProperty = (value: string): string =>
    escapeCommandData(value).replace(/:/gu, '%3A').replace(/,/gu, '%2C');

class RecentOutput {
    readonly #lines: string[] = [];
    #pending = '';

    append(chunk: string): void {
        const lines = `${this.#pending}${chunk}`.split(/\r\n|\n|\r/u);
        this.#pending = lines.pop() ?? '';
        for (const line of lines) this.#push(line);
    }

    finish(): void {
        this.#push(this.#pending);
        this.#pending = '';
    }

    snapshot(): readonly string[] {
        const pending = stripVTControlCharacters(this.#pending);
        return [
            ...this.#lines,
            ...(pending.trim().length === 0 ? [] : [pending]),
        ].slice(-recentOutputLineLimit);
    }

    #push(line: string): void {
        const plainLine = stripVTControlCharacters(line);
        if (plainLine.trim().length === 0) return;
        this.#lines.push(plainLine);
        if (this.#lines.length > recentOutputLineLimit) this.#lines.shift();
    }
}

class Reporter {
    readonly #commandsByLane = new Map<string, CommandState[]>();
    readonly #continuousIntegration: boolean;
    readonly #write: (text: string) => void;

    constructor(options: CheckOptions) {
        this.#continuousIntegration = options.continuousIntegration;
        this.#write = options.write;
    }

    observer(laneName: string, signal?: AbortSignal): CommandRunObserver {
        return {
            onCommandStart: (event) => {
                const commands = this.#commandsByLane.get(laneName) ?? [];
                commands.push({
                    description: event.invocation.description,
                    logPath: event.logFiles?.combinedPath,
                    output: new RecentOutput(),
                    status: 'running',
                });
                this.#commandsByLane.set(laneName, commands);
                this.#write(
                    `RUN  ${laneName}${this.#suffix(laneName, event.invocation.description)}\n`,
                );
            },
            onCommandOutput: (event) => {
                this.#running(laneName).output.append(event.chunk);
            },
            onCommandExit: (event) => {
                const command = this.#running(laneName);
                command.output.finish();
                command.exitCode = event.exitCode;
                command.status =
                    event.exitCode === 0
                        ? 'passed'
                        : signal?.aborted === true
                          ? 'stopped'
                          : 'failed';
                this.#write(
                    `${statusLabel[command.status]} ${laneName} (${formatDuration(event.durationMilliseconds)})${this.#suffix(laneName, command.description)}\n`,
                );
            },
        };
    }

    printFailureDetails(results: readonly LaneResult[]): void {
        for (const result of results) {
            if (result.status !== 'failed') continue;
            const command = this.#commandsByLane
                .get(result.name)
                ?.find((candidate) => candidate.status === 'failed');
            const lines = [
                ...(result.timedOut
                    ? [
                          `Exceeded its limit after ${formatDuration(result.durationMilliseconds)}.`,
                      ]
                    : []),
                ...(command === undefined
                    ? []
                    : [
                          ...(command.description === result.name
                              ? []
                              : [`Command: ${command.description}`]),
                          `Exit code: ${command.exitCode ?? 1}`,
                          ...(command.logPath === undefined
                              ? []
                              : [`Log: ${command.logPath}`]),
                      ]),
            ];
            const recentOutput = command?.output.snapshot() ?? [];
            if (this.#continuousIntegration) {
                this.#write(
                    `::error title=${escapeCommandProperty(`${result.name} failed`)}::${escapeCommandData(
                        [...lines, ...recentOutput.slice(-5)].join('\n'),
                    )}\n`,
                );
                this.#write(
                    `::group::${escapeCommandData(`Failure detail: ${result.name}`)}\n`,
                );
            } else {
                this.#write(`\nFailure detail: ${result.name}\n`);
            }
            this.#write(lines.map((line) => `${line}\n`).join(''));
            if (recentOutput.length > 0) {
                this.#write(
                    `Recent output:\n${recentOutput.map((line) => `  ${line}`).join('\n')}\n`,
                );
            }
            if (this.#continuousIntegration) this.#write('::endgroup::\n');
        }
    }

    recordStoppedLane(laneName: string, durationMilliseconds: number): void {
        const alreadyReported = this.#commandsByLane
            .get(laneName)
            ?.some((command) => command.status === 'stopped');
        if (alreadyReported !== true) {
            this.#write(
                `STOP ${laneName} (${formatDuration(durationMilliseconds)})\n`,
            );
        }
    }

    #running(laneName: string): CommandState {
        const command = this.#commandsByLane
            .get(laneName)
            ?.find((candidate) => candidate.status === 'running');
        if (command === undefined) {
            throw new Error(`No command is running in ${laneName}.`);
        }
        return command;
    }

    #suffix(laneName: string, description: string): string {
        return description === laneName ? '' : ` - ${description}`;
    }
}

const buildLanes = (includeDesktopBrowser: boolean): CheckGraph => {
    const packageManagerRunner = resolvePackageManagerRunner();
    const processors = availableParallelism();
    const nodeTestWorkers = Math.max(
        1,
        Math.min(parallelLaneProcessorLimit, processors - 1),
    );
    const rustBuildJobs = String(
        Math.min(parallelLaneProcessorLimit, processors),
    );
    const limitRustBuildJobs = (
        command: CommandInvocation,
    ): CommandInvocation => ({
        ...command,
        env: {
            ...(command.env ?? process.env),
            CARGO_BUILD_JOBS: rustBuildJobs,
        },
    });
    const lane = (
        name: string,
        logFileSlug: string,
        args: readonly string[],
        limitMinutes: number,
    ): Lane => ({
        commands: [
            createPackageManagerCommand(name, args, {
                logFileSlug,
                packageManagerRunner,
            }),
        ],
        limitMilliseconds: limitMinutes * minute,
        name,
    });

    return {
        ...(includeDesktopBrowser
            ? {
                  desktopBrowser: lane(
                      'Desktop browser tests',
                      'browser-desktop',
                      ['run', 'test:browser:built'],
                      10,
                  ),
              }
            : {}),
        gating: [
            lane('Build workspace packages', 'build', ['run', 'build'], 15),
            lane('Type-check workspace', 'tsc', ['run', 'tsc'], 5),
            lane(
                'Smoke npm package',
                'smoke-pack-npm',
                ['run', 'smoke:pack:npm:built'],
                10,
            ),
        ],
        parallel: [
            lane('Lint', 'lint', ['run', 'lint'], 10),
            {
                commands: [
                    rustWorkspaceCommand(
                        'cargo fmt --check',
                        ['fmt', '--all', '--', '--check'],
                        'cargo-fmt',
                    ),
                    rustWorkspaceCommand(
                        'cargo clippy',
                        [
                            'clippy',
                            '--offline',
                            '--locked',
                            '--no-default-features',
                            '--workspace',
                            '--all-targets',
                            '--',
                            '-D',
                            'warnings',
                        ],
                        'cargo-clippy',
                    ),
                    // The participant module's browser exports and session
                    // state compile only for WebAssembly, including its
                    // corrupt-participant build.
                    ...[[], ['--features', 'invalid-ballot']].map((features) =>
                        rustWorkspaceCommand(
                            `cargo clippy WebAssembly${features.length === 0 ? '' : ' invalid-ballot'}`,
                            [
                                'clippy',
                                '--offline',
                                '--locked',
                                '-p',
                                'participant-module',
                                '--lib',
                                '--target',
                                'wasm32-unknown-unknown',
                                ...features,
                                '--',
                                '-D',
                                'warnings',
                            ],
                            features.length === 0
                                ? 'cargo-clippy-wasm'
                                : 'cargo-clippy-wasm-invalid-ballot',
                        ),
                    ),
                    // The numerical probes and the key-source screen, with
                    // their binaries, compile only under their features.
                    ...[
                        ['encrypted-ranking', 'numerical-probes'],
                        ['setup-witness', 'key-source-screen'],
                    ].map(([packageName, feature]) =>
                        rustWorkspaceCommand(
                            `cargo clippy ${feature}`,
                            [
                                'clippy',
                                '--offline',
                                '--locked',
                                '--no-default-features',
                                '-p',
                                packageName,
                                '--features',
                                feature,
                                '--all-targets',
                                '--',
                                '-D',
                                'warnings',
                            ],
                            `cargo-clippy-${feature}`,
                        ),
                    ),
                    ...rustFastTestCommands(),
                ].map(limitRustBuildJobs),
                limitMilliseconds: 20 * minute,
                name: 'Rust (fmt, clippy, fast test)',
            },
            lane('Knip unused-code scan', 'knip', ['exec', 'knip'], 5),
            lane(
                'Node tests',
                'node',
                [
                    'run',
                    'test:node:built',
                    '--maxWorkers',
                    String(nodeTestWorkers),
                ],
                30,
            ),
        ],
    };
};

const runLane = async (
    lane: Lane,
    reporter: Reporter,
    options: CheckOptions,
    siblings?: AbortController,
): Promise<LaneResult> => {
    const startedAt = performance.now();
    const limit = new AbortController();
    const limitTimer = options.continuousIntegration
        ? setTimeout(
              () =>
                  limit.abort({
                      classification: 'lane-timeout',
                      limitMilliseconds: lane.limitMilliseconds,
                  }),
              lane.limitMilliseconds,
          )
        : undefined;
    let exitCode: number;
    try {
        exitCode = await runCommandsInSeries(lane.commands, {
            observer: reporter.observer(lane.name, siblings?.signal),
            outputMode: 'capture',
            runLog: options.runLog,
            signal:
                siblings === undefined
                    ? limit.signal
                    : AbortSignal.any([siblings.signal, limit.signal]),
        });
    } finally {
        clearTimeout(limitTimer);
    }
    const durationMilliseconds = Math.round(performance.now() - startedAt);
    const timedOut = limit.signal.aborted;
    let status: LaneStatus = exitCode === 0 ? 'passed' : 'failed';

    if (exitCode !== 0 && !timedOut && siblings?.signal.aborted === true) {
        status = 'stopped';
        reporter.recordStoppedLane(lane.name, durationMilliseconds);
    } else if (exitCode !== 0 && siblings !== undefined) {
        siblings.abort({
            classification: 'sibling-abort',
            initiator: lane.name,
        });
    }

    return {
        durationMilliseconds,
        exitCode: exitCode === 0 && timedOut ? 1 : exitCode,
        name: lane.name,
        status: timedOut ? 'failed' : status,
        timedOut,
    };
};

const writeStepSummary = (
    results: readonly LaneResult[],
    options: CheckOptions,
): void => {
    if (options.stepSummaryPath === undefined) return;
    const failed = results.filter((result) => result.status === 'failed');
    appendFileSync(
        options.stepSummaryPath,
        [
            '### Validation summary',
            '',
            '| Lane | Result | Duration |',
            '| --- | --- | --- |',
            ...results.map(
                (result) =>
                    `| ${result.name} | ${summaryStatus[result.status]}${result.timedOut ? ' (limit exceeded)' : ''} | ${formatDuration(result.durationMilliseconds)} |`,
            ),
            '',
            failed.length === 0
                ? 'All validation lanes passed.'
                : `Failed: ${failed.map((result) => result.name).join(', ')}. The run directory \`${options.runLog.runDirectoryPath}\` holds every lane's log.`,
            '',
        ].join('\n'),
        'utf8',
    );
};

const printSummary = (
    results: readonly LaneResult[],
    reporter: Reporter,
    options: CheckOptions,
): void => {
    options.write('\nValidation summary\n');
    for (const result of results) {
        options.write(
            `  ${statusLabel[result.status]}  ${formatDuration(result.durationMilliseconds).padStart(8)}  ${result.name}\n`,
        );
    }
    writeStepSummary(results, options);
    const failed = results.filter((result) => result.status === 'failed');
    if (failed.length === 0) {
        options.write('\nAll validation lanes passed.\n');
        return;
    }
    const stoppedCount = results.filter(
        (result) => result.status === 'stopped',
    ).length;
    const stoppedNote =
        stoppedCount === 0
            ? ''
            : ` (${stoppedCount} other lane(s) stopped early)`;
    options.write(
        `\nFailed: ${failed.map((result) => result.name).join(', ')}${stoppedNote}.\nPer-lane logs: ${options.runLog.runDirectoryPath}\n`,
    );
    reporter.printFailureDetails(results);
};

// Runs the check graph and returns the lanes' results with the exit code of
// the first failed lane, or zero.
export const runCheckGraph = async (
    graph: CheckGraph,
    options: CheckOptions,
): Promise<{
    readonly exitCode: number;
    readonly results: readonly LaneResult[];
}> => {
    const reporter = new Reporter(options);
    const results: LaneResult[] = [];
    const finish = () => {
        printSummary(results, reporter, options);
        return {
            exitCode:
                results.find((result) => result.status === 'failed')
                    ?.exitCode ?? 0,
            results,
        };
    };
    for (const lane of graph.gating) {
        const result = await runLane(lane, reporter, options);
        results.push(result);
        if (result.status === 'failed') return finish();
    }

    const siblings = new AbortController();
    results.push(
        ...(
            await Promise.all(
                graph.parallel.map((lane) =>
                    runLane(lane, reporter, options, siblings),
                ),
            )
        ).sort(
            (first, second) =>
                second.durationMilliseconds - first.durationMilliseconds,
        ),
    );
    if (
        graph.desktopBrowser !== undefined &&
        results.every((result) => result.status === 'passed')
    ) {
        results.push(await runLane(graph.desktopBrowser, reporter, options));
    }
    return finish();
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const includeDesktopBrowser = rawArguments.includes(desktopBrowserArgument);
    if (
        rawArguments.some((argument) => argument !== desktopBrowserArgument) ||
        rawArguments.length > 1
    ) {
        throw new Error(`Usage: run-check.ts [${desktopBrowserArgument}].`);
    }

    const graph = buildLanes(includeDesktopBrowser);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [
                ...graph.gating,
                ...graph.parallel,
                ...(graph.desktopBrowser === undefined
                    ? []
                    : [graph.desktopBrowser]),
            ].map((lane) => lane.name),
            scriptName: includeDesktopBrowser ? 'check:desktop' : 'check',
        },
        async (runLog) => {
            const continuousIntegration = process.env.GITHUB_ACTIONS === 'true';
            const { exitCode } = await runCheckGraph(graph, {
                continuousIntegration,
                runLog,
                ...(continuousIntegration &&
                process.env.GITHUB_STEP_SUMMARY !== undefined
                    ? { stepSummaryPath: process.env.GITHUB_STEP_SUMMARY }
                    : {}),
                write: (text) => process.stdout.write(text),
            });
            process.exitCode = exitCode || undefined;
        },
    );
};

if (import.meta.main) void main();
