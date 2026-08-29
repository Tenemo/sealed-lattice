import { performance } from 'node:perf_hooks';
import { stripVTControlCharacters } from 'node:util';

import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
    type CommandInvocation,
    type CommandRunObserver,
} from './run-command.js';

type Lane = {
    readonly commands: readonly CommandInvocation[];
    readonly name: string;
};
type LaneStatus = 'failed' | 'passed' | 'stopped';
type LaneResult = {
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly name: string;
    readonly status: LaneStatus;
};
type CommandState = {
    readonly description: string;
    exitCode?: number;
    readonly logPath?: string;
    readonly output: RecentOutput;
    status: LaneStatus | 'running';
};

const desktopBrowserArgument = '--include-desktop-browser';
const recentOutputLineLimit = 20;
const statusLabel: Readonly<Record<LaneStatus, string>> = {
    failed: 'FAIL',
    passed: 'PASS',
    stopped: 'STOP',
};
const formatDuration = (milliseconds: number): string =>
    `${(milliseconds / 1_000).toFixed(1)}s`;

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
                process.stdout.write(
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
                process.stdout.write(
                    `${statusLabel[command.status]} ${laneName} (${formatDuration(event.durationMilliseconds)})${this.#suffix(laneName, command.description)}\n`,
                );
            },
        };
    }

    printFailureDetails(): void {
        for (const [laneName, commands] of this.#commandsByLane) {
            const command = commands.find(
                (candidate) => candidate.status === 'failed',
            );
            if (command === undefined) continue;
            process.stdout.write(`\nFailure detail: ${laneName}\n`);
            if (command.description !== laneName) {
                process.stdout.write(`Command: ${command.description}\n`);
            }
            process.stdout.write(`Exit code: ${command.exitCode ?? 1}\n`);
            if (command.logPath !== undefined) {
                process.stdout.write(`Log: ${command.logPath}\n`);
            }
            const recentOutput = command.output.snapshot();
            if (recentOutput.length > 0) {
                process.stdout.write(
                    `Recent output:\n${recentOutput.map((line) => `  ${line}`).join('\n')}\n`,
                );
            }
        }
    }

    recordStoppedLane(laneName: string, durationMilliseconds: number): void {
        const alreadyReported = this.#commandsByLane
            .get(laneName)
            ?.some((command) => command.status === 'stopped');
        if (alreadyReported !== true) {
            process.stdout.write(
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

const createCargoCommand = (
    description: string,
    args: readonly string[],
    logFileSlug: string,
): CommandInvocation => ({
    args,
    command: 'cargo',
    description,
    env: {
        ...process.env,
        CARGO_INCREMENTAL: '0',
        RUST_BACKTRACE: '1',
    },
    logFileSlug,
});

const buildLanes = (): {
    readonly desktopBrowser: Lane;
    readonly gating: readonly Lane[];
    readonly parallel: readonly Lane[];
} => {
    const packageManagerRunner = resolvePackageManagerRunner();
    const lane = (
        name: string,
        logFileSlug: string,
        args: readonly string[],
    ): Lane => ({
        commands: [
            createPackageManagerCommand(name, args, {
                logFileSlug,
                packageManagerRunner,
            }),
        ],
        name,
    });

    return {
        desktopBrowser: lane('Desktop browser tests', 'browser-desktop', [
            'run',
            'test:browser:built',
        ]),
        gating: [
            lane('Build workspace packages', 'build', ['run', 'build']),
            lane('Type-check workspace', 'tsc', ['run', 'tsc']),
            lane('Smoke npm package', 'smoke-pack-npm', [
                'exec',
                'tsx',
                './tools/ci/verify-packed-package.ts',
            ]),
        ],
        parallel: [
            lane('Lint', 'lint', ['run', 'lint']),
            {
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
                    createCargoCommand(
                        'cargo test (optimized test profile, fast)',
                        [
                            'test',
                            '--locked',
                            '-p',
                            'sealed-lattice-kernel',
                            '--',
                            '--test-threads',
                            '1',
                            '--show-output',
                        ],
                        'cargo-test',
                    ),
                ],
                name: 'Rust kernel (fmt, clippy, fast test)',
            },
            lane('Knip unused-code scan', 'knip', ['exec', 'knip']),
            lane('Node tests', 'node', [
                'run',
                'test:node:built',
                '--',
                '--maxWorkers',
                '50%',
            ]),
        ],
    };
};

const runLane = async (
    lane: Lane,
    runLog: ActiveLocalRunLog,
    reporter: Reporter,
    abortController?: AbortController,
): Promise<LaneResult> => {
    const startedAt = performance.now();
    const exitCode = await runCommandsInSeries(lane.commands, {
        observer: reporter.observer(lane.name, abortController?.signal),
        outputMode: 'capture',
        runLog,
        signal: abortController?.signal,
    });
    const durationMilliseconds = Math.round(performance.now() - startedAt);
    let status: LaneStatus = exitCode === 0 ? 'passed' : 'failed';

    if (exitCode !== 0 && abortController?.signal.aborted === true) {
        status = 'stopped';
        reporter.recordStoppedLane(lane.name, durationMilliseconds);
    } else if (exitCode !== 0 && abortController !== undefined) {
        abortController.abort({ initiator: lane.name });
    }

    return { durationMilliseconds, exitCode, name: lane.name, status };
};

const printSummary = (
    results: readonly LaneResult[],
    runLog: ActiveLocalRunLog,
    reporter: Reporter,
): void => {
    process.stdout.write('\nValidation summary\n');
    for (const result of results) {
        process.stdout.write(
            `  ${statusLabel[result.status]}  ${formatDuration(result.durationMilliseconds).padStart(8)}  ${result.name}\n`,
        );
    }
    const failed = results.filter((result) => result.status === 'failed');
    if (failed.length === 0) {
        process.stdout.write('\nAll validation lanes passed.\n');
        return;
    }
    const stoppedCount = results.filter(
        (result) => result.status === 'stopped',
    ).length;
    const stoppedNote =
        stoppedCount === 0
            ? ''
            : ` (${stoppedCount} other lane(s) stopped early)`;
    process.stdout.write(
        `\nFailed: ${failed.map((result) => result.name).join(', ')}${stoppedNote}.\nPer-lane logs: ${runLog.runDirectoryPath}\n`,
    );
    reporter.printFailureDetails();
};

const resultExitCode = (results: readonly LaneResult[]): number =>
    results.find((result) => result.status === 'failed')?.exitCode ?? 0;

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const includeDesktopBrowser = rawArguments.includes(desktopBrowserArgument);
    if (
        rawArguments.some((argument) => argument !== desktopBrowserArgument) ||
        rawArguments.length > 1
    ) {
        throw new Error(`Usage: run-check.ts [${desktopBrowserArgument}].`);
    }

    const lanes = buildLanes();
    const selectedLanes = [
        ...lanes.gating,
        ...lanes.parallel,
        ...(includeDesktopBrowser ? [lanes.desktopBrowser] : []),
    ];
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: selectedLanes.map((lane) => lane.name),
            scriptName: includeDesktopBrowser ? 'check:desktop' : 'check',
        },
        async (runLog) => {
            const reporter = new Reporter();
            const results: LaneResult[] = [];
            for (const lane of lanes.gating) {
                const result = await runLane(lane, runLog, reporter);
                results.push(result);
                if (result.status === 'failed') {
                    printSummary(results, runLog, reporter);
                    process.exitCode = result.exitCode || 1;
                    return;
                }
            }

            const abortController = new AbortController();
            results.push(
                ...(
                    await Promise.all(
                        lanes.parallel.map((lane) =>
                            runLane(lane, runLog, reporter, abortController),
                        ),
                    )
                ).sort(
                    (first, second) =>
                        second.durationMilliseconds -
                        first.durationMilliseconds,
                ),
            );
            if (resultExitCode(results) === 0 && includeDesktopBrowser) {
                results.push(
                    await runLane(lanes.desktopBrowser, runLog, reporter),
                );
            }
            printSummary(results, runLog, reporter);
            process.exitCode = resultExitCode(results) || undefined;
        },
    );
};

if (import.meta.main) void main();
