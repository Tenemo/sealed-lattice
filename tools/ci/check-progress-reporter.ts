import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { Writable } from 'node:stream';

import { createLogUpdate } from 'log-update';

import type {
    CommandInvocation,
    CommandOutputEvent,
    CommandRunObserver,
    CommandStartEvent,
} from './run-command.js';

export type CheckProgressStatus =
    | 'failed'
    | 'passed'
    | 'running'
    | 'stopped'
    | 'waiting';

type CheckCommandStatus = CheckProgressStatus;

type CheckProgressSource =
    | 'commands'
    | 'libtest'
    | 'opaque'
    | 'turbo'
    | 'vitest';
type CheckProgressUnit =
    | 'command'
    | 'task'
    | 'task seen'
    | 'test'
    | 'test file';

type CheckProgressMetric = {
    completed: number;
    total?: number;
    unit: CheckProgressUnit;
};

export type CheckProgressCommandPlan = {
    readonly description: string;
    readonly expectedDurationMilliseconds?: number;
};

export type CheckProgressLanePlan = {
    readonly commands: readonly CheckProgressCommandPlan[];
    readonly expectedDurationMilliseconds?: number;
    readonly name: string;
    readonly progress?: {
        readonly primary?: CheckProgressMetric;
        readonly secondary?: CheckProgressMetric;
        readonly source: CheckProgressSource;
    };
};

type CheckProgressHistoryMetric = {
    readonly primary?: CheckProgressMetric;
    readonly secondary?: CheckProgressMetric;
};

export type CheckTimingHistory = {
    readonly commandDurationMilliseconds: ReadonlyMap<string, number>;
    readonly laneProgress: ReadonlyMap<string, CheckProgressHistoryMetric>;
    readonly laneDurationMilliseconds: ReadonlyMap<string, number>;
    readonly totalDurationMilliseconds?: number;
};

export type CheckRunCommandTiming = {
    readonly description: string;
    readonly durationMilliseconds?: number;
    readonly exitCode?: number;
    readonly logPath?: string;
    readonly status: CheckCommandStatus;
};

export type CheckRunLaneTiming = {
    readonly commands: readonly CheckRunCommandTiming[];
    readonly durationMilliseconds?: number;
    readonly name: string;
    readonly progress?: CheckProgressHistoryMetric;
    readonly status: CheckProgressStatus;
};

export type CheckRunTimingDetails = {
    readonly completedCommandCount: number;
    readonly lanes: readonly CheckRunLaneTiming[];
    readonly objectVersion: 'sealed-lattice-check-run-details-v1';
    readonly totalCommandCount: number;
};

export type CheckFailureDetail = {
    readonly commandDescription?: string;
    readonly exitCode?: number;
    readonly laneName: string;
    readonly logPath?: string;
    readonly recentOutputLines: readonly string[];
};

type CommandState = {
    description: string;
    durationMilliseconds?: number;
    exitCode?: number;
    expectedDurationMilliseconds?: number;
    outputLineBuffer: OutputLineBuffer;
    logPath?: string;
    recentOutput: RecentOutputBuffer;
    startedAtMilliseconds?: number;
    status: CheckCommandStatus;
};

type LaneState = {
    commands: CommandState[];
    durationMilliseconds?: number;
    expectedDurationMilliseconds?: number;
    finishedAtMilliseconds?: number;
    name: string;
    primaryProgress?: CheckProgressMetric;
    progressSource: CheckProgressSource;
    secondaryProgress?: CheckProgressMetric;
    startedAtMilliseconds?: number;
    status: CheckProgressStatus;
    libtestCompletedTestCount: number;
    libtestDiscoveredTestCount: number;
    libtestRunningTestCount?: number;
    turboTaskIdsSeen: Set<string>;
};

type TerminalWriter = Pick<Writable, 'write'> & {
    readonly columns?: number;
    readonly isTTY?: boolean;
    readonly rows?: number;
};

const previousTimingDetailsVersion = 'sealed-lattice-check-run-details-v1';
const outputLineLimit = 80;
const latestOutputLineLimit = 6;
const failureOutputLineLimit = 40;
const defaultRenderIntervalMilliseconds = 100;
const renderDebounceMilliseconds = 25;
const fallbackTerminalWidth = 80;
const minimumTerminalWidth = 40;
const ansiEscapePattern = new RegExp(
    String.raw`\u001B\[[0-?]*[ -/]*[@-~]`,
    'gu',
);
const progressEventPrefix = 'sealed-lattice-progress ';

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const isUsableDuration = (value: unknown): value is number =>
    typeof value === 'number' && Number.isFinite(value) && value >= 0;

const emptyTimingHistory = (): CheckTimingHistory => ({
    commandDurationMilliseconds: new Map(),
    laneProgress: new Map(),
    laneDurationMilliseconds: new Map(),
});

export const checkCommandTimingKey = (
    laneName: string,
    commandDescription: string,
): string => `${laneName}\u0000${commandDescription}`;

export const formatProgressDuration = (
    durationMilliseconds: number,
): string => {
    const durationSeconds = durationMilliseconds / 1000;
    if (durationSeconds < 60) {
        return `${durationSeconds.toFixed(1)}s`;
    }

    const wholeSeconds = Math.round(durationSeconds);
    const minutes = Math.floor(wholeSeconds / 60);
    const seconds = wholeSeconds % 60;

    return `${minutes}m${String(seconds).padStart(2, '0')}s`;
};

const sanitizeOutputLine = (line: string): string =>
    line.replace(ansiEscapePattern, '').trimEnd();

const formatBufferedOutputLine = (prefix: string, line: string): string => {
    const sanitizedLine = sanitizeOutputLine(line);

    return sanitizedLine.length === 0 ? '' : `${prefix} > ${sanitizedLine}`;
};

export class RecentOutputBuffer {
    readonly #limit: number;
    #lines: string[] = [];
    #pendingLine:
        | {
              readonly prefix: string;
              readonly text: string;
          }
        | undefined;

    constructor(limit = outputLineLimit) {
        this.#limit = limit;
    }

    append(prefix: string, chunk: string): void {
        const normalizedChunk = chunk
            .replace(/\r\n/gu, '\n')
            .replace(/\r/gu, '\n');
        if (normalizedChunk.length === 0) {
            return;
        }
        if (
            this.#pendingLine !== undefined &&
            this.#pendingLine.prefix !== prefix
        ) {
            this.#pushLine(this.#pendingLine.prefix, this.#pendingLine.text);
            this.#pendingLine = undefined;
        }

        const chunkLines = normalizedChunk.split('\n');
        const firstLine = chunkLines[0] ?? '';
        const firstLinePrefix = this.#pendingLine?.prefix ?? prefix;
        chunkLines[0] = `${this.#pendingLine?.text ?? ''}${firstLine}`;
        this.#pendingLine = undefined;

        for (const chunkLine of chunkLines.slice(0, -1)) {
            this.#pushLine(firstLinePrefix, chunkLine);
        }

        const trailingLine = chunkLines[chunkLines.length - 1] ?? '';
        if (trailingLine.length > 0) {
            this.#pendingLine = {
                prefix,
                text: trailingLine,
            };
        }
    }

    snapshot(limit = this.#limit): readonly string[] {
        const pendingLine =
            this.#pendingLine === undefined
                ? ''
                : formatBufferedOutputLine(
                      this.#pendingLine.prefix,
                      this.#pendingLine.text,
                  );
        const lines =
            pendingLine.length === 0
                ? this.#lines
                : [...this.#lines, pendingLine];

        return lines.slice(-limit);
    }

    #pushLine(prefix: string, line: string): void {
        const formattedLine = formatBufferedOutputLine(prefix, line);
        if (formattedLine.length === 0) {
            return;
        }

        this.#lines.push(formattedLine);
        if (this.#lines.length > this.#limit) {
            this.#lines = this.#lines.slice(-this.#limit);
        }
    }
}

class OutputLineBuffer {
    #pendingLine = '';

    append(chunk: string, onLine: (line: string) => void): void {
        const normalizedChunk = chunk
            .replace(/\r\n/gu, '\n')
            .replace(/\r/gu, '\n');
        if (normalizedChunk.length === 0) {
            return;
        }

        const lines = `${this.#pendingLine}${normalizedChunk}`.split('\n');
        this.#pendingLine = lines.pop() ?? '';
        for (const line of lines) {
            onLine(line);
        }
    }

    flush(onLine: (line: string) => void): void {
        if (this.#pendingLine.length === 0) {
            return;
        }

        onLine(this.#pendingLine);
        this.#pendingLine = '';
    }
}

const cloneProgressMetric = (
    metric: CheckProgressMetric | undefined,
): CheckProgressMetric | undefined =>
    metric === undefined
        ? undefined
        : {
              completed: metric.completed,
              total: metric.total,
              unit: metric.unit,
          };

const isProgressUnit = (value: unknown): value is CheckProgressUnit =>
    value === 'command' ||
    value === 'task' ||
    value === 'task seen' ||
    value === 'test' ||
    value === 'test file';

const readProgressMetric = (
    value: unknown,
): CheckProgressMetric | undefined => {
    if (!isRecord(value) || !isUsableDuration(value.completed)) {
        return undefined;
    }
    if (!isProgressUnit(value.unit)) {
        return undefined;
    }

    return {
        completed: value.completed,
        total: isUsableDuration(value.total) ? value.total : undefined,
        unit: value.unit,
    };
};

const readProgressHistoryMetric = (
    value: unknown,
): CheckProgressHistoryMetric | undefined => {
    if (!isRecord(value)) {
        return undefined;
    }
    const primary = readProgressMetric(value.primary);
    const secondary = readProgressMetric(value.secondary);
    if (primary === undefined && secondary === undefined) {
        return undefined;
    }

    return {
        primary,
        secondary,
    };
};

const readCheckRunDetails = (
    value: unknown,
): CheckRunTimingDetails | undefined => {
    if (
        !isRecord(value) ||
        value.objectVersion !== previousTimingDetailsVersion ||
        !Array.isArray(value.lanes)
    ) {
        return undefined;
    }

    const lanes: CheckRunLaneTiming[] = [];
    for (const laneValue of value.lanes) {
        if (
            !isRecord(laneValue) ||
            typeof laneValue.name !== 'string' ||
            !Array.isArray(laneValue.commands)
        ) {
            return undefined;
        }

        const commands: CheckRunCommandTiming[] = [];
        for (const commandValue of laneValue.commands) {
            if (
                !isRecord(commandValue) ||
                typeof commandValue.description !== 'string'
            ) {
                return undefined;
            }
            commands.push({
                description: commandValue.description,
                durationMilliseconds: isUsableDuration(
                    commandValue.durationMilliseconds,
                )
                    ? commandValue.durationMilliseconds
                    : undefined,
                exitCode:
                    typeof commandValue.exitCode === 'number'
                        ? commandValue.exitCode
                        : undefined,
                logPath:
                    typeof commandValue.logPath === 'string'
                        ? commandValue.logPath
                        : undefined,
                status:
                    typeof commandValue.status === 'string'
                        ? (commandValue.status as CheckCommandStatus)
                        : 'waiting',
            });
        }

        lanes.push({
            commands,
            durationMilliseconds: isUsableDuration(
                laneValue.durationMilliseconds,
            )
                ? laneValue.durationMilliseconds
                : undefined,
            name: laneValue.name,
            progress: readProgressHistoryMetric(laneValue.progress),
            status:
                typeof laneValue.status === 'string'
                    ? (laneValue.status as CheckProgressStatus)
                    : 'waiting',
        });
    }

    return {
        completedCommandCount: isUsableDuration(value.completedCommandCount)
            ? value.completedCommandCount
            : 0,
        lanes,
        objectVersion: previousTimingDetailsVersion,
        totalCommandCount: isUsableDuration(value.totalCommandCount)
            ? value.totalCommandCount
            : 0,
    };
};

export const extractCheckTimingHistoryFromSummary = (
    summary: unknown,
): CheckTimingHistory | undefined => {
    if (!isRecord(summary)) {
        return undefined;
    }
    if (summary.scriptName !== 'check' || summary.exitCode !== 0) {
        return undefined;
    }

    const totalDurationMilliseconds = isUsableDuration(
        summary.durationMilliseconds,
    )
        ? summary.durationMilliseconds
        : undefined;
    const details = readCheckRunDetails(summary.details);
    const laneDurationMilliseconds = new Map<string, number>();
    const commandDurationMilliseconds = new Map<string, number>();
    const laneProgress = new Map<string, CheckProgressHistoryMetric>();

    if (details !== undefined) {
        for (const lane of details.lanes) {
            if (isUsableDuration(lane.durationMilliseconds)) {
                laneDurationMilliseconds.set(
                    lane.name,
                    lane.durationMilliseconds,
                );
            }
            if (lane.progress !== undefined) {
                laneProgress.set(lane.name, lane.progress);
            }
            for (const command of lane.commands) {
                if (isUsableDuration(command.durationMilliseconds)) {
                    commandDurationMilliseconds.set(
                        checkCommandTimingKey(lane.name, command.description),
                        command.durationMilliseconds,
                    );
                }
            }
        }
    }

    return {
        commandDurationMilliseconds,
        laneProgress,
        laneDurationMilliseconds,
        totalDurationMilliseconds,
    };
};

export const readPreviousCheckTimingHistory = async (
    logRootDirectoryPath = path.join(process.cwd(), 'logs'),
): Promise<CheckTimingHistory> => {
    const runIndexPath = path.join(logRootDirectoryPath, 'runs.jsonl');
    let runIndexText: string;
    try {
        runIndexText = await readFile(runIndexPath, 'utf8');
    } catch (error) {
        if (isRecord(error) && 'code' in error && error.code === 'ENOENT') {
            return emptyTimingHistory();
        }
        throw error;
    }

    const runIndexLines = runIndexText
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    for (const runIndexLine of [...runIndexLines].reverse()) {
        try {
            const timingHistory = extractCheckTimingHistoryFromSummary(
                JSON.parse(runIndexLine) as unknown,
            );
            if (timingHistory !== undefined) {
                return timingHistory;
            }
        } catch {
            // Ignore corrupt local history lines. They are diagnostics only.
        }
    }

    return emptyTimingHistory();
};

const laneStatusLabels: Readonly<Record<CheckProgressStatus, string>> = {
    failed: 'fail',
    passed: 'pass',
    running: 'run',
    stopped: 'stop',
    waiting: 'wait',
};

const commandIsFinished = (command: CommandState): boolean =>
    command.status === 'failed' || command.status === 'passed';

const commandProgressForLane = (lane: LaneState): CheckProgressMetric => ({
    completed: lane.commands.filter(commandIsFinished).length,
    total: lane.commands.length,
    unit: 'command',
});

const primaryProgressForLane = (
    lane: LaneState,
): CheckProgressMetric | undefined => {
    if (
        lane.progressSource === 'commands' ||
        lane.progressSource === 'libtest'
    ) {
        return commandProgressForLane(lane);
    }

    return lane.primaryProgress;
};

const laneElapsedMilliseconds = (
    lane: LaneState,
    nowMilliseconds: number,
): number => {
    if (lane.durationMilliseconds !== undefined) {
        return lane.durationMilliseconds;
    }
    if (lane.startedAtMilliseconds === undefined) {
        return 0;
    }

    return Math.max(0, nowMilliseconds - lane.startedAtMilliseconds);
};

const truncateLine = (line: string, maximumLength: number): string => {
    if (line.length <= maximumLength) {
        return line;
    }
    if (maximumLength <= 3) {
        return line.slice(0, maximumLength);
    }

    return `${line.slice(0, maximumLength - 3)}...`;
};

const progressUnitLabel = (unit: CheckProgressUnit, count: number): string => {
    switch (unit) {
        case 'command':
            return count === 1 ? 'command' : 'commands';
        case 'task':
            return count === 1 ? 'task' : 'tasks';
        case 'task seen':
            return count === 1 ? 'task seen' : 'tasks seen';
        case 'test':
            return count === 1 ? 'test' : 'tests';
        case 'test file':
            return count === 1 ? 'test file' : 'test files';
    }
};

const formatProgressMetric = (metric: CheckProgressMetric): string => {
    if (metric.total !== undefined) {
        return `${metric.completed}/${metric.total} ${progressUnitLabel(
            metric.unit,
            metric.total,
        )}`;
    }

    return `${metric.completed} ${progressUnitLabel(
        metric.unit,
        metric.completed,
    )}`;
};

const formatLaneProgress = (lane: LaneState): string => {
    const primary = primaryProgressForLane(lane);
    const secondary = lane.secondaryProgress;
    if (lane.progressSource === 'vitest') {
        return secondary === undefined ? '' : formatProgressMetric(secondary);
    }
    if (lane.progressSource === 'libtest' && secondary !== undefined) {
        return formatProgressMetric(secondary);
    }
    if (primary === undefined) {
        return '';
    }
    if (secondary === undefined) {
        return formatProgressMetric(primary);
    }

    return `${formatProgressMetric(primary)}, ${formatProgressMetric(
        secondary,
    )}`;
};

const readProgressCount = (value: unknown): number | undefined =>
    isUsableDuration(value) ? Math.trunc(value) : undefined;

const readPositiveIntegerEnvironment = (
    environmentVariableName: string,
): number | undefined => {
    const value = process.env[environmentVariableName];
    if (value === undefined) {
        return undefined;
    }

    const parsedValue = Number.parseInt(value, 10);

    return Number.isFinite(parsedValue) && parsedValue > 0
        ? parsedValue
        : undefined;
};

const terminalColumnCount = (output: TerminalWriter): number =>
    Math.max(
        output.columns ??
            readPositiveIntegerEnvironment('COLUMNS') ??
            fallbackTerminalWidth,
        minimumTerminalWidth,
    );

const terminalRowCount = (output: TerminalWriter): number | undefined =>
    output.rows ?? readPositiveIntegerEnvironment('LINES');

export class CheckProgressReporter {
    readonly #history: CheckTimingHistory;
    readonly #laneStates: LaneState[];
    readonly #latestOutput = new RecentOutputBuffer();
    readonly #logUpdate: ReturnType<typeof createLogUpdate> | undefined;
    readonly #now: () => number;
    readonly #output: TerminalWriter;
    readonly #redrawEnabled: boolean;
    readonly #renderIntervalMilliseconds: number;
    readonly #startedAtMilliseconds: number;
    #interval: NodeJS.Timeout | undefined;
    #lastRenderedFrame: string | undefined;
    #renderTimeout: NodeJS.Timeout | undefined;

    constructor(input: {
        readonly history?: CheckTimingHistory;
        readonly lanes: readonly CheckProgressLanePlan[];
        readonly now?: () => number;
        readonly output?: TerminalWriter;
        readonly redrawEnabled?: boolean;
        readonly renderIntervalMilliseconds?: number;
    }) {
        this.#history = input.history ?? emptyTimingHistory();
        this.#laneStates = input.lanes.map((lane) => ({
            commands: lane.commands.map((command) => ({
                description: command.description,
                expectedDurationMilliseconds:
                    command.expectedDurationMilliseconds,
                outputLineBuffer: new OutputLineBuffer(),
                recentOutput: new RecentOutputBuffer(),
                status: 'waiting',
            })),
            expectedDurationMilliseconds: lane.expectedDurationMilliseconds,
            name: lane.name,
            primaryProgress: cloneProgressMetric(lane.progress?.primary),
            progressSource:
                lane.progress?.source ??
                (lane.commands.length > 1 ? 'commands' : 'opaque'),
            secondaryProgress: cloneProgressMetric(lane.progress?.secondary),
            status: 'waiting',
            libtestCompletedTestCount: 0,
            libtestDiscoveredTestCount: 0,
            turboTaskIdsSeen: new Set<string>(),
        }));
        this.#now = input.now ?? performance.now.bind(performance);
        this.#output = input.output ?? process.stdout;
        this.#redrawEnabled =
            input.redrawEnabled ??
            (this.#output.isTTY === true && process.env.CI !== 'true');
        this.#logUpdate = this.#redrawEnabled
            ? createLogUpdate(this.#output as NodeJS.WritableStream, {
                  defaultHeight: terminalRowCount(this.#output),
                  defaultWidth: terminalColumnCount(this.#output),
                  showCursor: true,
              })
            : undefined;
        this.#renderIntervalMilliseconds =
            input.renderIntervalMilliseconds ??
            defaultRenderIntervalMilliseconds;
        this.#startedAtMilliseconds = this.#now();
    }

    createCommandObserver(laneName: string): CommandRunObserver {
        return {
            onCommandExit: (event) => {
                this.#recordCommandExit(laneName, event);
            },
            onCommandOutput: (event) => {
                this.#recordCommandOutput(laneName, event);
            },
            onCommandStart: (event) => {
                this.#recordCommandStart(laneName, event);
            },
        };
    }

    createTimingDetails(): CheckRunTimingDetails {
        return {
            completedCommandCount: this.completedCommandCount(),
            lanes: this.#laneStates.map((lane) => ({
                commands: lane.commands.map((command) => ({
                    description: command.description,
                    durationMilliseconds: command.durationMilliseconds,
                    exitCode: command.exitCode,
                    logPath: command.logPath,
                    status: command.status,
                })),
                durationMilliseconds: lane.durationMilliseconds,
                name: lane.name,
                progress:
                    lane.primaryProgress === undefined &&
                    lane.secondaryProgress === undefined
                        ? undefined
                        : {
                              primary: cloneProgressMetric(
                                  lane.primaryProgress,
                              ),
                              secondary: cloneProgressMetric(
                                  lane.secondaryProgress,
                              ),
                          },
                status: lane.status,
            })),
            objectVersion: previousTimingDetailsVersion,
            totalCommandCount: this.totalCommandCount(),
        };
    }

    failureDetails(): readonly CheckFailureDetail[] {
        const failedDetails: CheckFailureDetail[] = [];
        for (const lane of this.#laneStates) {
            if (lane.status !== 'failed') {
                continue;
            }
            const failedCommand = lane.commands.find(
                (command) => command.status === 'failed',
            );
            if (failedCommand === undefined) {
                failedDetails.push({
                    laneName: lane.name,
                    recentOutputLines: this.#latestOutput.snapshot(
                        latestOutputLineLimit,
                    ),
                });
                continue;
            }

            failedDetails.push({
                commandDescription: failedCommand.description,
                exitCode: failedCommand.exitCode,
                laneName: lane.name,
                logPath: failedCommand.logPath,
                recentOutputLines: failedCommand.recentOutput.snapshot(
                    failureOutputLineLimit,
                ),
            });
        }

        return failedDetails;
    }

    recordLaneResult(laneName: string, status: CheckProgressStatus): void {
        const lane = this.#requiredLane(laneName);
        const nowMilliseconds = this.#now();
        lane.status = status;
        lane.finishedAtMilliseconds = nowMilliseconds;
        lane.durationMilliseconds =
            lane.startedAtMilliseconds === undefined
                ? 0
                : Math.round(nowMilliseconds - lane.startedAtMilliseconds);

        if (status === 'stopped') {
            for (const command of lane.commands) {
                if (command.status === 'waiting') {
                    command.status = 'stopped';
                }
                if (command.status === 'running') {
                    command.status = 'stopped';
                    command.durationMilliseconds =
                        command.startedAtMilliseconds === undefined
                            ? undefined
                            : Math.round(
                                  nowMilliseconds -
                                      command.startedAtMilliseconds,
                              );
                }
            }
        }

        if (
            !this.#redrawEnabled &&
            (lane.commands.length > 1 || status === 'stopped')
        ) {
            this.#writeLine(
                `${laneStatusLabels[status]} ${lane.name} ${formatProgressDuration(
                    lane.durationMilliseconds,
                )}`,
            );
        }
        this.#requestRender();
    }

    start(): void {
        if (this.#redrawEnabled) {
            this.#render();
            this.#interval = setInterval(
                () => this.#render(),
                this.#renderIntervalMilliseconds,
            );
            this.#interval.unref?.();

            return;
        }

        this.#writeLine(this.#headerLine());
    }

    stop(): void {
        if (this.#interval !== undefined) {
            clearInterval(this.#interval);
            this.#interval = undefined;
        }
        if (this.#renderTimeout !== undefined) {
            clearTimeout(this.#renderTimeout);
            this.#renderTimeout = undefined;
        }
        if (this.#redrawEnabled) {
            this.#logUpdate?.clear();
            this.#lastRenderedFrame = undefined;
        }
    }

    totalCommandCount(): number {
        return this.#laneStates.reduce(
            (total, lane) => total + lane.commands.length,
            0,
        );
    }

    completedCommandCount(): number {
        return this.#laneStates.reduce(
            (total, lane) =>
                total +
                lane.commands.filter((command) => commandIsFinished(command))
                    .length,
            0,
        );
    }

    #currentCommand(lane: LaneState): CommandState | undefined {
        return lane.commands.find((command) => command.status === 'running');
    }

    #headerLine(): string {
        const elapsedMilliseconds = Math.round(
            this.#now() - this.#startedAtMilliseconds,
        );
        const expectedDuration =
            this.#history.totalDurationMilliseconds === undefined
                ? ''
                : `  expected ${formatProgressDuration(
                      this.#history.totalDurationMilliseconds,
                  )}`;

        return `check  commands ${this.completedCommandCount()}/${this.totalCommandCount()}  elapsed ${formatProgressDuration(
            elapsedMilliseconds,
        )}${expectedDuration}`;
    }

    #laneLine(lane: LaneState): string {
        const nowMilliseconds = this.#now();
        const progressText = formatLaneProgress(lane);
        const formattedProgress =
            progressText.length === 0 ? ''.padEnd(24) : progressText.padEnd(24);
        const elapsedDuration = formatProgressDuration(
            laneElapsedMilliseconds(lane, nowMilliseconds),
        ).padStart(8);
        const expectedDuration =
            lane.expectedDurationMilliseconds === undefined
                ? ''.padEnd(15)
                : ` expected ${formatProgressDuration(
                      lane.expectedDurationMilliseconds,
                  )}`.padEnd(15);
        const currentCommand = this.#currentCommand(lane);
        const currentCommandExpectedDuration =
            currentCommand?.expectedDurationMilliseconds === undefined
                ? ''
                : ` expected ${formatProgressDuration(
                      currentCommand.expectedDurationMilliseconds,
                  )}`;
        const currentCommandText =
            currentCommand === undefined ||
            currentCommand.description === lane.name
                ? ''
                : ` - ${currentCommand.description}${currentCommandExpectedDuration}`;

        return `[${laneStatusLabels[lane.status].padEnd(
            4,
        )}] ${formattedProgress} ${elapsedDuration}${expectedDuration} ${lane.name}${currentCommandText}`;
    }

    #recordCommandExit(
        laneName: string,
        event: {
            readonly durationMilliseconds: number;
            readonly exitCode: number;
            readonly invocation: CommandInvocation;
        },
    ): void {
        const command = this.#requiredCommand(
            laneName,
            event.invocation.description,
        );
        command.outputLineBuffer.flush((line) => {
            this.#recordCommandOutputLine(laneName, command, line);
        });
        command.durationMilliseconds = event.durationMilliseconds;
        command.exitCode = event.exitCode;
        command.status = event.exitCode === 0 ? 'passed' : 'failed';

        if (!this.#redrawEnabled) {
            const commandDescription =
                event.invocation.description === laneName
                    ? ''
                    : ` ${event.invocation.description}`;
            this.#writeLine(
                `${laneStatusLabels[command.status]} ${laneName} ${formatProgressDuration(
                    event.durationMilliseconds,
                )}${commandDescription}`,
            );
        }
        this.#requestRender();
    }

    #recordCommandOutput(laneName: string, event: CommandOutputEvent): void {
        const command = this.#requiredCommand(
            laneName,
            event.invocation.description,
        );
        command.outputLineBuffer.append(event.chunk, (line) => {
            this.#recordCommandOutputLine(laneName, command, line);
        });
        this.#requestRender();
    }

    #recordCommandOutputLine(
        laneName: string,
        command: CommandState,
        line: string,
    ): void {
        const lane = this.#requiredLane(laneName);
        if (this.#consumeProgressLine(lane, line)) {
            return;
        }

        const outputPrefix = `${laneName}`;
        const lineWithTerminator = `${line}\n`;
        command.recentOutput.append(outputPrefix, lineWithTerminator);
        this.#latestOutput.append(outputPrefix, lineWithTerminator);
    }

    #recordCommandStart(laneName: string, event: CommandStartEvent): void {
        const lane = this.#requiredLane(laneName);
        const command = this.#requiredCommand(
            laneName,
            event.invocation.description,
        );
        const nowMilliseconds = this.#now();
        lane.status = 'running';
        lane.startedAtMilliseconds ??= nowMilliseconds;
        command.status = 'running';
        command.startedAtMilliseconds = nowMilliseconds;
        command.logPath = event.logFiles?.combinedPath;

        if (!this.#redrawEnabled) {
            const progressText = formatLaneProgress(lane);
            const commandDescription =
                event.invocation.description === lane.name
                    ? ''
                    : ` ${event.invocation.description}`;
            const progressDescription =
                progressText.length === 0 ? '' : ` ${progressText}`;
            this.#writeLine(
                `run ${laneName}${progressDescription}${commandDescription}`,
            );
        }
        this.#requestRender();
    }

    #render(): void {
        if (!this.#redrawEnabled) {
            return;
        }
        const terminalWidth = terminalColumnCount(this.#output);
        const frame = this.#renderLines()
            .map((line) => truncateLine(line, terminalWidth))
            .join('\n');
        if (frame === this.#lastRenderedFrame) {
            return;
        }

        this.#lastRenderedFrame = frame;
        this.#logUpdate?.(frame);
    }

    #renderLines(): readonly string[] {
        const lines = [
            this.#headerLine(),
            '',
            ...this.#laneStates.map((lane) => this.#laneLine(lane)),
        ];
        const latestOutput = this.#latestOutput.snapshot(latestOutputLineLimit);
        if (latestOutput.length > 0) {
            lines.push('', 'latest output', ...latestOutput);
        }

        return lines;
    }

    #consumeProgressLine(lane: LaneState, line: string): boolean {
        if (line.startsWith(progressEventPrefix)) {
            this.#consumeStructuredProgressLine(lane, line);

            return true;
        }
        if (lane.progressSource === 'turbo') {
            this.#consumeTurboProgressLine(lane, line);
        }
        if (lane.progressSource === 'libtest') {
            this.#consumeLibtestProgressLine(lane, line);
        }

        return false;
    }

    #consumeStructuredProgressLine(lane: LaneState, line: string): void {
        try {
            const payload = JSON.parse(
                line.slice(progressEventPrefix.length),
            ) as unknown;
            if (!isRecord(payload) || payload.tool !== 'vitest') {
                return;
            }

            const files = isRecord(payload.files) ? payload.files : undefined;
            const tests = isRecord(payload.tests) ? payload.tests : undefined;
            const completedFiles = readProgressCount(files?.completed);
            const totalFiles = readProgressCount(files?.total);
            const completedTests = readProgressCount(tests?.completed);
            const totalTests = readProgressCount(tests?.total);
            if (completedFiles !== undefined) {
                lane.primaryProgress = {
                    completed: completedFiles,
                    total: totalFiles,
                    unit: 'test file',
                };
            }
            if (
                completedTests !== undefined &&
                (completedTests > 0 ||
                    (totalTests !== undefined && totalTests > 0))
            ) {
                lane.secondaryProgress = {
                    completed: completedTests,
                    total: totalTests,
                    unit: 'test',
                };
            }
        } catch {
            // Progress markers are diagnostic only; malformed lines should not
            // fail the validation run.
        }
    }

    #consumeTurboProgressLine(lane: LaneState, line: string): void {
        const runningMatch = /Running build in (\d+) packages/u.exec(line);
        if (runningMatch?.[1] !== undefined) {
            lane.primaryProgress = {
                completed: lane.primaryProgress?.completed ?? 0,
                total: Number(runningMatch[1]),
                unit: 'task seen',
            };

            return;
        }

        const taskSeenMatch =
            /^([^:\s]+):build:\s+(?:cache hit|cache miss)/u.exec(line);
        if (taskSeenMatch?.[1] !== undefined) {
            lane.turboTaskIdsSeen.add(taskSeenMatch[1]);
            lane.primaryProgress = {
                completed: lane.turboTaskIdsSeen.size,
                total: lane.primaryProgress?.total,
                unit: 'task seen',
            };

            return;
        }

        const finalTaskMatch =
            /Tasks:\s+(\d+)\s+successful,\s+(\d+)\s+total/u.exec(line);
        if (
            finalTaskMatch?.[1] !== undefined &&
            finalTaskMatch[2] !== undefined
        ) {
            lane.primaryProgress = {
                completed: Number(finalTaskMatch[1]),
                total: Number(finalTaskMatch[2]),
                unit: 'task',
            };
        }
    }

    #consumeLibtestProgressLine(lane: LaneState, line: string): void {
        const runningMatch = /^running (\d+) tests$/u.exec(line.trim());
        if (runningMatch?.[1] !== undefined) {
            const runningTestCount = Number(runningMatch[1]);
            lane.libtestRunningTestCount = runningTestCount;
            lane.libtestDiscoveredTestCount += runningTestCount;
            lane.secondaryProgress = {
                completed: lane.libtestCompletedTestCount,
                total: Math.max(
                    lane.secondaryProgress?.total ?? 0,
                    lane.libtestDiscoveredTestCount,
                ),
                unit: 'test',
            };

            return;
        }

        if (/^test .+ \.\.\. (?:ok|ignored|FAILED)$/u.test(line.trim())) {
            lane.libtestCompletedTestCount += 1;
            const discoveredTestCount =
                lane.libtestDiscoveredTestCount === 0
                    ? lane.secondaryProgress?.total
                    : lane.libtestDiscoveredTestCount;
            lane.secondaryProgress = {
                completed: lane.libtestCompletedTestCount,
                total: discoveredTestCount,
                unit: 'test',
            };
        }
    }

    #requestRender(): void {
        if (!this.#redrawEnabled || this.#renderTimeout !== undefined) {
            return;
        }

        this.#renderTimeout = setTimeout(() => {
            this.#renderTimeout = undefined;
            this.#render();
        }, renderDebounceMilliseconds);
        this.#renderTimeout.unref?.();
    }

    #requiredCommand(
        laneName: string,
        commandDescription: string,
    ): CommandState {
        const lane = this.#requiredLane(laneName);
        const command = lane.commands.find(
            (candidate) => candidate.description === commandDescription,
        );
        if (command === undefined) {
            throw new Error(
                `Unknown check command for ${laneName}: ${commandDescription}`,
            );
        }

        return command;
    }

    #requiredLane(laneName: string): LaneState {
        const lane = this.#laneStates.find(
            (candidate) => candidate.name === laneName,
        );
        if (lane === undefined) {
            throw new Error(`Unknown check lane: ${laneName}`);
        }

        return lane;
    }

    #writeLine(line: string): void {
        this.#output.write(`${line}\n`);
    }
}
