import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { Writable } from 'node:stream';

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

export type CheckProgressCommandPlan = {
    readonly description: string;
    readonly expectedDurationMilliseconds?: number;
};

export type CheckProgressLanePlan = {
    readonly commands: readonly CheckProgressCommandPlan[];
    readonly expectedDurationMilliseconds?: number;
    readonly name: string;
};

export type CheckTimingHistory = {
    readonly commandDurationMilliseconds: ReadonlyMap<string, number>;
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
    startedAtMilliseconds?: number;
    status: CheckProgressStatus;
};

type TerminalWriter = Pick<Writable, 'write'> & {
    readonly columns?: number;
    readonly isTTY?: boolean;
};

const previousTimingDetailsVersion = 'sealed-lattice-check-run-details-v1';
const outputLineLimit = 80;
const latestOutputLineLimit = 6;
const failureOutputLineLimit = 40;
const defaultRenderIntervalMilliseconds = 200;
const ansiEscapePattern = new RegExp(
    String.raw`\u001B\[[0-?]*[ -/]*[@-~]`,
    'gu',
);

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const isUsableDuration = (value: unknown): value is number =>
    typeof value === 'number' && Number.isFinite(value) && value >= 0;

const emptyTimingHistory = (): CheckTimingHistory => ({
    commandDurationMilliseconds: new Map(),
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

    if (details !== undefined) {
        for (const lane of details.lanes) {
            if (isUsableDuration(lane.durationMilliseconds)) {
                laneDurationMilliseconds.set(
                    lane.name,
                    lane.durationMilliseconds,
                );
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

export class CheckProgressReporter {
    readonly #history: CheckTimingHistory;
    readonly #laneStates: LaneState[];
    readonly #latestOutput = new RecentOutputBuffer();
    readonly #now: () => number;
    readonly #output: TerminalWriter;
    readonly #redrawEnabled: boolean;
    readonly #renderIntervalMilliseconds: number;
    readonly #startedAtMilliseconds: number;
    #interval: NodeJS.Timeout | undefined;
    #lastRenderedLineCount = 0;

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
                recentOutput: new RecentOutputBuffer(),
                status: 'waiting',
            })),
            expectedDurationMilliseconds: lane.expectedDurationMilliseconds,
            name: lane.name,
            status: 'waiting',
        }));
        this.#now = input.now ?? performance.now.bind(performance);
        this.#output = input.output ?? process.stdout;
        this.#redrawEnabled =
            input.redrawEnabled ??
            (this.#output.isTTY === true && process.env.CI !== 'true');
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
        if (this.#redrawEnabled) {
            this.#clearPreviousRender();
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

    #clearPreviousRender(): void {
        if (this.#lastRenderedLineCount === 0) {
            return;
        }

        this.#output.write(`\u001B[${this.#lastRenderedLineCount}A`);
        for (
            let lineIndex = 0;
            lineIndex < this.#lastRenderedLineCount;
            lineIndex += 1
        ) {
            this.#output.write('\u001B[2K');
            if (lineIndex < this.#lastRenderedLineCount - 1) {
                this.#output.write('\u001B[1B');
            }
        }
        if (this.#lastRenderedLineCount > 1) {
            this.#output.write(`\u001B[${this.#lastRenderedLineCount - 1}A`);
        }
        this.#lastRenderedLineCount = 0;
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

        return `check  ${this.completedCommandCount()}/${this.totalCommandCount()}  elapsed ${formatProgressDuration(
            elapsedMilliseconds,
        )}${expectedDuration}`;
    }

    #laneLine(lane: LaneState): string {
        const nowMilliseconds = this.#now();
        const completedCommands =
            lane.commands.filter(commandIsFinished).length;
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
            currentCommand === undefined
                ? ''
                : ` - ${currentCommand.description}${currentCommandExpectedDuration}`;

        return `[${laneStatusLabels[lane.status].padEnd(
            4,
        )}] ${completedCommands}/${lane.commands.length} ${elapsedDuration}${expectedDuration} ${lane.name}${currentCommandText}`;
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
        command.durationMilliseconds = event.durationMilliseconds;
        command.exitCode = event.exitCode;
        command.status = event.exitCode === 0 ? 'passed' : 'failed';

        if (!this.#redrawEnabled) {
            this.#writeLine(
                `${laneStatusLabels[command.status]} ${laneName} ${formatProgressDuration(
                    event.durationMilliseconds,
                )} ${event.invocation.description}`,
            );
        }
    }

    #recordCommandOutput(laneName: string, event: CommandOutputEvent): void {
        const command = this.#requiredCommand(
            laneName,
            event.invocation.description,
        );
        const outputPrefix = `${laneName}`;
        command.recentOutput.append(outputPrefix, event.chunk);
        this.#latestOutput.append(outputPrefix, event.chunk);
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
            this.#writeLine(
                `run ${laneName} ${
                    lane.commands.filter(commandIsFinished).length
                }/${lane.commands.length} ${event.invocation.description}`,
            );
        }
    }

    #render(): void {
        const terminalWidth = Math.max(this.#output.columns ?? 120, 40);
        const lines = this.#renderLines().map((line) =>
            truncateLine(line, terminalWidth),
        );
        this.#clearPreviousRender();
        this.#output.write(`${lines.join('\n')}\n`);
        this.#lastRenderedLineCount = lines.length;
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
