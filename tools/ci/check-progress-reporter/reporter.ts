import { performance } from 'node:perf_hooks';

import { createLogUpdate } from 'log-update';

import type {
    CommandInvocation,
    CommandOutputEvent,
    CommandRunObserver,
    CommandStartEvent,
} from '../run-command.js';

import {
    commandIsFinished,
    formatLaneProgress,
    formatProgressDuration,
    laneElapsedMilliseconds,
    laneStatusLabels,
    terminalColumnCount,
    terminalRowCount,
    truncateLine,
} from './formatting.js';
import { OutputLineBuffer, RecentOutputBuffer } from './output-buffers.js';
import {
    consumeLibtestProgressLine,
    consumeStructuredProgressLine,
    consumeTurboProgressLine,
} from './progress-parsers.js';
import { cloneProgressMetric, emptyTimingHistory } from './timing-history.js';
import {
    defaultRenderIntervalMilliseconds,
    failureOutputLineLimit,
    latestOutputLineLimit,
    previousTimingDetailsVersion,
    progressEventPrefix,
    renderDebounceMilliseconds,
    type CheckFailureDetail,
    type CheckProgressLanePlan,
    type CheckProgressStatus,
    type CheckRunTimingDetails,
    type CheckTimingHistory,
    type CommandState,
    type LaneState,
    type TerminalWriter,
} from './types.js';

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
            libtestCompletedTestCountBeforeCurrentBatch: 0,
            libtestDiscoveredTestCount: 0,
            libtestObservedCompactTestCountInCurrentBatch: 0,
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
        const outputLine = this.#consumeProgressLine(lane, line);
        if (outputLine === undefined) {
            return;
        }

        const outputPrefix = `${laneName}`;
        const lineWithTerminator = `${outputLine}\n`;
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

    #consumeProgressLine(lane: LaneState, line: string): string | undefined {
        if (line.startsWith(progressEventPrefix)) {
            consumeStructuredProgressLine(lane, line);

            return undefined;
        }
        if (lane.progressSource === 'turbo') {
            consumeTurboProgressLine(lane, line);
        }
        if (lane.progressSource === 'libtest') {
            return consumeLibtestProgressLine(lane, line);
        }

        return line;
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
