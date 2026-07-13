import { stripVTControlCharacters } from 'node:util';

import type { CommandOutputEvent, CommandRunObserver } from './run-command.js';
import { createStreamingLineAccumulator } from './streaming-lines.js';

export type CheckFailureDetail = {
    readonly commandDescription?: string;
    readonly exitCode?: number;
    readonly laneName: string;
    readonly logPath?: string;
    readonly recentOutputLines: readonly string[];
};

type CommandState = {
    readonly description: string;
    exitCode?: number;
    logPath?: string;
    readonly output: RecentLineBuffer;
    status: 'failed' | 'passed' | 'running' | 'stopped';
};

const recentOutputLineLimit = 20;
const formatDuration = (durationMilliseconds: number): string =>
    `${(durationMilliseconds / 1000).toFixed(1)}s`;

class RecentLineBuffer {
    readonly #lines: string[] = [];
    readonly #streamingLines = createStreamingLineAccumulator((line) => {
        this.#push(stripVTControlCharacters(line));
    });

    append(chunk: string): void {
        this.#streamingLines.push(chunk);
    }

    finish(): void {
        this.#streamingLines.flush();
    }

    snapshot(): readonly string[] {
        const remainder = stripVTControlCharacters(
            this.#streamingLines.pending(),
        );
        return [
            ...this.#lines,
            ...(remainder.length === 0 ? [] : [remainder]),
        ].slice(-recentOutputLineLimit);
    }

    #push(line: string): void {
        if (line.trim().length === 0) {
            return;
        }
        this.#lines.push(line);
        if (this.#lines.length > recentOutputLineLimit) {
            this.#lines.splice(0, this.#lines.length - recentOutputLineLimit);
        }
    }
}

export class CheckReporter {
    readonly #commandsByLane = new Map<string, CommandState[]>();

    createCommandObserver(
        laneName: string,
        signal?: AbortSignal,
    ): CommandRunObserver {
        return {
            onCommandExit: (event): void => {
                const command = this.#requireCommand(
                    laneName,
                    event.invocation.description,
                );
                command.output.finish();
                command.exitCode = event.exitCode;
                command.status =
                    event.exitCode === 0
                        ? 'passed'
                        : signal?.aborted === true
                          ? 'stopped'
                          : 'failed';
                const label =
                    command.status === 'passed'
                        ? 'PASS'
                        : command.status === 'stopped'
                          ? 'STOP'
                          : 'FAIL';
                process.stdout.write(
                    `${label} ${laneName} (${formatDuration(event.durationMilliseconds)})${this.#commandSuffix(laneName, command.description)}\n`,
                );
            },
            onCommandOutput: (event): void => {
                this.#recordOutput(laneName, event);
            },
            onCommandStart: (event): void => {
                const command: CommandState = {
                    description: event.invocation.description,
                    logPath: event.logFiles?.combinedPath,
                    output: new RecentLineBuffer(),
                    status: 'running',
                };
                const commands = this.#commandsByLane.get(laneName) ?? [];
                commands.push(command);
                this.#commandsByLane.set(laneName, commands);
                process.stdout.write(
                    `RUN  ${laneName}${this.#commandSuffix(laneName, command.description)}\n`,
                );
            },
        };
    }

    failureDetails(): readonly CheckFailureDetail[] {
        const details: CheckFailureDetail[] = [];
        for (const [laneName, commands] of this.#commandsByLane) {
            const failedCommand = commands.find(
                (command) => command.status === 'failed',
            );
            if (failedCommand === undefined) {
                continue;
            }
            details.push({
                commandDescription: failedCommand.description,
                exitCode: failedCommand.exitCode,
                laneName,
                logPath: failedCommand.logPath,
                recentOutputLines: failedCommand.output.snapshot(),
            });
        }

        return details;
    }

    recordStoppedLane(laneName: string, durationMilliseconds: number): void {
        if (
            this.#commandsByLane
                .get(laneName)
                ?.some((command) => command.status === 'stopped') === true
        ) {
            return;
        }
        process.stdout.write(
            `STOP ${laneName} (${formatDuration(durationMilliseconds)})\n`,
        );
    }

    #commandSuffix(laneName: string, description: string): string {
        return description === laneName ? '' : ` - ${description}`;
    }

    #recordOutput(laneName: string, event: CommandOutputEvent): void {
        this.#requireCommand(
            laneName,
            event.invocation.description,
        ).output.append(event.chunk);
    }

    #requireCommand(laneName: string, description: string): CommandState {
        const command = this.#commandsByLane
            .get(laneName)
            ?.find(
                (candidate) =>
                    candidate.description === description &&
                    candidate.status === 'running',
            );
        if (command === undefined) {
            throw new Error(
                `No running check command ${description} exists in ${laneName}.`,
            );
        }

        return command;
    }
}
