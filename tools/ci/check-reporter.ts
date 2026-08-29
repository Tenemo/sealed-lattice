import { stripVTControlCharacters } from 'node:util';

import type { CommandRunObserver } from './run-command.js';

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
    readonly output: RecentOutput;
    readonly logPath?: string;
    status: 'failed' | 'passed' | 'running' | 'stopped';
};

const recentOutputLineLimit = 20;
const formatDuration = (durationMilliseconds: number): string =>
    `${(durationMilliseconds / 1000).toFixed(1)}s`;

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

export class CheckReporter {
    readonly #commandsByLane = new Map<string, CommandState[]>();

    createCommandObserver(
        laneName: string,
        signal?: AbortSignal,
    ): CommandRunObserver {
        return {
            onCommandExit: (event) => {
                const command = this.#runningCommand(
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
                    `${label} ${laneName} (${formatDuration(
                        event.durationMilliseconds,
                    )})${this.#commandSuffix(laneName, command.description)}\n`,
                );
            },
            onCommandOutput: (event) => {
                this.#runningCommand(
                    laneName,
                    event.invocation.description,
                ).output.append(event.chunk);
            },
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
                    `RUN  ${laneName}${this.#commandSuffix(
                        laneName,
                        event.invocation.description,
                    )}\n`,
                );
            },
        };
    }

    failureDetails(): readonly CheckFailureDetail[] {
        return [...this.#commandsByLane].flatMap(([laneName, commands]) => {
            const command = commands.find(
                (candidate) => candidate.status === 'failed',
            );
            return command === undefined
                ? []
                : [
                      {
                          commandDescription: command.description,
                          exitCode: command.exitCode,
                          laneName,
                          logPath: command.logPath,
                          recentOutputLines: command.output.snapshot(),
                      },
                  ];
        });
    }

    recordStoppedLane(laneName: string, durationMilliseconds: number): void {
        if (
            this.#commandsByLane
                .get(laneName)
                ?.some((command) => command.status === 'stopped') !== true
        ) {
            process.stdout.write(
                `STOP ${laneName} (${formatDuration(durationMilliseconds)})\n`,
            );
        }
    }

    #commandSuffix(laneName: string, description: string): string {
        return description === laneName ? '' : ` - ${description}`;
    }

    #runningCommand(laneName: string, description: string): CommandState {
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
