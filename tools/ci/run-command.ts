import {
    spawn,
    spawnSync,
    type ChildProcess,
    type SpawnOptions,
} from 'node:child_process';
import { createWriteStream, type WriteStream } from 'node:fs';
import { performance } from 'node:perf_hooks';

import type { ActiveLocalRunLog, CommandLogFiles } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import type { PackageManagerRunner } from './package-manager-runner.js';
import { createTerminalLineFilter } from './terminal-line-filter.js';

export type CommandInvocation = {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly logFileSlug?: string;
    readonly workingDirectoryPath?: string;
};

type CommandOutputMode = 'capture' | 'inherit';

export type CommandOutputStreamName = 'stderr' | 'stdout';

export type CommandStartEvent = {
    readonly invocation: CommandInvocation;
    readonly logFiles?: CommandLogFiles;
    readonly startedAtMilliseconds: number;
};

export type CommandOutputEvent = {
    readonly chunk: string;
    readonly invocation: CommandInvocation;
    readonly streamName: CommandOutputStreamName;
};

export type CommandExitEvent = {
    readonly durationMilliseconds: number;
    readonly error?: Error;
    readonly exitCode: number;
    readonly invocation: CommandInvocation;
    readonly terminationSignal: NodeJS.Signals | null;
};

export type CommandRunObserver = {
    readonly onCommandExit?: (event: CommandExitEvent) => void;
    readonly onCommandOutput?: (event: CommandOutputEvent) => void;
    readonly onCommandStart?: (event: CommandStartEvent) => void;
};

type PackageManagerSpawnCommand = {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
};

export const createPackageManagerCommand = (
    description: string,
    commandArguments: readonly string[],
    input: {
        readonly env?: NodeJS.ProcessEnv;
        readonly logFileSlug?: string;
        readonly packageManagerRunner?: PackageManagerRunner;
    } = {},
): CommandInvocation => {
    const packageManagerRunner =
        input.packageManagerRunner ?? resolvePackageManagerRunner();

    return {
        args: [
            ...packageManagerRunner.commandArgumentsPrefix,
            ...commandArguments,
        ],
        command: packageManagerRunner.command,
        description,
        env: input.env,
        logFileSlug: input.logFileSlug,
    };
};

const createPackageManagerSpawnCommand = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
): PackageManagerSpawnCommand => {
    const commandArgs = [...runner.commandArgumentsPrefix, ...commandArguments];
    const description = [runner.command, ...commandArgs].join(' ');

    return {
        command: runner.command,
        args: commandArgs,
        description,
    };
};

export const runPackageManagerAndCaptureOutput = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    workingDirectoryPath: string,
    input: {
        readonly environment?: NodeJS.ProcessEnv;
    } = {},
): string => {
    const spawnCommand = createPackageManagerSpawnCommand(
        runner,
        commandArguments,
    );
    const result = spawnSync(spawnCommand.command, spawnCommand.args, {
        cwd: workingDirectoryPath,
        env: input.environment ?? process.env,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start command: ${spawnCommand.description}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `Command terminated by signal ${result.signal}: ${spawnCommand.description}`,
        );
    }
    if (result.status !== 0) {
        const stdout = result.stdout?.trim();
        const stderr = result.stderr?.trim();
        const formattedOutput =
            stdout !== '' || stderr !== ''
                ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                : '';

        throw new Error(
            `Command exited with status ${result.status ?? 'null'}: ${spawnCommand.description}${formattedOutput}`,
        );
    }

    return result.stdout ?? '';
};

type KillableChildProcess = Pick<ChildProcess, 'kill' | 'pid'>;

type ProcessGroupKiller = (
    processIdentifier: number,
    signal: NodeJS.Signals,
) => unknown;

type WindowsTaskKiller = (
    command: string,
    commandArguments: readonly string[],
    options: { readonly stdio: 'ignore' },
) => unknown;

type ProcessSignalName = 'SIGINT' | 'SIGTERM';

type ProcessSignalEventSource = {
    off: (
        signal: ProcessSignalName,
        listener: () => void,
    ) => ProcessSignalEventSource;
    on: (
        signal: ProcessSignalName,
        listener: () => void,
    ) => ProcessSignalEventSource;
};

type ProcessSignalEscalationScheduler = (
    callback: () => void,
    delayMilliseconds: number,
) => unknown;

const forceKillDelayMilliseconds = 5_000;

export const createAbortableCommandSpawnOptions = (
    env: NodeJS.ProcessEnv,
    stdio: SpawnOptions['stdio'],
    platform: NodeJS.Platform = process.platform,
    workingDirectoryPath?: string,
): SpawnOptions => ({
    ...(workingDirectoryPath === undefined
        ? {}
        : { cwd: workingDirectoryPath }),
    detached: platform !== 'win32',
    env,
    stdio,
});

export const killProcessTree = (
    childProcess: KillableChildProcess,
    input: {
        readonly platform?: NodeJS.Platform;
        readonly processGroupKiller?: ProcessGroupKiller;
        readonly signal?: NodeJS.Signals;
        readonly windowsTaskKiller?: WindowsTaskKiller;
    } = {},
): void => {
    const processId = childProcess.pid;
    if (processId === undefined) {
        return;
    }
    if ((input.platform ?? process.platform) === 'win32') {
        // child.kill() only ends the direct child on Windows; package-manager
        // and test-runner grandchildren survive. taskkill /t ends the whole
        // tree. spawnSync keeps the abort path free of dangling listeners.
        (input.windowsTaskKiller ?? spawnSync)(
            'taskkill',
            ['/pid', String(processId), '/t', '/f'],
            {
                stdio: 'ignore',
            },
        );
        return;
    }
    const signal = input.signal ?? 'SIGTERM';
    try {
        (input.processGroupKiller ?? process.kill)(-processId, signal);
    } catch {
        childProcess.kill(signal);
    }
};

export const installProcessSignalChildCleanup = (input: {
    readonly activeChildProcesses: ReadonlySet<KillableChildProcess>;
    readonly clearScheduledForceKill?: (timer: unknown) => void;
    readonly forceKillChildProcess?: (
        childProcess: KillableChildProcess,
    ) => void;
    readonly killChildProcess?: (childProcess: KillableChildProcess) => void;
    readonly processEvents?: ProcessSignalEventSource;
    readonly scheduleForceKill?: ProcessSignalEscalationScheduler;
}): (() => void) => {
    const processEvents = input.processEvents ?? process;
    const killChildProcess =
        input.killChildProcess ??
        ((childProcess: KillableChildProcess): void => {
            killProcessTree(childProcess);
        });
    const forceKillChildProcess =
        input.forceKillChildProcess ??
        ((childProcess: KillableChildProcess): void => {
            killProcessTree(childProcess, { signal: 'SIGKILL' });
        });
    const scheduleForceKill =
        input.scheduleForceKill ??
        ((callback: () => void, delayMilliseconds: number) =>
            setTimeout(callback, delayMilliseconds));
    const clearScheduledForceKill =
        input.clearScheduledForceKill ??
        ((timer: unknown) => {
            clearTimeout(timer as ReturnType<typeof setTimeout>);
        });
    const signalHandlers = new Map<ProcessSignalName, () => void>();
    let scheduledForceKill: unknown;
    let handlersAreInstalled = true;

    const removeSignalHandlers = (): void => {
        if (!handlersAreInstalled) {
            return;
        }
        handlersAreInstalled = false;
        for (const [signal, signalHandler] of signalHandlers) {
            processEvents.off(signal, signalHandler);
        }
    };

    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
        const signalHandler = (): void => {
            process.exitCode = process.exitCode ?? 1;
            for (const childProcess of input.activeChildProcesses) {
                killChildProcess(childProcess);
            }
            scheduledForceKill ??= scheduleForceKill(() => {
                scheduledForceKill = undefined;
                for (const childProcess of input.activeChildProcesses) {
                    forceKillChildProcess(childProcess);
                }
            }, forceKillDelayMilliseconds);
            removeSignalHandlers();
        };
        signalHandlers.set(signal, signalHandler);
        processEvents.on(signal, signalHandler);
    }

    return (): void => {
        removeSignalHandlers();
        if (scheduledForceKill !== undefined) {
            clearScheduledForceKill(scheduledForceKill);
            scheduledForceKill = undefined;
        }
    };
};

const activeChildProcesses = new Set<KillableChildProcess>();
let uninstallProcessSignalChildCleanup: (() => void) | undefined;

const trackChildProcessForSignalCleanup = (
    childProcess: KillableChildProcess,
): (() => void) => {
    activeChildProcesses.add(childProcess);
    uninstallProcessSignalChildCleanup ??= installProcessSignalChildCleanup({
        activeChildProcesses,
    });

    let isTracked = true;
    return (): void => {
        if (!isTracked) {
            return;
        }
        isTracked = false;
        activeChildProcesses.delete(childProcess);
        if (activeChildProcesses.size === 0) {
            uninstallProcessSignalChildCleanup?.();
            uninstallProcessSignalChildCleanup = undefined;
        }
    };
};

const runCommandWithInheritedOutput = (
    invocation: CommandInvocation,
    signal?: AbortSignal,
    observer?: CommandRunObserver,
): Promise<number> =>
    new Promise((resolve, reject) => {
        if (signal?.aborted === true) {
            resolve(1);
            return;
        }
        console.log(`\n${invocation.description}`);
        const startedAtMilliseconds = performance.now();
        observer?.onCommandStart?.({
            invocation,
            startedAtMilliseconds,
        });
        const childProcess = spawn(
            invocation.command,
            invocation.args,
            createAbortableCommandSpawnOptions(
                invocation.env ?? process.env,
                'inherit',
                process.platform,
                invocation.workingDirectoryPath,
            ),
        );
        const untrackChildProcess =
            trackChildProcessForSignalCleanup(childProcess);
        const onAbort = (): void => {
            killProcessTree(childProcess);
        };
        signal?.addEventListener('abort', onAbort, { once: true });
        let settled = false;
        childProcess.once('error', (error) => {
            if (settled) {
                return;
            }
            settled = true;
            untrackChildProcess();
            signal?.removeEventListener('abort', onAbort);
            observer?.onCommandExit?.({
                durationMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                error,
                exitCode: 1,
                invocation,
                terminationSignal: null,
            });
            reject(error);
        });
        childProcess.once('close', (exitCode, terminationSignal) => {
            if (settled) {
                return;
            }
            settled = true;
            untrackChildProcess();
            signal?.removeEventListener('abort', onAbort);
            const resolvedExitCode =
                terminationSignal === null ? (exitCode ?? 1) : 1;
            if (terminationSignal !== null) {
                console.error(
                    `${invocation.description} terminated by signal ${terminationSignal}.`,
                );
            }

            observer?.onCommandExit?.({
                durationMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                exitCode: resolvedExitCode,
                invocation,
                terminationSignal,
            });
            resolve(resolvedExitCode);
        });
    });

const closeWritableStream = async (stream: WriteStream): Promise<void> =>
    new Promise((resolve, reject) => {
        stream.once('error', reject);
        stream.end(resolve);
    });

const openCommandLogStreams = (
    files: CommandLogFiles,
): {
    readonly combined: WriteStream;
    readonly stderr: WriteStream;
    readonly stdout: WriteStream;
} => ({
    combined: createWriteStream(files.combinedPath, { flags: 'a' }),
    stderr: createWriteStream(files.stderrPath, { flags: 'a' }),
    stdout: createWriteStream(files.stdoutPath, { flags: 'a' }),
});

const closeCommandLogStreams = async (streams: {
    readonly combined: WriteStream;
    readonly stderr: WriteStream;
    readonly stdout: WriteStream;
}): Promise<void> => {
    await Promise.all([
        closeWritableStream(streams.combined),
        closeWritableStream(streams.stderr),
        closeWritableStream(streams.stdout),
    ]);
};

const closeOptionalCommandLogStreams = async (
    streams:
        | {
              readonly combined: WriteStream;
              readonly stderr: WriteStream;
              readonly stdout: WriteStream;
          }
        | undefined,
): Promise<void> => {
    if (streams === undefined) {
        return;
    }

    await closeCommandLogStreams(streams);
};

const runCommandWithOptionalLog = async (
    invocation: CommandInvocation,
    input: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
        readonly terminalOutputFilter?: (line: string) => boolean;
    } = {},
): Promise<number> => {
    const outputMode = input.outputMode ?? 'inherit';
    if (
        input.runLog === undefined &&
        outputMode === 'inherit' &&
        input.terminalOutputFilter === undefined
    ) {
        return runCommandWithInheritedOutput(
            invocation,
            input.signal,
            input.observer,
        );
    }
    if (input.signal?.aborted === true) {
        return 1;
    }

    const commandLogFiles = input.runLog?.createCommandLogFiles({
        description: invocation.description,
        preferredSlug: invocation.logFileSlug,
    });
    const commandLogStreams =
        commandLogFiles === undefined
            ? undefined
            : openCommandLogStreams(commandLogFiles);
    const heading = `\n${invocation.description}\n`;
    if (outputMode === 'inherit') {
        process.stdout.write(heading);
    }
    commandLogStreams?.combined.write(heading);
    input.runLog?.writeCombinedOutput(heading);
    const startedAtMilliseconds = performance.now();
    input.observer?.onCommandStart?.({
        invocation,
        logFiles: commandLogFiles,
        startedAtMilliseconds,
    });

    return new Promise((resolve, reject) => {
        const childProcess = spawn(
            invocation.command,
            invocation.args,
            createAbortableCommandSpawnOptions(
                invocation.env ?? process.env,
                ['ignore', 'pipe', 'pipe'],
                process.platform,
                invocation.workingDirectoryPath,
            ),
        );
        const untrackChildProcess =
            trackChildProcessForSignalCleanup(childProcess);
        const childStandardOutput = childProcess.stdout;
        const childStandardError = childProcess.stderr;
        if (childStandardOutput === null || childStandardError === null) {
            killProcessTree(childProcess);
            untrackChildProcess();
            void (async () => {
                try {
                    await closeOptionalCommandLogStreams(commandLogStreams);
                } finally {
                    reject(
                        new Error(
                            'Command log capture requires piped stdout and stderr.',
                        ),
                    );
                }
            })();
            return;
        }
        const onAbort = (): void => {
            killProcessTree(childProcess);
        };
        input.signal?.addEventListener('abort', onAbort, { once: true });
        // When a terminal output filter is supplied, the child's terminal echo
        // is reassembled into whole lines per stream so the filter can drop
        // specific noise lines (for example libtest's slow-test notices). Log
        // files and observers still receive the raw, unfiltered chunks.
        const terminalLineFilters =
            outputMode === 'inherit' && input.terminalOutputFilter !== undefined
                ? {
                      stderr: createTerminalLineFilter(
                          input.terminalOutputFilter,
                      ),
                      stdout: createTerminalLineFilter(
                          input.terminalOutputFilter,
                      ),
                  }
                : undefined;
        const flushTerminalLineFilters = (): void => {
            if (terminalLineFilters === undefined) {
                return;
            }
            const stdoutRemainder = terminalLineFilters.stdout.flush();
            if (stdoutRemainder.length > 0) {
                process.stdout.write(stdoutRemainder);
            }
            const stderrRemainder = terminalLineFilters.stderr.flush();
            if (stderrRemainder.length > 0) {
                process.stderr.write(stderrRemainder);
            }
        };
        const writeChunk = (
            streamName: CommandOutputStreamName,
            chunk: string,
        ): void => {
            const terminalStream =
                streamName === 'stdout' ? process.stdout : process.stderr;
            const childStream =
                streamName === 'stdout'
                    ? commandLogStreams?.stdout
                    : commandLogStreams?.stderr;
            if (outputMode === 'inherit') {
                terminalStream.write(
                    terminalLineFilters === undefined
                        ? chunk
                        : terminalLineFilters[streamName].push(chunk),
                );
            }
            childStream?.write(chunk);
            commandLogStreams?.combined.write(chunk);
            input.runLog?.writeCombinedOutput(chunk);
            input.observer?.onCommandOutput?.({
                chunk,
                invocation,
                streamName,
            });
        };
        let settled = false;
        childStandardOutput.setEncoding('utf8');
        childStandardError.setEncoding('utf8');
        childStandardOutput.on('data', (chunk: string) => {
            writeChunk('stdout', chunk);
        });
        childStandardError.on('data', (chunk: string) => {
            writeChunk('stderr', chunk);
        });
        childProcess.once('error', (error) => {
            if (settled) {
                return;
            }
            settled = true;
            untrackChildProcess();
            input.signal?.removeEventListener('abort', onAbort);
            void (async () => {
                try {
                    flushTerminalLineFilters();
                    input.observer?.onCommandExit?.({
                        durationMilliseconds: Math.round(
                            performance.now() - startedAtMilliseconds,
                        ),
                        error,
                        exitCode: 1,
                        invocation,
                        terminationSignal: null,
                    });
                    await closeOptionalCommandLogStreams(commandLogStreams);
                } catch {
                    // Preserve the original process start failure.
                }
                reject(error);
            })();
        });
        childProcess.once('close', (exitCode, terminationSignal) => {
            if (settled) {
                return;
            }
            settled = true;
            untrackChildProcess();
            input.signal?.removeEventListener('abort', onAbort);
            void (async () => {
                try {
                    flushTerminalLineFilters();
                    const resolvedExitCode =
                        terminationSignal === null ? (exitCode ?? 1) : 1;
                    if (terminationSignal !== null) {
                        const signalMessage = `${invocation.description} terminated by signal ${terminationSignal}.\n`;
                        if (outputMode === 'inherit') {
                            process.stderr.write(signalMessage);
                        }
                        commandLogStreams?.stderr.write(signalMessage);
                        commandLogStreams?.combined.write(signalMessage);
                        input.runLog?.writeCombinedOutput(signalMessage);
                        input.observer?.onCommandOutput?.({
                            chunk: signalMessage,
                            invocation,
                            streamName: 'stderr',
                        });
                    }
                    input.observer?.onCommandExit?.({
                        durationMilliseconds: Math.round(
                            performance.now() - startedAtMilliseconds,
                        ),
                        exitCode: resolvedExitCode,
                        invocation,
                        terminationSignal,
                    });
                    await closeOptionalCommandLogStreams(commandLogStreams);
                    resolve(resolvedExitCode);
                } catch (error) {
                    reject(
                        error instanceof Error
                            ? error
                            : new Error(String(error)),
                    );
                }
            })();
        });
    });
};

const runCommandsInParallel = async (
    invocations: readonly CommandInvocation[],
    input: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
        readonly terminalOutputFilter?: (line: string) => boolean;
    } = {},
): Promise<number> => {
    const exitCodes = await Promise.all(
        invocations.map((invocation) =>
            runCommandWithOptionalLog(invocation, input),
        ),
    );

    return exitCodes.find((exitCode) => exitCode !== 0) ?? 0;
};

export const runCommandsInSeries = async (
    invocations: readonly CommandInvocation[],
    input: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
        readonly terminalOutputFilter?: (line: string) => boolean;
    } = {},
): Promise<number> => {
    for (const invocation of invocations) {
        if (input.signal?.aborted === true) {
            return 1;
        }
        const exitCode = await runCommandWithOptionalLog(invocation, input);
        if (exitCode !== 0) {
            return exitCode;
        }
    }

    return 0;
};

export const runCommandsAfterSeriesGate = async (
    input: {
        readonly gateCommands: readonly CommandInvocation[];
        readonly parallelCommands: readonly CommandInvocation[];
    },
    options: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
        readonly terminalOutputFilter?: (line: string) => boolean;
    } = {},
): Promise<number> => {
    const gateExitCode = await runCommandsInSeries(input.gateCommands, options);
    if (gateExitCode !== 0) {
        return gateExitCode;
    }

    return runCommandsInParallel(input.parallelCommands, options);
};
