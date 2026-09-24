import {
    spawn,
    spawnSync,
    type ChildProcess,
    type SpawnOptions,
} from 'node:child_process';
import { performance } from 'node:perf_hooks';

import type { ActiveLocalRunLog, CommandLogFiles } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    redactCommandLineArguments,
    redactDiagnosticText,
    selectDiagnosticEnvironment,
    serializeErrorDiagnostic,
} from './run-log-diagnostics.js';

export type CommandInvocation = {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly logFileSlug?: string;
    readonly workingDirectoryPath?: string;
};

type CapturedCommandResult = {
    readonly exitCode: number;
    readonly stderr: string;
    readonly stdout: string;
    readonly terminationSignal: NodeJS.Signals | null;
};

type CommandStartEvent = {
    readonly invocation: CommandInvocation;
    readonly logFiles?: CommandLogFiles;
    readonly processIdentifier?: number;
    readonly startedAtMilliseconds: number;
};

type CommandOutputEvent = {
    readonly chunk: string;
    readonly invocation: CommandInvocation;
    readonly streamName: 'stderr' | 'stdout';
};

type CommandExitEvent = {
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

type CommandOutputMode = 'capture' | 'inherit';
type KillableChildProcess = Pick<ChildProcess, 'kill' | 'pid'>;
type ProcessTreeKillResult = {
    readonly error?: ReturnType<typeof serializeErrorDiagnostic>;
    readonly fallbackReason?: ReturnType<typeof serializeErrorDiagnostic>;
    readonly mechanism:
        | 'direct-signal'
        | 'none'
        | 'process-group-signal'
        | 'taskkill-tree-force';
    readonly succeeded: boolean;
};
type ProcessSignalName = 'SIGINT' | 'SIGTERM';
type ProcessSignalEventSource = {
    off(signal: ProcessSignalName, listener: () => void): unknown;
    on(signal: ProcessSignalName, listener: () => void): unknown;
};
type WindowsTaskKiller = (
    command: string,
    commandArguments: readonly string[],
    options: { readonly stdio: 'ignore'; readonly windowsHide: true },
) =>
    | {
          readonly error?: unknown;
          readonly status?: number | null;
      }
    | undefined;

const forceKillDelayMilliseconds = 5_000;

type CommandTerminationReasonDiagnostic =
    | Readonly<{
          classification: 'sibling-abort';
          initiator: string;
      }>
    | ReturnType<typeof serializeErrorDiagnostic>;

const serializeCommandTerminationReason = (
    reason: unknown,
): CommandTerminationReasonDiagnostic => {
    if (reason !== null && typeof reason === 'object') {
        const reasonRecord = reason as Readonly<Record<string, unknown>>;
        if (
            reasonRecord.classification === 'sibling-abort' &&
            typeof reasonRecord.initiator === 'string'
        ) {
            return {
                classification: 'sibling-abort',
                initiator: redactDiagnosticText(reasonRecord.initiator),
            };
        }
    }
    return serializeErrorDiagnostic(reason);
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
    const runner = input.packageManagerRunner ?? resolvePackageManagerRunner();
    return {
        args: [...runner.commandArgumentsPrefix, ...commandArguments],
        command: runner.command,
        description,
        env: input.env,
        logFileSlug: input.logFileSlug,
    };
};

export const runPackageManagerAndCaptureOutput = (
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    workingDirectoryPath: string,
    input: { readonly environment?: NodeJS.ProcessEnv } = {},
): string => {
    const commandArgumentsWithPrefix = [
        ...runner.commandArgumentsPrefix,
        ...commandArguments,
    ];
    const result = spawnSync(runner.command, commandArgumentsWithPrefix, {
        cwd: workingDirectoryPath,
        encoding: 'utf8',
        env: input.environment ?? process.env,
        maxBuffer: 100 * 1024 * 1024,
        windowsHide: true,
    });
    const description = [runner.command, ...commandArgumentsWithPrefix].join(
        ' ',
    );
    if (result.error !== undefined) {
        throw new Error(
            `Failed to start ${description}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(`${description} terminated by ${result.signal}.`);
    }
    if (result.status !== 0) {
        const output = [result.stdout, result.stderr]
            .map((value) => value?.trim())
            .filter(Boolean)
            .join('\n');
        throw new Error(
            `${description} exited with ${String(result.status)}.${
                output.length === 0 ? '' : `\n${output}`
            }`,
        );
    }
    return result.stdout ?? '';
};

export const killProcessTree = (
    childProcess: KillableChildProcess,
    input: {
        readonly platform?: NodeJS.Platform;
        readonly processGroupKiller?: (
            processIdentifier: number,
            signal: NodeJS.Signals,
        ) => unknown;
        readonly signal?: NodeJS.Signals;
        readonly windowsTaskKiller?: WindowsTaskKiller;
    } = {},
): ProcessTreeKillResult => {
    const processIdentifier = childProcess.pid;
    if (processIdentifier === undefined) {
        return { mechanism: 'none', succeeded: false };
    }

    if ((input.platform ?? process.platform) === 'win32') {
        try {
            const result = (input.windowsTaskKiller ?? spawnSync)(
                'taskkill',
                ['/pid', String(processIdentifier), '/t', '/f'],
                { stdio: 'ignore', windowsHide: true },
            );
            return {
                ...(result?.error === undefined
                    ? {}
                    : { error: serializeErrorDiagnostic(result.error) }),
                mechanism: 'taskkill-tree-force',
                succeeded:
                    result?.error === undefined &&
                    (result?.status === undefined ||
                        result.status === null ||
                        result.status === 0),
            };
        } catch (error) {
            return {
                error: serializeErrorDiagnostic(error),
                mechanism: 'taskkill-tree-force',
                succeeded: false,
            };
        }
    }

    const signal = input.signal ?? 'SIGTERM';
    try {
        (input.processGroupKiller ?? process.kill)(-processIdentifier, signal);
        return { mechanism: 'process-group-signal', succeeded: true };
    } catch (groupError) {
        try {
            return {
                fallbackReason: serializeErrorDiagnostic(groupError),
                mechanism: 'direct-signal',
                succeeded: childProcess.kill(signal),
            };
        } catch (error) {
            return {
                error: serializeErrorDiagnostic(error),
                fallbackReason: serializeErrorDiagnostic(groupError),
                mechanism: 'direct-signal',
                succeeded: false,
            };
        }
    }
};

export const installProcessSignalChildCleanup = (input: {
    readonly activeChildProcesses: ReadonlySet<KillableChildProcess>;
    readonly clearScheduledForceKill?: (timer: unknown) => void;
    readonly forceKillChildProcess?: (
        childProcess: KillableChildProcess,
    ) => ProcessTreeKillResult;
    readonly killChildProcess?: (
        childProcess: KillableChildProcess,
    ) => ProcessTreeKillResult;
    readonly processEvents?: ProcessSignalEventSource;
    readonly scheduleForceKill?: (
        callback: () => void,
        delayMilliseconds: number,
    ) => unknown;
}): (() => void) => {
    const processEvents = input.processEvents ?? process;
    const handlers = new Map<ProcessSignalName, () => void>();
    let forceKillTimer: unknown;

    const removeHandlers = (): void => {
        for (const [signal, handler] of handlers) {
            processEvents.off(signal, handler);
        }
        handlers.clear();
    };
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
        const handler = (): void => {
            process.exitCode = currentFailureExitCode();
            for (const childProcess of input.activeChildProcesses) {
                (input.killChildProcess ?? killProcessTree)(childProcess);
            }
            forceKillTimer ??= (
                input.scheduleForceKill ??
                ((callback, delay) => setTimeout(callback, delay))
            )(() => {
                for (const childProcess of input.activeChildProcesses) {
                    (
                        input.forceKillChildProcess ??
                        ((child) =>
                            killProcessTree(child, { signal: 'SIGKILL' }))
                    )(childProcess);
                }
            }, forceKillDelayMilliseconds);
            removeHandlers();
        };
        handlers.set(signal, handler);
        processEvents.on(signal, handler);
    }

    return (): void => {
        removeHandlers();
        if (forceKillTimer !== undefined) {
            (
                input.clearScheduledForceKill ??
                ((timer) => clearTimeout(timer as NodeJS.Timeout))
            )(forceKillTimer);
        }
    };
};

const activeChildProcesses = new Set<KillableChildProcess>();
let uninstallSignalCleanup: (() => void) | undefined;

const trackChildProcess = (
    childProcess: KillableChildProcess,
): (() => void) => {
    activeChildProcesses.add(childProcess);
    uninstallSignalCleanup ??= installProcessSignalChildCleanup({
        activeChildProcesses,
    });
    return () => {
        activeChildProcesses.delete(childProcess);
        if (activeChildProcesses.size === 0) {
            uninstallSignalCleanup?.();
            uninstallSignalCleanup = undefined;
        }
    };
};

const currentFailureExitCode = (): number =>
    typeof process.exitCode === 'number' && process.exitCode !== 0
        ? process.exitCode
        : 1;

const spawnOptions = (
    invocation: CommandInvocation,
    environment: NodeJS.ProcessEnv,
): SpawnOptions => ({
    ...(invocation.workingDirectoryPath === undefined
        ? {}
        : { cwd: invocation.workingDirectoryPath }),
    detached: process.platform !== 'win32',
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
});

const runCommand = async (
    invocation: CommandInvocation,
    input: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
    },
): Promise<number> => {
    if (input.signal?.aborted === true) return 1;
    const outputMode = input.outputMode ?? 'inherit';
    const logFiles = input.runLog?.createCommandLogFiles({
        description: invocation.description,
        preferredSlug: invocation.logFileSlug,
    });
    const commandId = logFiles?.commandId;
    const environment = {
        ...(invocation.env ?? process.env),
        ...(input.runLog === undefined
            ? {}
            : { SEALED_LATTICE_RUN_DIRECTORY: input.runLog.runDirectoryPath }),
    };
    const heading = `\n${invocation.description}\n`;
    if (outputMode === 'inherit') process.stdout.write(heading);
    if (commandId !== undefined) {
        input.runLog?.writeCommandOutput({
            chunk: heading,
            commandId,
            streamName: 'runner',
        });
        input.runLog?.writeEvent({
            commandId,
            details: {
                arguments: redactCommandLineArguments(invocation.args),
                command: invocation.command,
                description: invocation.description,
                diagnosticEnvironment: selectDiagnosticEnvironment(environment),
                workingDirectoryPath:
                    invocation.workingDirectoryPath ?? process.cwd(),
            },
            eventType: 'command-prepared',
        });
    }

    const startedAtMilliseconds = performance.now();
    return new Promise((resolve, reject) => {
        let childProcess: ChildProcess;
        try {
            childProcess = spawn(
                invocation.command,
                invocation.args,
                spawnOptions(invocation, environment),
            );
        } catch (error) {
            reject(error instanceof Error ? error : new Error(String(error)));
            return;
        }
        const stopTracking = trackChildProcess(childProcess);
        let forceKillTimer: NodeJS.Timeout | undefined;
        let settled = false;
        let terminationReason: CommandTerminationReasonDiagnostic | undefined;

        if (commandId !== undefined) {
            input.runLog?.writeEvent({
                commandId,
                details: { processIdentifier: childProcess.pid ?? null },
                eventType: 'command-started',
            });
        }
        input.observer?.onCommandStart?.({
            invocation,
            logFiles,
            processIdentifier: childProcess.pid,
            startedAtMilliseconds,
        });

        const finish = (): void => {
            if (forceKillTimer !== undefined) clearTimeout(forceKillTimer);
            input.signal?.removeEventListener('abort', abortCommand);
            stopTracking();
        };
        const abortCommand = (): void => {
            if (settled) return;
            terminationReason ??= serializeCommandTerminationReason(
                input.signal?.reason ?? 'abort',
            );
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: {
                        reason: terminationReason,
                    },
                    eventType: 'command-termination-requested',
                });
            }
            killProcessTree(childProcess);
            forceKillTimer ??= setTimeout(
                () => killProcessTree(childProcess, { signal: 'SIGKILL' }),
                forceKillDelayMilliseconds,
            );
            forceKillTimer.unref?.();
        };
        input.signal?.addEventListener('abort', abortCommand, { once: true });
        if (input.signal?.aborted === true) abortCommand();

        const writeOutput = (
            streamName: 'stderr' | 'stdout',
            chunk: string,
        ): void => {
            if (outputMode === 'inherit') {
                (streamName === 'stdout'
                    ? process.stdout
                    : process.stderr
                ).write(chunk);
            }
            if (commandId !== undefined) {
                input.runLog?.writeCommandOutput({
                    chunk,
                    commandId,
                    streamName,
                });
            }
            input.observer?.onCommandOutput?.({
                chunk,
                invocation,
                streamName,
            });
        };
        childProcess.stdout?.setEncoding('utf8');
        childProcess.stderr?.setEncoding('utf8');
        childProcess.stdout?.on('data', (chunk: string) =>
            writeOutput('stdout', chunk),
        );
        childProcess.stderr?.on('data', (chunk: string) =>
            writeOutput('stderr', chunk),
        );

        childProcess.once('error', (error) => {
            if (settled) return;
            settled = true;
            finish();
            const durationMilliseconds = Math.round(
                performance.now() - startedAtMilliseconds,
            );
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: {
                        durationMilliseconds,
                        error: serializeErrorDiagnostic(error),
                        exitCode: 1,
                    },
                    eventType: 'command-spawn-failed',
                });
            }
            input.observer?.onCommandExit?.({
                durationMilliseconds,
                error,
                exitCode: 1,
                invocation,
                terminationSignal: null,
            });
            reject(error);
        });
        childProcess.once('close', (rawExitCode, terminationSignal) => {
            if (settled) return;
            settled = true;
            finish();
            const exitCode =
                terminationSignal === null ? (rawExitCode ?? 1) : 1;
            const durationMilliseconds = Math.round(
                performance.now() - startedAtMilliseconds,
            );
            if (terminationSignal !== null) {
                writeOutput(
                    'stderr',
                    `${invocation.description} terminated by ${terminationSignal}.\n`,
                );
            }
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: {
                        durationMilliseconds,
                        exitCode,
                        rawExitCode,
                        ...(terminationReason === undefined
                            ? {}
                            : {
                                  terminationReason,
                                  terminationRequested: true,
                              }),
                        terminationSignal,
                    },
                    eventType: 'command-finished',
                });
            }
            input.observer?.onCommandExit?.({
                durationMilliseconds,
                exitCode,
                invocation,
                terminationSignal,
            });
            resolve(exitCode);
        });
    });
};

export const runCommandAndCaptureOutput = async (
    invocation: CommandInvocation,
    input: {
        readonly echoOutput?: boolean;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
    } = {},
): Promise<CapturedCommandResult> => {
    let stdout = '';
    let stderr = '';
    let terminationSignal: NodeJS.Signals | null = null;
    const exitCode = await runCommand(invocation, {
        observer: {
            onCommandExit: (event) => {
                terminationSignal = event.terminationSignal;
            },
            onCommandOutput: (event) => {
                if (event.streamName === 'stdout') stdout += event.chunk;
                else stderr += event.chunk;
            },
        },
        outputMode: input.echoOutput === true ? 'inherit' : 'capture',
        runLog: input.runLog,
        signal: input.signal,
    });
    return { exitCode, stderr, stdout, terminationSignal };
};

export const runCommandsInSeries = async (
    invocations: readonly CommandInvocation[],
    input: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
    } = {},
): Promise<number> => {
    for (const invocation of invocations) {
        if (input.signal?.aborted === true) return 1;
        const exitCode = await runCommand(invocation, input);
        if (exitCode !== 0) return exitCode;
    }
    return 0;
};
