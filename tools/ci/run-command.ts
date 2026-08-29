import {
    spawn,
    spawnSync,
    type ChildProcess,
    type SpawnOptions,
} from 'node:child_process';
import { performance } from 'node:perf_hooks';

import type { ActiveLocalRunLog, CommandLogFiles } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import type { PackageManagerRunner } from './package-manager-runner.js';
import {
    normalizeProcessStatus,
    redactCommandLineArguments,
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

type CommandOutputMode = 'capture' | 'inherit';

export type CapturedCommandResult = {
    readonly exitCode: number;
    readonly processStatus?: ReturnType<typeof normalizeProcessStatus>;
    readonly stderr: string;
    readonly stdout: string;
    readonly terminationSignal: NodeJS.Signals | null;
};

export type CommandOutputStreamName = 'stderr' | 'stdout';

export type CommandStartEvent = {
    readonly invocation: CommandInvocation;
    readonly logFiles?: CommandLogFiles;
    readonly processIdentifier?: number;
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
    readonly processStatus?: ReturnType<typeof normalizeProcessStatus>;
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

type CommandAbortReason = {
    readonly classification: string;
    readonly initiator?: string;
};

type ProcessTreeKillResult = {
    readonly mechanism:
        | 'direct-signal'
        | 'none'
        | 'process-group-signal'
        | 'taskkill-tree-force';
    readonly error?: ReturnType<typeof serializeErrorDiagnostic>;
    readonly fallbackReason?: ReturnType<typeof serializeErrorDiagnostic>;
    readonly processIdentifier?: number;
    readonly status?: number | null;
    readonly succeeded: boolean;
    readonly terminationSignal?: NodeJS.Signals | null;
};

const isCommandAbortReason = (value: unknown): value is CommandAbortReason =>
    typeof value === 'object' &&
    value !== null &&
    'classification' in value &&
    typeof value.classification === 'string' &&
    (!('initiator' in value) ||
        value.initiator === undefined ||
        typeof value.initiator === 'string');

const createAbortableCommandSpawnOptions = (
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
): ProcessTreeKillResult => {
    const requestedSignal = input.signal ?? 'SIGTERM';
    const processId = childProcess.pid;
    if (processId === undefined) {
        return {
            mechanism: 'none',
            succeeded: false,
        };
    }
    if ((input.platform ?? process.platform) === 'win32') {
        // child.kill() only ends the direct child on Windows; package-manager
        // and test-runner grandchildren survive. taskkill /t ends the whole
        // tree. spawnSync keeps the abort path free of dangling listeners.
        try {
            const rawResult = (input.windowsTaskKiller ?? spawnSync)(
                'taskkill',
                ['/pid', String(processId), '/t', '/f'],
                {
                    stdio: 'ignore',
                },
            );
            const result =
                typeof rawResult === 'object' && rawResult !== null
                    ? (rawResult as {
                          readonly error?: unknown;
                          readonly signal?: NodeJS.Signals | null;
                          readonly status?: number | null;
                      })
                    : undefined;
            const error =
                result?.error === undefined
                    ? undefined
                    : serializeErrorDiagnostic(result.error);
            const status = result?.status;

            return {
                mechanism: 'taskkill-tree-force',
                ...(error === undefined ? {} : { error }),
                processIdentifier: processId,
                ...(status === undefined ? {} : { status }),
                succeeded:
                    error === undefined &&
                    (status === undefined || status === 0),
                ...(result?.signal === undefined
                    ? {}
                    : { terminationSignal: result.signal }),
            };
        } catch (error) {
            return {
                mechanism: 'taskkill-tree-force',
                error: serializeErrorDiagnostic(error),
                processIdentifier: processId,
                succeeded: false,
            };
        }
    }
    try {
        (input.processGroupKiller ?? process.kill)(-processId, requestedSignal);

        return {
            mechanism: 'process-group-signal',
            processIdentifier: processId,
            succeeded: true,
        };
    } catch (processGroupError) {
        try {
            const succeeded = childProcess.kill(requestedSignal);

            return {
                mechanism: 'direct-signal',
                fallbackReason: serializeErrorDiagnostic(processGroupError),
                processIdentifier: processId,
                succeeded,
            };
        } catch (directChildError) {
            return {
                mechanism: 'direct-signal',
                error: serializeErrorDiagnostic(
                    Object.assign(
                        new Error(
                            'Process-group and direct-child termination failed.',
                        ),
                        { cause: directChildError },
                    ),
                ),
                processIdentifier: processId,
                succeeded: false,
            };
        }
    }
};

const describeProcessTerminationAttempt = (input: {
    readonly requestedSignal: NodeJS.Signals;
    readonly requestedStage: 'forced' | 'requested';
    readonly result: ProcessTreeKillResult;
}): Readonly<Record<string, unknown>> => ({
    ...input.result,
    actualSignal:
        input.result.mechanism === 'taskkill-tree-force'
            ? null
            : input.requestedSignal,
    requestedSignal: input.requestedSignal,
    stage: input.requestedStage,
});

export const installProcessSignalChildCleanup = (input: {
    readonly activeChildProcesses: ReadonlySet<KillableChildProcess>;
    readonly clearScheduledForceKill?: (timer: unknown) => void;
    readonly forceKillChildProcess?: (
        childProcess: KillableChildProcess,
    ) => ProcessTreeKillResult;
    readonly killChildProcess?: (
        childProcess: KillableChildProcess,
    ) => ProcessTreeKillResult;
    readonly onTerminationAttempt?: (event: {
        readonly childProcess: KillableChildProcess;
        readonly processSignal: ProcessSignalName;
        readonly result: ProcessTreeKillResult;
        readonly stage: 'forced' | 'requested';
    }) => void;
    readonly processEvents?: ProcessSignalEventSource;
    readonly scheduleForceKill?: ProcessSignalEscalationScheduler;
}): (() => void) => {
    const processEvents = input.processEvents ?? process;
    const killChildProcess =
        input.killChildProcess ??
        ((childProcess: KillableChildProcess): ProcessTreeKillResult =>
            killProcessTree(childProcess));
    const forceKillChildProcess =
        input.forceKillChildProcess ??
        ((childProcess: KillableChildProcess): ProcessTreeKillResult =>
            killProcessTree(childProcess, { signal: 'SIGKILL' }));
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
                const result = killChildProcess(childProcess);
                input.onTerminationAttempt?.({
                    childProcess,
                    processSignal: signal,
                    result,
                    stage: 'requested',
                });
            }
            scheduledForceKill ??= scheduleForceKill(() => {
                scheduledForceKill = undefined;
                for (const childProcess of input.activeChildProcesses) {
                    const result = forceKillChildProcess(childProcess);
                    input.onTerminationAttempt?.({
                        childProcess,
                        processSignal: signal,
                        result,
                        stage: 'forced',
                    });
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
const childProcessTerminationRecorders = new WeakMap<
    KillableChildProcess,
    (input: {
        readonly processSignal: ProcessSignalName;
        readonly result: ProcessTreeKillResult;
        readonly stage: 'forced' | 'requested';
    }) => void
>();
let uninstallProcessSignalChildCleanup: (() => void) | undefined;

const trackChildProcessForSignalCleanup = (
    childProcess: KillableChildProcess,
    terminationRecorder?: (input: {
        readonly processSignal: ProcessSignalName;
        readonly result: ProcessTreeKillResult;
        readonly stage: 'forced' | 'requested';
    }) => void,
): (() => void) => {
    activeChildProcesses.add(childProcess);
    if (terminationRecorder !== undefined) {
        childProcessTerminationRecorders.set(childProcess, terminationRecorder);
    }
    uninstallProcessSignalChildCleanup ??= installProcessSignalChildCleanup({
        activeChildProcesses,
        onTerminationAttempt: ({
            childProcess: terminatedChildProcess,
            processSignal,
            result,
            stage,
        }) => {
            childProcessTerminationRecorders.get(terminatedChildProcess)?.({
                processSignal,
                result,
                stage,
            });
        },
    });

    let isTracked = true;
    return (): void => {
        if (!isTracked) {
            return;
        }
        isTracked = false;
        activeChildProcesses.delete(childProcess);
        childProcessTerminationRecorders.delete(childProcess);
        if (activeChildProcesses.size === 0) {
            uninstallProcessSignalChildCleanup?.();
            uninstallProcessSignalChildCleanup = undefined;
        }
    };
};

const commandEnvironment = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog | undefined,
): NodeJS.ProcessEnv => ({
    ...(invocation.env ?? process.env),
    ...(runLog === undefined
        ? {}
        : { SEALED_LATTICE_RUN_DIRECTORY: runLog.runDirectoryPath }),
});

const abortReasonDetails = (
    signal: AbortSignal,
): Pick<CommandAbortReason, 'classification' | 'initiator'> => {
    if (isCommandAbortReason(signal.reason)) {
        return {
            classification: signal.reason.classification,
            ...(signal.reason.initiator === undefined
                ? {}
                : { initiator: signal.reason.initiator }),
        };
    }

    return { classification: 'external-request' };
};

const runCommandWithOptionalLog = async (
    invocation: CommandInvocation,
    input: {
        readonly observer?: CommandRunObserver;
        readonly outputMode?: CommandOutputMode;
        readonly runLog?: ActiveLocalRunLog;
        readonly signal?: AbortSignal;
    } = {},
): Promise<number> => {
    const outputMode = input.outputMode ?? 'inherit';
    if (input.signal?.aborted === true) {
        return 1;
    }

    const commandLogFiles = input.runLog?.createCommandLogFiles({
        description: invocation.description,
        preferredSlug: invocation.logFileSlug,
    });
    const commandId = commandLogFiles?.commandId;
    const environment = commandEnvironment(invocation, input.runLog);
    const heading = `\n${invocation.description}\n`;
    if (outputMode === 'inherit') {
        process.stdout.write(heading);
    }
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
                createAbortableCommandSpawnOptions(
                    environment,
                    ['ignore', 'pipe', 'pipe'],
                    process.platform,
                    invocation.workingDirectoryPath,
                ),
            );
        } catch (error) {
            const resolvedError =
                error instanceof Error ? error : new Error(String(error));
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: {
                        durationMilliseconds: Math.round(
                            performance.now() - startedAtMilliseconds,
                        ),
                        error: serializeErrorDiagnostic(resolvedError),
                    },
                    eventType: 'command-spawn-failed',
                });
            }
            input.observer?.onCommandExit?.({
                durationMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                error: resolvedError,
                exitCode: 1,
                invocation,
                processStatus: normalizeProcessStatus(null, null),
                terminationSignal: null,
            });
            reject(resolvedError);

            return;
        }
        if (commandId !== undefined) {
            input.runLog?.writeEvent({
                commandId,
                details: {
                    processIdentifier: childProcess.pid ?? null,
                },
                eventType: 'command-started',
            });
        }
        input.observer?.onCommandStart?.({
            invocation,
            logFiles: commandLogFiles,
            processIdentifier: childProcess.pid,
            startedAtMilliseconds,
        });
        let requestedTermination:
            | {
                  readonly classification: string;
                  readonly initiator?: string;
                  readonly source: string;
              }
            | undefined;
        let scheduledForceKill: NodeJS.Timeout | undefined;
        const recordTerminationAttempt = (input_: {
            readonly processSignal: NodeJS.Signals;
            readonly result: ProcessTreeKillResult;
            readonly source: string;
            readonly stage: 'forced' | 'requested';
        }): void => {
            if (commandId === undefined) {
                return;
            }
            input.runLog?.writeEvent({
                commandId,
                details: {
                    ...describeProcessTerminationAttempt({
                        requestedSignal: input_.processSignal,
                        requestedStage: input_.stage,
                        result: input_.result,
                    }),
                    source: input_.source,
                },
                eventType: 'command-termination-attempted',
            });
        };
        const untrackChildProcess = trackChildProcessForSignalCleanup(
            childProcess,
            ({ processSignal, result, stage }) => {
                requestedTermination = {
                    classification: 'external-signal',
                    initiator: processSignal,
                    source: 'parent-process-signal',
                };
                if (commandId !== undefined && stage === 'requested') {
                    input.runLog?.writeEvent({
                        commandId,
                        details: requestedTermination,
                        eventType: 'command-termination-requested',
                    });
                }
                recordTerminationAttempt({
                    processSignal: stage === 'forced' ? 'SIGKILL' : 'SIGTERM',
                    result,
                    source: 'parent-process-signal',
                    stage,
                });
            },
        );
        const childStandardOutput = childProcess.stdout;
        const childStandardError = childProcess.stderr;
        if (childStandardOutput === null || childStandardError === null) {
            const killResult = killProcessTree(childProcess);
            recordTerminationAttempt({
                processSignal: 'SIGTERM',
                result: killResult,
                source: 'runner-invariant-failure',
                stage: 'requested',
            });
            untrackChildProcess();
            const error = new Error(
                'Command log capture requires piped stdout and stderr.',
            );
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: { error: serializeErrorDiagnostic(error) },
                    eventType: 'command-spawn-failed',
                });
            }
            reject(error);

            return;
        }
        let abortHandled = false;
        const onAbort = (): void => {
            if (abortHandled) {
                return;
            }
            abortHandled = true;
            const reasonDetails = abortReasonDetails(input.signal!);
            requestedTermination = {
                ...reasonDetails,
                source: 'abort-signal',
            };
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: requestedTermination,
                    eventType: 'command-termination-requested',
                });
            }
            const killResult = killProcessTree(childProcess);
            recordTerminationAttempt({
                processSignal: 'SIGTERM',
                result: killResult,
                source: 'abort-signal',
                stage: 'requested',
            });
            scheduledForceKill ??= setTimeout(() => {
                scheduledForceKill = undefined;
                const forceKillResult = killProcessTree(childProcess, {
                    signal: 'SIGKILL',
                });
                recordTerminationAttempt({
                    processSignal: 'SIGKILL',
                    result: forceKillResult,
                    source: 'abort-signal',
                    stage: 'forced',
                });
            }, forceKillDelayMilliseconds);
            scheduledForceKill.unref?.();
        };
        input.signal?.addEventListener('abort', onAbort, { once: true });
        if (input.signal?.aborted === true) {
            onAbort();
        }
        const writeChunk = (
            streamName: CommandOutputStreamName,
            chunk: string,
        ): void => {
            const terminalStream =
                streamName === 'stdout' ? process.stdout : process.stderr;
            if (outputMode === 'inherit') {
                terminalStream.write(chunk);
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
            if (scheduledForceKill !== undefined) {
                clearTimeout(scheduledForceKill);
            }
            untrackChildProcess();
            input.signal?.removeEventListener('abort', onAbort);
            const durationMilliseconds = Math.round(
                performance.now() - startedAtMilliseconds,
            );
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: {
                        durationMilliseconds,
                        error: serializeErrorDiagnostic(error),
                    },
                    eventType: 'command-spawn-failed',
                });
            }
            input.observer?.onCommandExit?.({
                durationMilliseconds,
                error,
                exitCode: 1,
                invocation,
                processStatus: normalizeProcessStatus(null, null),
                terminationSignal: null,
            });
            reject(error);
        });
        childProcess.once('close', (exitCode, terminationSignal) => {
            if (settled) {
                return;
            }
            settled = true;
            if (scheduledForceKill !== undefined) {
                clearTimeout(scheduledForceKill);
            }
            untrackChildProcess();
            input.signal?.removeEventListener('abort', onAbort);
            const resolvedExitCode =
                terminationSignal === null ? (exitCode ?? 1) : 1;
            if (terminationSignal !== null) {
                const signalMessage = `${invocation.description} terminated by signal ${terminationSignal}.\n`;
                if (outputMode === 'inherit') {
                    process.stderr.write(signalMessage);
                }
                if (commandId !== undefined) {
                    input.runLog?.writeCommandOutput({
                        chunk: signalMessage,
                        commandId,
                        streamName: 'stderr',
                    });
                }
                input.observer?.onCommandOutput?.({
                    chunk: signalMessage,
                    invocation,
                    streamName: 'stderr',
                });
            }
            const durationMilliseconds = Math.round(
                performance.now() - startedAtMilliseconds,
            );
            const processStatus = normalizeProcessStatus(
                exitCode,
                terminationSignal,
            );
            const resultClassification =
                requestedTermination?.classification ??
                (terminationSignal !== null
                    ? 'external-signal'
                    : exitCode === null
                      ? 'unknown-abrupt-termination'
                      : exitCode === 0
                        ? 'completed'
                        : 'test-failure');
            if (commandId !== undefined) {
                input.runLog?.writeEvent({
                    commandId,
                    details: {
                        durationMilliseconds,
                        processStatus,
                        ...(requestedTermination === undefined
                            ? {}
                            : { requestedTermination }),
                        resultClassification,
                    },
                    eventType: 'command-finished',
                });
            }
            input.observer?.onCommandExit?.({
                durationMilliseconds,
                exitCode: resolvedExitCode,
                invocation,
                processStatus,
                terminationSignal,
            });
            resolve(resolvedExitCode);
        });
    });
};

/**
 * Runs a command through the normal asynchronous diagnostic path while
 * retaining stdout and stderr for callers that must parse command output.
 * Output is still written incrementally to the owning run log; terminal echo
 * is opt-in so machine-readable stdout does not pollute routine output.
 */
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
    let exitEvent: CommandExitEvent | undefined;
    const exitCode = await runCommandWithOptionalLog(invocation, {
        observer: {
            onCommandExit: (event) => {
                exitEvent = event;
            },
            onCommandOutput: (event) => {
                if (event.streamName === 'stdout') {
                    stdout += event.chunk;
                } else {
                    stderr += event.chunk;
                }
            },
        },
        outputMode: input.echoOutput === true ? 'inherit' : 'capture',
        runLog: input.runLog,
        signal: input.signal,
    });

    return {
        exitCode,
        ...(exitEvent?.processStatus === undefined
            ? {}
            : { processStatus: exitEvent.processStatus }),
        stderr,
        stdout,
        terminationSignal: exitEvent?.terminationSignal ?? null,
    };
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
