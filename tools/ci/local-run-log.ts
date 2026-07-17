import {
    closeSync,
    existsSync,
    fsyncSync,
    openSync,
    readdirSync,
    writeSync,
} from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import {
    normalizeProcessStatus,
    redactCommandLineArguments,
    selectDiagnosticEnvironment,
    serializeErrorDiagnostic,
} from './run-log-diagnostics.js';

export type CommandLogFiles = {
    readonly combinedPath: string;
    readonly commandId: string;
    readonly stderrPath?: string;
    readonly stdoutPath?: string;
};

export type CommandLogRequest = {
    readonly description: string;
    readonly preferredSlug?: string;
};

export type LocalRunEventInput = {
    readonly commandId?: string;
    readonly details?: Readonly<Record<string, unknown>>;
    readonly eventType: string;
};

export type ActiveLocalRunLog = {
    readonly runDirectoryPath: string;
    createCommandLogFiles(request: CommandLogRequest): CommandLogFiles;
    finish(input: {
        readonly details?: unknown;
        readonly error?: unknown;
        readonly exitCode: number;
    }): Promise<void>;
    writeCombinedOutput(chunk: string | Uint8Array): void;
    writeCommandOutput(input: {
        readonly chunk: string | Uint8Array;
        readonly commandId: string;
        readonly streamName: 'runner' | 'stderr' | 'stdout';
    }): void;
    writeEvent(event: LocalRunEventInput): void;
};

type LocalRunLogMetadata = {
    readonly architecture: string;
    readonly commandLineArguments: readonly string[];
    readonly cpu: {
        readonly logicalProcessorCount: number;
        readonly model?: string;
    };
    readonly currentWorkingDirectoryPath: string;
    readonly diagnosticEnvironment: Readonly<Record<string, string>>;
    readonly hostMemory: {
        readonly freeBytesAtStart: number;
        readonly totalBytes: number;
    };
    readonly lanes: readonly string[];
    readonly nodeVersion: string;
    readonly operatingSystem: {
        readonly platform: NodeJS.Platform;
        readonly release: string;
        readonly type: string;
        readonly version: string;
    };
    readonly parentProcessIdentifier: number;
    readonly parentRunDirectoryPath?: string;
    readonly runDirectoryPath: string;
    readonly runnerProcessIdentifier: number;
    readonly scriptName: string;
    readonly startedAtIso: string;
};

type LocalRunLogSummary = {
    readonly details?: unknown;
    readonly diagnosticFailureCount: number;
    readonly durationMilliseconds: number;
    readonly error?: ReturnType<typeof serializeErrorDiagnostic>;
    readonly exitCode: number;
    readonly failedCommandId?: string;
    readonly finishedAtIso: string;
    readonly lastCommandId?: string;
    readonly processStatus: ReturnType<typeof normalizeProcessStatus>;
    readonly resourceExtrema: {
        readonly minimumHostFreeMemoryBytes: number;
        readonly peakHeapUsedBytes: number;
        readonly peakResidentSetBytes: number;
    };
    readonly resultClassification:
        | 'completed'
        | 'completed-with-diagnostic-failure'
        | 'runner-failure'
        | 'test-failure';
    readonly runDirectoryPath: string;
    readonly scriptName: string;
    readonly startedAtIso: string;
};

type ResourceSample = {
    readonly activeCommandIds: readonly string[];
    readonly elapsedMilliseconds: number;
    readonly hostMemory: {
        readonly freeBytes: number;
        readonly totalBytes: number;
    };
    readonly millisecondsSinceLastOutput: number;
    readonly occurredAtIso: string;
    readonly processMemory: {
        readonly arrayBuffersBytes: number;
        readonly externalBytes: number;
        readonly heapTotalBytes: number;
        readonly heapUsedBytes: number;
        readonly residentSetBytes: number;
    };
    readonly processCpu: {
        readonly systemMicroseconds: number;
        readonly userMicroseconds: number;
    };
    readonly processUptimeSeconds: number;
    readonly resourceScope: 'orchestration-process-and-host';
    readonly sequenceNumber: number;
};

type LocalRunLogInput = {
    readonly commandLineArguments: readonly string[];
    readonly environment?: NodeJS.ProcessEnv;
    readonly lanes: readonly string[];
    readonly now?: Date;
    readonly resourceSampleIntervalMilliseconds?: number;
    readonly rootDirectoryPath?: string;
    readonly scriptName: string;
};

type ProcessEventSource = {
    off(eventName: string, listener: (...arguments_: never[]) => void): unknown;
    on(eventName: string, listener: (...arguments_: never[]) => void): unknown;
};

const defaultResourceSampleIntervalMilliseconds = 15_000;

export const currentProcessExitCode = (): number => {
    if (process.exitCode === undefined) {
        return 0;
    }
    if (typeof process.exitCode === 'number') {
        return process.exitCode;
    }

    return 1;
};

export const safeLogSlug = (value: string): string => {
    const slug = value
        .trim()
        .replace(/[^a-zA-Z0-9]+/gu, '-')
        .replace(/^-+|-+$/gu, '')
        .toLowerCase();

    return slug.length > 0 ? slug : 'run';
};

const timestampForPath = (date: Date): string =>
    date.toISOString().replace(/:/gu, '-');

const escapeUnsafeLogControls = (value: string): string =>
    [...value]
        .map((character) => {
            const codePoint = character.codePointAt(0);
            const isUnsafeControl =
                codePoint !== undefined &&
                ((codePoint >= 0 && codePoint <= 8) ||
                    codePoint === 11 ||
                    codePoint === 12 ||
                    (codePoint >= 14 && codePoint <= 31) ||
                    codePoint === 127);

            return isUnsafeControl
                ? `\\x${codePoint.toString(16).padStart(2, '0')}`
                : character;
        })
        .join('');

const repositoryRootDirectoryPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
);

const defaultLogRootDirectoryPath = (): string =>
    path.join(repositoryRootDirectoryPath, 'logs');

const writeJsonFile = async (
    filePath: string,
    value: unknown,
    flags?: 'wx',
): Promise<void> => {
    await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, {
        encoding: 'utf8',
        ...(flags === undefined ? {} : { flag: flags }),
    });
    const fileDescriptor = openSync(filePath, 'r+');
    try {
        fsyncSync(fileDescriptor);
    } finally {
        closeSync(fileDescriptor);
    }
};

const writeJsonFileAtomically = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    const temporaryPath = `${filePath}.${process.pid}.tmp`;
    await writeJsonFile(temporaryPath, value, 'wx');
    await rename(temporaryPath, filePath);
};

const isFileAlreadyPresentError = (error: unknown): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'EEXIST';

const allocateRunDirectory = async (
    rootDirectoryPath: string,
    startedAt: Date,
    scriptName: string,
): Promise<string> => {
    const dayDirectoryPath = path.join(
        rootDirectoryPath,
        startedAt.toISOString().slice(0, 10),
    );
    await mkdir(dayDirectoryPath, { recursive: true });
    const runDirectoryBaseName = `${timestampForPath(startedAt)}-${safeLogSlug(
        scriptName,
    )}`;

    for (let suffix = 1; ; suffix += 1) {
        const runDirectoryPath = path.join(
            dayDirectoryPath,
            suffix === 1
                ? runDirectoryBaseName
                : `${runDirectoryBaseName}-${suffix}`,
        );
        try {
            await mkdir(runDirectoryPath);

            return runDirectoryPath;
        } catch (error) {
            if (!isFileAlreadyPresentError(error)) {
                throw error;
            }
        }
    }
};

class LocalRunLog implements ActiveLocalRunLog {
    readonly runDirectoryPath: string;
    #activeCommandIds = new Set<string>();
    #commandSlugCounts = new Map<string, number>();
    #diagnosticFailures: ReturnType<typeof serializeErrorDiagnostic>[] = [];
    #eventSequenceNumber = 0;
    #failedCommandId: string | undefined;
    #eventsFileDescriptor: number;
    #closed = false;
    #finishStarted = false;
    #lastResourceSample: ResourceSample | undefined;
    #lastCommandId: string | undefined;
    #lastOutputAtMilliseconds: number;
    #outputFileDescriptor: number;
    #outputPath: string;
    #outputRemainders = new Map<string, string>();
    #peakHeapUsedBytes = 0;
    #peakResidentSetBytes = 0;
    #minimumHostFreeMemoryBytes = Number.POSITIVE_INFINITY;
    #processEventSource: ProcessEventSource;
    #processListeners: {
        readonly eventName: string;
        readonly listener: (...arguments_: never[]) => void;
    }[] = [];
    #resourceSampleInterval: NodeJS.Timeout;
    #resourceSampleSequenceNumber = 0;
    #resourcesFileDescriptor: number;
    #scriptName: string;
    #startedAtIso: string;
    #startedAtMilliseconds: number;
    #summaryPath: string;

    constructor(input: {
        readonly eventsPath: string;
        readonly outputPath: string;
        readonly processEventSource?: ProcessEventSource;
        readonly resourceSampleIntervalMilliseconds: number;
        readonly resourcesPath: string;
        readonly runDirectoryPath: string;
        readonly scriptName: string;
        readonly startedAtIso: string;
        readonly startedAtMilliseconds: number;
        readonly summaryPath: string;
    }) {
        this.runDirectoryPath = input.runDirectoryPath;
        this.#eventsFileDescriptor = openSync(input.eventsPath, 'ax');
        this.#outputFileDescriptor = openSync(input.outputPath, 'ax');
        this.#outputPath = input.outputPath;
        this.#lastOutputAtMilliseconds = input.startedAtMilliseconds;
        this.#processEventSource =
            input.processEventSource ??
            (process as unknown as ProcessEventSource);
        this.#resourcesFileDescriptor = openSync(input.resourcesPath, 'ax');
        this.#scriptName = input.scriptName;
        this.#startedAtIso = input.startedAtIso;
        this.#startedAtMilliseconds = input.startedAtMilliseconds;
        this.#summaryPath = input.summaryPath;

        this.writeEvent({ eventType: 'run-started' });
        this.#writeHeartbeatAndResourceSample();
        this.#installProcessObservers();
        this.#resourceSampleInterval = setInterval(() => {
            try {
                this.#writeHeartbeatAndResourceSample();
            } catch (error) {
                this.#recordDiagnosticFailure('resource-sampling', error);
            }
        }, input.resourceSampleIntervalMilliseconds);
        this.#resourceSampleInterval.unref?.();
    }

    createCommandLogFiles(request: CommandLogRequest): CommandLogFiles {
        const baseSlug = safeLogSlug(
            request.preferredSlug ?? request.description,
        );
        const previousCount = this.#commandSlugCounts.get(baseSlug) ?? 0;
        this.#commandSlugCounts.set(baseSlug, previousCount + 1);
        const commandId =
            previousCount === 0 ? baseSlug : `${baseSlug}-${previousCount + 1}`;

        return {
            combinedPath: this.#outputPath,
            commandId,
        };
    }

    async finish(input: {
        readonly details?: unknown;
        readonly error?: unknown;
        readonly exitCode: number;
    }): Promise<void> {
        if (this.#finishStarted) {
            return;
        }
        this.#finishStarted = true;
        clearInterval(this.#resourceSampleInterval);
        this.#removeProcessObservers();

        try {
            this.#writeHeartbeatAndResourceSample();
        } catch (error) {
            this.#recordDiagnosticFailure('final-resource-sampling', error);
        }
        this.#flushOutputRemainders();

        const serializedError =
            input.error === undefined
                ? undefined
                : serializeErrorDiagnostic(input.error);
        const effectiveExitCode =
            input.exitCode === 0 &&
            (serializedError !== undefined ||
                this.#diagnosticFailures.length > 0)
                ? 1
                : input.exitCode;
        if (effectiveExitCode !== input.exitCode) {
            process.exitCode = effectiveExitCode;
        }
        const finishedAtIso = new Date().toISOString();
        const durationMilliseconds = Math.round(
            performance.now() - this.#startedAtMilliseconds,
        );
        const processStatus = normalizeProcessStatus(effectiveExitCode, null);
        const resultClassification =
            serializedError !== undefined
                ? 'runner-failure'
                : this.#diagnosticFailures.length > 0
                  ? 'completed-with-diagnostic-failure'
                  : effectiveExitCode === 0
                    ? 'completed'
                    : 'test-failure';
        const summary: LocalRunLogSummary = {
            durationMilliseconds,
            details: input.details,
            diagnosticFailureCount: this.#diagnosticFailures.length,
            ...(serializedError === undefined
                ? {}
                : { error: serializedError }),
            exitCode: effectiveExitCode,
            ...(this.#failedCommandId === undefined
                ? {}
                : { failedCommandId: this.#failedCommandId }),
            finishedAtIso,
            ...(this.#lastCommandId === undefined
                ? {}
                : { lastCommandId: this.#lastCommandId }),
            processStatus,
            resourceExtrema: {
                minimumHostFreeMemoryBytes: this.#minimumHostFreeMemoryBytes,
                peakHeapUsedBytes: this.#peakHeapUsedBytes,
                peakResidentSetBytes: this.#peakResidentSetBytes,
            },
            resultClassification,
            runDirectoryPath: this.runDirectoryPath,
            scriptName: this.#scriptName,
            startedAtIso: this.#startedAtIso,
        };

        try {
            this.writeEvent({
                details: {
                    diagnosticFailureCount: this.#diagnosticFailures.length,
                    durationMilliseconds,
                    ...(serializedError === undefined
                        ? {}
                        : { error: serializedError }),
                    ...(this.#failedCommandId === undefined
                        ? {}
                        : { failedCommandId: this.#failedCommandId }),
                    ...(this.#lastCommandId === undefined
                        ? {}
                        : { lastCommandId: this.#lastCommandId }),
                    processStatus,
                    resourceExtrema: summary.resourceExtrema,
                    resultClassification,
                },
                eventType: 'run-finished',
            });
            await writeJsonFileAtomically(this.#summaryPath, summary);
            await writeFile(
                path.join(this.runDirectoryPath, 'diagnostics.txt'),
                this.#formatDiagnostics(summary),
                'utf8',
            );
        } finally {
            this.#closeFileDescriptors();
            this.#closed = true;
        }
    }

    writeCombinedOutput(chunk: string | Uint8Array): void {
        this.writeCommandOutput({
            chunk,
            commandId: 'runner',
            streamName: 'runner',
        });
    }

    writeCommandOutput(input: {
        readonly chunk: string | Uint8Array;
        readonly commandId: string;
        readonly streamName: 'runner' | 'stderr' | 'stdout';
    }): void {
        this.#requireActive();
        this.#lastOutputAtMilliseconds = performance.now();
        const key = `${input.commandId}\u0000${input.streamName}`;
        const chunkText =
            typeof input.chunk === 'string'
                ? input.chunk
                : Buffer.from(input.chunk).toString('utf8');
        const completeText = `${this.#outputRemainders.get(key) ?? ''}${chunkText}`;
        const lines = completeText.split(/\r\n|\n|\r/u);
        const remainder = lines.pop() ?? '';
        if (remainder.length === 0) {
            this.#outputRemainders.delete(key);
        } else {
            this.#outputRemainders.set(key, remainder);
        }
        for (const line of lines) {
            this.#writeOutputLine(input.commandId, input.streamName, line);
        }
    }

    #writeOutputLine(
        commandId: string,
        streamName: 'runner' | 'stderr' | 'stdout',
        line: string,
    ): void {
        const elapsedMilliseconds = Math.round(
            performance.now() - this.#startedAtMilliseconds,
        );
        writeSync(
            this.#outputFileDescriptor,
            `${new Date().toISOString()} +${String(
                elapsedMilliseconds,
            ).padStart(
                10,
                '0',
            )}ms [${commandId}] [${streamName}] ${escapeUnsafeLogControls(
                line,
            )}\n`,
        );
    }

    writeEvent(event: LocalRunEventInput): void {
        this.#requireActive();
        if (
            event.commandId !== undefined &&
            event.eventType.startsWith('command-')
        ) {
            this.#lastCommandId = event.commandId;
        }
        if (
            event.commandId !== undefined &&
            event.eventType === 'command-started'
        ) {
            this.#activeCommandIds.add(event.commandId);
        }
        if (
            event.commandId !== undefined &&
            (event.eventType === 'command-finished' ||
                event.eventType === 'command-spawn-failed')
        ) {
            this.#flushOutputRemainders(event.commandId);
            this.#activeCommandIds.delete(event.commandId);
            const resultClassification = event.details?.resultClassification;
            if (
                event.eventType === 'command-spawn-failed' ||
                (typeof resultClassification === 'string' &&
                    resultClassification !== 'completed')
            ) {
                this.#failedCommandId = event.commandId;
            }
        }

        const eventRecord = {
            ...(event.commandId === undefined
                ? {}
                : { commandId: event.commandId }),
            ...(event.details === undefined ? {} : { details: event.details }),
            elapsedMilliseconds: Math.round(
                performance.now() - this.#startedAtMilliseconds,
            ),
            eventType: event.eventType,
            occurredAtIso: new Date().toISOString(),
            sequenceNumber: ++this.#eventSequenceNumber,
        };
        writeSync(
            this.#eventsFileDescriptor,
            `${JSON.stringify(eventRecord)}\n`,
        );
        fsyncSync(this.#eventsFileDescriptor);
        fsyncSync(this.#outputFileDescriptor);
    }

    #closeFileDescriptors(): void {
        for (const fileDescriptor of [
            this.#eventsFileDescriptor,
            this.#outputFileDescriptor,
            this.#resourcesFileDescriptor,
        ]) {
            try {
                fsyncSync(fileDescriptor);
            } finally {
                closeSync(fileDescriptor);
            }
        }
    }

    #formatDiagnostics(summary: LocalRunLogSummary): string {
        const lastResourceSample = this.#lastResourceSample;
        const status = summary.processStatus;
        const lines = [
            `Result: ${summary.resultClassification}`,
            `Script: ${summary.scriptName}`,
            `Started: ${summary.startedAtIso}`,
            `Finished: ${summary.finishedAtIso}`,
            `Runtime: ${summary.durationMilliseconds} ms`,
            `Exit code: ${summary.exitCode}`,
            `Raw exit code: ${status.rawExitCode ?? 'none'}`,
            `Signed exit code: ${status.signedExitCode ?? 'none'}`,
            `Unsigned exit code: ${status.unsignedExitCode ?? 'none'}`,
            `Hexadecimal exit code: ${status.hexadecimalExitCode ?? 'none'}`,
            `Symbolic status: ${status.symbolicStatus ?? 'none'}`,
            `Termination signal: ${status.terminationSignal ?? 'none'}`,
            `Diagnostic failures: ${summary.diagnosticFailureCount}`,
            `Last command: ${summary.lastCommandId ?? 'none'}`,
            `Failed command: ${summary.failedCommandId ?? 'none'}`,
            `Peak parent RSS: ${summary.resourceExtrema.peakResidentSetBytes} bytes`,
            `Peak parent heap used: ${summary.resourceExtrema.peakHeapUsedBytes} bytes`,
            `Minimum observed host free memory: ${summary.resourceExtrema.minimumHostFreeMemoryBytes} bytes`,
            `Last active commands: ${
                lastResourceSample === undefined ||
                lastResourceSample.activeCommandIds.length === 0
                    ? 'none'
                    : lastResourceSample.activeCommandIds.join(', ')
            }`,
            `Last parent RSS: ${
                lastResourceSample?.processMemory.residentSetBytes ?? 'unknown'
            } bytes`,
            `Last host free memory: ${
                lastResourceSample?.hostMemory.freeBytes ?? 'unknown'
            } bytes`,
            `Last output age: ${
                lastResourceSample?.millisecondsSinceLastOutput ?? 'unknown'
            } ms`,
            `Parent CPU user: ${
                lastResourceSample?.processCpu.userMicroseconds ?? 'unknown'
            } microseconds`,
            `Parent CPU system: ${
                lastResourceSample?.processCpu.systemMicroseconds ?? 'unknown'
            } microseconds`,
            `Events: ${path.join(this.runDirectoryPath, 'events.jsonl')}`,
            `Resources: ${path.join(this.runDirectoryPath, 'resources.jsonl')}`,
            `Output: ${this.#outputPath}`,
        ];
        if (summary.error !== undefined) {
            lines.push(
                `Error: ${summary.error.name}: ${summary.error.message}`,
            );
        }
        const conventionalDiagnosticPaths = [
            ['Test events', path.join(this.runDirectoryPath, 'tests')],
            ['Guard resources', path.join(this.runDirectoryPath, 'resources')],
            [
                'Diagnostic reports',
                path.join(this.runDirectoryPath, 'diagnostic-reports'),
            ],
        ] as const;
        for (const [label, diagnosticPath] of conventionalDiagnosticPaths) {
            if (existsSync(diagnosticPath)) {
                lines.push(`${label}: ${diagnosticPath}`);
            }
        }
        lines.push(...this.#formatAttachmentDiagnostics());

        return `${lines.join('\n')}\n`;
    }

    #formatAttachmentDiagnostics(): readonly string[] {
        const attachmentRootPath = path.join(
            this.runDirectoryPath,
            'attachments',
        );
        if (!existsSync(attachmentRootPath)) {
            return [];
        }

        const lines = [`Attachments: ${attachmentRootPath}`];
        const projectDirectories = readdirSync(attachmentRootPath, {
            withFileTypes: true,
        })
            .filter((entry) => entry.isDirectory())
            .sort((left, right) => left.name.localeCompare(right.name));
        for (const projectDirectory of projectDirectories) {
            const projectDirectoryPath = path.join(
                attachmentRootPath,
                projectDirectory.name,
            );
            lines.push(
                `Attachment files (${projectDirectory.name}): ${projectDirectoryPath}`,
            );
        }

        return lines;
    }

    #installProcessObservers(): void {
        const addListener = (
            eventName: string,
            listener: (...arguments_: never[]) => void,
        ): void => {
            this.#processEventSource.on(eventName, listener);
            this.#processListeners.push({ eventName, listener });
        };

        addListener(
            'uncaughtExceptionMonitor',
            (error: Error, origin: string): void => {
                try {
                    this.writeEvent({
                        details: {
                            error: serializeErrorDiagnostic(error),
                            origin,
                        },
                        eventType: 'uncaught-exception-observed',
                    });
                } catch (loggingError) {
                    process.stderr.write(
                        `Failed to journal uncaught exception: ${String(
                            loggingError,
                        )}\n`,
                    );
                }
            },
        );
        addListener('beforeExit', (exitCode: number): void => {
            this.writeEvent({
                details: {
                    processStatus: normalizeProcessStatus(exitCode, null),
                },
                eventType: 'process-before-exit-observed',
            });
        });
        addListener('exit', (exitCode: number): void => {
            try {
                this.writeEvent({
                    details: {
                        processStatus: normalizeProcessStatus(exitCode, null),
                    },
                    eventType: 'process-exit-observed',
                });
            } catch (loggingError) {
                process.stderr.write(
                    `Failed to journal process exit: ${String(loggingError)}\n`,
                );
            }
        });
    }

    #flushOutputRemainders(commandId?: string): void {
        for (const [key, remainder] of this.#outputRemainders) {
            const separatorIndex = key.indexOf('\u0000');
            const remainderCommandId = key.slice(0, separatorIndex);
            if (commandId !== undefined && remainderCommandId !== commandId) {
                continue;
            }
            const streamName = key.slice(separatorIndex + 1) as
                | 'runner'
                | 'stderr'
                | 'stdout';
            this.#writeOutputLine(remainderCommandId, streamName, remainder);
            this.#outputRemainders.delete(key);
        }
    }

    #recordDiagnosticFailure(operation: string, error: unknown): void {
        const diagnostic = serializeErrorDiagnostic(error);
        this.#diagnosticFailures.push(diagnostic);
        process.exitCode = currentProcessExitCode() || 1;
        this.writeEvent({
            details: { error: diagnostic, operation },
            eventType: 'diagnostic-write-failed',
        });
    }

    #removeProcessObservers(): void {
        for (const { eventName, listener } of this.#processListeners) {
            this.#processEventSource.off(eventName, listener);
        }
        this.#processListeners.length = 0;
    }

    #requireActive(): void {
        if (this.#closed) {
            throw new Error('Cannot write to a finished local run log.');
        }
    }

    #writeHeartbeatAndResourceSample(): void {
        const processMemory = process.memoryUsage();
        const processCpu = process.cpuUsage();
        const nowMilliseconds = performance.now();
        const sample: ResourceSample = {
            activeCommandIds: [...this.#activeCommandIds].sort(),
            elapsedMilliseconds: Math.round(
                nowMilliseconds - this.#startedAtMilliseconds,
            ),
            hostMemory: {
                freeBytes: os.freemem(),
                totalBytes: os.totalmem(),
            },
            millisecondsSinceLastOutput: Math.round(
                nowMilliseconds - this.#lastOutputAtMilliseconds,
            ),
            occurredAtIso: new Date().toISOString(),
            processMemory: {
                arrayBuffersBytes: processMemory.arrayBuffers,
                externalBytes: processMemory.external,
                heapTotalBytes: processMemory.heapTotal,
                heapUsedBytes: processMemory.heapUsed,
                residentSetBytes: processMemory.rss,
            },
            processCpu: {
                systemMicroseconds: processCpu.system,
                userMicroseconds: processCpu.user,
            },
            processUptimeSeconds: process.uptime(),
            resourceScope: 'orchestration-process-and-host',
            sequenceNumber: ++this.#resourceSampleSequenceNumber,
        };
        writeSync(this.#resourcesFileDescriptor, `${JSON.stringify(sample)}\n`);
        fsyncSync(this.#resourcesFileDescriptor);
        this.#lastResourceSample = sample;
        this.#peakResidentSetBytes = Math.max(
            this.#peakResidentSetBytes,
            sample.processMemory.residentSetBytes,
        );
        this.#peakHeapUsedBytes = Math.max(
            this.#peakHeapUsedBytes,
            sample.processMemory.heapUsedBytes,
        );
        this.#minimumHostFreeMemoryBytes = Math.min(
            this.#minimumHostFreeMemoryBytes,
            sample.hostMemory.freeBytes,
        );
        this.writeEvent({
            details: {
                activeCommandIds: sample.activeCommandIds,
                resourceSampleSequenceNumber: sample.sequenceNumber,
            },
            eventType: 'run-heartbeat',
        });
    }
}

export const createLocalRunLog = async (
    input: LocalRunLogInput,
): Promise<ActiveLocalRunLog> => {
    const startedAtMilliseconds = performance.now();
    const startedAt = input.now ?? new Date();
    const startedAtIso = startedAt.toISOString();
    const rootDirectoryPath =
        input.rootDirectoryPath ?? defaultLogRootDirectoryPath();
    const runDirectoryPath = await allocateRunDirectory(
        rootDirectoryPath,
        startedAt,
        input.scriptName,
    );
    const processors = os.cpus();
    const diagnosticEnvironment = input.environment ?? process.env;
    const inheritedRunDirectoryPath =
        diagnosticEnvironment.SEALED_LATTICE_RUN_DIRECTORY;
    const metadata: LocalRunLogMetadata = {
        architecture: os.arch(),
        commandLineArguments: redactCommandLineArguments(
            input.commandLineArguments,
        ),
        cpu: {
            logicalProcessorCount: processors.length,
            ...(processors[0]?.model === undefined
                ? {}
                : { model: processors[0].model }),
        },
        currentWorkingDirectoryPath: process.cwd(),
        diagnosticEnvironment: {
            ...selectDiagnosticEnvironment(diagnosticEnvironment),
            SEALED_LATTICE_RUN_DIRECTORY: runDirectoryPath,
        },
        hostMemory: {
            freeBytesAtStart: os.freemem(),
            totalBytes: os.totalmem(),
        },
        lanes: input.lanes,
        nodeVersion: process.version,
        operatingSystem: {
            platform: os.platform(),
            release: os.release(),
            type: os.type(),
            version: os.version(),
        },
        parentProcessIdentifier: process.ppid,
        ...(inheritedRunDirectoryPath === undefined ||
        path.resolve(inheritedRunDirectoryPath) ===
            path.resolve(runDirectoryPath)
            ? {}
            : { parentRunDirectoryPath: inheritedRunDirectoryPath }),
        runDirectoryPath,
        runnerProcessIdentifier: process.pid,
        scriptName: input.scriptName,
        startedAtIso,
    };
    await writeJsonFile(
        path.join(runDirectoryPath, 'metadata.json'),
        metadata,
        'wx',
    );

    return new LocalRunLog({
        eventsPath: path.join(runDirectoryPath, 'events.jsonl'),
        outputPath: path.join(runDirectoryPath, 'output.log'),
        resourceSampleIntervalMilliseconds:
            input.resourceSampleIntervalMilliseconds ??
            defaultResourceSampleIntervalMilliseconds,
        resourcesPath: path.join(runDirectoryPath, 'resources.jsonl'),
        runDirectoryPath,
        scriptName: input.scriptName,
        startedAtIso,
        startedAtMilliseconds,
        summaryPath: path.join(runDirectoryPath, 'summary.json'),
    });
};

export const runWithLocalRunLog = async <Result>(
    input: LocalRunLogInput,
    callback: (runLog: ActiveLocalRunLog) => Promise<Result>,
): Promise<Result> => {
    const runLog = await createLocalRunLog(input);
    let callbackError: unknown;
    let result: Result | undefined;

    try {
        result = await callback(runLog);
    } catch (error) {
        callbackError = error;
        process.exitCode = currentProcessExitCode() || 1;
    }

    try {
        await runLog.finish({
            ...(callbackError === undefined ? {} : { error: callbackError }),
            exitCode: currentProcessExitCode(),
        });
    } catch (loggingError) {
        if (callbackError === undefined) {
            throw loggingError;
        }
        process.stderr.write(
            `Failed to finish local run diagnostics: ${String(loggingError)}\n`,
        );
    }

    if (callbackError !== undefined) {
        throw callbackError instanceof Error
            ? callbackError
            : Object.assign(new Error('Callback threw a non-Error value.'), {
                  cause: callbackError,
              });
    }

    return result as Result;
};
