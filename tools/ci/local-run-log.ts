import { execFileSync } from 'node:child_process';
import { closeSync, fsyncSync, openSync, writeSync } from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import {
    redactCommandLineArguments,
    redactDiagnosticText,
    selectDiagnosticEnvironment,
    serializeErrorDiagnostic,
} from './run-log-diagnostics.js';

export type CommandLogFiles = {
    readonly combinedPath: string;
    readonly commandId: string;
};

export type LocalRunEventInput = {
    readonly commandId?: string;
    readonly details?: Readonly<Record<string, unknown>>;
    readonly eventType: string;
};

export type ActiveLocalRunLog = {
    readonly runDirectoryPath: string;
    createCommandLogFiles(input: {
        readonly description: string;
        readonly preferredSlug?: string;
    }): CommandLogFiles;
    finish(input: {
        readonly details?: unknown;
        readonly error?: unknown;
        readonly exitCode: number;
    }): Promise<void>;
    writeCommandOutput(input: {
        readonly chunk: string | Uint8Array;
        readonly commandId: string;
        readonly streamName: 'runner' | 'stderr' | 'stdout';
    }): void;
    writeEvent(event: LocalRunEventInput): void;
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

type RepositorySnapshot = {
    readonly commitHash: string;
    readonly treeDirty: boolean;
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
    readonly sequenceNumber: number;
};

const repositoryRootDirectoryPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
);
const defaultResourceSampleIntervalMilliseconds = 15_000;

export const currentProcessExitCode = (): number =>
    typeof process.exitCode === 'number' ? process.exitCode : 0;

const readRepositorySnapshot = (): RepositorySnapshot => ({
    commitHash: execFileSync(
        'git',
        ['rev-parse', '--verify', 'HEAD^{commit}'],
        {
            cwd: repositoryRootDirectoryPath,
            encoding: 'utf8',
            windowsHide: true,
        },
    ).trim(),
    treeDirty:
        execFileSync(
            'git',
            [
                'status',
                '--porcelain=v1',
                '--untracked-files=normal',
                '--ignore-submodules=none',
            ],
            {
                cwd: repositoryRootDirectoryPath,
                encoding: 'utf8',
                windowsHide: true,
            },
        ).length > 0,
});

const safeSlug = (value: string): string =>
    value
        .trim()
        .replace(/[^a-zA-Z0-9]+/gu, '-')
        .replace(/^-+|-+$/gu, '')
        .toLowerCase() || 'run';

const allocateRunDirectory = async (
    rootDirectoryPath: string,
    startedAt: Date,
    scriptName: string,
): Promise<string> => {
    const dateDirectoryPath = path.join(
        rootDirectoryPath,
        startedAt.toISOString().slice(0, 10),
    );
    await mkdir(dateDirectoryPath, { recursive: true });
    const baseName = `${startedAt
        .toISOString()
        .replace(/:/gu, '-')}-${safeSlug(scriptName)}`;

    for (let suffix = 1; ; suffix += 1) {
        const runDirectoryPath = path.join(
            dateDirectoryPath,
            suffix === 1 ? baseName : `${baseName}-${suffix}`,
        );
        try {
            await mkdir(runDirectoryPath);
            return runDirectoryPath;
        } catch (error) {
            if (
                !(error instanceof Error) ||
                !('code' in error) ||
                error.code !== 'EEXIST'
            ) {
                throw error;
            }
        }
    }
};

const writeJsonDurably = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
    });
    const fileDescriptor = openSync(filePath, 'r+');
    try {
        fsyncSync(fileDescriptor);
    } finally {
        closeSync(fileDescriptor);
    }
};

const writeJsonAtomically = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    const temporaryPath = `${filePath}.${process.pid}.tmp`;
    await writeJsonDurably(temporaryPath, value);
    await rename(temporaryPath, filePath);
};

const escapeUnsafeLogControls = (value: string): string =>
    [...value]
        .map((character) => {
            const codePoint = character.codePointAt(0) ?? 0;
            return codePoint <= 8 ||
                codePoint === 11 ||
                codePoint === 12 ||
                (codePoint >= 14 && codePoint <= 31) ||
                codePoint === 127
                ? `\\x${codePoint.toString(16).padStart(2, '0')}`
                : character;
        })
        .join('');

class LocalRunLog implements ActiveLocalRunLog {
    readonly runDirectoryPath: string;
    readonly #activeCommandIds = new Set<string>();
    readonly #commandSlugCounts = new Map<string, number>();
    readonly #eventsFileDescriptor: number;
    readonly #outputFileDescriptor: number;
    readonly #outputPath: string;
    readonly #outputRemainders = new Map<string, string>();
    readonly #repositorySnapshot: RepositorySnapshot;
    readonly #resourcesFileDescriptor: number;
    readonly #scriptName: string;
    readonly #startedAtIso: string;
    readonly #startedAtMilliseconds: number;
    readonly #summaryPath: string;
    #eventSequenceNumber = 0;
    #failedCommandId: string | undefined;
    #finishStarted = false;
    #lastCommandId: string | undefined;
    #lastOutputAtMilliseconds: number;
    #minimumHostFreeMemoryBytes = Number.POSITIVE_INFINITY;
    #peakHeapUsedBytes = 0;
    #peakResidentSetBytes = 0;
    #resourceSampleSequenceNumber = 0;
    #resourceSampleTimer: NodeJS.Timeout;

    constructor(input: {
        readonly repositorySnapshot: RepositorySnapshot;
        readonly resourceSampleIntervalMilliseconds: number;
        readonly runDirectoryPath: string;
        readonly scriptName: string;
        readonly startedAtIso: string;
        readonly startedAtMilliseconds: number;
    }) {
        this.runDirectoryPath = input.runDirectoryPath;
        this.#eventsFileDescriptor = openSync(
            path.join(input.runDirectoryPath, 'events.jsonl'),
            'ax',
        );
        this.#outputPath = path.join(input.runDirectoryPath, 'output.log');
        this.#outputFileDescriptor = openSync(this.#outputPath, 'ax');
        this.#resourcesFileDescriptor = openSync(
            path.join(input.runDirectoryPath, 'resources.jsonl'),
            'ax',
        );
        this.#repositorySnapshot = input.repositorySnapshot;
        this.#scriptName = input.scriptName;
        this.#startedAtIso = input.startedAtIso;
        this.#startedAtMilliseconds = input.startedAtMilliseconds;
        this.#lastOutputAtMilliseconds = input.startedAtMilliseconds;
        this.#summaryPath = path.join(input.runDirectoryPath, 'summary.json');

        this.writeEvent({ eventType: 'run-started' });
        this.#writeResourceSample();
        this.#resourceSampleTimer = setInterval(
            () => this.#writeResourceSample(),
            input.resourceSampleIntervalMilliseconds,
        );
        this.#resourceSampleTimer.unref?.();
    }

    createCommandLogFiles(input: {
        readonly description: string;
        readonly preferredSlug?: string;
    }): CommandLogFiles {
        const baseSlug = safeSlug(input.preferredSlug ?? input.description);
        const count = (this.#commandSlugCounts.get(baseSlug) ?? 0) + 1;
        this.#commandSlugCounts.set(baseSlug, count);
        return {
            combinedPath: this.#outputPath,
            commandId: count === 1 ? baseSlug : `${baseSlug}-${count}`,
        };
    }

    async finish(input: {
        readonly details?: unknown;
        readonly error?: unknown;
        readonly exitCode: number;
    }): Promise<void> {
        if (this.#finishStarted) return;
        this.#finishStarted = true;
        clearInterval(this.#resourceSampleTimer);
        this.#writeResourceSample();
        this.#flushOutputRemainders();

        const error =
            input.error === undefined
                ? undefined
                : serializeErrorDiagnostic(input.error);
        const exitCode =
            input.exitCode === 0 && error !== undefined ? 1 : input.exitCode;
        if (exitCode !== input.exitCode) process.exitCode = exitCode;
        const durationMilliseconds = Math.round(
            performance.now() - this.#startedAtMilliseconds,
        );
        const summary = {
            ...(input.details === undefined ? {} : { details: input.details }),
            durationMilliseconds,
            ...(error === undefined ? {} : { error }),
            exitCode,
            ...(this.#failedCommandId === undefined
                ? {}
                : { failedCommandId: this.#failedCommandId }),
            finishedAtIso: new Date().toISOString(),
            ...(this.#lastCommandId === undefined
                ? {}
                : { lastCommandId: this.#lastCommandId }),
            repositoryCommitHash: this.#repositorySnapshot.commitHash,
            repositoryTreeDirty: this.#repositorySnapshot.treeDirty,
            resourceExtrema: {
                minimumHostFreeMemoryBytes: this.#minimumHostFreeMemoryBytes,
                peakHeapUsedBytes: this.#peakHeapUsedBytes,
                peakResidentSetBytes: this.#peakResidentSetBytes,
            },
            result:
                error === undefined
                    ? exitCode === 0
                        ? 'passed'
                        : 'failed'
                    : 'runner-failure',
            runDirectoryPath: this.runDirectoryPath,
            scriptName: this.#scriptName,
            startedAtIso: this.#startedAtIso,
        };

        try {
            this.writeEvent({
                details: {
                    durationMilliseconds,
                    exitCode,
                    result: summary.result,
                },
                eventType: 'run-finished',
            });
            await writeJsonAtomically(this.#summaryPath, summary);
            await writeFile(
                path.join(this.runDirectoryPath, 'diagnostics.txt'),
                [
                    `Result: ${summary.result}`,
                    `Script: ${this.#scriptName}`,
                    `Repository commit: ${this.#repositorySnapshot.commitHash}`,
                    `Repository tree dirty: ${String(this.#repositorySnapshot.treeDirty)}`,
                    `Started: ${this.#startedAtIso}`,
                    `Finished: ${summary.finishedAtIso}`,
                    `Runtime: ${durationMilliseconds} ms`,
                    `Exit code: ${exitCode}`,
                    `Last command: ${this.#lastCommandId ?? 'none'}`,
                    `Failed command: ${this.#failedCommandId ?? 'none'}`,
                    `Events: ${path.join(this.runDirectoryPath, 'events.jsonl')}`,
                    `Resources: ${path.join(this.runDirectoryPath, 'resources.jsonl')}`,
                    `Output: ${this.#outputPath}`,
                    '',
                ].join('\n'),
                'utf8',
            );
        } finally {
            for (const fileDescriptor of [
                this.#eventsFileDescriptor,
                this.#outputFileDescriptor,
                this.#resourcesFileDescriptor,
            ]) {
                fsyncSync(fileDescriptor);
                closeSync(fileDescriptor);
            }
        }
    }

    writeCommandOutput(input: {
        readonly chunk: string | Uint8Array;
        readonly commandId: string;
        readonly streamName: 'runner' | 'stderr' | 'stdout';
    }): void {
        this.#lastOutputAtMilliseconds = performance.now();
        const key = `${input.commandId}\u0000${input.streamName}`;
        const text = `${this.#outputRemainders.get(key) ?? ''}${
            typeof input.chunk === 'string'
                ? input.chunk
                : Buffer.from(input.chunk).toString('utf8')
        }`;
        const lines = text.split(/\r\n|\n|\r/u);
        const remainder = lines.pop() ?? '';
        if (remainder.length === 0) this.#outputRemainders.delete(key);
        else this.#outputRemainders.set(key, remainder);
        for (const line of lines) {
            this.#writeOutputLine(input.commandId, input.streamName, line);
        }
    }

    writeEvent(event: LocalRunEventInput): void {
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
            if (
                event.eventType === 'command-spawn-failed' ||
                (typeof event.details?.exitCode === 'number' &&
                    event.details.exitCode !== 0)
            ) {
                this.#failedCommandId = event.commandId;
            }
        }

        writeSync(
            this.#eventsFileDescriptor,
            `${JSON.stringify({
                ...(event.commandId === undefined
                    ? {}
                    : { commandId: event.commandId }),
                ...(event.details === undefined
                    ? {}
                    : { details: event.details }),
                elapsedMilliseconds: Math.round(
                    performance.now() - this.#startedAtMilliseconds,
                ),
                eventType: event.eventType,
                occurredAtIso: new Date().toISOString(),
                sequenceNumber: ++this.#eventSequenceNumber,
            })}\n`,
        );
        fsyncSync(this.#eventsFileDescriptor);
        fsyncSync(this.#outputFileDescriptor);
    }

    #flushOutputRemainders(commandId?: string): void {
        for (const [key, remainder] of this.#outputRemainders) {
            const separator = key.indexOf('\u0000');
            const remainderCommandId = key.slice(0, separator);
            if (commandId !== undefined && remainderCommandId !== commandId)
                continue;
            this.#writeOutputLine(
                remainderCommandId,
                key.slice(separator + 1) as 'runner' | 'stderr' | 'stdout',
                remainder,
            );
            this.#outputRemainders.delete(key);
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
                redactDiagnosticText(line),
            )}\n`,
        );
    }

    #writeResourceSample(): void {
        const memory = process.memoryUsage();
        const nowMilliseconds = performance.now();
        const sample: ResourceSample = {
            activeCommandIds: [...this.#activeCommandIds].sort(),
            elapsedMilliseconds: Math.round(
                nowMilliseconds - this.#startedAtMilliseconds,
            ),
            hostMemory: { freeBytes: os.freemem(), totalBytes: os.totalmem() },
            millisecondsSinceLastOutput: Math.round(
                nowMilliseconds - this.#lastOutputAtMilliseconds,
            ),
            occurredAtIso: new Date().toISOString(),
            processMemory: {
                arrayBuffersBytes: memory.arrayBuffers,
                externalBytes: memory.external,
                heapTotalBytes: memory.heapTotal,
                heapUsedBytes: memory.heapUsed,
                residentSetBytes: memory.rss,
            },
            sequenceNumber: ++this.#resourceSampleSequenceNumber,
        };
        writeSync(this.#resourcesFileDescriptor, `${JSON.stringify(sample)}\n`);
        fsyncSync(this.#resourcesFileDescriptor);
        this.#minimumHostFreeMemoryBytes = Math.min(
            this.#minimumHostFreeMemoryBytes,
            sample.hostMemory.freeBytes,
        );
        this.#peakHeapUsedBytes = Math.max(
            this.#peakHeapUsedBytes,
            sample.processMemory.heapUsedBytes,
        );
        this.#peakResidentSetBytes = Math.max(
            this.#peakResidentSetBytes,
            sample.processMemory.residentSetBytes,
        );
    }
}

export const createLocalRunLog = async (
    input: LocalRunLogInput,
): Promise<ActiveLocalRunLog> => {
    const startedAtMilliseconds = performance.now();
    const startedAt = input.now ?? new Date();
    const repositorySnapshot = readRepositorySnapshot();
    const runDirectoryPath = await allocateRunDirectory(
        input.rootDirectoryPath ??
            path.join(repositoryRootDirectoryPath, 'logs'),
        startedAt,
        input.scriptName,
    );
    const environment = input.environment ?? process.env;
    await writeJsonDurably(path.join(runDirectoryPath, 'metadata.json'), {
        architecture: os.arch(),
        commandLineArguments: redactCommandLineArguments(
            input.commandLineArguments,
        ),
        currentWorkingDirectoryPath: process.cwd(),
        diagnosticEnvironment: {
            ...selectDiagnosticEnvironment(environment),
            SEALED_LATTICE_RUN_DIRECTORY: runDirectoryPath,
        },
        lanes: input.lanes,
        logicalProcessorCount: os.cpus().length,
        nodeVersion: process.version,
        operatingSystem: {
            platform: os.platform(),
            release: os.release(),
        },
        parentRunDirectoryPath: environment.SEALED_LATTICE_RUN_DIRECTORY,
        repositoryCommitHash: repositorySnapshot.commitHash,
        repositoryTreeDirty: repositorySnapshot.treeDirty,
        runDirectoryPath,
        runnerProcessIdentifier: process.pid,
        scriptName: input.scriptName,
        startedAtIso: startedAt.toISOString(),
    });

    return new LocalRunLog({
        repositorySnapshot,
        resourceSampleIntervalMilliseconds:
            input.resourceSampleIntervalMilliseconds ??
            defaultResourceSampleIntervalMilliseconds,
        runDirectoryPath,
        scriptName: input.scriptName,
        startedAtIso: startedAt.toISOString(),
        startedAtMilliseconds,
    });
};

export const runWithLocalRunLog = async <Result>(
    input: LocalRunLogInput,
    callback: (runLog: ActiveLocalRunLog) => Promise<Result>,
): Promise<Result> => {
    const runLog = await createLocalRunLog(input);
    try {
        const result = await callback(runLog);
        await runLog.finish({ exitCode: currentProcessExitCode() });
        return result;
    } catch (error) {
        process.exitCode = currentProcessExitCode() || 1;
        try {
            await runLog.finish({ error, exitCode: currentProcessExitCode() });
        } catch (loggingError) {
            process.stderr.write(
                `Failed to finish local run diagnostics: ${String(loggingError)}\n`,
            );
        }
        throw error;
    }
};
