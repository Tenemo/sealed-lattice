import { createWriteStream, type WriteStream } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

export type CommandLogFiles = {
    readonly combinedPath: string;
    readonly stderrPath: string;
    readonly stdoutPath: string;
};

export type CommandLogRequest = {
    readonly description: string;
    readonly preferredSlug?: string;
};

export type ActiveLocalRunLog = {
    readonly runDirectoryPath: string;
    createCommandLogFiles(request: CommandLogRequest): CommandLogFiles;
    discardCommandLogFiles(files: CommandLogFiles): Promise<void>;
    finish(input: {
        readonly details?: unknown;
        readonly exitCode: number;
    }): Promise<void>;
    writeCombinedOutput(chunk: string | Uint8Array): void;
};

type LocalRunLogMetadata = {
    readonly arch: string;
    readonly commandLineArguments: readonly string[];
    readonly cwd: string;
    readonly lanes: readonly string[];
    readonly nodeVersion: string;
    readonly objectVersion: 'sealed-lattice-local-run-log-metadata-v1';
    readonly platform: string;
    readonly runDirectoryPath: string;
    readonly scriptName: string;
    readonly startedAtIso: string;
};

type LocalRunLogSummary = {
    readonly details?: unknown;
    readonly durationMilliseconds: number;
    readonly exitCode: number;
    readonly finishedAtIso: string;
    readonly objectVersion: 'sealed-lattice-local-run-log-summary-v1';
    readonly runDirectoryPath: string;
    readonly scriptName: string;
    readonly startedAtIso: string;
};

type LocalRunLogInput = {
    readonly commandLineArguments: readonly string[];
    readonly lanes: readonly string[];
    readonly now?: Date;
    readonly rootDirectoryPath?: string;
    readonly scriptName: string;
};

export const successfulCheckTimingHistoryLimit = 8;

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
    date.toISOString().replace(/[:.]/gu, '-');

const defaultLogRootDirectoryPath = (): string =>
    path.join(process.cwd(), 'logs');

const writeJsonFile = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
};

const closeStream = async (stream: WriteStream): Promise<void> =>
    new Promise((resolve, reject) => {
        stream.once('error', reject);
        stream.end(resolve);
    });

const isSuccessfulCheckSummary = (value: unknown): boolean =>
    typeof value === 'object' &&
    value !== null &&
    'scriptName' in value &&
    value.scriptName === 'check' &&
    'exitCode' in value &&
    value.exitCode === 0;

const readSuccessfulCheckSummaries = async (
    historyPath: string,
): Promise<readonly unknown[]> => {
    let historyText: string;
    try {
        historyText = await readFile(historyPath, 'utf8');
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return [];
        }
        throw error;
    }

    return historyText
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .flatMap((line) => {
            try {
                const value = JSON.parse(line) as unknown;
                return isSuccessfulCheckSummary(value) ? [value] : [];
            } catch {
                return [];
            }
        });
};

const writeBoundedSuccessfulCheckHistory = async (
    rootDirectoryPath: string,
    summary: LocalRunLogSummary,
): Promise<void> => {
    if (!isSuccessfulCheckSummary(summary)) {
        return;
    }
    const historyPath = path.join(rootDirectoryPath, 'runs.jsonl');
    const previousSummaries = await readSuccessfulCheckSummaries(historyPath);
    const summaries = [...previousSummaries, summary].slice(
        -successfulCheckTimingHistoryLimit,
    );
    await writeFile(
        historyPath,
        `${summaries.map((entry) => JSON.stringify(entry)).join('\n')}\n`,
        'utf8',
    );
};

class LocalRunLog implements ActiveLocalRunLog {
    readonly runDirectoryPath: string;
    #combinedStream: WriteStream;
    #commandSlugCounts = new Map<string, number>();
    #finished = false;
    #rootDirectoryPath: string;
    #scriptName: string;
    #startedAtIso: string;
    #startedAtMilliseconds: number;
    #summaryPath: string;

    constructor(input: {
        readonly combinedLogPath: string;
        readonly rootDirectoryPath: string;
        readonly runDirectoryPath: string;
        readonly scriptName: string;
        readonly startedAtIso: string;
        readonly startedAtMilliseconds: number;
        readonly summaryPath: string;
    }) {
        this.runDirectoryPath = input.runDirectoryPath;
        this.#combinedStream = createWriteStream(input.combinedLogPath, {
            flags: 'a',
        });
        this.#rootDirectoryPath = input.rootDirectoryPath;
        this.#scriptName = input.scriptName;
        this.#startedAtIso = input.startedAtIso;
        this.#startedAtMilliseconds = input.startedAtMilliseconds;
        this.#summaryPath = input.summaryPath;
    }

    createCommandLogFiles(request: CommandLogRequest): CommandLogFiles {
        const baseSlug = safeLogSlug(
            request.preferredSlug ?? request.description,
        );
        const previousCount = this.#commandSlugCounts.get(baseSlug) ?? 0;
        this.#commandSlugCounts.set(baseSlug, previousCount + 1);
        const slug =
            previousCount === 0 ? baseSlug : `${baseSlug}-${previousCount + 1}`;

        return {
            combinedPath: path.join(this.runDirectoryPath, `${slug}.log`),
            stderrPath: path.join(this.runDirectoryPath, `${slug}.stderr.log`),
            stdoutPath: path.join(this.runDirectoryPath, `${slug}.stdout.log`),
        };
    }

    async discardCommandLogFiles(files: CommandLogFiles): Promise<void> {
        await Promise.all([
            rm(files.combinedPath, { force: true }),
            rm(files.stderrPath, { force: true }),
            rm(files.stdoutPath, { force: true }),
        ]);
    }

    async finish(input: {
        readonly details?: unknown;
        readonly exitCode: number;
    }): Promise<void> {
        if (this.#finished) {
            return;
        }
        this.#finished = true;

        const finishedAtIso = new Date().toISOString();
        const summary: LocalRunLogSummary = {
            durationMilliseconds: Math.round(
                performance.now() - this.#startedAtMilliseconds,
            ),
            details: input.details,
            exitCode: input.exitCode,
            finishedAtIso,
            objectVersion: 'sealed-lattice-local-run-log-summary-v1',
            runDirectoryPath: this.runDirectoryPath,
            scriptName: this.#scriptName,
            startedAtIso: this.#startedAtIso,
        };
        const discardSuccessfulCheckRun = isSuccessfulCheckSummary(summary);
        try {
            await writeJsonFile(this.#summaryPath, summary);
            await writeBoundedSuccessfulCheckHistory(
                this.#rootDirectoryPath,
                summary,
            );
        } finally {
            await closeStream(this.#combinedStream);
        }
        if (discardSuccessfulCheckRun) {
            await rm(this.runDirectoryPath, {
                force: true,
                recursive: true,
            });
        }
    }

    writeCombinedOutput(chunk: string | Uint8Array): void {
        this.#combinedStream.write(chunk);
    }
}

export const createLocalRunLog = async (
    input: LocalRunLogInput,
): Promise<ActiveLocalRunLog> => {
    const startedAt = input.now ?? new Date();
    const startedAtIso = startedAt.toISOString();
    const rootDirectoryPath =
        input.rootDirectoryPath ?? defaultLogRootDirectoryPath();
    const runDirectoryPath = path.join(
        rootDirectoryPath,
        startedAtIso.slice(0, 10),
        `${timestampForPath(startedAt)}-${safeLogSlug(input.scriptName)}`,
    );
    await mkdir(runDirectoryPath, { recursive: true });

    const metadata: LocalRunLogMetadata = {
        arch: os.arch(),
        commandLineArguments: input.commandLineArguments,
        cwd: process.cwd(),
        lanes: input.lanes,
        nodeVersion: process.version,
        objectVersion: 'sealed-lattice-local-run-log-metadata-v1',
        platform: os.platform(),
        runDirectoryPath,
        scriptName: input.scriptName,
        startedAtIso,
    };
    await writeJsonFile(path.join(runDirectoryPath, 'metadata.json'), metadata);

    return new LocalRunLog({
        combinedLogPath: path.join(runDirectoryPath, 'combined.log'),
        rootDirectoryPath,
        runDirectoryPath,
        scriptName: input.scriptName,
        startedAtIso,
        startedAtMilliseconds: performance.now(),
        summaryPath: path.join(runDirectoryPath, 'summary.json'),
    });
};
