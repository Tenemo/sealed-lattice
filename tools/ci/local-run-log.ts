import { createWriteStream, type WriteStream } from 'node:fs';
import { appendFile, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const noRunLogArgument = '--no-run-log';
// Package managers forward a bare `--` separator ahead of script arguments
// (for example CI runs `pnpm test:node:fast -- --no-run-log`, which reaches the
// script as `--only fast -- --no-run-log`). Drop it so the run scripts validate
// only meaningful tokens.
const packageManagerArgumentSeparator = '--';

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
    readonly combinedLogPath: string;
    readonly runDirectoryPath: string;
    createCommandLogFiles(request: CommandLogRequest): CommandLogFiles;
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

export const removeRunLogArguments = (
    commandLineArguments: readonly string[],
): readonly string[] =>
    commandLineArguments.filter(
        (argument) =>
            argument !== noRunLogArgument &&
            argument !== packageManagerArgumentSeparator,
    );

export const runLogDisabledByArguments = (
    commandLineArguments: readonly string[],
): boolean => commandLineArguments.includes(noRunLogArgument);

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

class LocalRunLog implements ActiveLocalRunLog {
    readonly combinedLogPath: string;
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
        this.combinedLogPath = input.combinedLogPath;
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
        await writeJsonFile(this.#summaryPath, summary);
        await appendFile(
            path.join(this.#rootDirectoryPath, 'runs.jsonl'),
            `${JSON.stringify(summary)}\n`,
            'utf8',
        );
        await closeStream(this.#combinedStream);
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

export const installProcessOutputLogTee = (
    runLog: ActiveLocalRunLog,
): (() => void) => {
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    const originalStderrWrite = process.stderr.write.bind(process.stderr);
    process.stdout.write = (chunk: string | Uint8Array): boolean => {
        runLog.writeCombinedOutput(chunk);

        return originalStdoutWrite(chunk);
    };
    process.stderr.write = (chunk: string | Uint8Array): boolean => {
        runLog.writeCombinedOutput(chunk);

        return originalStderrWrite(chunk);
    };

    return () => {
        process.stdout.write = originalStdoutWrite;
        process.stderr.write = originalStderrWrite;
    };
};
