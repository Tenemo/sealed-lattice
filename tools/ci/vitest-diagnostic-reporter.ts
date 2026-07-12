import { createHash } from 'node:crypto';
import {
    appendFileSync,
    mkdirSync,
    readdirSync,
    readFileSync,
    statSync,
    writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import type { TestCase, TestModule } from 'vitest/node';
import type { Reporter } from 'vitest/reporters';

import { resolveTestDiagnosticPaths } from './test-diagnostic-environment.js';

type SerializedTestError = {
    readonly cause?: SerializedTestError;
    readonly message: string;
    readonly name?: string;
    readonly stack?: string;
};

type TestDiagnosticEvent = Readonly<{
    elapsedMilliseconds: number;
    event: string;
    objectVersion: 'sealed-lattice-test-diagnostic-event-v1';
    processIdentifier: number;
    projectLabel: string;
    sequence: number;
    timestampIso: string;
}> &
    Readonly<Record<string, unknown>>;

const serializeTestError = (
    error: unknown,
    seen: Set<unknown> = new Set(),
): SerializedTestError => {
    if (typeof error !== 'object' || error === null) {
        return { message: String(error) };
    }
    if (seen.has(error)) {
        return { message: '[Circular error cause]' };
    }
    seen.add(error);
    const errorRecord = error as Readonly<Record<string, unknown>>;
    const cause = errorRecord.cause;

    return {
        message:
            typeof errorRecord.message === 'string'
                ? errorRecord.message
                : 'Non-Error object thrown',
        ...(typeof errorRecord.name === 'string'
            ? { name: errorRecord.name }
            : {}),
        ...(typeof errorRecord.stack === 'string'
            ? { stack: errorRecord.stack }
            : {}),
        ...(cause === undefined
            ? {}
            : { cause: serializeTestError(cause, seen) }),
    };
};

const testIdentity = (
    testCase: TestCase,
): Readonly<Record<string, unknown>> => ({
    file: testCase.module.relativeModuleId,
    fullName: testCase.fullName,
    location: testCase.location,
    project: testCase.project.name,
    testIdentifier: testCase.id,
    timeoutMilliseconds: testCase.options.timeout,
});

const moduleIdentity = (
    testModule: TestModule,
): Readonly<Record<string, unknown>> => ({
    file: testModule.relativeModuleId,
    moduleIdentifier: testModule.id,
    project: testModule.project.name,
});

const listFilesRecursively = (directoryPath: string): readonly string[] => {
    const files: string[] = [];
    for (const entry of readdirSync(directoryPath, { withFileTypes: true })) {
        const entryPath = path.join(directoryPath, entry.name);
        if (entry.isDirectory()) {
            files.push(...listFilesRecursively(entryPath));
        } else if (entry.isFile() && entry.name !== 'manifest.json') {
            files.push(entryPath);
        }
    }

    return files.sort((left, right) => left.localeCompare(right));
};

export class VitestDiagnosticReporter implements Reporter {
    readonly #attachmentDirectoryPath: string | undefined;
    readonly #eventFilePath: string | undefined;
    readonly #projectLabel: string;
    readonly #startedAtMilliseconds = performance.now();
    #sequence = 0;

    constructor(
        environment: NodeJS.ProcessEnv = process.env,
        private readonly now: () => Date = () => new Date(),
    ) {
        const paths = resolveTestDiagnosticPaths(environment);
        this.#attachmentDirectoryPath = paths.attachmentDirectoryPath;
        this.#eventFilePath = paths.eventFilePath;
        this.#projectLabel = paths.projectLabel;
        if (this.#eventFilePath !== undefined) {
            mkdirSync(path.dirname(this.#eventFilePath), { recursive: true });
        }
        if (this.#attachmentDirectoryPath !== undefined) {
            mkdirSync(this.#attachmentDirectoryPath, { recursive: true });
        }
    }

    #writeEvent(
        event: string,
        details: Readonly<Record<string, unknown>>,
    ): void {
        if (this.#eventFilePath === undefined) {
            return;
        }
        const value: TestDiagnosticEvent = {
            ...details,
            elapsedMilliseconds: Math.round(
                performance.now() - this.#startedAtMilliseconds,
            ),
            event,
            objectVersion: 'sealed-lattice-test-diagnostic-event-v1',
            processIdentifier: process.pid,
            projectLabel: this.#projectLabel,
            sequence: ++this.#sequence,
            timestampIso: this.now().toISOString(),
        };
        appendFileSync(
            this.#eventFilePath,
            `${JSON.stringify(value)}\n`,
            'utf8',
        );
    }

    #writeAttachmentManifest(): void {
        if (this.#attachmentDirectoryPath === undefined) {
            return;
        }
        const files = listFilesRecursively(this.#attachmentDirectoryPath).map(
            (filePath) => {
                const contents = readFileSync(filePath);
                const statistics = statSync(filePath);

                return {
                    modifiedAtIso: statistics.mtime.toISOString(),
                    path: path
                        .relative(this.#attachmentDirectoryPath!, filePath)
                        .split(path.sep)
                        .join('/'),
                    sha256: createHash('sha256').update(contents).digest('hex'),
                    sizeBytes: statistics.size,
                };
            },
        );
        writeFileSync(
            path.join(this.#attachmentDirectoryPath, 'manifest.json'),
            `${JSON.stringify(
                {
                    files,
                    generatedAtIso: this.now().toISOString(),
                    objectVersion: 'sealed-lattice-test-attachment-manifest-v1',
                    projectLabel: this.#projectLabel,
                },
                null,
                2,
            )}\n`,
            'utf8',
        );
    }

    onProcessTimeout(): void {
        this.#writeEvent('vitest-process-timeout', {});
    }

    onTestCaseReady(testCase: TestCase): void {
        this.#writeEvent('test-started', testIdentity(testCase));
    }

    onTestCaseResult(testCase: TestCase): void {
        const result = testCase.result();
        const diagnostic = testCase.diagnostic();
        this.#writeEvent('test-finished', {
            ...testIdentity(testCase),
            durationMilliseconds: diagnostic?.duration,
            errors: result.errors?.map((error) => serializeTestError(error)),
            heapBytes: diagnostic?.heap,
            result: result.state,
            retryCount: diagnostic?.retryCount,
            slow: diagnostic?.slow,
        });
    }

    onTestModuleEnd(testModule: TestModule): void {
        const diagnostic = testModule.diagnostic();
        this.#writeEvent('test-file-finished', {
            ...moduleIdentity(testModule),
            durationMilliseconds: diagnostic.duration,
            result: testModule.state(),
        });
    }

    onTestModuleStart(testModule: TestModule): void {
        this.#writeEvent('test-file-started', moduleIdentity(testModule));
    }

    onTestRunEnd(
        _testModules: readonly TestModule[],
        unhandledErrors: readonly unknown[],
        reason: 'failed' | 'interrupted' | 'passed',
    ): void {
        this.#writeEvent('test-run-finished', {
            reason,
            unhandledErrors: unhandledErrors.map((error) =>
                serializeTestError(error),
            ),
        });
        this.#writeAttachmentManifest();
    }

    onTestRunStart(): void {
        this.#writeEvent('test-run-started', {});
    }

    onUserConsoleLog(log: {
        readonly browser?: boolean;
        readonly content: string;
        readonly origin?: string;
        readonly taskId?: string;
        readonly type: 'stderr' | 'stdout';
    }): void {
        if (log.type !== 'stderr') {
            return;
        }
        this.#writeEvent('test-stderr', {
            browser: log.browser,
            content: log.content,
            origin: log.origin,
            testIdentifier: log.taskId,
        });
    }
}
