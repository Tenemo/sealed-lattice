import { spawnSync } from 'node:child_process';
import {
    access,
    mkdir,
    mkdtemp,
    readFile,
    rm,
    writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
    createLocalRunLog,
    runWithLocalRunLog,
    safeLogSlug,
} from '#tools/ci/local-run-log';
import {
    runCommandsInSeries,
    type CommandInvocation,
} from '#tools/ci/run-command';

const createTemporaryLogRoot = (): Promise<string> =>
    mkdtemp(path.join(os.tmpdir(), 'sealed-lattice-local-run-log-'));

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const readJsonFile = async <Value>(filePath: string): Promise<Value> =>
    JSON.parse(await readFile(filePath, 'utf8')) as Value;

const combinedLogPathForRun = (runDirectoryPath: string): string =>
    path.join(runDirectoryPath, 'output.log');

const captureProcessOutput = async <Result>(
    action: () => Promise<Result>,
): Promise<{
    readonly result: Result;
    readonly stderr: string;
    readonly stdout: string;
}> => {
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    const originalStderrWrite = process.stderr.write.bind(process.stderr);
    let stdout = '';
    let stderr = '';
    process.stdout.write = (chunk: string | Uint8Array): boolean => {
        stdout += chunk.toString();

        return true;
    };
    process.stderr.write = (chunk: string | Uint8Array): boolean => {
        stderr += chunk.toString();

        return true;
    };

    try {
        return {
            result: await action(),
            stderr,
            stdout,
        };
    } finally {
        process.stdout.write = originalStdoutWrite;
        process.stderr.write = originalStderrWrite;
    }
};

describe('local run logs', () => {
    it('creates a timestamped run directory with metadata and summary', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: ['kernel'],
                lanes: ['kernel'],
                now: new Date('2026-05-29T18:12:28.884Z'),
                rootDirectoryPath,
                scriptName: 'test:node:kernel',
            });
            expect(log.runDirectoryPath).toBe(
                path.join(
                    rootDirectoryPath,
                    '2026-05-29',
                    '2026-05-29T18-12-28.884Z-test-node-kernel',
                ),
            );

            const metadata = await readJsonFile<{
                readonly commandLineArguments: readonly string[];
                readonly lanes: readonly string[];
                readonly objectVersion: string;
                readonly scriptName: string;
            }>(path.join(log.runDirectoryPath, 'metadata.json'));
            expect(metadata).toMatchObject({
                commandLineArguments: ['kernel'],
                lanes: ['kernel'],
                objectVersion: 'sealed-lattice-local-run-log-metadata-v2',
                scriptName: 'test:node:kernel',
            });

            await log.finish({ exitCode: 0 });

            const summary = await readJsonFile<{
                readonly exitCode: number;
                readonly objectVersion: string;
                readonly scriptName: string;
            }>(path.join(log.runDirectoryPath, 'summary.json'));
            expect(summary).toMatchObject({
                exitCode: 0,
                objectVersion: 'sealed-lattice-local-run-log-summary-v2',
                scriptName: 'test:node:kernel',
            });
            await expect(
                access(path.join(rootDirectoryPath, 'runs.jsonl')),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('writes attributed stdout and stderr once in the run output log', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: ['--sample'],
                lanes: ['sample'],
                now: new Date('2026-05-29T19:00:00.000Z'),
                rootDirectoryPath,
                scriptName: 'sample run',
            });
            const command: CommandInvocation = {
                args: [
                    '-e',
                    [
                        "process.stdout.write('stdout-line\\n');",
                        "process.stderr.write('stderr-line\\n');",
                        'process.exit(7);',
                    ].join(''),
                ],
                command: process.execPath,
                description: 'Exercise output capture',
                logFileSlug: 'exercise-output',
            };
            const { result: exitCode } = await captureProcessOutput(() =>
                runCommandsInSeries([command], {
                    runLog: log,
                }),
            );
            await log.finish({ exitCode });

            expect(exitCode).toBe(7);
            const commandLog = await readFile(
                combinedLogPathForRun(log.runDirectoryPath),
                'utf8',
            );
            expect(commandLog).toMatch(
                /\[exercise-output\] \[stdout\] stdout-line/u,
            );
            expect(commandLog).toMatch(
                /\[exercise-output\] \[stderr\] stderr-line/u,
            );
            expect(commandLog.match(/stdout-line/gu)).toHaveLength(1);
            expect(commandLog.match(/stderr-line/gu)).toHaveLength(1);
            for (const fileName of [
                'exercise-output.log',
                'exercise-output.stderr.log',
                'exercise-output.stdout.log',
            ]) {
                await expect(
                    access(path.join(log.runDirectoryPath, fileName)),
                ).rejects.toMatchObject({ code: 'ENOENT' });
            }

            const summary = await readJsonFile<{ readonly exitCode: number }>(
                path.join(log.runDirectoryPath, 'summary.json'),
            );
            expect(summary.exitCode).toBe(7);
            const events = (
                await readFile(
                    path.join(log.runDirectoryPath, 'events.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(
                events
                    .filter((event) => event.commandId === 'exercise-output')
                    .map((event) => event.eventType),
            ).toEqual([
                'command-prepared',
                'command-started',
                'command-finished',
            ]);
            const finishedCommand = events.find(
                (event) => event.eventType === 'command-finished',
            ) as {
                readonly details: {
                    readonly processStatus: {
                        readonly hexadecimalExitCode: string;
                        readonly rawExitCode: number;
                    };
                    readonly resultClassification: string;
                };
            };
            expect(finishedCommand.details).toMatchObject({
                processStatus: {
                    hexadecimalExitCode: '0x00000007',
                    rawExitCode: 7,
                },
                resultClassification: 'test-failure',
            });
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('captures command output for caller-owned progress reporting', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: ['--sample'],
                lanes: ['sample'],
                now: new Date('2026-05-29T19:30:00.000Z'),
                rootDirectoryPath,
                scriptName: 'sample run',
            });
            const command: CommandInvocation = {
                args: [
                    '-e',
                    [
                        "process.stdout.write('captured stdout\\n');",
                        "process.stderr.write('captured stderr\\n');",
                    ].join(''),
                ],
                command: process.execPath,
                description: 'Exercise captured output',
                logFileSlug: 'captured-output',
            };
            const observedOutput: string[] = [];
            const {
                result: exitCode,
                stderr,
                stdout,
            } = await captureProcessOutput(() =>
                runCommandsInSeries([command], {
                    observer: {
                        onCommandOutput: (event) => {
                            observedOutput.push(
                                `${event.streamName}:${event.chunk}`,
                            );
                        },
                    },
                    outputMode: 'capture',
                    runLog: log,
                }),
            );
            await log.finish({ exitCode });

            expect(exitCode).toBe(0);
            expect(stdout).not.toContain('captured stdout');
            expect(stderr).not.toContain('captured stderr');
            expect(observedOutput.join('')).toContain('stdout:captured stdout');
            expect(observedOutput.join('')).toContain('stderr:captured stderr');
            await expect(
                readFile(combinedLogPathForRun(log.runDirectoryPath), 'utf8'),
            ).resolves.toContain('captured stderr');
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('creates safe path names', () => {
        expect(safeLogSlug('../Kernel: merged<>?')).toBe('kernel-merged');
    });

    it('deduplicates command identifiers inside one run', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                now: new Date('2026-05-29T20:00:00.000Z'),
                rootDirectoryPath,
                scriptName: 'sample',
            });
            const first = log.createCommandLogFiles({
                description: 'Duplicate command',
                preferredSlug: 'duplicate',
            });
            const second = log.createCommandLogFiles({
                description: 'Duplicate command',
                preferredSlug: 'duplicate',
            });
            await log.finish({ exitCode: 0 });

            expect(path.basename(first.combinedPath)).toBe('output.log');
            expect(path.basename(second.combinedPath)).toBe('output.log');
            expect(first.commandId).toBe('duplicate');
            expect(second.commandId).toBe('duplicate-2');
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('redacts sensitive arguments and records only allowlisted environment values', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: [
                    '--token',
                    'never-write-this-token',
                    'https://user:password@example.test/input',
                ],
                environment: {
                    GITHUB_SHA: '0123456789abcdef',
                    NODE_OPTIONS: '--sample token=never-write-this-value',
                    SEALED_LATTICE_RUN_DIRECTORY: path.join(
                        rootDirectoryPath,
                        'parent-run',
                    ),
                    UNRELATED_SECRET: 'never-write-this-environment-value',
                },
                lanes: ['sample'],
                rootDirectoryPath,
                scriptName: 'redaction sample',
            });
            await log.finish({ exitCode: 0 });

            const metadataText = await readFile(
                path.join(log.runDirectoryPath, 'metadata.json'),
                'utf8',
            );
            expect(metadataText).not.toContain('never-write-this');
            const metadata = JSON.parse(metadataText) as {
                readonly commandLineArguments: readonly string[];
                readonly diagnosticEnvironment: Readonly<
                    Record<string, string>
                >;
                readonly parentRunDirectoryPath?: string;
            };
            expect(metadata.commandLineArguments).toEqual([
                '--token',
                '[redacted]',
                'https://[redacted]@example.test/input',
            ]);
            expect(metadata.diagnosticEnvironment).toMatchObject({
                GITHUB_SHA: '0123456789abcdef',
                NODE_OPTIONS: '--sample token=[redacted]',
                SEALED_LATTICE_RUN_DIRECTORY: log.runDirectoryPath,
            });
            expect(metadata.diagnosticEnvironment).not.toHaveProperty(
                'UNRELATED_SECRET',
            );
            expect(metadata.parentRunDirectoryPath).toBe(
                path.join(rootDirectoryPath, 'parent-run'),
            );
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('prefixes every complete output line and flushes partial lines on finish', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                rootDirectoryPath,
                scriptName: 'line buffering sample',
            });
            log.writeCommandOutput({
                chunk: 'first line\npartial',
                commandId: 'first-command',
                streamName: 'stdout',
            });
            log.writeCommandOutput({
                chunk: ' line\ncontrol:\u001b[31m\n',
                commandId: 'first-command',
                streamName: 'stdout',
            });
            log.writeCommandOutput({
                chunk: 'unterminated error',
                commandId: 'second-command',
                streamName: 'stderr',
            });
            await log.finish({ exitCode: 0 });

            const outputLines = (
                await readFile(
                    path.join(log.runDirectoryPath, 'output.log'),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u);
            expect(outputLines).toHaveLength(4);
            expect(outputLines[0]).toMatch(
                /\[first-command\] \[stdout\] first line$/u,
            );
            expect(outputLines[1]).toMatch(
                /\[first-command\] \[stdout\] partial line$/u,
            );
            expect(outputLines[2]).toMatch(
                /\[first-command\] \[stdout\] control:\\x1b\[31m$/u,
            );
            expect(outputLines[3]).toMatch(
                /\[second-command\] \[stderr\] unterminated error$/u,
            );
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('records resources, ordered events, extrema, and human diagnostics', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                resourceSampleIntervalMilliseconds: 60_000,
                rootDirectoryPath,
                scriptName: 'resource sample',
            });
            log.writeEvent({
                commandId: 'sample-command',
                eventType: 'command-started',
            });
            log.writeEvent({
                commandId: 'sample-command',
                details: { resultClassification: 'test-failure' },
                eventType: 'command-finished',
            });
            await log.finish({ exitCode: 7 });

            const events = (
                await readFile(
                    path.join(log.runDirectoryPath, 'events.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(events.map((event) => event.sequenceNumber)).toEqual(
                events.map((_event, index) => index + 1),
            );
            expect(events[events.length - 1]).toMatchObject({
                eventType: 'run-finished',
                objectVersion: 'sealed-lattice-local-run-event-v1',
            });

            const resources = (
                await readFile(
                    path.join(log.runDirectoryPath, 'resources.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(resources.length).toBeGreaterThanOrEqual(2);
            expect(resources[0]).toMatchObject({
                activeCommandIds: [],
                objectVersion: 'sealed-lattice-local-run-resource-sample-v1',
                resourceScope: 'orchestration-process-and-host',
            });
            if (
                !isRecord(resources[0]?.processCpu) ||
                !isRecord(resources[0]?.processMemory)
            ) {
                throw new Error('Expected process resource diagnostics.');
            }
            expect(typeof resources[0].processCpu.systemMicroseconds).toBe(
                'number',
            );
            expect(typeof resources[0].processCpu.userMicroseconds).toBe(
                'number',
            );
            expect(typeof resources[0].processMemory.heapUsedBytes).toBe(
                'number',
            );
            expect(typeof resources[0].processMemory.residentSetBytes).toBe(
                'number',
            );

            const summary = await readJsonFile<{
                readonly failedCommandId?: string;
                readonly resourceExtrema: {
                    readonly minimumHostFreeMemoryBytes: number;
                    readonly peakHeapUsedBytes: number;
                    readonly peakResidentSetBytes: number;
                };
            }>(path.join(log.runDirectoryPath, 'summary.json'));
            expect(summary.failedCommandId).toBe('sample-command');
            expect(
                summary.resourceExtrema.peakResidentSetBytes,
            ).toBeGreaterThan(0);
            expect(summary.resourceExtrema.peakHeapUsedBytes).toBeGreaterThan(
                0,
            );
            expect(
                summary.resourceExtrema.minimumHostFreeMemoryBytes,
            ).toBeGreaterThan(0);
            const diagnostics = await readFile(
                path.join(log.runDirectoryPath, 'diagnostics.txt'),
                'utf8',
            );
            expect(diagnostics).toContain('Runtime:');
            expect(diagnostics).toContain('Failed command: sample-command');
            expect(diagnostics).toContain('Peak parent RSS:');
            expect(diagnostics).toContain('Last output age:');
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('links nested attachment projects and manifests without listing every attachment', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['browser'],
                rootDirectoryPath,
                scriptName: 'attachment diagnostics',
            });
            const browserAttachmentDirectoryPath = path.join(
                log.runDirectoryPath,
                'attachments',
                'browser-webkit',
            );
            const nodeAttachmentDirectoryPath = path.join(
                log.runDirectoryPath,
                'attachments',
                'node-fast',
            );
            await mkdir(browserAttachmentDirectoryPath, { recursive: true });
            await mkdir(nodeAttachmentDirectoryPath, { recursive: true });
            await writeFile(
                path.join(browserAttachmentDirectoryPath, 'manifest.json'),
                '{}\n',
                'utf8',
            );
            await writeFile(
                path.join(browserAttachmentDirectoryPath, 'failure-trace.zip'),
                'trace bytes',
                'utf8',
            );
            await writeFile(
                path.join(nodeAttachmentDirectoryPath, 'heap-report.json'),
                '{}\n',
                'utf8',
            );
            await log.finish({ exitCode: 1 });

            const diagnostics = await readFile(
                path.join(log.runDirectoryPath, 'diagnostics.txt'),
                'utf8',
            );
            expect(diagnostics).toContain(
                `Attachments: ${path.join(log.runDirectoryPath, 'attachments')}`,
            );
            expect(diagnostics).toContain(
                `Attachment files (browser-webkit): ${browserAttachmentDirectoryPath}`,
            );
            expect(diagnostics).toContain(
                `Attachment manifest (browser-webkit): ${path.join(browserAttachmentDirectoryPath, 'manifest.json')}`,
            );
            expect(diagnostics).toContain(
                `Attachment files (node-fast): ${nodeAttachmentDirectoryPath}`,
            );
            expect(diagnostics).not.toContain('failure-trace.zip');
            expect(diagnostics).not.toContain('heap-report.json');
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('finishes a failed callback with its cause chain and rethrows the original error', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        const originalExitCode = process.exitCode;
        const innerError = new Error(
            'inner token=never-write-this-cause-secret',
        );
        const outerError = Object.assign(new Error('outer failure'), {
            cause: innerError,
        });
        try {
            process.exitCode = undefined;
            await expect(
                runWithLocalRunLog(
                    {
                        commandLineArguments: [],
                        lanes: ['sample'],
                        rootDirectoryPath,
                        scriptName: 'callback failure',
                    },
                    () => Promise.reject(outerError),
                ),
            ).rejects.toBe(outerError);

            const dateDirectoryNames = await (
                await import('node:fs/promises')
            ).readdir(rootDirectoryPath);
            const dateDirectoryPath = path.join(
                rootDirectoryPath,
                dateDirectoryNames[0],
            );
            const runDirectoryNames = await (
                await import('node:fs/promises')
            ).readdir(dateDirectoryPath);
            const runDirectoryPath = path.join(
                dateDirectoryPath,
                runDirectoryNames[0],
            );
            const summaryText = await readFile(
                path.join(runDirectoryPath, 'summary.json'),
                'utf8',
            );
            expect(summaryText).not.toContain('never-write-this');
            const summary = JSON.parse(summaryText) as {
                readonly error: {
                    readonly cause?: { readonly message: string };
                    readonly message: string;
                };
                readonly exitCode: number;
                readonly resultClassification: string;
            };
            expect(summary).toMatchObject({
                exitCode: 1,
                resultClassification: 'runner-failure',
            });
            expect(summary.error.cause?.message).toContain('[redacted]');
        } finally {
            process.exitCode = originalExitCode;
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('leaves parseable durable journals when a child process dies before finish', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const moduleUrl = pathToFileURL(
                path.resolve('tools/ci/local-run-log.ts'),
            ).href;
            const childSource = [
                `const { createLocalRunLog } = await import(${JSON.stringify(
                    moduleUrl,
                )});`,
                `const log = await createLocalRunLog({ commandLineArguments: [], lanes: ['abrupt'], rootDirectoryPath: ${JSON.stringify(
                    rootDirectoryPath,
                )}, scriptName: 'abrupt-child' });`,
                "log.writeEvent({ eventType: 'before-abrupt-death' });",
                "process.kill(process.pid, 'SIGKILL');",
            ].join('\n');
            const child = spawnSync(
                process.execPath,
                [
                    '--import',
                    'tsx',
                    '--input-type=module',
                    '--eval',
                    childSource,
                ],
                { encoding: 'utf8' },
            );
            expect(child.status).not.toBe(0);

            const { readdir } = await import('node:fs/promises');
            const [dateDirectoryName] = await readdir(rootDirectoryPath);
            const dateDirectoryPath = path.join(
                rootDirectoryPath,
                dateDirectoryName,
            );
            const [runDirectoryName] = await readdir(dateDirectoryPath);
            const runDirectoryPath = path.join(
                dateDirectoryPath,
                runDirectoryName,
            );
            const eventLines = (
                await readFile(
                    path.join(runDirectoryPath, 'events.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u);
            expect(
                eventLines.map((line) => JSON.parse(line) as unknown),
            ).toHaveLength(eventLines.length);
            expect(eventLines.join('\n')).toContain('before-abrupt-death');
            await expect(
                access(path.join(runDirectoryPath, 'summary.json')),
            ).rejects.toMatchObject({ code: 'ENOENT' });
            const resourceLines = (
                await readFile(
                    path.join(runDirectoryPath, 'resources.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split(/\r?\n/u);
            expect(
                resourceLines.map((line) => JSON.parse(line) as unknown),
            ).toHaveLength(resourceLines.length);
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });
});
