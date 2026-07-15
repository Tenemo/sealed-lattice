import { spawnSync } from 'node:child_process';
import { access, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createLocalRunLog, runWithLocalRunLog } from '#tools/ci/local-run-log';
import {
    runCommandsInSeries,
    type CommandInvocation,
} from '#tools/ci/run-command';

const withTemporaryLogRoot = async <Result>(
    action: (rootDirectoryPath: string) => Promise<Result>,
): Promise<Result> => {
    const rootDirectoryPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-local-run-log-'),
    );
    try {
        return await action(rootDirectoryPath);
    } finally {
        await rm(rootDirectoryPath, { force: true, recursive: true });
    }
};

const readJsonLines = async (
    filePath: string,
): Promise<Record<string, unknown>[]> =>
    (await readFile(filePath, 'utf8'))
        .trim()
        .split(/\r?\n/u)
        .map((line) => JSON.parse(line) as Record<string, unknown>);

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const findOnlyRunDirectory = async (
    rootDirectoryPath: string,
): Promise<string> => {
    const [dateDirectoryName] = await readdir(rootDirectoryPath);
    if (dateDirectoryName === undefined) {
        throw new Error('Expected a dated log directory.');
    }
    const dateDirectoryPath = path.join(rootDirectoryPath, dateDirectoryName);
    const [runDirectoryName] = await readdir(dateDirectoryPath);
    if (runDirectoryName === undefined) {
        throw new Error('Expected a run directory.');
    }
    return path.join(dateDirectoryPath, runDirectoryName);
};

describe('local run logs', () => {
    it('records command output once with its stream and failure result', () =>
        withTemporaryLogRoot(async (rootDirectoryPath) => {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                rootDirectoryPath,
                scriptName: 'sample',
            });
            const command: CommandInvocation = {
                args: [
                    '-e',
                    "process.stdout.write('out\\n'); process.stderr.write('error\\n'); process.exit(7);",
                ],
                command: process.execPath,
                description: 'Exercise output capture',
                logFileSlug: 'sample-command',
            };

            const exitCode = await runCommandsInSeries([command], {
                outputMode: 'capture',
                runLog: log,
            });
            await log.finish({ exitCode });

            expect(exitCode).toBe(7);
            const output = await readFile(
                path.join(log.runDirectoryPath, 'output.log'),
                'utf8',
            );
            expect(output).toMatch(/\[sample-command\] \[stdout\] out/u);
            expect(output).toMatch(/\[sample-command\] \[stderr\] error/u);
            expect(output.match(/\bout\b/gu)).toHaveLength(1);
            expect(output.match(/\berror\b/gu)).toHaveLength(1);

            const events = await readJsonLines(
                path.join(log.runDirectoryPath, 'events.jsonl'),
            );
            expect(
                events
                    .filter((event) => event.commandId === 'sample-command')
                    .map((event) => event.eventType),
            ).toEqual([
                'command-prepared',
                'command-started',
                'command-finished',
            ]);
        }));

    it('redacts secrets from metadata and nested callback failures', () =>
        withTemporaryLogRoot(async (rootDirectoryPath) => {
            const originalExitCode = process.exitCode;
            const failure = Object.assign(
                new Error('Authorization: Bearer outer-secret'),
                { cause: new Error('password=inner-secret') },
            );
            try {
                process.exitCode = undefined;
                await expect(
                    runWithLocalRunLog(
                        {
                            commandLineArguments: [
                                '--token',
                                'argument-secret',
                                'https://user:url-secret@example.test/input',
                            ],
                            environment: {
                                GITHUB_SHA: '0123456789abcdef',
                                NODE_OPTIONS: 'token=option-secret',
                                UNRELATED_SECRET: 'environment-secret',
                            },
                            lanes: ['sample'],
                            rootDirectoryPath,
                            scriptName: 'redaction sample',
                        },
                        () => Promise.reject(failure),
                    ),
                ).rejects.toBe(failure);

                const runDirectoryPath =
                    await findOnlyRunDirectory(rootDirectoryPath);
                const metadataText = await readFile(
                    path.join(runDirectoryPath, 'metadata.json'),
                    'utf8',
                );
                const summaryText = await readFile(
                    path.join(runDirectoryPath, 'summary.json'),
                    'utf8',
                );
                expect(`${metadataText}\n${summaryText}`).not.toMatch(
                    /argument-secret|url-secret|option-secret|environment-secret|outer-secret|inner-secret/u,
                );
                expect(metadataText).toContain('[redacted]');
                expect(summaryText).toContain('[redacted]');
            } finally {
                process.exitCode = originalExitCode;
            }
        }));

    it('writes complete attributed lines and flushes partial output', () =>
        withTemporaryLogRoot(async (rootDirectoryPath) => {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                rootDirectoryPath,
                scriptName: 'line buffering sample',
            });
            log.writeCommandOutput({
                chunk: 'first line\npartial',
                commandId: 'command',
                streamName: 'stdout',
            });
            log.writeCommandOutput({
                chunk: ' line\ncontrol:\u001b[31m\n',
                commandId: 'command',
                streamName: 'stdout',
            });
            log.writeCommandOutput({
                chunk: 'unterminated error',
                commandId: 'other-command',
                streamName: 'stderr',
            });
            await log.finish({ exitCode: 0 });

            const output = await readFile(
                path.join(log.runDirectoryPath, 'output.log'),
                'utf8',
            );
            expect(output).toMatch(/\[command\] \[stdout\] first line/u);
            expect(output).toMatch(/\[command\] \[stdout\] partial line/u);
            expect(output).toContain('control:\\x1b[31m');
            expect(output).toMatch(
                /\[other-command\] \[stderr\] unterminated error/u,
            );
        }));

    it('keeps ordered event and resource journals through normal completion', () =>
        withTemporaryLogRoot(async (rootDirectoryPath) => {
            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                resourceSampleIntervalMilliseconds: 60_000,
                rootDirectoryPath,
                scriptName: 'diagnostic sample',
            });
            log.writeEvent({
                commandId: 'failed-command',
                eventType: 'command-started',
            });
            log.writeEvent({
                commandId: 'failed-command',
                details: { resultClassification: 'test-failure' },
                eventType: 'command-finished',
            });
            await log.finish({ exitCode: 1 });

            const events = await readJsonLines(
                path.join(log.runDirectoryPath, 'events.jsonl'),
            );
            expect(events.map((event) => event.sequenceNumber)).toEqual(
                events.map((_event, index) => index + 1),
            );
            expect(events[events.length - 1]?.eventType).toBe('run-finished');

            const resources = await readJsonLines(
                path.join(log.runDirectoryPath, 'resources.jsonl'),
            );
            expect(resources.length).toBeGreaterThanOrEqual(2);
            if (!isRecord(resources[0]?.processMemory)) {
                throw new Error('Expected process memory diagnostics.');
            }
            expect(typeof resources[0].processMemory.residentSetBytes).toBe(
                'number',
            );
            await expect(
                readFile(
                    path.join(log.runDirectoryPath, 'diagnostics.txt'),
                    'utf8',
                ),
            ).resolves.toContain('failed-command');
        }));

    it('leaves parseable durable journals when a child dies before finish', () =>
        withTemporaryLogRoot(async (rootDirectoryPath) => {
            const moduleUrl = pathToFileURL(
                path.resolve('tools/ci/local-run-log.ts'),
            ).href;
            const childSource = [
                `const { createLocalRunLog } = await import(${JSON.stringify(moduleUrl)});`,
                `const log = await createLocalRunLog({ commandLineArguments: [], lanes: ['abrupt'], rootDirectoryPath: ${JSON.stringify(rootDirectoryPath)}, scriptName: 'abrupt-child' });`,
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

            const runDirectoryPath =
                await findOnlyRunDirectory(rootDirectoryPath);
            const events = await readJsonLines(
                path.join(runDirectoryPath, 'events.jsonl'),
            );
            expect(events).toContainEqual(
                expect.objectContaining({
                    eventType: 'before-abrupt-death',
                }),
            );
            expect(
                await readJsonLines(
                    path.join(runDirectoryPath, 'resources.jsonl'),
                ),
            ).not.toHaveLength(0);
            await expect(
                access(path.join(runDirectoryPath, 'summary.json')),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        }));
});
