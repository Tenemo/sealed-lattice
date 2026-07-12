import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    createLocalRunLog,
    safeLogSlug,
    successfulCheckTimingHistoryLimit,
} from '#tools/ci/local-run-log';
import {
    runCommandsInSeries,
    type CommandInvocation,
} from '#tools/ci/run-command';

const createTemporaryLogRoot = (): Promise<string> =>
    mkdtemp(path.join(os.tmpdir(), 'sealed-lattice-local-run-log-'));

const readJsonFile = async <Value>(filePath: string): Promise<Value> =>
    JSON.parse(await readFile(filePath, 'utf8')) as Value;

const combinedLogPathForRun = (runDirectoryPath: string): string =>
    path.join(runDirectoryPath, 'combined.log');

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
                    '2026-05-29T18-12-28-884Z-test-node-kernel',
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
                objectVersion: 'sealed-lattice-local-run-log-metadata-v1',
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
                objectVersion: 'sealed-lattice-local-run-log-summary-v1',
                scriptName: 'test:node:kernel',
            });
            await expect(
                access(path.join(rootDirectoryPath, 'runs.jsonl')),
            ).rejects.toMatchObject({ code: 'ENOENT' });
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('bounds timing history to the latest successful check summaries', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const previousSuccessfulChecks = Array.from(
                { length: successfulCheckTimingHistoryLimit + 2 },
                (_, index) => ({
                    durationMilliseconds: index,
                    exitCode: 0,
                    scriptName: 'check',
                }),
            );
            await writeFile(
                path.join(rootDirectoryPath, 'runs.jsonl'),
                [
                    '{corrupt',
                    JSON.stringify({ exitCode: 1, scriptName: 'check' }),
                    JSON.stringify({
                        exitCode: 0,
                        scriptName: 'test:node',
                    }),
                    ...previousSuccessfulChecks.map((entry) =>
                        JSON.stringify(entry),
                    ),
                ].join('\n'),
                'utf8',
            );

            const log = await createLocalRunLog({
                commandLineArguments: [],
                lanes: ['sample'],
                now: new Date('2026-05-29T18:30:00.000Z'),
                rootDirectoryPath,
                scriptName: 'check',
            });
            await log.finish({ exitCode: 0 });

            const summaries = (
                await readFile(
                    path.join(rootDirectoryPath, 'runs.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split('\n')
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(summaries).toHaveLength(successfulCheckTimingHistoryLimit);
            expect(
                summaries.every(
                    (summary) =>
                        summary.scriptName === 'check' &&
                        summary.exitCode === 0,
                ),
            ).toBe(true);
            expect(
                summaries
                    .slice(0, -1)
                    .map((summary) => summary.durationMilliseconds),
            ).toEqual([3, 4, 5, 6, 7, 8, 9]);
            await expect(access(log.runDirectoryPath)).rejects.toMatchObject({
                code: 'ENOENT',
            });
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('tees command stdout and stderr into per-command and combined logs', async () => {
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
            await expect(
                readFile(
                    path.join(
                        log.runDirectoryPath,
                        'exercise-output.stdout.log',
                    ),
                    'utf8',
                ),
            ).resolves.toContain('stdout-line');
            await expect(
                readFile(
                    path.join(
                        log.runDirectoryPath,
                        'exercise-output.stderr.log',
                    ),
                    'utf8',
                ),
            ).resolves.toContain('stderr-line');
            const commandLog = await readFile(
                path.join(log.runDirectoryPath, 'exercise-output.log'),
                'utf8',
            );
            expect(commandLog).toContain('stdout-line');
            expect(commandLog).toContain('stderr-line');
            const combinedLog = await readFile(
                combinedLogPathForRun(log.runDirectoryPath),
                'utf8',
            );
            expect(combinedLog).toContain('Exercise output capture');
            expect(combinedLog).toContain('stdout-line');
            expect(combinedLog).toContain('stderr-line');

            const summary = await readJsonFile<{ readonly exitCode: number }>(
                path.join(log.runDirectoryPath, 'summary.json'),
            );
            expect(summary.exitCode).toBe(7);
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
            for (const fileName of [
                'captured-output.log',
                'captured-output.stderr.log',
                'captured-output.stdout.log',
            ]) {
                await expect(
                    access(path.join(log.runDirectoryPath, fileName)),
                ).rejects.toMatchObject({ code: 'ENOENT' });
            }
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

    it('deduplicates command log filenames inside one run', async () => {
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

            expect(path.basename(first.combinedPath)).toBe('duplicate.log');
            expect(path.basename(second.combinedPath)).toBe('duplicate-2.log');
        } finally {
            await rm(rootDirectoryPath, { force: true, recursive: true });
        }
    });
});
