import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    createLocalRunLog,
    removeRunLogArguments,
    runLogDisabledByArguments,
    safeLogSlug,
} from '#tools/ci/local-run-log';
import {
    runCommandsInSeries,
    type CommandInvocation,
} from '#tools/ci/run-command';

const createTemporaryLogRoot = (): Promise<string> =>
    mkdtemp(path.join(os.tmpdir(), 'sealed-lattice-local-run-log-'));

const readJsonFile = async <Value>(filePath: string): Promise<Value> =>
    JSON.parse(await readFile(filePath, 'utf8')) as Value;

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
    it('creates a timestamped run directory with metadata, summary, and an index entry', async () => {
        const rootDirectoryPath = await createTemporaryLogRoot();
        try {
            const log = await createLocalRunLog({
                commandLineArguments: ['--only', 'kernel'],
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
                commandLineArguments: ['--only', 'kernel'],
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
            const indexLines = (
                await readFile(
                    path.join(rootDirectoryPath, 'runs.jsonl'),
                    'utf8',
                )
            )
                .trim()
                .split('\n');
            expect(indexLines).toHaveLength(1);
            expect(JSON.parse(indexLines[0])).toMatchObject({
                exitCode: 0,
                scriptName: 'test:node:kernel',
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
            const combinedLog = await readFile(log.combinedLogPath, 'utf8');
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

    it('uses explicit arguments for disabling logs and safe path names', () => {
        expect(runLogDisabledByArguments(['--no-run-log'])).toBe(true);
        expect(
            removeRunLogArguments(['--only', 'kernel', '--no-run-log']),
        ).toEqual(['--only', 'kernel']);
        expect(safeLogSlug('../Kernel: merged<>?')).toBe('kernel-merged');
    });

    it('drops the package manager separator forwarded with run-log flags', () => {
        // CI runs `pnpm test:node:fast -- --no-run-log`, which reaches the
        // script as `--only fast -- --no-run-log`.
        expect(
            removeRunLogArguments(['--only', 'fast', '--', '--no-run-log']),
        ).toEqual(['--only', 'fast']);
        // CI runs `pnpm test:browser -- --no-run-log`, leaving only `-- --no-run-log`.
        expect(removeRunLogArguments(['--', '--no-run-log'])).toEqual([]);
        expect(runLogDisabledByArguments(['--', '--no-run-log'])).toBe(true);
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
