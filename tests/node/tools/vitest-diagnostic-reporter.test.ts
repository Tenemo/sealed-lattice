import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';
import type { TestCase } from 'vitest/node';

import {
    buildTestDiagnosticEnvironment,
    resolveTestDiagnosticPaths,
    testDiagnosticEnvironmentVariables,
} from '#tools/ci/test-diagnostic-environment';
import { VitestDiagnosticReporter } from '#tools/ci/vitest-diagnostic-reporter';

const temporaryDirectories: string[] = [];

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const createTemporaryDirectory = async (): Promise<string> => {
    const directoryPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-vitest-diagnostics-'),
    );
    temporaryDirectories.push(directoryPath);
    return directoryPath;
};

afterEach(async () => {
    await Promise.all(
        temporaryDirectories.splice(0).map((directoryPath) =>
            rm(directoryPath, {
                force: true,
                recursive: true,
            }),
        ),
    );
});

describe('Vitest diagnostics', () => {
    it('derives process-isolated paths from the current run directory', () => {
        const paths = resolveTestDiagnosticPaths({
            SEALED_LATTICE_RUN_DIRECTORY: path.resolve('logs', 'run'),
        });

        expect(paths.projectLabel).toBe(`vitest-${process.pid}`);
        expect(paths.eventFilePath).toBe(
            path.resolve('logs', 'run', 'tests', `vitest-${process.pid}.jsonl`),
        );
        expect(paths.diagnosticReportDirectoryPath).toContain(
            path.join('diagnostic-reports', `vitest-${process.pid}`),
        );
    });

    it('builds explicit per-command paths without modifying inherited Node options', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        const environment = buildTestDiagnosticEnvironment({
            baseEnvironment: { NODE_OPTIONS: '--max-old-space-size=4096' },
            projectLabel: 'node-fast',
            runDirectoryPath,
        });

        expect(environment.NODE_OPTIONS).toBe('--max-old-space-size=4096');
        expect(
            environment[testDiagnosticEnvironmentVariables.runDirectory],
        ).toBe(runDirectoryPath);
        expect(
            environment[testDiagnosticEnvironmentVariables.projectLabel],
        ).toBe('node-fast');
    });

    it('persists test runtime, complete error causes, and an attachment manifest', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        const eventFilePath = path.join(
            runDirectoryPath,
            'tests',
            'node-fast.jsonl',
        );
        const attachmentDirectoryPath = path.join(
            runDirectoryPath,
            'attachments',
            'node-fast',
        );
        await mkdir(path.join(attachmentDirectoryPath, 'traces'), {
            recursive: true,
        });
        await writeFile(
            path.join(attachmentDirectoryPath, 'traces', 'failure.zip'),
            'trace bytes',
            'utf8',
        );
        const reporter = new VitestDiagnosticReporter({
            [testDiagnosticEnvironmentVariables.projectLabel]: 'node-fast',
            [testDiagnosticEnvironmentVariables.runDirectory]: runDirectoryPath,
        });
        const testCase = {
            diagnostic: () => ({
                duration: 1_234,
                heap: 4096,
                retryCount: 0,
                slow: true,
                startTime: 0,
            }),
            fullName: 'suite > rejects malformed input',
            id: 'test-id',
            location: { column: 3, line: 12 },
            module: { relativeModuleId: 'tests/example.test.ts' },
            options: { timeout: 5_000 },
            project: { name: 'node-fast' },
            result: () => ({
                errors: [
                    {
                        cause: new Error('token=underlying-secret'),
                        message: 'assertion failed password=hunter2',
                        name: 'AssertionError',
                        stack: 'Authorization: Bearer stack-secret\n at test',
                    },
                ],
                state: 'failed',
            }),
        } as unknown as TestCase;

        reporter.onTestCaseReady?.(testCase);
        reporter.onTestCaseResult?.(testCase);
        reporter.onUserConsoleLog?.({
            content: 'stderr credential=console-secret',
            taskId: 'test-id',
            type: 'stderr',
        });
        reporter.onTestRunEnd?.([], [], 'failed');

        const events = (await readFile(eventFilePath, 'utf8'))
            .trim()
            .split(/\r?\n/u)
            .map((line) => JSON.parse(line) as Record<string, unknown>);
        expect(events.map((event) => event.event)).toEqual([
            'test-started',
            'test-finished',
            'test-stderr',
            'test-run-finished',
        ]);
        expect(events[1]).toMatchObject({
            durationMilliseconds: 1_234,
            fullName: 'suite > rejects malformed input',
            heapBytes: 4096,
            result: 'failed',
        });
        const errors = events[1]?.errors;
        expect(Array.isArray(errors)).toBe(true);
        if (!Array.isArray(errors) || !isRecord(errors[0])) {
            throw new Error('Expected one serialized test error.');
        }
        expect(errors[0].message).toBe('assertion failed password=[redacted]');
        expect(errors[0].stack).toContain('Authorization=[redacted]');
        expect(errors[0].stack).toContain('at test');
        if (!isRecord(errors[0].cause)) {
            throw new Error('Expected a serialized test error cause.');
        }
        expect(errors[0].cause.message).toBe('token=[redacted]');
        expect(events[2]).toMatchObject({
            content: 'stderr credential=[redacted]',
            event: 'test-stderr',
        });
        expect(await readFile(eventFilePath, 'utf8')).not.toMatch(
            /underlying-secret|hunter2|stack-secret|console-secret/u,
        );

        const manifest = JSON.parse(
            await readFile(
                path.join(attachmentDirectoryPath, 'manifest.json'),
                'utf8',
            ),
        ) as { readonly files: readonly Record<string, unknown>[] };
        expect(manifest.files).toHaveLength(1);
        expect(manifest.files[0]).toMatchObject({
            path: 'traces/failure.zip',
            sizeBytes: 11,
        });
        expect(manifest.files[0]?.sha256).toMatch(/^[a-f0-9]{64}$/u);
    });
});
