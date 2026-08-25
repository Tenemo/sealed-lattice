import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import type { TestCase } from 'vitest/node';

import { testDiagnosticEnvironmentVariables } from '#tools/ci/test-diagnostic-environment';
import { VitestDiagnosticReporter } from '#tools/ci/vitest-diagnostic-reporter';

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

describe('Vitest diagnostics', () => {
    it('persists useful failure diagnostics without leaking hostile secrets', async () => {
        const runDirectoryPath = await mkdtemp(
            path.join(os.tmpdir(), 'sealed-lattice-vitest-diagnostics-'),
        );
        try {
            const eventFilePath = path.join(
                runDirectoryPath,
                'tests',
                'node-fast.jsonl',
            );
            const reporter = new VitestDiagnosticReporter({
                [testDiagnosticEnvironmentVariables.projectLabel]: 'node-fast',
                [testDiagnosticEnvironmentVariables.runDirectory]:
                    runDirectoryPath,
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

            const eventText = await readFile(eventFilePath, 'utf8');
            const events = eventText
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
                heapBytes: 4096,
                result: 'failed',
            });
            const errors = events[1]?.errors;
            if (!Array.isArray(errors) || !isRecord(errors[0])) {
                throw new Error('Expected one serialized test error.');
            }
            expect(errors[0].message).toContain('[redacted]');
            expect(errors[0].stack).toContain('[redacted]');
            if (!isRecord(errors[0].cause)) {
                throw new Error('Expected a serialized test error cause.');
            }
            expect(errors[0].cause.message).toContain('[redacted]');
            expect(events[2]?.content).toContain('[redacted]');
            expect(eventText).not.toMatch(
                /underlying-secret|hunter2|stack-secret|console-secret/u,
            );
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });
});
