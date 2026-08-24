import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import type { TestCase } from 'vitest/node';

import { desktopBrowserProofMeasurementConsolePrefix } from '#tests/support/desktop-browser-proof-measurement';
import { testDiagnosticEnvironmentVariables } from '#tools/ci/test-diagnostic-environment';
import { VitestDiagnosticReporter } from '#tools/ci/vitest-diagnostic-reporter';

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const createTemporaryDirectory = async (): Promise<string> => {
    return mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-vitest-diagnostics-'),
    );
};

describe('Vitest diagnostics', () => {
    it('persists useful failure diagnostics without leaking hostile secrets', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
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

    it('persists validated desktop-browser proof measurements as structured events', async () => {
        const runDirectoryPath = await createTemporaryDirectory();
        try {
            const eventFilePath = path.join(
                runDirectoryPath,
                'tests',
                'desktop-proof.jsonl',
            );
            const reporter = new VitestDiagnosticReporter({
                [testDiagnosticEnvironmentVariables.projectLabel]:
                    'desktop-proof',
                [testDiagnosticEnvironmentVariables.runDirectory]:
                    runDirectoryPath,
            });
            const measurement = {
                browserCacheState: 'cold',
                browserProcessResidentMemoryEndByteLength: 1_050_000,
                browserProcessResidentMemoryPeakByteLength: 1_100_000,
                browserProcessResidentMemoryStartByteLength: 1_000_000,
                canonicalInputByteLength: 11,
                canonicalInputSha512Hex: '12'.repeat(64),
                canonicalOutputByteLength: 17,
                caseIdentifier: 'ballot-validity-verification',
                copiedBufferPeakByteLength: 1024,
                durationMilliseconds: 12.5,
                executionKind: 'verification',
                externalScratchPeakByteLength: 2048,
                externalScratchReadByteLength: 4096,
                externalScratchTransactionCount: 2,
                externalScratchWriteByteLength: 2048,
                finishedAtUnixMilliseconds: 1_020,
                fullBufferCopiedByteLength: 2048,
                fullBufferCopyCount: 2,
                javascriptHeapEndByteLength: 12_000,
                javascriptHeapPeakByteLength: 15_000,
                javascriptHeapStartByteLength: 10_000,
                observedHostAllocationVolumeByteLength: 4096,
                outputSha512Hex: 'ab'.repeat(64),
                resourceAccounting: {
                    cleanupCompleted: true,
                    cleanupDeletedByteLength: 0,
                    cleanupDeletionCount: 0,
                    cleanupDurationMilliseconds: 0,
                    commitReadbackByteLength: 0,
                    commitReadbackCallCount: 0,
                    ciphertextReadByteLength: 0,
                    ciphertextReadCallCount: 0,
                    ciphertextWriteByteLength: 0,
                    ciphertextWriteCallCount: 0,
                    deletionDurationMilliseconds: 0,
                    deterministicRegeneratedByteLength: 0,
                    deterministicRegenerationCallCount: 0,
                    indexedDbRequestCount: 0,
                    indexedDbTransactionCount: 0,
                    javascriptToWasmCopyByteLength: 0,
                    javascriptToWasmCopyCount: 0,
                    kernelStorageRequestCount: 2,
                    openCallCount: 0,
                    openCiphertextByteLength: 0,
                    openPlaintextByteLength: 0,
                    physicalQuotaByteLength: 1,
                    physicalQuotaHeadroomByteLength: 1,
                    physicalQuotaReservedByteLength: 0,
                    physicalStoredEndByteLength: 0,
                    physicalStoredPeakByteLength: 0,
                    plaintextReadByteLength: 0,
                    plaintextReadCallCount: 0,
                    plaintextWriteByteLength: 0,
                    plaintextWriteCallCount: 0,
                    repairHashCallCount: 0,
                    repairHashedByteLength: 0,
                    sealCallCount: 0,
                    sealCiphertextByteLength: 0,
                    sealPlaintextByteLength: 0,
                    simultaneousLiveBufferPeakByteLength: 0,
                    simultaneousLiveBufferPeakCount: 0,
                    wasmToJavascriptCopyByteLength: 0,
                    wasmToJavascriptCopyCount: 0,
                    workerTransferByteLength: 0,
                    workerTransferCount: 0,
                },
                retainedResidentPeakByteLength: 4096,
                runOrdinal: 1,
                suiteId: 'cd'.repeat(64),
                startedAtUnixMilliseconds: 1_000,
                wasmSha256Hex: 'ef'.repeat(32),
                wasmLinearMemoryEndByteLength: 196_608,
                wasmLinearMemoryEndPageCount: 3,
                wasmLinearMemoryPeakByteLength: 262_144,
                wasmLinearMemoryPeakPageCount: 4,
                wasmLinearMemoryStartByteLength: 131_072,
                wasmLinearMemoryStartPageCount: 2,
                workerInstanceIdentifier: 'reporter-proof-worker',
                workerOperationOrdinal: 1,
            };

            reporter.onUserConsoleLog?.({
                browser: true,
                content: `${desktopBrowserProofMeasurementConsolePrefix}${JSON.stringify(measurement)}\n`,
                origin: 'proof evidence',
                taskId: 'test-id',
                type: 'stdout',
            });

            const events = (await readFile(eventFilePath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(events).toHaveLength(1);
            expect(events[0]).toMatchObject({
                ...measurement,
                browser: true,
                event: 'desktop-browser-proof-measurement',
                testIdentifier: 'test-id',
            });
        } finally {
            await rm(runDirectoryPath, { force: true, recursive: true });
        }
    });
});
