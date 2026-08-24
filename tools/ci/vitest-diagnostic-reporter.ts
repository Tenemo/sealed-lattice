import { mkdirSync } from 'node:fs';

import type { TestCase, TestModule } from 'vitest/node';
import type { Reporter } from 'vitest/reporters';

import {
    desktopBrowserProofMeasurementConsolePrefix,
    parseDesktopBrowserProofMeasurementRecord,
} from '../../tests/support/desktop-browser-proof-measurement.js';

import {
    redactDiagnosticText,
    serializeErrorDiagnostic,
} from './run-log-diagnostics.js';
import { resolveTestDiagnosticPaths } from './test-diagnostic-environment.js';
import { createTestEventWriter } from './test-event-journal.js';

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

export class VitestDiagnosticReporter implements Reporter {
    readonly #writeEvent: ReturnType<typeof createTestEventWriter>;

    constructor(
        environment: NodeJS.ProcessEnv = process.env,
        now: () => Date = () => new Date(),
    ) {
        const paths = resolveTestDiagnosticPaths(environment);
        this.#writeEvent = createTestEventWriter({
            eventFilePath: paths.eventFilePath,
            now,
            projectLabel: paths.projectLabel,
        });
        if (paths.attachmentDirectoryPath !== undefined) {
            mkdirSync(paths.attachmentDirectoryPath, { recursive: true });
        }
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
            errors: result.errors?.map((error) =>
                serializeErrorDiagnostic(error),
            ),
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
                serializeErrorDiagnostic(error),
            ),
        });
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
        if (log.type === 'stdout') {
            for (const line of log.content.split(/\r?\n/u)) {
                if (
                    !line.startsWith(
                        desktopBrowserProofMeasurementConsolePrefix,
                    )
                ) {
                    continue;
                }
                const encodedRecord = line.slice(
                    desktopBrowserProofMeasurementConsolePrefix.length,
                );
                const record = parseDesktopBrowserProofMeasurementRecord(
                    JSON.parse(encodedRecord) as unknown,
                );
                this.#writeEvent('desktop-browser-proof-measurement', {
                    ...record,
                    browser: log.browser,
                    origin: log.origin,
                    testIdentifier: log.taskId,
                });
            }
            return;
        }
        if (log.type !== 'stderr') {
            return;
        }
        this.#writeEvent('test-stderr', {
            browser: log.browser,
            content: redactDiagnosticText(log.content),
            origin: log.origin,
            testIdentifier: log.taskId,
        });
    }
}
