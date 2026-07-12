import { performance } from 'node:perf_hooks';

import {
    isLibtestSlowTestNotice,
    parseLibtestFinishedTestLine,
    parseLibtestRunningTestCount,
    parseLibtestStandaloneResult,
    parseLibtestStartedTestName,
    type LibtestResult,
} from './libtest-output.js';
import type {
    CommandOutputStreamName,
    CommandRunObserver,
} from './run-command.js';
import { createTestEventWriter } from './test-event-journal.js';

// The heavy accepted-setup tests run under the default libtest harness, which
// prints `running N tests`, then stays silent until each test finishes. With a
// handful of tests taking six to eleven minutes each, that looks indistinguishable
// from a hang. This reporter watches the streamed harness output and prints a
// periodic heartbeat plus a line per completion, so a long run always shows it is
// alive and how far along it is. It only reads the output; it never alters it.

const millisecondsPerSecond = 1000;
const secondsPerMinute = 60;
const defaultHeartbeatMilliseconds = 30 * millisecondsPerSecond;

const formatElapsed = (milliseconds: number): string => {
    const totalSeconds = Math.floor(milliseconds / millisecondsPerSecond);
    const minutes = Math.floor(totalSeconds / secondsPerMinute);
    const seconds = totalSeconds % secondsPerMinute;

    return `${minutes}m${seconds.toString().padStart(2, '0')}s`;
};

type HeavyTestProgressReporter = {
    readonly observer: CommandRunObserver;
    readonly stop: () => void;
    readonly terminalOutputFilter: (line: string) => boolean;
};

type RustTestTimingRecord = {
    readonly durationMicroseconds: number;
    readonly durationMilliseconds: number;
    readonly suite: string;
    readonly test: string;
};

const rustTestTimingPrefix = 'sealed-lattice-rust-test-timing ';

export const parseRustTestTimingLine = (
    line: string,
): RustTestTimingRecord | undefined => {
    const timingStart = line.indexOf(rustTestTimingPrefix);
    if (timingStart === -1) {
        return undefined;
    }
    const rawRecordWithSuffix = line.slice(
        timingStart + rustTestTimingPrefix.length,
    );
    const closingBraceIndex = rawRecordWithSuffix.lastIndexOf('}');
    if (closingBraceIndex === -1) {
        return undefined;
    }
    const rawRecord = rawRecordWithSuffix.slice(0, closingBraceIndex + 1);
    let parsed: unknown;
    try {
        parsed = JSON.parse(rawRecord) as unknown;
    } catch {
        return undefined;
    }
    if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !('suite' in parsed) ||
        typeof parsed.suite !== 'string' ||
        !('test' in parsed) ||
        typeof parsed.test !== 'string' ||
        !('durationMilliseconds' in parsed) ||
        typeof parsed.durationMilliseconds !== 'number' ||
        !Number.isFinite(parsed.durationMilliseconds) ||
        parsed.durationMilliseconds < 0 ||
        !('durationMicroseconds' in parsed) ||
        typeof parsed.durationMicroseconds !== 'number' ||
        !Number.isFinite(parsed.durationMicroseconds) ||
        parsed.durationMicroseconds < 0
    ) {
        return undefined;
    }

    return {
        durationMicroseconds: parsed.durationMicroseconds,
        durationMilliseconds: parsed.durationMilliseconds,
        suite: parsed.suite,
        test: parsed.test,
    };
};

export const createHeavyTestProgressReporter = (input: {
    readonly label: string;
    readonly threadCount: number;
    readonly heartbeatMilliseconds?: number;
    readonly eventFilePath?: string;
    readonly now?: () => number;
    readonly write?: (line: string) => void;
}): HeavyTestProgressReporter => {
    const heartbeatMilliseconds =
        input.heartbeatMilliseconds ?? defaultHeartbeatMilliseconds;
    const now = input.now ?? ((): number => performance.now());
    const write =
        input.write ??
        ((line: string): void => {
            process.stderr.write(line);
        });
    const writeEvent = createTestEventWriter({
        eventFilePath: input.eventFilePath,
        projectLabel: input.label,
    });

    let startedAtMilliseconds = now();
    let expectedTestCount: number | undefined;
    let completedTestCount = 0;
    let failedTestCount = 0;
    const lineBuffers: Record<CommandOutputStreamName, string> = {
        stderr: '',
        stdout: '',
    };
    let heartbeatTimer: NodeJS.Timeout | undefined;
    let pendingStartedTestName: string | undefined;
    let pendingTestStartedAtMilliseconds: number | undefined;
    let serializedCompletionBoundaryAtMilliseconds: number | undefined;
    const exactTimingsByTestName = new Map<string, RustTestTimingRecord>();

    const estimatedRunningCount = (): number => {
        if (expectedTestCount === undefined) {
            return input.threadCount;
        }

        return Math.max(
            0,
            Math.min(input.threadCount, expectedTestCount - completedTestCount),
        );
    };

    const renderCounts = (): string => {
        const completed =
            expectedTestCount === undefined
                ? `${completedTestCount} done`
                : `${completedTestCount}/${expectedTestCount} done`;
        const failures =
            failedTestCount > 0 ? `, ${failedTestCount} failed` : '';

        return `${completed}${failures}, ~${estimatedRunningCount()} running`;
    };

    const allTestsFinished = (): boolean =>
        expectedTestCount !== undefined &&
        completedTestCount >= expectedTestCount;

    const emitHeartbeat = (): void => {
        if (allTestsFinished()) {
            return;
        }
        write(
            `[${input.label}] ${formatElapsed(now() - startedAtMilliseconds)} elapsed - ${renderCounts()}\n`,
        );
        writeEvent('test-heartbeat', {
            activeTest: pendingStartedTestName,
            completedTestCount,
            elapsedMilliseconds: Math.round(now() - startedAtMilliseconds),
            expectedTestCount,
            failedTestCount,
            runningTestCount: estimatedRunningCount(),
        });
    };

    const recordCompletion = (
        testName: string,
        result: LibtestResult,
    ): void => {
        const completedAtMilliseconds = now();
        const exactTiming = [...exactTimingsByTestName.values()].find(
            (timing) =>
                testName === timing.test ||
                testName.endsWith(`::${timing.test}`),
        );
        const approximateObservedDurationMilliseconds =
            input.threadCount === 1
                ? pendingStartedTestName === testName &&
                  pendingTestStartedAtMilliseconds !== undefined
                    ? Math.round(
                          completedAtMilliseconds -
                              pendingTestStartedAtMilliseconds,
                      )
                    : serializedCompletionBoundaryAtMilliseconds === undefined
                      ? undefined
                      : Math.round(
                            completedAtMilliseconds -
                                serializedCompletionBoundaryAtMilliseconds,
                        )
                : undefined;
        const durationMilliseconds =
            exactTiming?.durationMilliseconds ??
            approximateObservedDurationMilliseconds;
        const durationBasis =
            exactTiming !== undefined
                ? 'exact-instrumented'
                : approximateObservedDurationMilliseconds === undefined
                  ? 'unavailable'
                  : 'approximate-observed-serialized-wall-clock';
        if (input.threadCount === 1) {
            serializedCompletionBoundaryAtMilliseconds =
                completedAtMilliseconds;
        }
        if (pendingStartedTestName === testName) {
            pendingStartedTestName = undefined;
            pendingTestStartedAtMilliseconds = undefined;
        }
        completedTestCount += 1;
        if (result === 'FAILED') {
            failedTestCount += 1;
        }
        write(
            `[${input.label}] ${formatElapsed(now() - startedAtMilliseconds)} - finished ${renderCounts()}: ${testName} (${result})\n`,
        );
        writeEvent('test-finished', {
            completedTestCount,
            durationMilliseconds,
            durationBasis,
            durationMicroseconds: exactTiming?.durationMicroseconds,
            expectedTestCount,
            failedTestCount,
            fullName: testName,
            result,
        });
    };

    const consumeLine = (line: string): void => {
        const exactTiming = parseRustTestTimingLine(line);
        if (exactTiming !== undefined) {
            exactTimingsByTestName.set(exactTiming.test, exactTiming);
            writeEvent('test-runtime-measured', {
                durationBasis: 'exact-instrumented',
                ...exactTiming,
            });
        } else if (line.includes(rustTestTimingPrefix)) {
            writeEvent('test-timing-record-malformed', { line });
        }
        const runningTestCount = parseLibtestRunningTestCount(line);
        if (runningTestCount !== undefined) {
            expectedTestCount = (expectedTestCount ?? 0) + runningTestCount;
            serializedCompletionBoundaryAtMilliseconds =
                input.threadCount === 1 ? now() : undefined;
            return;
        }
        const finishedTest = parseLibtestFinishedTestLine(line);
        if (finishedTest !== undefined) {
            recordCompletion(finishedTest.testName, finishedTest.result);
            return;
        }
        const startedTestName = parseLibtestStartedTestName(line);
        if (startedTestName !== undefined) {
            pendingStartedTestName = startedTestName;
            pendingTestStartedAtMilliseconds = now();
            writeEvent('test-started', { fullName: startedTestName });
            return;
        }
        const resultOnly = parseLibtestStandaloneResult(line);
        if (pendingStartedTestName !== undefined && resultOnly !== undefined) {
            recordCompletion(pendingStartedTestName, resultOnly);
        }
    };

    const consumeOutputChunk = (
        streamName: CommandOutputStreamName,
        chunk: string,
    ): void => {
        lineBuffers[streamName] += chunk;
        let newlineIndex = lineBuffers[streamName].indexOf('\n');
        while (newlineIndex !== -1) {
            const line = lineBuffers[streamName]
                .slice(0, newlineIndex)
                .replace(/\r$/u, '');
            lineBuffers[streamName] = lineBuffers[streamName].slice(
                newlineIndex + 1,
            );
            consumeLine(line);
            newlineIndex = lineBuffers[streamName].indexOf('\n');
        }
    };

    const flushOutputRemainders = (): void => {
        for (const streamName of ['stdout', 'stderr'] as const) {
            const remainder = lineBuffers[streamName].replace(/\r$/u, '');
            lineBuffers[streamName] = '';
            if (remainder.length > 0) {
                consumeLine(remainder);
            }
        }
    };

    const stop = (): void => {
        if (heartbeatTimer !== undefined) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = undefined;
        }
    };

    const observer: CommandRunObserver = {
        onCommandStart: (): void => {
            startedAtMilliseconds = now();
            expectedTestCount = undefined;
            completedTestCount = 0;
            failedTestCount = 0;
            lineBuffers.stderr = '';
            lineBuffers.stdout = '';
            pendingStartedTestName = undefined;
            pendingTestStartedAtMilliseconds = undefined;
            serializedCompletionBoundaryAtMilliseconds = undefined;
            exactTimingsByTestName.clear();
            stop();
            writeEvent('test-run-started', {
                threadCount: input.threadCount,
            });
            heartbeatTimer = setInterval(emitHeartbeat, heartbeatMilliseconds);
            // Do not let the heartbeat alone keep the process alive.
            heartbeatTimer.unref?.();
        },
        onCommandOutput: (event): void => {
            consumeOutputChunk(event.streamName, event.chunk);
        },
        onCommandExit: (event): void => {
            flushOutputRemainders();
            stop();
            writeEvent('test-run-finished', {
                durationMilliseconds: event.durationMilliseconds,
                exitCode: event.exitCode,
                terminationSignal: event.terminationSignal,
            });
        },
    };

    return {
        observer,
        stop,
        terminalOutputFilter: (line: string): boolean =>
            !isLibtestSlowTestNotice(line),
    };
};
