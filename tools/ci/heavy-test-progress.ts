import { performance } from 'node:perf_hooks';

import {
    isLibtestSlowTestNotice,
    parseLibtestFinishedTestLine,
    parseLibtestRunningTestCount,
    parseLibtestStandaloneResult,
    parseLibtestStartedTestName,
    type LibtestResult,
} from './libtest-output.js';
import type { CommandRunObserver } from './run-command.js';

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

export const createHeavyTestProgressReporter = (input: {
    readonly label: string;
    readonly threadCount: number;
    readonly heartbeatMilliseconds?: number;
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

    let startedAtMilliseconds = now();
    let expectedTestCount: number | undefined;
    let completedTestCount = 0;
    let failedTestCount = 0;
    let lineBuffer = '';
    let heartbeatTimer: NodeJS.Timeout | undefined;
    let pendingStartedTestName: string | undefined;

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
    };

    const recordCompletion = (
        testName: string,
        result: LibtestResult,
    ): void => {
        if (pendingStartedTestName === testName) {
            pendingStartedTestName = undefined;
        }
        completedTestCount += 1;
        if (result === 'FAILED') {
            failedTestCount += 1;
        }
        write(
            `[${input.label}] ${formatElapsed(now() - startedAtMilliseconds)} - finished ${renderCounts()}: ${testName} (${result})\n`,
        );
    };

    const consumeLine = (line: string): void => {
        const runningTestCount = parseLibtestRunningTestCount(line);
        if (runningTestCount !== undefined) {
            expectedTestCount = (expectedTestCount ?? 0) + runningTestCount;
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
            return;
        }
        const resultOnly = parseLibtestStandaloneResult(line);
        if (pendingStartedTestName !== undefined && resultOnly !== undefined) {
            recordCompletion(pendingStartedTestName, resultOnly);
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
            lineBuffer = '';
            pendingStartedTestName = undefined;
            stop();
            heartbeatTimer = setInterval(emitHeartbeat, heartbeatMilliseconds);
            // Do not let the heartbeat alone keep the process alive.
            heartbeatTimer.unref?.();
        },
        onCommandOutput: (event): void => {
            lineBuffer += event.chunk;
            let newlineIndex = lineBuffer.indexOf('\n');
            while (newlineIndex !== -1) {
                const line = lineBuffer
                    .slice(0, newlineIndex)
                    .replace(/\r$/, '');
                lineBuffer = lineBuffer.slice(newlineIndex + 1);
                consumeLine(line);
                newlineIndex = lineBuffer.indexOf('\n');
            }
        },
        onCommandExit: (): void => {
            stop();
        },
    };

    return {
        observer,
        stop,
        terminalOutputFilter: (line: string): boolean =>
            !isLibtestSlowTestNotice(line),
    };
};
