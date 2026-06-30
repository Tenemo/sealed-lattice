import { performance } from 'node:perf_hooks';

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

export type HeavyTestProgressReporter = {
    readonly observer: CommandRunObserver;
    readonly stop: () => void;
    readonly terminalOutputFilter: (line: string) => boolean;
};

// `running N tests` is emitted once per test binary as it starts.
const runningTestsPattern = /^running (\d+) tests?/;
// A finished test prints `test <name> ... ok|FAILED|ignored`. The
// `has been running for over 60 seconds` notices use a different shape and are
// intentionally not matched here.
const finishedTestPattern = /^test (\S+) \.\.\. (ok|FAILED|ignored)\b/;
const startedTestPattern = /^test (\S+) \.\.\.(?:\s|$)/;
const resultOnlyPattern = /^(ok|FAILED|ignored)\b/;
// libtest prints "test <name> has been running for over N seconds" roughly every
// minute for a still-running test. The heartbeat above already conveys liveness
// and progress, so on a suite whose tests routinely run several minutes these
// notices are redundant terminal noise. The reporter exposes a filter that drops
// them from the terminal echo; the on-disk run log still keeps every line.
const libtestSlowTestNoticePattern =
    /\bhas been running for over \d+ seconds?\b/;

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
        result: 'ok' | 'FAILED' | 'ignored',
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
        const runningMatch = runningTestsPattern.exec(line);
        if (runningMatch?.[1] !== undefined) {
            expectedTestCount =
                (expectedTestCount ?? 0) + Number(runningMatch[1]);
            return;
        }
        const finishedMatch = finishedTestPattern.exec(line);
        if (finishedMatch?.[1] !== undefined) {
            recordCompletion(
                finishedMatch[1],
                finishedMatch[2] as 'ok' | 'FAILED' | 'ignored',
            );
            return;
        }
        const startedMatch = startedTestPattern.exec(line);
        if (startedMatch?.[1] !== undefined) {
            pendingStartedTestName = startedMatch[1];
            return;
        }
        const resultOnlyMatch = resultOnlyPattern.exec(line);
        if (
            pendingStartedTestName !== undefined &&
            resultOnlyMatch?.[1] !== undefined
        ) {
            recordCompletion(
                pendingStartedTestName,
                resultOnlyMatch[1] as 'ok' | 'FAILED' | 'ignored',
            );
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
            !libtestSlowTestNoticePattern.test(line),
    };
};
