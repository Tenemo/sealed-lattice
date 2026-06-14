import { afterEach, describe, expect, it, vi } from 'vitest';

import { createHeavyTestProgressReporter } from '#tools/ci/heavy-test-progress';

const invocation = {
    args: [] as const,
    command: 'cargo',
    description: 'cargo test heavy accepted setup tests',
} as const;

const feedOutput = (
    reporter: ReturnType<typeof createHeavyTestProgressReporter>,
    chunk: string,
): void => {
    reporter.observer.onCommandOutput?.({
        chunk,
        invocation,
        streamName: 'stdout',
    });
};

const startRun = (
    reporter: ReturnType<typeof createHeavyTestProgressReporter>,
): void => {
    reporter.observer.onCommandStart?.({
        invocation,
        startedAtMilliseconds: 0,
    });
};

describe('createHeavyTestProgressReporter', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('reports each finished test with cumulative counts and a thread estimate', () => {
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 3,
            now: () => 0,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 2 tests\n');
        feedOutput(reporter, 'test accepted_setup::one ... ok\n');
        feedOutput(reporter, 'test accepted_setup::two ... FAILED\n');
        reporter.stop();

        expect(lines).toHaveLength(2);
        expect(lines[0]).toContain('finished 1/2 done, ~1 running');
        expect(lines[0]).toContain('accepted_setup::one (ok)');
        expect(lines[1]).toContain('2/2 done, 1 failed, ~0 running');
        expect(lines[1]).toContain('accepted_setup::two (FAILED)');
    });

    it('joins a completion line split across output chunks', () => {
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 4,
            now: () => 0,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 1 tests\n');
        feedOutput(reporter, 'test accepted_setup::sp');
        feedOutput(reporter, 'lit_across_chunks ... ');
        // A trailing fragment without a newline must not be reported yet.
        expect(lines).toHaveLength(0);
        feedOutput(reporter, 'ok\nstray fragment without newline');

        expect(lines).toHaveLength(1);
        expect(lines[0]).toContain('accepted_setup::split_across_chunks (ok)');
        expect(lines[0]).toContain('1/1 done');
    });

    it('does not count the libtest slow-test notice as a completion', () => {
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 3,
            now: () => 0,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 1 tests\n');
        feedOutput(
            reporter,
            'test accepted_setup::slow has been running for over 60 seconds\n',
        );

        expect(lines).toHaveLength(0);
    });

    it('accumulates the expected total across multiple test binaries', () => {
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 8,
            now: () => 0,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 2 tests\n');
        feedOutput(reporter, 'running 3 tests\n');
        feedOutput(reporter, 'test accepted_setup::first ... ok\n');

        expect(lines[0]).toContain('1/5 done');
    });

    it('emits an elapsed heartbeat while tests are still running', () => {
        vi.useFakeTimers();
        let nowMilliseconds = 0;
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 3,
            heartbeatMilliseconds: 1_000,
            now: () => nowMilliseconds,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 2 tests\n');
        nowMilliseconds = 65_000;
        vi.advanceTimersByTime(1_000);

        const heartbeat = lines.find((line) => line.includes('elapsed'));
        expect(heartbeat).toBeDefined();
        expect(heartbeat).toContain('1m05s elapsed');
        expect(heartbeat).toContain('0/2 done, ~2 running');
        reporter.stop();
    });

    it('stops the heartbeat once every test has finished', () => {
        vi.useFakeTimers();
        let nowMilliseconds = 0;
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 1,
            heartbeatMilliseconds: 1_000,
            now: () => nowMilliseconds,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 1 tests\n');
        feedOutput(reporter, 'test accepted_setup::only ... ok\n');
        const lineCountAfterCompletion = lines.length;

        nowMilliseconds = 120_000;
        vi.advanceTimersByTime(10_000);

        expect(lines).toHaveLength(lineCountAfterCompletion);
    });

    it('stops emitting heartbeats after the reporter is stopped', () => {
        vi.useFakeTimers();
        let nowMilliseconds = 0;
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 2,
            heartbeatMilliseconds: 1_000,
            now: () => nowMilliseconds,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 2 tests\n');
        reporter.observer.onCommandExit?.({
            durationMilliseconds: 10,
            exitCode: 0,
            invocation,
            terminationSignal: null,
        });

        nowMilliseconds = 90_000;
        vi.advanceTimersByTime(10_000);

        expect(lines).toHaveLength(0);
    });
});
