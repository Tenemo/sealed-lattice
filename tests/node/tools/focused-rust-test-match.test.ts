import { describe, expect, it } from 'vitest';

import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from '#tools/ci/focused-rust-test-match';
import { parseLibtestResultSummary } from '#tools/ci/libtest-output';
import type {
    CommandOutputStreamName,
    CommandRunObserver,
} from '#tools/ci/run-command';

const invocation = {
    args: [] as const,
    command: 'cargo',
    description: 'cargo test focused',
} as const;

const startObserver = (observer: CommandRunObserver): void => {
    observer.onCommandStart?.({
        invocation,
        startedAtMilliseconds: 0,
    });
};

const feedObserver = (
    observer: CommandRunObserver,
    chunk: string,
    streamName: CommandOutputStreamName = 'stdout',
): void => {
    observer.onCommandOutput?.({ chunk, invocation, streamName });
};

const finishObserver = (observer: CommandRunObserver): void => {
    observer.onCommandExit?.({
        durationMilliseconds: 1,
        exitCode: 0,
        invocation,
        terminationSignal: null,
    });
};

describe('focused Rust test matching', () => {
    it('parses all libtest result counts', () => {
        expect(
            parseLibtestResultSummary(
                'test result: ok. 3 passed; 1 failed; 2 ignored; 4 measured; 17 filtered out; finished in 0.02s',
            ),
        ).toEqual({
            failedTestCount: 1,
            filteredOutTestCount: 17,
            ignoredTestCount: 2,
            measuredTestCount: 4,
            passedTestCount: 3,
        });
        expect(parseLibtestResultSummary('running 0 tests')).toBeUndefined();
    });

    it('counts matched tests across binaries and split output chunks', () => {
        const tracker = createFocusedRustTestMatchTracker();
        startObserver(tracker.observer);
        feedObserver(
            tracker.observer,
            'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 52 filtered out; finished in 0.00s\n' +
                'test result: ok. 1 passed; 0 failed; ',
        );
        feedObserver(
            tracker.observer,
            '1 ignored; 0 measured; 50 filtered out; finished in 0.01s\n',
        );
        feedObserver(
            tracker.observer,
            'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 49 filtered out',
            'stderr',
        );
        finishObserver(tracker.observer);

        expect(tracker.matchedTestCount()).toBe(3);
    });

    it('keeps stream fragments separate and resets between commands', () => {
        const tracker = createFocusedRustTestMatchTracker();
        startObserver(tracker.observer);
        feedObserver(
            tracker.observer,
            'test result: ok. 1 passed; 0 failed; ',
            'stdout',
        );
        feedObserver(
            tracker.observer,
            '0 ignored; 0 measured; 8 filtered out\n',
            'stderr',
        );
        finishObserver(tracker.observer);
        expect(tracker.matchedTestCount()).toBe(0);

        startObserver(tracker.observer);
        feedObserver(
            tracker.observer,
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out\n',
        );
        finishObserver(tracker.observer);
        expect(tracker.matchedTestCount()).toBe(1);
    });

    it('fails a successful command when its focused filter matched zero tests', () => {
        expect(
            resolveFocusedRustTestRunResult({
                commandExitCode: 0,
                matchedTestCount: 0,
                runnerName: 'Rust kernel fast',
                testFilter: 'misspelled_test',
            }),
        ).toEqual({
            exitCode: 1,
            failureMessage:
                'Rust kernel fast filter "misspelled_test" matched zero tests.',
        });
    });

    it('does not treat an ignored test as an executed focused match', () => {
        const tracker = createFocusedRustTestMatchTracker();
        startObserver(tracker.observer);
        feedObserver(
            tracker.observer,
            'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 50 filtered out; finished in 0.00s\n',
        );
        finishObserver(tracker.observer);

        expect(tracker.matchedTestCount()).toBe(0);
    });

    it('preserves a command failure and accepts at least one matched test', () => {
        expect(
            resolveFocusedRustTestRunResult({
                commandExitCode: 101,
                matchedTestCount: 0,
                runnerName: 'Rust accepted setup focused',
                testFilter: 'candidate_test',
            }),
        ).toEqual({ exitCode: 101 });
        expect(
            resolveFocusedRustTestRunResult({
                commandExitCode: 0,
                matchedTestCount: 1,
                runnerName: 'Rust accepted setup focused',
                testFilter: 'candidate_test',
            }),
        ).toEqual({ exitCode: 0 });
    });
});
