import { describe, expect, it } from 'vitest';

import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from '#tools/ci/focused-rust-test-match';

const invocation = {
    args: [] as const,
    command: 'cargo',
    description: 'cargo test focused',
};

describe('focused Rust test matching', () => {
    it('counts executed tests across chunks without joining output streams', () => {
        const tracker = createFocusedRustTestMatchTracker();
        tracker.observer.onCommandStart?.({
            invocation,
            startedAtMilliseconds: 0,
        });
        tracker.observer.onCommandOutput?.({
            chunk: 'test result: ok. 1 passed; 0 failed; ',
            invocation,
            streamName: 'stdout',
        });
        tracker.observer.onCommandOutput?.({
            chunk: 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 8 filtered out\n',
            invocation,
            streamName: 'stderr',
        });
        tracker.observer.onCommandOutput?.({
            chunk: '0 ignored; 1 measured; 8 filtered out\n',
            invocation,
            streamName: 'stdout',
        });
        tracker.observer.onCommandExit?.({
            durationMilliseconds: 1,
            exitCode: 0,
            invocation,
            terminationSignal: null,
        });

        expect(tracker.matchedTestCount()).toBe(2);
    });

    it('refuses zero matches without masking command failures', () => {
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
        expect(
            resolveFocusedRustTestRunResult({
                commandExitCode: 101,
                matchedTestCount: 0,
                runnerName: 'Rust kernel fast',
                testFilter: 'candidate',
            }),
        ).toEqual({ exitCode: 101 });
        expect(
            resolveFocusedRustTestRunResult({
                commandExitCode: 0,
                matchedTestCount: 1,
                runnerName: 'Rust kernel fast',
                testFilter: 'candidate',
            }),
        ).toEqual({ exitCode: 0 });
    });
});
