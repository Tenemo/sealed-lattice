import { describe, expect, it } from 'vitest';

import {
    createFuzzProgressObserver,
    foundationParserFuzzToolchain,
    parseFuzzDurationSeconds,
    requireExpectedCargoFuzzVersion,
} from '#tools/ci/run-foundation-parser-fuzzing';

describe('foundation parser fuzz runner', () => {
    it('pins the manual toolchain and campaign duration', () => {
        expect(foundationParserFuzzToolchain).toEqual({
            cargoFuzzVersion: '0.13.2',
            rustToolchain: 'nightly-2026-06-15',
        });
        expect(parseFuzzDurationSeconds([])).toBe(60);
        expect(parseFuzzDurationSeconds(['3600'])).toBe(3600);
        expect(() => parseFuzzDurationSeconds(['0'])).toThrow();
        expect(() => parseFuzzDurationSeconds(['1.5'])).toThrow();
        expect(() => parseFuzzDurationSeconds(['1', '2'])).toThrow();
    });

    it('requires the exact cargo-fuzz version', () => {
        expect(() =>
            requireExpectedCargoFuzzVersion('cargo-fuzz 0.13.2\n'),
        ).not.toThrow();
        expect(() =>
            requireExpectedCargoFuzzVersion('cargo-fuzz 0.13.1\n'),
        ).toThrow(/requires cargo-fuzz 0\.13\.2/u);
    });

    it('flushes final progress from each output stream', () => {
        const observedExecutions: number[] = [];
        const observer = createFuzzProgressObserver({
            onProgress: (progress) => {
                if (progress.executions !== undefined) {
                    observedExecutions.push(progress.executions);
                }
            },
        });
        const invocation = {
            args: [],
            command: 'cargo',
            description: 'fuzz',
        };

        for (const [streamName, executions] of [
            ['stdout', 10],
            ['stderr', 20],
        ] as const) {
            observer.onCommandOutput?.({
                chunk: `#${executions} pulse cov: 2 corp: 1/8b exec/s: 3`,
                invocation,
                streamName,
            });
        }
        observer.onCommandExit?.({
            durationMilliseconds: 1,
            exitCode: 0,
            invocation,
            terminationSignal: null,
        });

        expect(observedExecutions).toEqual([10, 20]);
    });
});
