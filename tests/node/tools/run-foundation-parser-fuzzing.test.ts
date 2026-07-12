import { describe, expect, it } from 'vitest';

import {
    createFuzzProgressObserver,
    foundationParserFuzzToolchain,
    parseFuzzDurationSeconds,
    parseFuzzProgressLine,
    requireExpectedCargoFuzzVersion,
} from '#tools/ci/run-foundation-parser-fuzzing';

describe('foundation parser fuzz runner', () => {
    it('pins the manual toolchain and accepts the default or one positive duration', () => {
        expect(foundationParserFuzzToolchain).toEqual({
            cargoFuzzVersion: '0.13.2',
            rustToolchain: 'nightly-2026-06-15',
        });
        expect(parseFuzzDurationSeconds([])).toBe(60);
        expect(parseFuzzDurationSeconds(['--', '3600'])).toBe(3600);
    });

    it.each([
        ['0'],
        ['-1'],
        ['1.5'],
        ['one'],
        ['1', '2'],
        ['999999999999999999999999999999999999'],
    ])('refuses invalid duration arguments %j', (...arguments_) => {
        expect(() => parseFuzzDurationSeconds(arguments_)).toThrow();
    });

    it('requires the exact cargo-fuzz version', () => {
        expect(() =>
            requireExpectedCargoFuzzVersion('cargo-fuzz 0.13.2\n'),
        ).not.toThrow();
        expect(() =>
            requireExpectedCargoFuzzVersion('cargo-fuzz 0.13.1\n'),
        ).toThrow(/requires cargo-fuzz 0\.13\.2/u);
        expect(() => requireExpectedCargoFuzzVersion('')).toThrow(
            /no version output/u,
        );
    });

    it('extracts runtime campaign progress without treating unrelated output as progress', () => {
        expect(
            parseFuzzProgressLine(
                '#12345 pulse  cov: 87 ft: 111 corp: 9/2048b lim: 4096 exec/s: 321 rss: 99Mb',
            ),
        ).toEqual({
            corpusBytes: 2_048,
            corpusEntries: 9,
            coverageEdges: 87,
            executions: 12_345,
            executionsPerSecond: 321,
        });
        expect(
            parseFuzzProgressLine('INFO: seed corpus: files: 1'),
        ).toBeUndefined();
    });

    it('keeps progress streams separate and flushes final partial lines', () => {
        const observedProgress: unknown[] = [];
        const observer = createFuzzProgressObserver({
            onProgress: (progress) => observedProgress.push(progress),
        });
        const invocation = {
            args: [],
            command: 'cargo',
            description: 'fuzz',
        };

        observer.onCommandOutput?.({
            chunk: '#10 pulse cov: 2 corp: 1/8b exec/s: 3',
            invocation,
            streamName: 'stdout',
        });
        observer.onCommandOutput?.({
            chunk: '#20 pulse cov: 4 corp: 2/16b exec/s: 6',
            invocation,
            streamName: 'stderr',
        });
        observer.onCommandExit?.({
            durationMilliseconds: 1,
            exitCode: 0,
            invocation,
            terminationSignal: null,
        });

        expect(observedProgress).toEqual([
            {
                corpusBytes: 8,
                corpusEntries: 1,
                coverageEdges: 2,
                executions: 10,
                executionsPerSecond: 3,
            },
            {
                corpusBytes: 16,
                corpusEntries: 2,
                coverageEdges: 4,
                executions: 20,
                executionsPerSecond: 6,
            },
        ]);
    });
});
