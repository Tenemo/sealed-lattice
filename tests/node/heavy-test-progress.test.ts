import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    createHeavyTestProgressReporter,
    parseRustTestTimingLine,
} from '#tools/ci/heavy-test-progress';

const invocation = {
    args: [] as const,
    command: 'cargo',
    description: 'cargo test heavy accepted setup tests',
} as const;

const feedOutput = (
    reporter: ReturnType<typeof createHeavyTestProgressReporter>,
    chunk: string,
    streamName: 'stderr' | 'stdout' = 'stdout',
): void => {
    reporter.observer.onCommandOutput?.({ chunk, invocation, streamName });
};

const startRun = (
    reporter: ReturnType<typeof createHeavyTestProgressReporter>,
): void => {
    reporter.observer.onCommandStart?.({
        invocation,
        startedAtMilliseconds: 0,
    });
};

const finishRun = (
    reporter: ReturnType<typeof createHeavyTestProgressReporter>,
    exitCode = 0,
): void => {
    reporter.observer.onCommandExit?.({
        durationMilliseconds: 500,
        exitCode,
        invocation,
        terminationSignal: null,
    });
};

const withEventFile = async (
    action: (eventFilePath: string) => Promise<void>,
): Promise<void> => {
    const temporaryDirectoryPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-libtest-events-'),
    );
    try {
        await action(path.join(temporaryDirectoryPath, 'rust.jsonl'));
    } finally {
        await rm(temporaryDirectoryPath, { force: true, recursive: true });
    }
};

const readEvents = async (
    eventFilePath: string,
): Promise<Record<string, unknown>[]> =>
    (await readFile(eventFilePath, 'utf8'))
        .trim()
        .split(/\r?\n/u)
        .map((line) => JSON.parse(line) as Record<string, unknown>);

describe('createHeavyTestProgressReporter', () => {
    it('parses only complete instrumented Rust timing records', () => {
        expect(
            parseRustTestTimingLine(
                'test module::proof ... sealed-lattice-rust-test-timing ' +
                    '{"suite":"module","test":"proof","durationMilliseconds":123,"durationMicroseconds":123456}',
            ),
        ).toEqual({
            durationMicroseconds: 123_456,
            durationMilliseconds: 123,
            suite: 'module',
            test: 'proof',
        });

        for (const malformedLine of [
            'ordinary libtest output',
            'sealed-lattice-rust-test-timing {',
            'sealed-lattice-rust-test-timing {"durationMilliseconds":"wrong"}',
        ]) {
            expect(parseRustTestTimingLine(malformedLine)).toBeUndefined();
        }
    });

    it('records exact, approximate, and unavailable runtimes honestly', async () => {
        await withEventFile(async (eventFilePath) => {
            let currentTimeMilliseconds = 100;
            const exactReporter = createHeavyTestProgressReporter({
                eventFilePath,
                label: 'rust-test',
                now: () => currentTimeMilliseconds,
                threadCount: 1,
                write: () => undefined,
            });
            startRun(exactReporter);
            feedOutput(exactReporter, 'running 2 tests\n');
            feedOutput(
                exactReporter,
                'test module::proof ... sealed-lattice-rust-test-timing ' +
                    '{"suite":"module","test":"proof","durationMilliseconds":321,"durationMicroseconds":321987}\n',
            );
            feedOutput(exactReporter, 'ok\n');
            currentTimeMilliseconds = 500;
            feedOutput(exactReporter, 'test module::second ... FAILED\n');
            finishRun(exactReporter, 1);

            const finishedEvents = (await readEvents(eventFilePath)).filter(
                (event) => event.event === 'test-finished',
            );
            expect(finishedEvents).toEqual([
                expect.objectContaining({
                    durationBasis: 'exact-instrumented',
                    durationMicroseconds: 321_987,
                    durationMilliseconds: 321,
                    fullName: 'module::proof',
                    result: 'ok',
                }),
                expect.objectContaining({
                    durationBasis: 'approximate-observed-serialized-wall-clock',
                    durationMilliseconds: 400,
                    fullName: 'module::second',
                    result: 'FAILED',
                }),
            ]);
        });

        await withEventFile(async (eventFilePath) => {
            const concurrentReporter = createHeavyTestProgressReporter({
                eventFilePath,
                label: 'concurrent',
                now: () => 100,
                threadCount: 2,
                write: () => undefined,
            });
            startRun(concurrentReporter);
            feedOutput(concurrentReporter, 'running 2 tests\n');
            feedOutput(concurrentReporter, 'test module::first ... ok\n');
            finishRun(concurrentReporter);

            expect(await readEvents(eventFilePath)).toContainEqual(
                expect.objectContaining({
                    durationBasis: 'unavailable',
                    event: 'test-finished',
                    fullName: 'module::first',
                }),
            );
        });
    });

    it('tracks totals, split completions, nocapture output, and slow notices', () => {
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            now: () => 0,
            threadCount: 3,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 2 tests\nrunning 1 test\n');
        feedOutput(
            reporter,
            'test accepted_setup::slow has been running for over 60 seconds\n',
        );
        feedOutput(reporter, 'test accepted_setup::sp');
        feedOutput(reporter, 'lit ... ok\n');
        feedOutput(reporter, 'test accepted_setup::with_output ... ');
        feedOutput(reporter, 'diagnostic emitted by the test\nFAILED\n');

        expect(lines).toHaveLength(2);
        expect(lines[0]).toContain('finished 1/3 done');
        expect(lines[0]).toContain('accepted_setup::split (ok)');
        expect(lines[1]).toContain('2/3 done, 1 failed');
        expect(lines[1]).toContain('accepted_setup::with_output (FAILED)');
        reporter.stop();
    });

    it('keeps output streams independent and flushes both journals on exit', async () => {
        await withEventFile(async (eventFilePath) => {
            const lines: string[] = [];
            const reporter = createHeavyTestProgressReporter({
                eventFilePath,
                label: 'heavy',
                now: () => 0,
                threadCount: 2,
                write: (line) => lines.push(line),
            });
            startRun(reporter);
            feedOutput(reporter, 'running 2 tests\n');
            feedOutput(reporter, 'test accepted_setup::stdout ... ok');
            feedOutput(
                reporter,
                'test accepted_setup::stderr ... FAILED',
                'stderr',
            );
            finishRun(reporter, 1);

            expect(lines.join('\n')).toContain('accepted_setup::stdout (ok)');
            expect(lines.join('\n')).toContain(
                'accepted_setup::stderr (FAILED)',
            );
            expect(
                (await readEvents(eventFilePath))
                    .filter((event) => event.event === 'test-finished')
                    .map((event) => [event.fullName, event.result]),
            ).toEqual([
                ['accepted_setup::stdout', 'ok'],
                ['accepted_setup::stderr', 'FAILED'],
            ]);
        });
    });

    it('filters only libtest slow-test notices from terminal output', () => {
        const { terminalOutputFilter } = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 4,
        });

        expect(
            terminalOutputFilter(
                'test accepted_setup::slow has been running for over 60 seconds',
            ),
        ).toBe(false);
        for (const keptLine of [
            'test accepted_setup::one ... ok',
            'running 61 tests',
            '   Compiling sealed-lattice-kernel v0.1.0',
            'test result: ok. 61 passed; 0 failed; 0 ignored',
        ]) {
            expect(terminalOutputFilter(keptLine)).toBe(true);
        }
    });
});
