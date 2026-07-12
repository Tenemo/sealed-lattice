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
    reporter.observer.onCommandOutput?.({
        chunk,
        invocation,
        streamName,
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
    it('parses exact instrumented Rust test timing embedded in libtest output', () => {
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
        expect(
            parseRustTestTimingLine(
                'sealed-lattice-rust-test-timing {"durationMilliseconds":"wrong"}',
            ),
        ).toBeUndefined();
    });

    it('persists exact instrumented runtime separately from observed libtest timing', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(os.tmpdir(), 'sealed-lattice-libtest-events-'),
        );
        try {
            const eventFilePath = path.join(
                temporaryDirectoryPath,
                'rust.jsonl',
            );
            const reporter = createHeavyTestProgressReporter({
                eventFilePath,
                label: 'rust-test',
                now: () => 0,
                threadCount: 1,
                write: () => undefined,
            });
            startRun(reporter);
            feedOutput(reporter, 'running 1 test\n');
            feedOutput(reporter, 'test module::proof ... ');
            feedOutput(
                reporter,
                'sealed-lattice-rust-test-timing ' +
                    '{"suite":"module","test":"proof","durationMilliseconds":321,"durationMicroseconds":321987}\n',
            );
            feedOutput(reporter, 'ok\n');
            reporter.observer.onCommandExit?.({
                durationMilliseconds: 400,
                exitCode: 0,
                invocation,
                terminationSignal: null,
            });

            const events = (await readFile(eventFilePath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(events).toContainEqual(
                expect.objectContaining({
                    durationBasis: 'exact-instrumented',
                    durationMicroseconds: 321_987,
                    durationMilliseconds: 321,
                    event: 'test-finished',
                    fullName: 'module::proof',
                    result: 'ok',
                }),
            );
        } finally {
            await rm(temporaryDirectoryPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('records approximate wall runtimes between serialized completion boundaries', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(os.tmpdir(), 'sealed-lattice-libtest-events-'),
        );
        try {
            const eventFilePath = path.join(
                temporaryDirectoryPath,
                'serialized-rust.jsonl',
            );
            let currentTimeMilliseconds = 100;
            const reporter = createHeavyTestProgressReporter({
                eventFilePath,
                label: 'serialized-rust',
                now: () => currentTimeMilliseconds,
                threadCount: 1,
                write: () => undefined,
            });
            startRun(reporter);
            feedOutput(reporter, 'running 2 tests\n');
            currentTimeMilliseconds = 375;
            feedOutput(reporter, 'test module::first ... ok\n');
            currentTimeMilliseconds = 500;
            feedOutput(reporter, 'test module::second ... FAILED\n');
            reporter.observer.onCommandExit?.({
                durationMilliseconds: 400,
                exitCode: 1,
                invocation,
                terminationSignal: null,
            });

            const finishedEvents = (await readFile(eventFilePath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>)
                .filter((event) => event.event === 'test-finished');
            expect(finishedEvents).toEqual([
                expect.objectContaining({
                    durationBasis: 'approximate-observed-serialized-wall-clock',
                    durationMilliseconds: 275,
                    fullName: 'module::first',
                    result: 'ok',
                }),
                expect.objectContaining({
                    durationBasis: 'approximate-observed-serialized-wall-clock',
                    durationMilliseconds: 125,
                    fullName: 'module::second',
                    result: 'FAILED',
                }),
            ]);
        } finally {
            await rm(temporaryDirectoryPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('leaves runtime unavailable when concurrency or output boundaries make inference unsound', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(os.tmpdir(), 'sealed-lattice-libtest-events-'),
        );
        try {
            const scenarios = [
                {
                    eventFileName: 'concurrent.jsonl',
                    output: [
                        'running 2 tests\n',
                        'test module::first ... ok\n',
                    ],
                    threadCount: 2,
                },
                {
                    eventFileName: 'missing-boundary.jsonl',
                    output: ['test module::first ... ok\n'],
                    threadCount: 1,
                },
            ] as const;

            for (const scenario of scenarios) {
                const eventFilePath = path.join(
                    temporaryDirectoryPath,
                    scenario.eventFileName,
                );
                const reporter = createHeavyTestProgressReporter({
                    eventFilePath,
                    label: scenario.eventFileName,
                    now: () => 100,
                    threadCount: scenario.threadCount,
                    write: () => undefined,
                });
                startRun(reporter);
                for (const output of scenario.output) {
                    feedOutput(reporter, output);
                }
                reporter.observer.onCommandExit?.({
                    durationMilliseconds: 100,
                    exitCode: 0,
                    invocation,
                    terminationSignal: null,
                });

                const finishedEvent = (await readFile(eventFilePath, 'utf8'))
                    .trim()
                    .split(/\r?\n/u)
                    .map((line) => JSON.parse(line) as Record<string, unknown>)
                    .find((event) => event.event === 'test-finished');
                expect(finishedEvent).toEqual(
                    expect.objectContaining({
                        durationBasis: 'unavailable',
                        fullName: 'module::first',
                    }),
                );
                expect(finishedEvent).not.toHaveProperty(
                    'durationMilliseconds',
                );
            }
        } finally {
            await rm(temporaryDirectoryPath, {
                force: true,
                recursive: true,
            });
        }
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

    it('keeps stream fragments independent and flushes both on command exit', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(os.tmpdir(), 'sealed-lattice-libtest-events-'),
        );
        try {
            const eventFilePath = path.join(
                temporaryDirectoryPath,
                'rust.jsonl',
            );
            const lines: string[] = [];
            const reporter = createHeavyTestProgressReporter({
                eventFilePath,
                label: 'heavy',
                threadCount: 2,
                now: () => 0,
                write: (line) => lines.push(line),
            });
            startRun(reporter);
            feedOutput(reporter, 'running 2 tests\n');
            feedOutput(reporter, 'test accepted_setup::stdout_partial ... ok');
            feedOutput(
                reporter,
                'test accepted_setup::stderr_partial ... FAILED',
                'stderr',
            );
            reporter.observer.onCommandExit?.({
                durationMilliseconds: 500,
                exitCode: 1,
                invocation,
                terminationSignal: null,
            });

            expect(lines).toHaveLength(2);
            expect(lines.join('\n')).toContain(
                'accepted_setup::stdout_partial (ok)',
            );
            expect(lines.join('\n')).toContain(
                'accepted_setup::stderr_partial (FAILED)',
            );
            const events = (await readFile(eventFilePath, 'utf8'))
                .trim()
                .split(/\r?\n/u)
                .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(
                events
                    .filter((event) => event.event === 'test-finished')
                    .map((event) => ({
                        fullName: event.fullName,
                        result: event.result,
                    })),
            ).toEqual([
                {
                    fullName: 'accepted_setup::stdout_partial',
                    result: 'ok',
                },
                {
                    fullName: 'accepted_setup::stderr_partial',
                    result: 'FAILED',
                },
            ]);
        } finally {
            await rm(temporaryDirectoryPath, {
                force: true,
                recursive: true,
            });
        }
    });

    it('counts nocapture completions when the result is printed after test output', () => {
        const lines: string[] = [];
        const reporter = createHeavyTestProgressReporter({
            label: 'heavy',
            threadCount: 1,
            now: () => 0,
            write: (line) => lines.push(line),
        });

        startRun(reporter);
        feedOutput(reporter, 'running 1 test\n');
        feedOutput(reporter, 'test accepted_setup::with_output ... ');
        feedOutput(reporter, 'diagnostic emitted by the test\n');
        feedOutput(reporter, 'ok\n');

        expect(lines).toHaveLength(1);
        expect(lines[0]).toContain('finished 1/1 done, ~0 running');
        expect(lines[0]).toContain('accepted_setup::with_output (ok)');
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
});

describe('heavy test terminal output filter', () => {
    const { terminalOutputFilter } = createHeavyTestProgressReporter({
        label: 'heavy',
        threadCount: 4,
    });

    it('drops libtest slow-test notices', () => {
        expect(
            terminalOutputFilter(
                'test accepted_setup::slow has been running for over 60 seconds',
            ),
        ).toBe(false);
        expect(
            terminalOutputFilter(
                'test x has been running for over 120 seconds',
            ),
        ).toBe(false);
    });

    it('keeps real test output, progress, compile, and summary lines', () => {
        expect(terminalOutputFilter('test accepted_setup::one ... ok')).toBe(
            true,
        );
        expect(terminalOutputFilter('running 61 tests')).toBe(true);
        expect(
            terminalOutputFilter('   Compiling sealed-lattice-kernel v0.1.0'),
        ).toBe(true);
        expect(
            terminalOutputFilter(
                'test result: ok. 61 passed; 0 failed; 0 ignored',
            ),
        ).toBe(true);
        expect(terminalOutputFilter('')).toBe(true);
    });
});
