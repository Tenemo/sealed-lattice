import { afterEach, describe, expect, it, vi } from 'vitest';

import { ansiEscapePattern } from './check-progress-reporter/helpers.js';

import {
    CheckProgressReporter,
    type CheckProgressLanePlan,
} from '#tools/ci/check-progress-reporter';

describe('check progress reporter state', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('records command-count progress, failure output, and timing details', () => {
        let nowMilliseconds = 1_000;
        const writtenLines: string[] = [];
        const lanes: readonly CheckProgressLanePlan[] = [
            {
                commands: [
                    {
                        description: 'First command',
                    },
                    {
                        description: 'Second command',
                    },
                ],
                name: 'Sample lane',
            },
        ];
        const reporter = new CheckProgressReporter({
            lanes,
            now: () => nowMilliseconds,
            output: {
                write: (chunk: string | Uint8Array): boolean => {
                    writtenLines.push(chunk.toString());

                    return true;
                },
            },
            redrawEnabled: false,
        });
        const observer = reporter.createCommandObserver('Sample lane');

        reporter.start();
        observer.onCommandStart?.({
            invocation: {
                args: [],
                command: 'sample',
                description: 'First command',
            },
            logFiles: {
                combinedPath: 'first.log',
                stderrPath: 'first.stderr.log',
                stdoutPath: 'first.stdout.log',
            },
            startedAtMilliseconds: nowMilliseconds,
        });
        observer.onCommandOutput?.({
            chunk: 'failure line\n',
            invocation: {
                args: [],
                command: 'sample',
                description: 'First command',
            },
            streamName: 'stderr',
        });
        nowMilliseconds = 2_500;
        observer.onCommandExit?.({
            durationMilliseconds: 1_500,
            exitCode: 7,
            invocation: {
                args: [],
                command: 'sample',
                description: 'First command',
            },
            terminationSignal: null,
        });
        reporter.recordLaneResult('Sample lane', 'failed');
        reporter.stop();

        expect(writtenLines.join('')).toContain('check  commands 0/2');
        expect(reporter.completedCommandCount()).toBe(1);
        expect(reporter.totalCommandCount()).toBe(2);
        expect(reporter.failureDetails()).toEqual([
            {
                commandDescription: 'First command',
                exitCode: 7,
                laneName: 'Sample lane',
                logPath: 'first.log',
                recentOutputLines: ['Sample lane > failure line'],
            },
        ]);
        expect(reporter.createTimingDetails()).toMatchObject({
            completedCommandCount: 1,
            lanes: [
                {
                    commands: [
                        {
                            description: 'First command',
                            durationMilliseconds: 1_500,
                            exitCode: 7,
                            logPath: 'first.log',
                            status: 'failed',
                        },
                        {
                            description: 'Second command',
                            status: 'waiting',
                        },
                    ],
                    name: 'Sample lane',
                    status: 'failed',
                },
            ],
            totalCommandCount: 2,
        });
    });

    it('uses COLUMNS as the forced-redraw width when the output stream is not a TTY', () => {
        const previousColumns = process.env.COLUMNS;
        process.env.COLUMNS = '60';
        const writtenChunks: string[] = [];
        try {
            const reporter = new CheckProgressReporter({
                lanes: [
                    {
                        commands: [
                            {
                                description: 'Very long command name',
                            },
                        ],
                        expectedDurationMilliseconds: 10_000,
                        name: 'Very long validation lane name that should fit the configured terminal width',
                    },
                ],
                output: {
                    write: (chunk: string | Uint8Array): boolean => {
                        writtenChunks.push(chunk.toString());

                        return true;
                    },
                },
                redrawEnabled: true,
            });

            reporter.start();
            reporter.stop();
        } finally {
            if (previousColumns === undefined) {
                delete process.env.COLUMNS;
            } else {
                process.env.COLUMNS = previousColumns;
            }
        }

        const visibleLines = writtenChunks
            .join('')
            .replace(ansiEscapePattern, '')
            .split('\n')
            .filter((line) => line.length > 0);
        expect(visibleLines.length).toBeGreaterThan(0);
        expect(visibleLines.every((line) => line.length <= 60)).toBe(true);
    });

    it('uses Turbo progress from captured build output without opaque command fractions', () => {
        vi.useFakeTimers();
        let nowMilliseconds = 1_000;
        const writtenChunks: string[] = [];
        const reporter = new CheckProgressReporter({
            lanes: [
                {
                    commands: [
                        {
                            description: 'Build workspace packages',
                        },
                    ],
                    name: 'Build workspace packages',
                    progress: {
                        source: 'turbo',
                    },
                },
            ],
            now: () => nowMilliseconds,
            output: {
                columns: 140,
                isTTY: true,
                write: (chunk: string | Uint8Array): boolean => {
                    writtenChunks.push(chunk.toString());

                    return true;
                },
            },
            redrawEnabled: true,
            renderIntervalMilliseconds: 60_000,
        });
        const observer = reporter.createCommandObserver(
            'Build workspace packages',
        );
        const invocation = {
            args: [],
            command: 'sample',
            description: 'Build workspace packages',
        };

        reporter.start();
        observer.onCommandStart?.({
            invocation,
            startedAtMilliseconds: nowMilliseconds,
        });
        observer.onCommandOutput?.({
            chunk: [
                '   • Running build in 5 packages',
                '@sealed-lattice/types:build: cache miss, executing 123',
                '@sealed-lattice/crypto:build: cache hit, replaying logs abc',
                '',
            ].join('\n'),
            invocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_100;
        vi.advanceTimersByTime(150);
        observer.onCommandOutput?.({
            chunk: ' Tasks:    4 successful, 5 total\n',
            invocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_200;
        vi.advanceTimersByTime(150);
        reporter.stop();

        const terminalOutput = writtenChunks.join('');
        expect(terminalOutput).not.toContain('[run ] 0/1');
        expect(terminalOutput).toContain('2/5 tasks seen');
        expect(terminalOutput).toContain('4/5 tasks');
        expect(reporter.createTimingDetails()).toMatchObject({
            lanes: [
                {
                    progress: {
                        primary: {
                            completed: 4,
                            total: 5,
                            unit: 'task',
                        },
                    },
                },
            ],
        });
    });

    it('uses Vitest reporter progress markers without showing them as latest output', () => {
        vi.useFakeTimers();
        let nowMilliseconds = 1_000;
        const writtenChunks: string[] = [];
        const reporter = new CheckProgressReporter({
            lanes: [
                {
                    commands: [
                        {
                            description: 'Node tests (fast)',
                        },
                    ],
                    name: 'Node tests (fast)',
                    progress: {
                        source: 'vitest',
                    },
                },
            ],
            now: () => nowMilliseconds,
            output: {
                columns: 140,
                isTTY: true,
                write: (chunk: string | Uint8Array): boolean => {
                    writtenChunks.push(chunk.toString());

                    return true;
                },
            },
            redrawEnabled: true,
            renderIntervalMilliseconds: 60_000,
        });
        const observer = reporter.createCommandObserver('Node tests (fast)');
        const invocation = {
            args: [],
            command: 'sample',
            description: 'Node tests (fast)',
        };

        reporter.start();
        observer.onCommandStart?.({
            invocation,
            startedAtMilliseconds: nowMilliseconds,
        });
        observer.onCommandOutput?.({
            chunk: 'sealed-lattice-progress {"tool":"vitest","files":{"completed":1,"total":3},"tests":{"completed":2,"total":8}}\n',
            invocation,
            streamName: 'stdout',
        });
        observer.onCommandOutput?.({
            chunk: ' RUN  v4.1.4\n',
            invocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_100;
        vi.advanceTimersByTime(150);
        reporter.stop();

        const terminalOutput = writtenChunks.join('');
        expect(terminalOutput).toContain('2/8 tests');
        expect(terminalOutput).not.toContain('test file');
        expect(terminalOutput).toContain('Node tests (fast) >  RUN  v4.1.4');
        expect(terminalOutput).not.toContain('sealed-lattice-progress');
    });

    it('uses libtest output as secondary Rust progress', () => {
        vi.useFakeTimers();
        let nowMilliseconds = 1_000;
        const writtenChunks: string[] = [];
        const reporter = new CheckProgressReporter({
            lanes: [
                {
                    commands: [
                        {
                            description: 'cargo fmt --check',
                        },
                        {
                            description: 'cargo clippy',
                        },
                        {
                            description: 'cargo test',
                        },
                    ],
                    name: 'Rust kernel (fmt, clippy, test)',
                    progress: {
                        source: 'libtest',
                    },
                },
            ],
            now: () => nowMilliseconds,
            output: {
                columns: 160,
                isTTY: true,
                write: (chunk: string | Uint8Array): boolean => {
                    writtenChunks.push(chunk.toString());

                    return true;
                },
            },
            redrawEnabled: true,
            renderIntervalMilliseconds: 60_000,
        });
        const observer = reporter.createCommandObserver(
            'Rust kernel (fmt, clippy, test)',
        );
        const fmtInvocation = {
            args: [],
            command: 'cargo',
            description: 'cargo fmt --check',
        };
        const testInvocation = {
            args: [],
            command: 'cargo',
            description: 'cargo test',
        };

        reporter.start();
        observer.onCommandStart?.({
            invocation: fmtInvocation,
            startedAtMilliseconds: nowMilliseconds,
        });
        nowMilliseconds = 1_050;
        observer.onCommandExit?.({
            durationMilliseconds: 50,
            exitCode: 0,
            invocation: fmtInvocation,
            terminationSignal: null,
        });
        observer.onCommandStart?.({
            invocation: testInvocation,
            startedAtMilliseconds: nowMilliseconds,
        });
        observer.onCommandOutput?.({
            chunk: [
                'running 4 tests',
                'test bgv::setup::tests::first_case ... ok',
                'test bgv::setup::tests::second_case ... ignored',
                'test bgv::setup::tests::long_case has been running for over 60 seconds',
                'test bgv::setup::tests::long_case ... ok',
                '',
            ].join('\n'),
            invocation: testInvocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_150;
        vi.advanceTimersByTime(150);
        reporter.stop();

        const terminalOutput = writtenChunks.join('');
        expect(terminalOutput).toContain('3/4 tests');
        expect(terminalOutput).not.toContain('1/3 commands, 3/4 tests');
        expect(terminalOutput).toContain(
            'Rust kernel (fmt, clippy, test) > test bgv::setup::tests::long_case ... ok',
        );
        expect(reporter.createTimingDetails()).toMatchObject({
            lanes: [
                {
                    progress: {
                        secondary: {
                            completed: 3,
                            total: 4,
                            unit: 'test',
                        },
                    },
                },
            ],
        });
    });
});
