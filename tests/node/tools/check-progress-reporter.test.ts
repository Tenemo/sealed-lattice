import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    CheckProgressReporter,
    RecentOutputBuffer,
    checkCommandTimingKey,
    extractCheckTimingHistoryFromSummary,
    formatProgressDuration,
    readPreviousCheckTimingHistory,
    type CheckProgressLanePlan,
} from '#tools/ci/check-progress-reporter';

const createTemporaryDirectory = (): Promise<string> =>
    mkdtemp(path.join(os.tmpdir(), 'sealed-lattice-check-progress-'));

const waitForTimeout = (durationMilliseconds: number): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, durationMilliseconds);
    });

const ansiEscapePattern = new RegExp(
    String.raw`\u001B\[[0-?]*[ -/]*[@-~]`,
    'gu',
);

describe('check progress reporter timing history', () => {
    it('extracts total, lane, and command durations from a successful check summary', () => {
        const timingHistory = extractCheckTimingHistoryFromSummary({
            details: {
                completedCommandCount: 2,
                lanes: [
                    {
                        commands: [
                            {
                                description: 'Build workspace packages',
                                durationMilliseconds: 12_000,
                                exitCode: 0,
                                status: 'passed',
                            },
                        ],
                        durationMilliseconds: 12_000,
                        name: 'Build workspace packages',
                        status: 'passed',
                    },
                    {
                        commands: [
                            {
                                description: 'cargo clippy',
                                durationMilliseconds: 44_000,
                                exitCode: 0,
                                status: 'passed',
                            },
                        ],
                        durationMilliseconds: 44_000,
                        name: 'Rust kernel (fmt, clippy, test)',
                        progress: {
                            primary: {
                                completed: 3,
                                total: 3,
                                unit: 'command',
                            },
                        },
                        status: 'passed',
                    },
                ],
                objectVersion: 'sealed-lattice-check-run-details-v1',
                totalCommandCount: 2,
            },
            durationMilliseconds: 56_000,
            exitCode: 0,
            scriptName: 'check',
        });

        expect(timingHistory?.totalDurationMilliseconds).toBe(56_000);
        expect(
            timingHistory?.laneDurationMilliseconds.get(
                'Rust kernel (fmt, clippy, test)',
            ),
        ).toBe(44_000);
        expect(
            timingHistory?.commandDurationMilliseconds.get(
                checkCommandTimingKey(
                    'Rust kernel (fmt, clippy, test)',
                    'cargo clippy',
                ),
            ),
        ).toBe(44_000);
        const rustKernelProgress = timingHistory?.laneProgress.get(
            'Rust kernel (fmt, clippy, test)',
        )?.primary;
        expect(rustKernelProgress).toEqual({
            completed: 3,
            total: 3,
            unit: 'command',
        });
    });

    it('ignores failed summaries when selecting previous expected durations', async () => {
        const logRootDirectoryPath = await createTemporaryDirectory();
        try {
            await writeFile(
                path.join(logRootDirectoryPath, 'runs.jsonl'),
                [
                    JSON.stringify({
                        durationMilliseconds: 10_000,
                        exitCode: 0,
                        scriptName: 'test:node',
                    }),
                    '{not-json',
                    JSON.stringify({
                        durationMilliseconds: 20_000,
                        exitCode: 1,
                        scriptName: 'check',
                    }),
                    JSON.stringify({
                        durationMilliseconds: 30_000,
                        exitCode: 0,
                        scriptName: 'check',
                    }),
                ].join('\n'),
                'utf8',
            );

            const timingHistory =
                await readPreviousCheckTimingHistory(logRootDirectoryPath);

            expect(timingHistory.totalDurationMilliseconds).toBe(30_000);
            expect(timingHistory.laneDurationMilliseconds.size).toBe(0);
            expect(timingHistory.commandDurationMilliseconds.size).toBe(0);
        } finally {
            await rm(logRootDirectoryPath, { force: true, recursive: true });
        }
    });

    it('backfills missing lane progress from older successful summaries', async () => {
        const logRootDirectoryPath = await createTemporaryDirectory();
        try {
            await writeFile(
                path.join(logRootDirectoryPath, 'runs.jsonl'),
                [
                    JSON.stringify({
                        details: {
                            completedCommandCount: 3,
                            lanes: [
                                {
                                    commands: [],
                                    durationMilliseconds: 120_000,
                                    name: 'Rust kernel (fmt, clippy, test)',
                                    progress: {
                                        secondary: {
                                            completed: 166,
                                            total: 166,
                                            unit: 'test',
                                        },
                                    },
                                    status: 'passed',
                                },
                            ],
                            objectVersion:
                                'sealed-lattice-check-run-details-v1',
                            totalCommandCount: 3,
                        },
                        durationMilliseconds: 130_000,
                        exitCode: 0,
                        scriptName: 'check',
                    }),
                    JSON.stringify({
                        details: {
                            completedCommandCount: 3,
                            lanes: [
                                {
                                    commands: [],
                                    durationMilliseconds: 10_000,
                                    name: 'Rust kernel (fmt, clippy, optimized test)',
                                    status: 'passed',
                                },
                            ],
                            objectVersion:
                                'sealed-lattice-check-run-details-v1',
                            totalCommandCount: 3,
                        },
                        durationMilliseconds: 11_000,
                        exitCode: 0,
                        scriptName: 'check',
                    }),
                ].join('\n'),
                'utf8',
            );

            const timingHistory =
                await readPreviousCheckTimingHistory(logRootDirectoryPath);

            expect(timingHistory.totalDurationMilliseconds).toBe(11_000);
            expect(
                timingHistory.laneDurationMilliseconds.get(
                    'Rust kernel (fmt, clippy, optimized test)',
                ),
            ).toBe(10_000);
            expect(
                timingHistory.laneProgress.get(
                    'Rust kernel (fmt, clippy, test)',
                )?.secondary,
            ).toEqual({
                completed: 166,
                total: 166,
                unit: 'test',
            });
        } finally {
            await rm(logRootDirectoryPath, { force: true, recursive: true });
        }
    });
});

describe('check progress output buffers', () => {
    it('keeps recent complete and partial lines without ANSI control noise', () => {
        const recentOutput = new RecentOutputBuffer(3);

        recentOutput.append('Lint', '\u001B[32mfirst\u001B[39m\nsecond');
        recentOutput.append('Lint', ' continued\rthird\nfourth\n');

        expect(recentOutput.snapshot()).toEqual([
            'Lint > second continued',
            'Lint > third',
            'Lint > fourth',
        ]);
    });

    it('formats elapsed durations without fake precision for longer runs', () => {
        expect(formatProgressDuration(1_234)).toBe('1.2s');
        expect(formatProgressDuration(125_400)).toBe('2m05s');
    });
});

describe('check progress reporter state', () => {
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

    it('debounces live TTY redraws for output bursts', async () => {
        let nowMilliseconds = 1_000;
        const writtenChunks: string[] = [];
        const reporter = new CheckProgressReporter({
            lanes: [
                {
                    commands: [
                        {
                            description: 'Noisy command',
                        },
                    ],
                    name: 'Noisy lane',
                },
            ],
            now: () => nowMilliseconds,
            output: {
                columns: 120,
                isTTY: true,
                write: (chunk: string | Uint8Array): boolean => {
                    writtenChunks.push(chunk.toString());

                    return true;
                },
            },
            redrawEnabled: true,
            renderIntervalMilliseconds: 60_000,
        });
        const observer = reporter.createCommandObserver('Noisy lane');

        reporter.start();
        observer.onCommandStart?.({
            invocation: {
                args: [],
                command: 'sample',
                description: 'Noisy command',
            },
            startedAtMilliseconds: nowMilliseconds,
        });
        observer.onCommandOutput?.({
            chunk: 'first line\n',
            invocation: {
                args: [],
                command: 'sample',
                description: 'Noisy command',
            },
            streamName: 'stdout',
        });
        observer.onCommandOutput?.({
            chunk: 'second line\n',
            invocation: {
                args: [],
                command: 'sample',
                description: 'Noisy command',
            },
            streamName: 'stdout',
        });
        nowMilliseconds = 1_100;
        await waitForTimeout(150);
        reporter.stop();

        const terminalOutput = writtenChunks.join('');
        const latestOutputRenderCount =
            terminalOutput.split('latest output').length - 1;
        expect(terminalOutput).toContain('Noisy lane > first line');
        expect(terminalOutput).toContain('Noisy lane > second line');
        expect(latestOutputRenderCount).toBe(1);
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

    it('uses Turbo progress from captured build output without opaque command fractions', async () => {
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
        await waitForTimeout(150);
        observer.onCommandOutput?.({
            chunk: ' Tasks:    4 successful, 5 total\n',
            invocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_200;
        await waitForTimeout(150);
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

    it('uses Vitest reporter progress markers without showing them as latest output', async () => {
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
        await waitForTimeout(150);
        reporter.stop();

        const terminalOutput = writtenChunks.join('');
        expect(terminalOutput).toContain('2/8 tests');
        expect(terminalOutput).not.toContain('test file');
        expect(terminalOutput).toContain('Node tests (fast) >  RUN  v4.1.4');
        expect(terminalOutput).not.toContain('sealed-lattice-progress');
    });

    it('uses libtest output as secondary Rust progress', async () => {
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
        await waitForTimeout(150);
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

    it('uses compact libtest output as secondary Rust progress', async () => {
        let nowMilliseconds = 1_000;
        const writtenChunks: string[] = [];
        const reporter = new CheckProgressReporter({
            lanes: [
                {
                    commands: [
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
                columns: 180,
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
        const testInvocation = {
            args: [],
            command: 'cargo',
            description: 'cargo test',
        };

        reporter.start();
        observer.onCommandStart?.({
            invocation: testInvocation,
            startedAtMilliseconds: nowMilliseconds,
        });
        observer.onCommandOutput?.({
            chunk: [
                'running 398 tests',
                '....................................................................................... 87/398',
                '',
            ].join('\n'),
            invocation: testInvocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_100;
        await waitForTimeout(150);
        observer.onCommandOutput?.({
            chunk: [
                '......................................................................i......test bgv::setup::tests::slow_case has been running for over 60 seconds',
                '........................................................................................................................................................................................................................................................ 398/398',
                'test result: ok. 397 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 245.00s',
                '',
            ].join('\n'),
            invocation: testInvocation,
            streamName: 'stdout',
        });
        nowMilliseconds = 1_150;
        await waitForTimeout(150);
        reporter.stop();

        const terminalOutput = writtenChunks.join('');
        expect(terminalOutput).toContain('87/398 tests');
        expect(terminalOutput).toContain('398/398 tests');
        expect(terminalOutput).not.toContain(
            '....................................................................................... 87/398',
        );
        expect(terminalOutput).not.toContain(
            '......test bgv::setup::tests::slow_case',
        );
        expect(terminalOutput).toContain(
            'Rust kernel (fmt, clippy, test) > test bgv::setup::tests::slow_case has been running for over 60 seconds',
        );
        expect(reporter.createTimingDetails()).toMatchObject({
            lanes: [
                {
                    progress: {
                        secondary: {
                            completed: 398,
                            total: 398,
                            unit: 'test',
                        },
                    },
                },
            ],
        });
    });
});
