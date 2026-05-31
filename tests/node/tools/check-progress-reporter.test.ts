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

        expect(writtenLines.join('')).toContain('check  0/2');
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
});
