import { rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { createTemporaryDirectory } from './helpers.js';

import {
    checkCommandTimingKey,
    extractCheckTimingHistoryFromSummary,
    readPreviousCheckTimingHistory,
} from '#tools/ci/check-progress-reporter';

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
