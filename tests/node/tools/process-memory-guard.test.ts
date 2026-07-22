import { describe, expect, it } from 'vitest';

import { createProcessMemoryGuard } from '#tools/ci/process-memory-guard';

const command = {
    args: ['test'],
    command: 'cargo',
    description: 'test process-memory guard sampling',
} as const;

describe('Process-memory guard', () => {
    it('preserves the default cadence by omitting the sampling argument', () => {
        const guardedCommand = createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription: 'Process-memory guard tests',
        }).guardCommand(command);

        expect(guardedCommand.args).not.toContain(
            '--resource-sample-interval-milliseconds',
        );
    });

    it('passes the requested sampling interval to the guard', () => {
        const guardedCommand = createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription: 'Process-memory guard tests',
        }).guardCommand(command, {
            resourceSampleIntervalMilliseconds: 100,
        });
        const argumentIndex = guardedCommand.args.indexOf(
            '--resource-sample-interval-milliseconds',
        );

        expect(
            guardedCommand.args.slice(argumentIndex, argumentIndex + 2),
        ).toEqual(['--resource-sample-interval-milliseconds', '100']);
    });

    it('refuses invalid sampling intervals before starting the guard', () => {
        const processMemoryGuard = createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription: 'Process-memory guard tests',
        });

        for (const resourceSampleIntervalMilliseconds of [
            0,
            99,
            100.5,
            Number.NaN,
            Number.POSITIVE_INFINITY,
        ]) {
            expect(() =>
                processMemoryGuard.guardCommand(command, {
                    resourceSampleIntervalMilliseconds,
                }),
            ).toThrow('must be an integer of at least 100 milliseconds');
        }
        expect(() =>
            processMemoryGuard.guardCommand(command, {
                resourceSampleIntervalMilliseconds: '100' as unknown as number,
            }),
        ).toThrow('must be an integer of at least 100 milliseconds');
    });
});
