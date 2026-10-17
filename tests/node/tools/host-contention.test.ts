import { describe, expect, it, vi } from 'vitest';

import {
    busyProcessors,
    sampleCpuLoad,
    summarizeCpuLoad,
} from '#tools/ci/monitor-host-contention.js';

describe('cumulative host contention accounting', () => {
    it('counts CPU time regardless of which processes survive the interval', () => {
        const before = { at: 0, busySeconds: 1000, ownSeconds: 80 };
        // All of this unrelated CPU work can start and exit between samples.
        expect(
            busyProcessors(before, { ...before, at: 60000, busySeconds: 1060 }),
        ).toEqual({
            elapsedSeconds: 60,
            ownSeconds: 0,
            otherSeconds: 60,
            ownProcessors: 0,
            otherProcessors: 1,
        });
        // The workload's terminated descendants remain in its job counter.
        expect(
            busyProcessors(before, {
                at: 60000,
                busySeconds: 1090,
                ownSeconds: 140,
            }),
        ).toEqual({
            elapsedSeconds: 60,
            ownSeconds: 60,
            otherSeconds: 30,
            ownProcessors: 1,
            otherProcessors: 0.5,
        });
        expect(busyProcessors(before, { ...before, at: 60000 })).toEqual({
            elapsedSeconds: 60,
            ownSeconds: 0,
            otherSeconds: 0,
            ownProcessors: 0,
            otherProcessors: 0,
        });
        expect(() => busyProcessors(before, before)).toThrow('advance');
        expect(() =>
            busyProcessors(before, { at: 1, busySeconds: 999, ownSeconds: 80 }),
        ).toThrow('decrease');
        expect(() =>
            busyProcessors(before, {
                at: 1,
                busySeconds: 1001,
                ownSeconds: 79,
            }),
        ).toThrow('decrease');
    });

    it('takes its baseline before readiness and includes a short final interval', async () => {
        vi.useFakeTimers();
        try {
            const readings = [
                { at: 0, busySeconds: 0, ownSeconds: 0 },
                { at: 60000, busySeconds: 120, ownSeconds: 60 },
                { at: 65000, busySeconds: 150, ownSeconds: 65 },
            ];
            let stop!: () => void;
            const stopped = new Promise<void>((resolve) => {
                stop = resolve;
            });
            const events: string[] = [];
            const task = sampleCpuLoad({
                read: () => {
                    events.push('read');
                    return Promise.resolve(readings.shift()!);
                },
                ready: () => {
                    events.push('ready');
                    return Promise.resolve();
                },
                stopped,
                record: () => {
                    events.push('sample');
                },
            });
            await vi.advanceTimersByTimeAsync(60000);
            await vi.advanceTimersByTimeAsync(5000);
            stop();
            const samples = await task;
            expect(events).toEqual([
                'read',
                'ready',
                'read',
                'sample',
                'read',
                'sample',
            ]);
            expect(samples.map((value) => value.elapsedSeconds)).toEqual([
                60, 5,
            ]);
            expect(summarizeCpuLoad(samples)).toEqual({
                samples: 2,
                sampleSeconds: 60,
                measuredSeconds: 65,
                meanOwnProcessors: 1,
                meanOtherProcessors: 1.31,
                peakOtherProcessors: 5,
            });
            expect(vi.getTimerCount()).toBe(0);
        } finally {
            vi.useRealTimers();
        }
    });

    it('measures work that finishes before the first scheduled sample', async () => {
        const readings = [
            { at: 100, busySeconds: 500, ownSeconds: 200 },
            { at: 1100, busySeconds: 502, ownSeconds: 201 },
        ];
        const samples = await sampleCpuLoad({
            read: () => Promise.resolve(readings.shift()!),
            ready: () => Promise.resolve(),
            stopped: Promise.resolve(),
            record: () => undefined,
        });
        expect(samples).toHaveLength(1);
        expect(summarizeCpuLoad(samples)).toEqual({
            samples: 1,
            sampleSeconds: 60,
            measuredSeconds: 1,
            meanOwnProcessors: 1,
            meanOtherProcessors: 1,
            peakOtherProcessors: 1,
        });
    });
});
