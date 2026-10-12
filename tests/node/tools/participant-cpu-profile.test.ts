import { describe, expect, it } from 'vitest';

import { summarizeCpuTrace } from '#tools/ci/participant-cpu-profile.js';

const frame = (functionName: string, url = '') => ({ functionName, url });

// Two threads of one process whose node identifiers overlap. The first
// thread's profile arrives in two chunks, the second chunk adding a
// recursive call and an idle sample.
const trace = [
    { name: 'TracingStartedInBrowser', pid: 1 },
    {
        name: 'ProfileChunk',
        pid: 1,
        id: '0x1',
        args: {
            data: {
                cpuProfile: {
                    nodes: [
                        { id: 1, callFrame: frame('(root)') },
                        {
                            id: 2,
                            parent: 1,
                            callFrame: frame('run', 'https://p/worker.js'),
                        },
                        {
                            id: 3,
                            parent: 2,
                            callFrame: frame('transform', 'wasm://wasm/0a'),
                        },
                    ],
                    samples: [3, 2],
                },
                timeDeltas: [100, 50],
            },
        },
    },
    {
        name: 'ProfileChunk',
        pid: 1,
        id: '0x1',
        args: {
            data: {
                cpuProfile: {
                    nodes: [
                        {
                            id: 4,
                            parent: 3,
                            callFrame: frame('transform', 'wasm://wasm/0a'),
                        },
                        { id: 5, parent: 1, callFrame: frame('(idle)') },
                    ],
                    samples: [4, 5, 3],
                },
                timeDeltas: [30, 1000, 20],
            },
        },
    },
    {
        name: 'ProfileChunk',
        pid: 1,
        id: '0x2',
        args: {
            data: {
                cpuProfile: {
                    nodes: [
                        { id: 1, callFrame: frame('(root)') },
                        { id: 2, parent: 1, callFrame: frame('') },
                    ],
                    samples: [2, 2, 2],
                },
                timeDeltas: [5, -3, 400],
            },
        },
    },
];

describe('summarizeCpuTrace', () => {
    it('charges each sample until the next one to its stack and thread, once per function', () => {
        // The first thread's samples last 50, 30, 1000, 20 (idle) and 0
        // microseconds, and the second thread's 0 (a negative delta), 400
        // and 0.
        expect(summarizeCpuTrace(trace, 3)).toEqual({
            sampledMilliseconds: 1.48,
            self: [
                { name: 'transform', milliseconds: 1.05 },
                { name: '(anonymous)', milliseconds: 0.4 },
                { name: 'run https://p/worker.js', milliseconds: 0.03 },
            ],
            inclusive: [
                { name: 'run https://p/worker.js', milliseconds: 1.08 },
                { name: 'transform', milliseconds: 1.05 },
                { name: '(anonymous)', milliseconds: 0.4 },
            ],
            threads: [
                {
                    sampledMilliseconds: 1.08,
                    self: [
                        { name: 'transform', milliseconds: 1.05 },
                        { name: 'run https://p/worker.js', milliseconds: 0.03 },
                    ],
                    inclusive: [
                        { name: 'run https://p/worker.js', milliseconds: 1.08 },
                        { name: 'transform', milliseconds: 1.05 },
                    ],
                },
                {
                    sampledMilliseconds: 0.4,
                    self: [{ name: '(anonymous)', milliseconds: 0.4 }],
                    inclusive: [{ name: '(anonymous)', milliseconds: 0.4 }],
                },
            ],
        });
    });

    it('ranks only the requested number of functions', () => {
        const summary = summarizeCpuTrace(trace, 1);
        expect(summary.sampledMilliseconds).toBe(1.48);
        expect(summary.self).toEqual([
            { name: 'transform', milliseconds: 1.05 },
        ]);
        expect(summary.inclusive).toEqual([
            { name: 'run https://p/worker.js', milliseconds: 1.08 },
        ]);
    });

    it('summarizes a trace without samples as empty', () => {
        expect(
            summarizeCpuTrace([{ name: 'TracingStartedInBrowser' }], 5),
        ).toEqual({
            sampledMilliseconds: 0,
            self: [],
            inclusive: [],
            threads: [],
        });
    });
});
