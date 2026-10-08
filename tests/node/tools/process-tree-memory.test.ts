import { spawn } from 'node:child_process';

import { afterEach, describe, expect, it } from 'vitest';

import {
    guardProcessTreeMemory,
    sumProtocolProcessTree,
} from '#tools/ci/process-tree-memory.js';

const children: ReturnType<typeof spawn>[] = [];
// A child that stays alive until the test ends, so the guard samples a real
// process tree.
const spawnIdleChild = () => {
    const child = spawn(
        process.execPath,
        ['-e', 'setInterval(() => undefined, 1000)'],
        { stdio: 'ignore', windowsHide: true },
    );
    children.push(child);
    if (child.pid === undefined) throw new Error('The child did not start.');
    return child.pid;
};

afterEach(() => {
    for (const child of children.splice(0)) child.kill();
});

describe('process-tree memory', () => {
    it('charges descendants independent of enumeration order without charging unrelated processes', () => {
        const rows = [
            { identifier: 4, parent: 3, bytes: 40 },
            { identifier: 8, parent: 1, bytes: 800 },
            { identifier: 3, parent: 2, bytes: 30 },
            { identifier: 2, parent: 1, bytes: 20 },
        ];
        expect(sumProtocolProcessTree(2, rows)).toBe(90);
        expect(sumProtocolProcessTree(2, [...rows].reverse())).toBe(90);
        expect(sumProtocolProcessTree(5, rows)).toBeUndefined();
    });

    it('charges no process that started before the process of its recorded parent identifier, nor its descendants', () => {
        const rows = [
            { identifier: 2, parent: 1, bytes: 20, started: 500 },
            { identifier: 3, parent: 2, bytes: 30, started: 500 },
            { identifier: 4, parent: 3, bytes: 40, started: 900 },
            // An exited process that had the identifier 2 started these.
            { identifier: 7, parent: 2, bytes: 7000, started: 100 },
            { identifier: 9, parent: 7, bytes: 900, started: 499 },
        ];
        expect(sumProtocolProcessTree(2, rows)).toBe(90);
        expect(sumProtocolProcessTree(2, [...rows].reverse())).toBe(90);
        expect(sumProtocolProcessTree(7, rows)).toBe(7900);
    });

    it('reports every sample below the limit until stopped, awaiting each handler', async () => {
        const processIdentifier = spawnIdleChild();
        const samples: number[] = [];
        const aborted: unknown[] = [];
        let handled = 0;
        let sampled: () => void = () => undefined;
        const first = new Promise<void>((resolve) => {
            sampled = resolve;
        });
        const guard = guardProcessTreeMemory({
            processIdentifier,
            memoryLimit: Number.MAX_SAFE_INTEGER,
            exceededMessage: 'The test guard was exceeded.',
            onSample: async (bytes) => {
                samples.push(bytes);
                await Promise.resolve();
                handled++;
                sampled();
            },
            abort: (reason) => aborted.push(reason),
        });
        await first;
        await guard.stop();
        expect(samples.length).toBeGreaterThan(0);
        expect(handled).toBe(samples.length);
        expect(samples.every((bytes) => bytes > 0)).toBe(true);
        expect(aborted).toEqual([]);
    });

    it('aborts with its message once a sample exceeds the limit and samples no more', async () => {
        const processIdentifier = spawnIdleChild();
        const samples: number[] = [];
        const aborted = await new Promise<unknown>((resolve) => {
            guardProcessTreeMemory({
                processIdentifier,
                memoryLimit: 1,
                exceededMessage: 'The test guard was exceeded.',
                onSample: (bytes) => {
                    samples.push(bytes);
                },
                abort: resolve,
            });
        });
        expect(aborted).toBeInstanceOf(Error);
        expect((aborted as Error).message).toBe('The test guard was exceeded.');
        expect(samples).toHaveLength(1);
    });

    it('samples nothing for a process that does not exist and stops cleanly', async () => {
        const samples: number[] = [];
        const aborted: unknown[] = [];
        // No process has the largest positive 32-bit identifier: Windows
        // identifiers are multiples of four and POSIX ones stay below it.
        const guard = guardProcessTreeMemory({
            processIdentifier: 2_147_483_647,
            memoryLimit: 1,
            exceededMessage: 'The test guard was exceeded.',
            onSample: (bytes) => {
                samples.push(bytes);
            },
            abort: (reason) => aborted.push(reason),
        });
        await guard.stop();
        expect(samples).toEqual([]);
        expect(aborted).toEqual([]);
    });
});
