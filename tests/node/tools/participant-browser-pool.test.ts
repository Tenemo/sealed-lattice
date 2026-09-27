import { describe, expect, it } from 'vitest';

import { createBrowserPool } from '#tools/ci/participant-browser-pool.js';

const guardBytes = 100;

const deferred = () => {
    let resolve: () => void = () => undefined;
    const promise = new Promise<void>((settle) => {
        resolve = settle;
    });
    return { promise, resolve };
};

type FakeBrowser = Readonly<{
    key: string;
    // Settles once the browser has ended.
    gone: Promise<void>;
    close(): Promise<void>;
    crash(): Promise<void>;
}>;

// A pool of fake browsers that records every launch and ending in order. A
// crash waits for its gate, when one is set for the key.
const fakePool = (
    options: Readonly<{
        browsers: number;
        freeMemory: () => number;
        failLaunch?: (key: string) => boolean;
        failClose?: (key: string) => boolean;
    }>,
) => {
    const events: string[] = [];
    const crashGates = new Map<string, Promise<void>>();
    const pool = createBrowserPool<FakeBrowser>({
        browsers: options.browsers,
        guardBytes,
        freeMemory: options.freeMemory,
        onEndedForRoom: (key) => events.push(`room ${key}`),
    });
    const launch = (key: string) => async () => {
        await Promise.resolve();
        if (options.failLaunch?.(key) === true)
            throw new Error('Chrome startup deadline.');
        events.push(`launch ${key}`);
        const ended = deferred();
        return {
            key,
            gone: ended.promise,
            close: async () => {
                await Promise.resolve();
                events.push(`close ${key}`);
                ended.resolve();
                if (options.failClose?.(key) === true)
                    throw new Error(
                        'Chrome did not close within its deadline.',
                    );
            },
            crash: async () => {
                events.push(`crash ${key}`);
                await crashGates.get(key);
                events.push(`gone ${key}`);
                ended.resolve();
            },
        };
    };
    const use = <Result>(
        key: string,
        action: (browser: FakeBrowser) => Promise<Result>,
    ) => pool.use(key, launch(key), action);
    const visit = (key: string) => use(key, () => Promise.resolve());
    return { pool, events, crashGates, use, visit };
};

const plentifulMemory = () => 100 * guardBytes;

describe('participant browser pool', () => {
    it('keeps a browser open between visits and opens up to the browser count', async () => {
        const { events, visit } = fakePool({
            browsers: 2,
            freeMemory: plentifulMemory,
        });
        await visit('a');
        await visit('a');
        await visit('b');
        expect(events).toEqual(['launch a', 'launch b']);
        // A third browser needs the room of the least recently used one.
        await visit('c');
        await visit('a');
        expect(events).toEqual([
            'launch a',
            'launch b',
            'crash a',
            'gone a',
            'room a',
            'launch c',
            'crash b',
            'gone b',
            'room b',
            'launch a',
        ]);
    });

    it('waits for a busy browser to become idle before ending it', async () => {
        const { events, use, visit } = fakePool({
            browsers: 1,
            freeMemory: plentifulMemory,
        });
        const started = deferred();
        const finish = deferred();
        const busy = use('a', async () => {
            started.resolve();
            await finish.promise;
            return 'done';
        });
        await started.promise;
        const waiting = visit('b');
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(events).toEqual(['launch a']);
        finish.resolve();
        await expect(busy).resolves.toBe('done');
        await waiting;
        expect(events).toEqual([
            'launch a',
            'crash a',
            'gone a',
            'room a',
            'launch b',
        ]);
    });

    it('reserves the growth every open browser has left to its guard', async () => {
        // Free memory for one browser's guard and as much again, with 80
        // bytes to spare.
        const { pool, events, visit } = fakePool({
            browsers: 8,
            freeMemory: () => 2 * guardBytes + 80,
        });
        await visit('a');
        // Unsampled, the open browser may still grow by its whole guard.
        await visit('b');
        expect(events).toEqual([
            'launch a',
            'crash a',
            'gone a',
            'room a',
            'launch b',
        ]);
        // Sampled at 30 bytes, it may grow by 70 more, which fits.
        for (const { key, sampled } of pool.launched())
            if (key === 'b') sampled(30);
        await visit('c');
        expect(events.slice(5)).toEqual(['launch c']);
        // Two browsers' growth no longer fits beside a third.
        await visit('d');
        expect(events.slice(6)).toEqual([
            'crash b',
            'gone b',
            'room b',
            'crash c',
            'gone c',
            'room c',
            'launch d',
        ]);
    });

    it('refuses a browser the host has no room for', async () => {
        const { events, visit } = fakePool({
            browsers: 8,
            freeMemory: () => 2 * guardBytes - 1,
        });
        await expect(visit('a')).rejects.toThrow(
            'Insufficient host memory for a browser.',
        );
        expect(events).toEqual([]);
    });

    it('shares one launch among concurrent users of a key', async () => {
        const { events, use, visit } = fakePool({
            browsers: 1,
            freeMemory: plentifulMemory,
        });
        const finish = deferred();
        const users = [
            use('a', async (browser) => {
                await finish.promise;
                return browser.key;
            }),
            use('a', (browser) => Promise.resolve(browser.key)),
        ];
        await expect(users[1]).resolves.toBe('a');
        // One user still holds the browser, so another key waits.
        const waiting = visit('b');
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(events).toEqual(['launch a']);
        finish.resolve();
        await expect(users[0]).resolves.toBe('a');
        await waiting;
        expect(events).toEqual([
            'launch a',
            'crash a',
            'gone a',
            'room a',
            'launch b',
        ]);
    });

    it('ends a crashed browser completely before reopening its key', async () => {
        const { pool, events, crashGates, use, visit } = fakePool({
            browsers: 4,
            freeMemory: plentifulMemory,
        });
        const started = deferred();
        // The action fails once its browser is gone, as an operation does
        // when its browser crashes.
        const interrupted = use('a', async (browser) => {
            started.resolve();
            await browser.gone;
            throw new Error('The Chrome connection closed.');
        });
        await started.promise;
        const gate = deferred();
        crashGates.set('a', gate.promise);
        const crashing = pool.crash('a');
        const reopened = visit('a');
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(events).toEqual(['launch a', 'crash a']);
        const interruption = interrupted.then(
            () => 'completed',
            (error: unknown) => String(error),
        );
        gate.resolve();
        await crashing;
        expect(await interruption).toContain('connection closed');
        await reopened;
        expect(events).toEqual(['launch a', 'crash a', 'gone a', 'launch a']);
    });

    it('frees the key and room of a browser that fails to launch', async () => {
        let failing = true;
        const { events, visit } = fakePool({
            browsers: 1,
            freeMemory: plentifulMemory,
            failLaunch: () => failing,
        });
        await expect(visit('a')).rejects.toThrow('Chrome startup deadline.');
        failing = false;
        await visit('b');
        await visit('a');
        expect(events).toEqual([
            'launch b',
            'crash b',
            'gone b',
            'room b',
            'launch a',
        ]);
    });

    it('closes every open browser at the end despite a failing close', async () => {
        const { pool, events, visit } = fakePool({
            browsers: 4,
            freeMemory: plentifulMemory,
            failClose: (key) => key === 'a',
        });
        await visit('a');
        await visit('b');
        await pool.closeAll();
        expect(events).toEqual(['launch a', 'launch b', 'close a', 'close b']);
        expect(pool.launched()).toEqual([]);
    });
});
