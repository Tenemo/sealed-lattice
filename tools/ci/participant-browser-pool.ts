import assert from 'node:assert/strict';

// Keeps participants' browsers open between their operations while the host
// has room for them. Another browser opens only while fewer than the host's
// browser count are open and the host's free memory, once every open browser
// has grown to its guard, still holds twice the guard: the new browser's
// guard and as much again for the host. Without room, the least recently used idle browser ends
// first, as a crash would, or the opening waits until a browser is idle. A
// browser ends completely before another opens under its key, since both
// would use one profile.
type PooledBrowser = Readonly<{
    close(): Promise<void>;
    crash(): Promise<void>;
}>;

type OpenBrowser<Browser extends PooledBrowser> = {
    readonly browser: Promise<Browser>;
    launched: Browser | undefined;
    ending: Promise<void> | undefined;
    // Actions in flight.
    holds: number;
    // Its latest sampled process-tree bytes.
    bytes: number;
    // The order in which its last action ended.
    idleSince: number;
};

export const createBrowserPool = <Browser extends PooledBrowser>(
    options: Readonly<{
        // The most browsers the host's processors run at once.
        browsers: number;
        guardBytes: number;
        freeMemory: () => number;
        // Reports a browser that ended to make room for another.
        onEndedForRoom: (key: string) => void;
    }>,
) => {
    const open = new Map<string, OpenBrowser<Browser>>();
    let waiting: (() => void)[] = [];
    let actionsEnded = 0;
    const wake = () => {
        const woken = waiting;
        waiting = [];
        for (const resolve of woken) resolve();
    };
    const hasRoom = () =>
        open.size < options.browsers &&
        options.freeMemory() -
            [...open.values()].reduce(
                (total, entry) =>
                    total + Math.max(0, options.guardBytes - entry.bytes),
                0,
            ) >=
            2 * options.guardBytes;
    const end = (key: string, ending: (browser: Browser) => Promise<void>) => {
        const entry = open.get(key);
        if (entry === undefined) return Promise.resolve();
        entry.ending ??= (async () => {
            try {
                const browser = await entry.browser.catch(() => undefined);
                if (browser !== undefined) await ending(browser);
            } finally {
                if (open.get(key) === entry) open.delete(key);
                wake();
            }
        })();
        return entry.ending;
    };
    const acquire = async (key: string, launch: () => Promise<Browser>) => {
        for (;;) {
            const entry = open.get(key);
            if (entry?.ending !== undefined) {
                await entry.ending.catch(() => undefined);
                continue;
            }
            if (entry !== undefined) {
                entry.holds++;
                return entry;
            }
            if (hasRoom()) break;
            let idle: string | undefined;
            let idleSince = Infinity;
            for (const [candidateKey, candidate] of open)
                if (
                    candidate.holds === 0 &&
                    candidate.ending === undefined &&
                    candidate.idleSince < idleSince
                ) {
                    idle = candidateKey;
                    idleSince = candidate.idleSince;
                }
            if (idle !== undefined) {
                await end(idle, (browser) => browser.crash());
                options.onEndedForRoom(idle);
                continue;
            }
            assert.ok(open.size > 0, 'Insufficient host memory for a browser.');
            await new Promise<void>((resolve) => waiting.push(resolve));
        }
        const entry: OpenBrowser<Browser> = {
            browser: launch(),
            launched: undefined,
            ending: undefined,
            holds: 1,
            bytes: 0,
            idleSince: 0,
        };
        open.set(key, entry);
        void entry.browser.then(
            (browser) => {
                entry.launched = browser;
            },
            () => {
                if (open.get(key) === entry && entry.ending === undefined) {
                    open.delete(key);
                    wake();
                }
            },
        );
        return entry;
    };
    return {
        // Runs an action in the browser under a key, opening it first when it
        // is not open.
        use: async <Result>(
            key: string,
            launch: () => Promise<Browser>,
            action: (browser: Browser) => Promise<Result>,
        ) => {
            const entry = await acquire(key, launch);
            try {
                return await action(await entry.browser);
            } finally {
                entry.holds--;
                entry.idleSince = ++actionsEnded;
                wake();
            }
        },
        // Ends the browser under a key at once, as a crash would.
        crash: (key: string) => end(key, (browser) => browser.crash()),
        // Closes the browser under a key, letting it finish its shutdown work.
        close: (key: string) => end(key, (browser) => browser.close()),
        // Closes every browser, ignoring failures, when the run ends.
        closeAll: async () => {
            for (const key of [...open.keys()])
                await end(key, (browser) => browser.close()).catch(
                    () => undefined,
                );
        },
        // The browsers that have launched and not finished ending, each with
        // a record of its sampled process-tree bytes.
        launched: () =>
            [...open].flatMap(([key, entry]) => {
                const browser = entry.launched;
                return browser === undefined
                    ? []
                    : [
                          {
                              key,
                              browser,
                              sampled: (bytes: number) => {
                                  entry.bytes = bytes;
                              },
                          },
                      ];
            }),
    };
};
