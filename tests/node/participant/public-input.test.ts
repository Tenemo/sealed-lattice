import { createHash } from 'node:crypto';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { foregroundVisitMilliseconds } from '#packages/sdk/src/participant/worker/bounds.js';
import { PublicInputFailure } from '#packages/sdk/src/participant/worker/failures.js';
import {
    readBounded,
    streamBounded,
} from '#packages/sdk/src/participant/worker/public.js';

const relay = { base: 'https://relay.invalid/' };
const pageBytes = 1 << 20;
const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');
const deferred = () => {
    let complete: () => void;
    const promise = new Promise<void>((resolve) => {
        complete = resolve;
    });
    return { promise, resolve: () => complete() };
};

const response = (
    fragments: Iterable<Uint8Array>,
    headers?: Record<string, string>,
) => {
    const iterator = fragments[Symbol.iterator]();
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
        pull(controller) {
            const next = iterator.next();
            if (next.done) controller.close();
            else controller.enqueue(next.value);
        },
        cancel,
    });
    const fetch = vi.fn(() => Promise.resolve(new Response(body, { headers })));
    vi.stubGlobal('fetch', fetch);
    return { body, cancel, fetch };
};

// A relay that serves one byte each time the reader asks, the delay after
// the request, and errors the body once the request is aborted, as a
// fetch does.
const paced = (count: number, delay: number) => {
    const fetch = vi.fn((_url: string, init?: RequestInit) => {
        let served = 0;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const body = new ReadableStream<Uint8Array>(
            {
                start(controller) {
                    init?.signal?.addEventListener('abort', () => {
                        clearTimeout(timer);
                        controller.error(init.signal?.reason);
                    });
                },
                pull(controller) {
                    if (served === count) {
                        controller.close();
                        return;
                    }
                    return new Promise<void>((resolve) => {
                        timer = setTimeout(() => {
                            served++;
                            controller.enqueue(Uint8Array.of(served));
                            resolve();
                        }, delay);
                    });
                },
            },
            { highWaterMark: 0 },
        );
        return Promise.resolve(new Response(body));
    });
    vi.stubGlobal('fetch', fetch);
};
const fakeClock = () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
};
const outcome = (reading: Promise<number>) =>
    reading.then(
        (length) => length,
        (error: unknown) => error,
    );

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
});

describe('bounded public byte collection', () => {
    it('coalesces more tiny fragments than a spread argument list can hold', async () => {
        const length = 262_145;
        const expected = Uint8Array.from(
            { length },
            (_unused, index) => index % 251,
        );
        const received = response(
            (function* () {
                for (let index = 0; index < length; index++)
                    yield Uint8Array.of(index % 251);
            })(),
        );
        const bytes = await readBounded(relay.base + 'module.wasm', length);
        expect(bytes.length).toBe(length);
        expect(digest(bytes)).toBe(digest(expected));
        expect(bytes.buffer).toBeInstanceOf(ArrayBuffer);
        expect(bytes.byteOffset).toBe(0);
        expect(bytes.buffer.byteLength).toBe(length);
        expect(received.body.locked).toBe(false);
    });

    it('preserves page boundaries and owns the exact returned buffer', async () => {
        const source = Uint8Array.from(
            { length: 2 * pageBytes + 19 },
            (_unused, index) => (index * 17 + 3) % 251,
        );
        const expected = digest(source);
        const received = response([
            source.subarray(0, 3),
            source.subarray(3, pageBytes - 1),
            source.subarray(pageBytes - 1, pageBytes + 7),
            source.subarray(pageBytes + 7),
        ]);
        const bytes = await readBounded(
            relay.base + 'record.bin',
            source.length + 5,
        );
        expect(received.fetch).toHaveBeenCalledWith(
            relay.base + 'record.bin',
            expect.objectContaining({ cache: 'no-store' }),
        );
        expect(bytes.buffer.byteLength).toBe(source.length);
        source.fill(0);
        expect(digest(bytes)).toBe(expected);
    });

    it.each(['1', '9007199254740991'])(
        'uses delivered bytes rather than Content-Length %s',
        async (length) => {
            response([Uint8Array.of(7), Uint8Array.of(8, 9)], {
                'Content-Length': length,
            });
            expect(await readBounded(relay.base, 4)).toEqual(
                Uint8Array.of(7, 8, 9),
            );
        },
    );

    it('accepts an empty bounded body without a page or padded output', async () => {
        response([]);
        const bytes = await readBounded(relay.base, 0);
        expect(bytes.length).toBe(0);
        expect(bytes.buffer.byteLength).toBe(0);
    });

    it('refuses a whole oversized fragment before delivering any part', async () => {
        const received = response([new Uint8Array(5), new Uint8Array(1)]);
        const accept = vi.fn();
        await expect(
            streamBounded(relay.base + 'record.bin', 4, accept),
        ).rejects.toThrow('exceeds its bound');
        expect(accept).not.toHaveBeenCalled();
        expect(received.cancel).toHaveBeenCalledOnce();
        expect(received.body.locked).toBe(false);
    });

    it('refuses excess bytes after an accepted prefix and returns no partial body', async () => {
        const received = response([
            Uint8Array.of(1, 2, 3),
            Uint8Array.of(4, 5),
            Uint8Array.of(6),
        ]);
        await expect(readBounded(relay.base, 4)).rejects.toThrow(
            'exceeds its bound',
        );
        expect(received.cancel).toHaveBeenCalledOnce();
        expect(received.body.locked).toBe(false);
    });

    it.each([-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY])(
        'refuses invalid bound %s before a network request',
        async (maximum) => {
            const received = response([]);
            await expect(readBounded(relay.base, maximum)).rejects.toThrow(
                'invalid bound',
            );
            expect(received.fetch).not.toHaveBeenCalled();
        },
    );

    it('preserves bounded streaming chunks and consumer backpressure', async () => {
        response([new Uint8Array(pageBytes + 3), new Uint8Array(4)]);
        const entered = deferred();
        const released = deferred();
        const lengths: number[] = [];
        const reading = streamBounded(
            relay.base + 'record.bin',
            pageBytes + 7,
            async (bytes) => {
                lengths.push(bytes.length);
                if (lengths.length === 1) {
                    entered.resolve();
                    await released.promise;
                }
            },
        );
        await entered.promise;
        expect(lengths).toEqual([pageBytes]);
        released.resolve();
        expect(await reading).toBe(pageBytes + 7);
        expect(lengths).toEqual([pageBytes, 3, 4]);
    });
});

describe('public record waits', () => {
    it('ends a record whose relay sends each byte just within the minute once its waits reach the foreground visit limit', async () => {
        fakeClock();
        paced(pageBytes, 59_000);
        let accepted = 0;
        let ended = false;
        const reading = outcome(
            streamBounded(relay.base + 'record.bin', pageBytes, (bytes) => {
                accepted += bytes.length;
            }),
        );
        void reading.then(() => {
            ended = true;
        });
        await vi.advanceTimersByTimeAsync(foregroundVisitMilliseconds - 1);
        expect(ended).toBe(false);
        expect(accepted).toBe(15);
        await vi.advanceTimersByTimeAsync(1);
        expect(ended).toBe(true);
        const error = await reading;
        expect(error).toBeInstanceOf(PublicInputFailure);
        expect((error as Error).message).toMatch(
            /^A public record was interrupted: /u,
        );
        expect(accepted).toBe(15);
    });

    it('counts only the waits on the relay against the foreground visit limit, not the consumer work between them', async () => {
        fakeClock();
        paced(14, 59_000);
        let accepted = 0;
        const reading = outcome(
            streamBounded(relay.base + 'record.bin', 14, async () => {
                accepted++;
                await new Promise((resolve) => setTimeout(resolve, 60_000));
            }),
        );
        await vi.advanceTimersByTimeAsync(14 * (59_000 + 60_000));
        expect(await reading).toBe(14);
        expect(accepted).toBe(14);
    });

    it('ends a record whose relay sends nothing for a minute', async () => {
        fakeClock();
        paced(2, 61_000);
        const reading = outcome(
            streamBounded(relay.base + 'record.bin', 2, () => undefined),
        );
        await vi.advanceTimersByTimeAsync(60_000);
        expect(await reading).toBeInstanceOf(PublicInputFailure);
    });
});
