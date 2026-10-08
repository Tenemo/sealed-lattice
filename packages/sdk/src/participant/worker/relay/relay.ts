import { errorMessage } from '../module/context.js';
import { foregroundVisitMilliseconds } from '../module/runtime-bounds.js';
import { PublicInputFailure } from '../shared/failures.js';

// Public records come from an untrusted relay. Every read has an exact upper
// bound checked before the bytes are kept and ends however the relay paces
// its bytes, and every failure leaves the participant pending. Owning
// verifiers decide acceptance.
export const transferChunkBytes = 1 << 20;
const networkMilliseconds = 60_000;

export type PublicRelay = Readonly<{
    // The relay's base URL, ending with a slash. Immutable chunks and complete
    // manifests have opaque locators; logical keys only discover candidates.
    base: string;
}>;

// Runs one request's waits on the relay: none outlasts a minute, and
// together they never outlast the foreground visit limit. The consumer's own
// work between them is not counted.
const relayWaits = (controller: AbortController) => {
    let waited = 0;
    return async <Value>(operation: () => Promise<Value>): Promise<Value> => {
        const started = performance.now();
        const timer = setTimeout(
            () => controller.abort(),
            Math.min(networkMilliseconds, foregroundVisitMilliseconds - waited),
        );
        try {
            return await operation();
        } finally {
            clearTimeout(timer);
            waited += performance.now() - started;
        }
    };
};

// Streams one resource in chunks of at most one mebibyte and returns its
// length. A resource longer than its bound is refused before it is kept.
export const streamBounded = async (
    url: string,
    maximum: number,
    accept: (bytes: Uint8Array) => void | Promise<void>,
    publication?: Uint8Array,
): Promise<number> => {
    if (!Number.isSafeInteger(maximum) || maximum < 0)
        throw new PublicInputFailure('A public record has an invalid bound.');
    const controller = new AbortController();
    const wait = relayWaits(controller);
    let response: Response;
    try {
        response = await wait(() =>
            fetch(url, {
                signal: controller.signal,
                cache: 'no-store',
                ...(publication === undefined
                    ? {}
                    : {
                          method: 'POST',
                          body: new Blob([new Uint8Array(publication)]),
                      }),
            }),
        );
    } catch (error) {
        throw new PublicInputFailure(
            'A public record is unavailable: ' + errorMessage(error),
        );
    }
    if (!response.ok || response.body === null)
        throw new PublicInputFailure('A public record is unavailable.');
    const reader = response.body.getReader();
    let total = 0;
    try {
        for (;;) {
            let next: ReadableStreamReadResult<Uint8Array>;
            try {
                next = await wait(() => reader.read());
            } catch (error) {
                throw new PublicInputFailure(
                    'A public record was interrupted: ' + errorMessage(error),
                );
            }
            if (next.done) break;
            if (next.value.length > maximum - total)
                throw new PublicInputFailure(
                    'A public record exceeds its bound.',
                );
            for (
                let offset = 0;
                offset < next.value.length;
                offset += transferChunkBytes
            )
                await accept(
                    next.value.subarray(offset, offset + transferChunkBytes),
                );
            total += next.value.length;
        }
    } finally {
        await reader.cancel().catch(() => undefined);
        reader.releaseLock();
    }
    return total;
};

// Network fragmentation does not determine the retained object count. Pages
// are allocated only as bytes arrive, within the caller's trusted bound; the
// returned exact-sized buffer is owned and nonshared.
export const readBounded = async (
    url: string,
    maximum: number,
    publication?: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> => {
    const pages: Uint8Array<ArrayBuffer>[] = [];
    let length = 0;
    let used = 0;
    await streamBounded(
        url,
        maximum,
        (bytes) => {
            for (let offset = 0; offset < bytes.length;) {
                let page = pages[pages.length - 1];
                if (page === undefined || used === page.length) {
                    page = new Uint8Array(
                        Math.min(transferChunkBytes, maximum - length),
                    );
                    pages.push(page);
                    used = 0;
                }
                const count = Math.min(
                    page.length - used,
                    bytes.length - offset,
                );
                page.set(bytes.subarray(offset, offset + count), used);
                offset += count;
                used += count;
                length += count;
            }
        },
        publication,
    );
    if (pages.length === 1 && pages[0].length === length) return pages[0];
    const result = new Uint8Array(length);
    let offset = 0;
    for (const page of pages) {
        const count = Math.min(page.length, length - offset);
        result.set(page.subarray(0, count), offset);
        offset += count;
    }
    return result;
};

export const postPublic = async (url: string, bytes: Uint8Array) => {
    const controller = new AbortController();
    let response: Response;
    try {
        response = await relayWaits(controller)(() =>
            fetch(url, {
                method: 'POST',
                body: new Blob([new Uint8Array(bytes)]),
                signal: controller.signal,
            }),
        );
    } catch (error) {
        throw new PublicInputFailure(
            'Public delivery is unavailable: ' + errorMessage(error),
        );
    }
    if (!response.ok)
        throw new PublicInputFailure('Public delivery was refused.');
};
