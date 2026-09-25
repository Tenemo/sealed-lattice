import { concatenate } from './bytes.js';
import { describe, PublicInputFailure } from './context.js';

// Public records come from an untrusted relay. Every read has an exact upper
// bound checked before the bytes are kept, and every failure leaves the
// participant pending. Owning verifiers decide acceptance.
const transferChunkBytes = 1 << 20;
const networkMilliseconds = 60_000;

export type PublicRelay = Readonly<{
    // The origin of the host that serves this participant's application.
    origin: string;
}>;

const withDeadline = async <Value>(
    controller: AbortController,
    operation: () => Promise<Value>,
): Promise<Value> => {
    const timer = setTimeout(() => controller.abort(), networkMilliseconds);
    try {
        return await operation();
    } finally {
        clearTimeout(timer);
    }
};

// Streams one resource in chunks of at most one mebibyte and returns its
// length. A resource longer than its bound is refused before it is kept.
const streamBounded = async (
    url: string,
    maximum: number,
    accept: (bytes: Uint8Array) => void | Promise<void>,
): Promise<number> => {
    const controller = new AbortController();
    let response: Response;
    try {
        response = await withDeadline(controller, () =>
            fetch(url, { signal: controller.signal, cache: 'no-store' }),
        );
    } catch (error) {
        throw new PublicInputFailure(
            'A public record is unavailable: ' + describe(error),
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
                next = await withDeadline(controller, () => reader.read());
            } catch (error) {
                throw new PublicInputFailure(
                    'A public record was interrupted: ' + describe(error),
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

export const readBounded = async (url: string, maximum: number) => {
    const parts: Uint8Array[] = [];
    await streamBounded(url, maximum, (bytes) => {
        parts.push(bytes.slice());
    });
    return concatenate(...parts);
};

export const streamPublic = (
    relay: PublicRelay,
    name: string,
    maximum: number,
    accept: (bytes: Uint8Array) => void | Promise<void>,
) => streamBounded(relay.origin + '/public/' + name, maximum, accept);

export const readPublic = (relay: PublicRelay, name: string, maximum: number) =>
    readBounded(relay.origin + '/public/' + name, maximum);

// Publishes one record in transfer chunks. The relay keeps the first bytes
// at each offset and accepts only an identical retransmission.
export const publishRecord = async (
    relay: PublicRelay,
    name: string,
    bytes: Uint8Array,
) => {
    for (
        let offset = 0;
        offset < bytes.length || offset === 0;
        offset += transferChunkBytes
    ) {
        const controller = new AbortController();
        let response: Response;
        try {
            response = await withDeadline(controller, () =>
                fetch(
                    relay.origin +
                        '/publish/' +
                        name +
                        '?offset=' +
                        String(offset),
                    {
                        method: 'POST',
                        body: new Blob([
                            new Uint8Array(
                                bytes.subarray(
                                    offset,
                                    offset + transferChunkBytes,
                                ),
                            ),
                        ]),
                        signal: controller.signal,
                    },
                ),
            );
        } catch (error) {
            throw new PublicInputFailure(
                'Public delivery is unavailable: ' + describe(error),
            );
        }
        if (!response.ok)
            throw new PublicInputFailure('Public delivery was refused.');
        if (bytes.length === 0) break;
    }
};
