import { concatenate, readUnsigned32, readUnsigned64 } from './bytes.js';
import { describe, PublicInputFailure } from './context.js';

// Public records come from an untrusted relay. Every read has an exact upper
// bound checked before the bytes are kept, and every failure leaves the
// participant pending. Owning verifiers decide acceptance.
const transferChunkBytes = 1 << 20;
const networkMilliseconds = 60_000;

export type PublicRelay = Readonly<{
    // The relay's base URL, ending with a slash: it serves each record at
    // public/<name> and accepts publications at publish/<name>.
    base: string;
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
) => streamBounded(relay.base + 'public/' + name, maximum, accept);

export const readPublic = async (
    relay: PublicRelay,
    name: string,
    maximum: number,
) => {
    const parts: Uint8Array[] = [];
    await streamPublic(relay, name, maximum, (bytes) => {
        parts.push(bytes.slice());
    });
    return concatenate(...parts);
};

const postPublic = async (url: string, bytes: Uint8Array) => {
    const controller = new AbortController();
    let response: Response;
    try {
        response = await withDeadline(controller, () =>
            fetch(url, {
                method: 'POST',
                body: new Blob([new Uint8Array(bytes)]),
                signal: controller.signal,
            }),
        );
    } catch (error) {
        throw new PublicInputFailure(
            'Public delivery is unavailable: ' + describe(error),
        );
    }
    if (!response.ok)
        throw new PublicInputFailure('Public delivery was refused.');
};

// Immutable protocol records accept exact retransmission only.
export const publishChunk = async (
    relay: PublicRelay,
    name: string,
    offset: number,
    bytes: Uint8Array,
) => {
    if (bytes.length > transferChunkBytes)
        throw new Error('A publication chunk exceeds its bound.');
    await postPublic(
        relay.base + 'publish/' + name + '?offset=' + String(offset),
        bytes,
    );
};

// Discovery is an append-only list of untrusted body identities. Nobody can
// erase an earlier announcement, and no announcement occupies a selected slot
// until its signed body has passed the complete owning verifier.
export const offerDiscoveryPageEntries = 64;

export const publishOfferAnnouncement = (
    relay: PublicRelay,
    position: number,
    bodyIdentity: Uint8Array,
) => {
    if (bodyIdentity.length !== 64)
        throw new Error('An offer announcement must name one body identity.');
    return postPublic(relay.base + 'offers/' + String(position), bodyIdentity);
};

export const readOfferAnnouncements = async (
    relay: PublicRelay,
    position: number,
    offset: number,
) => {
    if (!Number.isSafeInteger(offset) || offset < 0)
        throw new PublicInputFailure(
            'The offer discovery cursor exceeds its bound.',
        );
    const bytes = await readBounded(
        relay.base + 'offers/' + String(position) + '?offset=' + String(offset),
        12 + offerDiscoveryPageEntries * 64,
    );
    if (bytes.length < 12)
        throw new PublicInputFailure('The offer discovery page is truncated.');
    const total = readUnsigned64(bytes, 0);
    const count = readUnsigned32(bytes, 8);
    if (
        total > BigInt(Number.MAX_SAFE_INTEGER) ||
        count > offerDiscoveryPageEntries ||
        bytes.length !== 12 + count * 64 ||
        count !==
            Math.min(
                offerDiscoveryPageEntries,
                Math.max(0, Number(total) - offset),
            )
    )
        throw new PublicInputFailure('The offer discovery page is malformed.');
    return {
        total: Number(total),
        identities: Array.from({ length: count }, (_, index) =>
            bytes.slice(12 + index * 64, 12 + (index + 1) * 64),
        ),
    };
};

// Publishes one record in transfer chunks.
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
        await publishChunk(
            relay,
            name,
            offset,
            bytes.subarray(offset, offset + transferChunkBytes),
        );
        if (bytes.length === 0) break;
    }
};
