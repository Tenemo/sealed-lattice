import { equalBytes, hexadecimal } from './bytes.js';
import {
    candidateChunkBytes,
    candidateIdentifierBytes,
    candidateManifestBytes,
    candidatePageEntries,
    decodeCandidateManifest,
    decodeCandidatePage,
    decodeCandidateReceipt,
    decodeDiscoveryPage,
    encodeCandidateManifest,
    fillsDiscoveryPage,
    isCandidateId,
    isCandidateKey,
    type CandidateFile,
    type CandidateManifest,
} from './candidate-codec.js';
import { errorMessage } from './context.js';
import type { Delivery } from './delivery.js';
import { PublicInputFailure } from './failures.js';
import { foregroundVisitMilliseconds } from './runtime-bounds.js';

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

// A view only correlates one untrusted manifest and its immutable transport
// locators. It carries no author, byte-identity or proof verification result.
export type CandidateView = Readonly<{
    id: string;
    manifest: () => Promise<CandidateManifest>;
}>;

const publicCandidate = (relay: PublicRelay, id: string): CandidateView => {
    if (!isCandidateId(id))
        throw new PublicInputFailure('Malformed candidate locator.');
    let loaded: Promise<CandidateManifest> | undefined;
    return {
        id,
        manifest: () =>
            (loaded ??= (async () => {
                const bytes = await readBounded(
                    relay.base + 'candidate/' + id,
                    candidateManifestBytes,
                );
                try {
                    return decodeCandidateManifest(bytes);
                } catch {
                    throw new PublicInputFailure(
                        'Malformed candidate manifest.',
                    );
                }
            })()),
    };
};

// One page of a key's candidate discovery list, from the offset.
const readCandidatePage = async (
    relay: PublicRelay,
    key: string,
    offset: number,
) =>
    decodeCandidatePage(
        await readBounded(
            relay.base + 'candidates/' + key + '?offset=' + String(offset),
            12 + candidatePageEntries * candidateIdentifierBytes,
        ),
    );

// Freeze a finite discovery prefix for this operation. Yield each locator before
// fetching its manifest, so a malformed candidate cannot monopolize a round
// of a caller's fair scan across authors. A later operation sees later appends.
export async function* readCandidates(relay: PublicRelay, key: string) {
    if (!isCandidateKey(key)) throw new Error('Invalid candidate key.');
    let offset = 0;
    let end: number | undefined;
    for (;;) {
        let page;
        try {
            page = await readCandidatePage(relay, key, offset);
        } catch (error) {
            if (
                error instanceof PublicInputFailure ||
                error instanceof RangeError
            )
                return;
            throw error;
        }
        end ??= page.total;
        if (
            page.total < end ||
            !fillsDiscoveryPage(
                page.ids.length,
                page.total,
                offset,
                candidatePageEntries,
            )
        )
            return;
        for (const id of page.ids.slice(0, end - offset))
            yield publicCandidate(relay, id);
        offset += page.ids.length;
        if (offset >= end) return;
    }
}

export const findCandidate = async <Value>(
    relay: PublicRelay,
    key: string,
    consume: (candidate: CandidateView) => Promise<Value>,
): Promise<Value> => {
    for await (const candidate of readCandidates(relay, key)) {
        try {
            return await consume(candidate);
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    throw new PublicInputFailure(
        'No valid complete candidate is available: ' + key,
    );
};

export const streamCandidateFile = async (
    relay: PublicRelay,
    candidate: CandidateView,
    name: string,
    maximum: number,
    accept: (bytes: Uint8Array) => void | Promise<void>,
) => {
    const file = (await candidate.manifest()).files.find(
        (entry) => entry.name === name,
    );
    if (
        !Number.isSafeInteger(maximum) ||
        maximum < 0 ||
        file === undefined ||
        file.length > maximum
    )
        throw new PublicInputFailure(
            'A candidate file is missing or exceeds its bound.',
        );
    let remaining = file.length;
    for (const id of file.chunks) {
        const length = Math.min(candidateChunkBytes, remaining);
        const bytes = await readBounded(relay.base + 'chunk/' + id, length);
        if (bytes.length !== length)
            throw new PublicInputFailure('A candidate chunk is incomplete.');
        await accept(bytes);
        remaining -= length;
    }
    return file.length;
};

export const readCandidateFile = async (
    relay: PublicRelay,
    candidate: CandidateView,
    name: string,
    maximum: number,
) => {
    if (!Number.isSafeInteger(maximum) || maximum < 0)
        throw new PublicInputFailure('A candidate file has an invalid bound.');
    let result: Uint8Array | undefined;
    let offset = 0;
    const file = (await candidate.manifest()).files.find(
        (entry) => entry.name === name,
    );
    if (file !== undefined && file.length <= maximum)
        result = new Uint8Array(file.length);
    await streamCandidateFile(relay, candidate, name, maximum, (bytes) => {
        result!.set(bytes, offset);
        offset += bytes.length;
    });
    return result!;
};

type PublicationReader = (
    accept: (bytes: Uint8Array) => Promise<void>,
) => Promise<void>;

// Consume owned source fragments into fixed transport chunks. Sent bytes are
// cleared from the source before an awaited transfer; failure clears its
// remaining fragment as well. A caller retaining bytes passes a copy.
const publicationChunks = async (
    length: number,
    read: PublicationReader,
    emit: (bytes: Uint8Array) => Promise<void>,
) => {
    let buffer: Uint8Array | undefined;
    let used = 0;
    let received = 0;
    const flush = async () => {
        await emit(buffer!.subarray(0, used));
        buffer!.fill(0);
        used = 0;
    };
    try {
        await read(async (bytes) => {
            try {
                if (
                    bytes.length > candidateChunkBytes ||
                    bytes.length > length - received
                )
                    throw new Error(
                        'Publication exceeds its declared length or chunk bound.',
                    );
                if (
                    used === 0 &&
                    (bytes.length === candidateChunkBytes ||
                        received + bytes.length === length)
                ) {
                    received += bytes.length;
                    if (bytes.length > 0) await emit(bytes);
                    return;
                }
                buffer ??= new Uint8Array(
                    Math.min(candidateChunkBytes, length),
                );
                for (let offset = 0; offset < bytes.length;) {
                    const count = Math.min(
                        buffer.length - used,
                        bytes.length - offset,
                    );
                    buffer.set(bytes.subarray(offset, offset + count), used);
                    bytes.fill(0, offset, offset + count);
                    used += count;
                    received += count;
                    offset += count;
                    if (used === buffer.length) await flush();
                }
            } finally {
                bytes.fill(0);
            }
        });
        if (received !== length) throw new Error('Publication is incomplete.');
        if (used > 0) await flush();
    } finally {
        buffer?.fill(0);
    }
};

// Upload immutable chunks first and append the correlated manifest last.
// Every request and named readback is guarded by the original local authority;
// a restart retransmits the same retained bytes without reserving a shared key.
export const createCandidatePublication = (
    relay: PublicRelay,
    key: string,
    delivery: Delivery,
) => {
    if (!isCandidateKey(key)) throw new Error('Invalid candidate key.');
    const files: CandidateFile[] = [];
    let completed = false;
    const checkFile = (name: string, length: number) => {
        if (
            completed ||
            !Number.isSafeInteger(length) ||
            length < 0 ||
            files.some((file) => file.name === name)
        )
            throw new Error('Invalid publication file.');
    };
    const addStream = async (
        name: string,
        length: number,
        read: PublicationReader,
    ) => {
        checkFile(name, length);
        const chunks: string[] = [];
        await publicationChunks(length, read, async (bytes) => {
            await delivery.transfer(async () => {
                const response = await readBounded(
                    relay.base + 'chunks',
                    candidateIdentifierBytes,
                    bytes,
                );
                if (response.length !== candidateIdentifierBytes)
                    throw new PublicInputFailure(
                        'Malformed chunk publication receipt.',
                    );
                const id = hexadecimal(response);
                const stored = await readBounded(
                    relay.base + 'chunk/' + id,
                    bytes.length,
                );
                if (!equalBytes(bytes, stored))
                    throw new PublicInputFailure(
                        'Published chunk readback differs.',
                    );
                chunks.push(id);
            }, bytes);
        });
        files.push({ name, length, chunks });
    };
    return {
        addStream,
        addBytes: (name: string, bytes: Uint8Array) =>
            addStream(name, bytes.length, async (accept) => {
                for (
                    let offset = 0;
                    offset < bytes.length;
                    offset += candidateChunkBytes
                )
                    await accept(
                        bytes.slice(offset, offset + candidateChunkBytes),
                    );
            }),
        // Reuse only locations whose complete contents equal this reader's
        // authenticated retained body. An unverified hint cannot suppress
        // forwarding; if no exact copy is retrievable, upload the same body.
        addRetainedFile: async (
            name: string,
            length: number,
            read: PublicationReader,
            sourceKey: string,
            sourceName: string,
        ) => {
            checkFile(name, length);
            for await (const candidate of readCandidates(relay, sourceKey)) {
                try {
                    const file = (await candidate.manifest()).files.find(
                        (value) => value.name === sourceName,
                    );
                    if (file === undefined || file.length !== length) continue;
                    let index = 0;
                    await publicationChunks(length, read, async (expected) => {
                        const id = file.chunks[index++];
                        await delivery.transfer(async () => {
                            const bytes = await readBounded(
                                relay.base + 'chunk/' + id,
                                expected.length,
                            );
                            if (!equalBytes(bytes, expected))
                                throw new PublicInputFailure(
                                    'A forwarded chunk differs from retained bytes.',
                                );
                        }, expected);
                    });
                    files.push({ name, length, chunks: file.chunks });
                    return;
                } catch (error) {
                    if (!(error instanceof PublicInputFailure)) throw error;
                }
            }
            await addStream(name, length, read);
        },
        finish: async () => {
            if (completed) throw new Error('Publication already completed.');
            const bytes = encodeCandidateManifest({ files });
            await delivery.transfer(async () => {
                let receipt;
                try {
                    receipt = decodeCandidateReceipt(
                        await readBounded(
                            relay.base + 'candidates/' + key,
                            candidateIdentifierBytes + 8,
                            bytes,
                        ),
                    );
                } catch (error) {
                    if (error instanceof RangeError)
                        throw new PublicInputFailure(
                            'Malformed candidate publication receipt.',
                        );
                    throw error;
                }
                const stored = await readBounded(
                    relay.base + 'candidate/' + receipt.id,
                    candidateManifestBytes,
                );
                if (!equalBytes(bytes, stored))
                    throw new PublicInputFailure(
                        'Published manifest readback differs.',
                    );
                let page;
                try {
                    page = await readCandidatePage(relay, key, receipt.index);
                } catch (error) {
                    if (error instanceof RangeError)
                        throw new PublicInputFailure(
                            'Malformed candidate discovery readback.',
                        );
                    throw error;
                }
                if (
                    page.ids[0] !== receipt.id ||
                    page.total <= receipt.index ||
                    !fillsDiscoveryPage(
                        page.ids.length,
                        page.total,
                        receipt.index,
                        candidatePageEntries,
                    )
                )
                    throw new PublicInputFailure(
                        'Published candidate discovery readback differs.',
                    );
            });
            completed = true;
        },
    };
};

const postPublic = async (url: string, bytes: Uint8Array) => {
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
    let page;
    try {
        page = decodeDiscoveryPage(bytes, 64, offerDiscoveryPageEntries);
    } catch (error) {
        if (error instanceof RangeError)
            throw new PublicInputFailure(
                'The offer discovery page is malformed.',
            );
        throw error;
    }
    if (
        !fillsDiscoveryPage(
            page.entries.length,
            page.total,
            offset,
            offerDiscoveryPageEntries,
        )
    )
        throw new PublicInputFailure('The offer discovery page is malformed.');
    return { total: page.total, identities: page.entries };
};
