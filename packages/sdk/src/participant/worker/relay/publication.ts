import { equalBytes, hexadecimal } from '../shared/bytes.js';
import { PublicInputFailure } from '../shared/failures.js';
import type { Delivery } from '../storage/delivery.js';

import {
    candidateChunkBytes,
    candidateIdentifierBytes,
    candidateManifestBytes,
    candidatePageEntries,
    decodeCandidateReceipt,
    encodeCandidateManifest,
    fillsDiscoveryPage,
    isCandidateKey,
    type CandidateFile,
} from './candidate-codec.js';
import { readCandidatePage, readCandidates } from './candidates.js';
import { readBounded } from './relay.js';
import type { PublicRelay } from './relay.js';

// A candidate's publication: its files' immutable chunks, then its manifest,
// each read back from the relay.

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
