import type {
    ArchiveRecord,
    ArchiveReference,
    ProtocolHash,
} from '@sealed-lattice/wasm';

import {
    concatenate,
    fromHexadecimal,
    hexadecimal,
    readUnsigned16,
    readUnsigned64,
    unsigned16,
    unsigned64,
} from './participant/worker/bytes.js';
import type { PublicArchive, PublicArchiveStore } from './public-archive.js';

// An archived transcript carries files under routes. Each file is a record
// whose payload is its length and route and whose dependencies are its
// ordered chunk records, none for an empty file. The file records fill
// consecutive parts in ascending route order, each part a root whose closure
// one retrieval carries, and an index root lists the parts and carries the
// target body. Routes, positions and the index payload are transport labels:
// only the owning verifiers, run over the retrieved files, accept protocol
// bytes.
export const transcriptChunkPurpose = 'sealed-lattice/transcript-chunk/v1';
export const transcriptFilePurpose = 'sealed-lattice/transcript-file/v1';
export const transcriptPartPurpose = 'sealed-lattice/transcript-part/v1';
export const transcriptIndexPurpose = 'sealed-lattice/transcript-index/v1';
export const transcriptChunkBytes = 1_048_576;
const maximumRouteBytes = 255;
const maximumDependencies = 4_096;
// The index lists each part as its raw identity and little-endian length.
const listedPartBytes = 64 + 8;

type EncodedRecord = Readonly<{
    reference: ArchiveReference;
    bytes: Uint8Array;
}>;

/** Receives every record an encoder produces; a record may arrive twice. */
export type TranscriptSink = (record: EncodedRecord) => Promise<void>;

/** The records and bytes one retrieval carries at most. */
export type TranscriptLimits = Readonly<{
    maximumRecords: number;
    maximumTotalBytes: number;
}>;

/** An encoded file with every record of its closure and that record's length. */
export type TranscriptFile = Readonly<{
    route: string;
    reference: ArchiveReference;
    records: ReadonlyMap<ProtocolHash, number>;
}>;

/** A part root with the records and bytes one retrieval of it carries. */
type TranscriptPart = Readonly<{
    root: ArchiveReference;
    records: number;
    byteLength: number;
}>;

/** Receives one file's bytes in order; the file is valid only if reading succeeds. */
type TranscriptFileWriter = Readonly<{
    write(bytes: Uint8Array): Promise<void>;
    close(): Promise<void>;
}>;

// A route is one or more '/'-separated parts of ASCII letters, digits, '_',
// '-' and '.', none starting with a dot, so no route leaves the directory
// that holds it.
const isTranscriptRoute = (route: string): boolean =>
    route.length <= maximumRouteBytes &&
    /^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/u.test(
        route,
    );

const byRoute = (left: string, right: string) =>
    left < right ? -1 : left > right ? 1 : 0;

/**
 * Encodes one file from its bytes in pieces of any length. Every chunk but the
 * last holds exactly one mebibyte, so every encoder of the same route and
 * bytes reaches the same records.
 */
export const createTranscriptFileEncoder = (
    archive: PublicArchive,
    route: string,
    sink: TranscriptSink,
) => {
    if (!isTranscriptRoute(route))
        throw new TypeError('Transcript route is not canonical.');
    const chunks: ArchiveReference[] = [];
    const records = new Map<ProtocolHash, number>();
    // Copies of the written pieces that the next chunk holds.
    let pending: Uint8Array[] = [];
    let filled = 0;
    let length = 0n;
    let finished = false;
    const flush = async () => {
        if (chunks.length === maximumDependencies)
            throw new RangeError('A transcript file exceeds its bound.');
        const chunk = archive.encodeRecord(
            transcriptChunkPurpose,
            [],
            pending.length === 1 ? pending[0] : concatenate(...pending),
        );
        pending = [];
        filled = 0;
        await sink(chunk);
        chunks.push(chunk.reference);
        records.set(chunk.reference.identity, chunk.reference.byteLength);
    };
    return {
        write: async (bytes: Uint8Array): Promise<void> => {
            if (finished) throw new Error('The transcript file is finished.');
            for (let offset = 0; offset < bytes.length;) {
                const taken = Math.min(
                    bytes.length - offset,
                    transcriptChunkBytes - filled,
                );
                pending.push(bytes.slice(offset, offset + taken));
                filled += taken;
                offset += taken;
                length += BigInt(taken);
                if (filled === transcriptChunkBytes) await flush();
            }
        },
        finish: async (): Promise<TranscriptFile> => {
            if (finished) throw new Error('The transcript file is finished.');
            finished = true;
            if (filled > 0) await flush();
            const payload = new Uint8Array(8 + route.length);
            payload.set(unsigned64(length));
            payload.set(new TextEncoder().encode(route), 8);
            const file = archive.encodeRecord(
                transcriptFilePurpose,
                chunks,
                payload,
            );
            await sink(file);
            records.set(file.reference.identity, file.reference.byteLength);
            return { route, reference: file.reference, records };
        },
    };
};

type PartDraft = {
    files: ArchiveReference[];
    records: Map<ProtocolHash, number>;
    byteLength: number;
};

/**
 * Encodes the parts and the index of the files. Each part's closure stays
 * within the limits. Returns the index, each part with its closure's size, and
 * the number and bytes of the transcript's distinct records.
 */
export const encodeTranscriptIndex = async (
    archive: PublicArchive,
    files: readonly TranscriptFile[],
    targetBody: Uint8Array,
    limits: TranscriptLimits,
    sink: TranscriptSink,
) => {
    const ordered = [...files].sort((left, right) =>
        byRoute(left.route, right.route),
    );
    if (
        ordered.length === 0 ||
        ordered.some(
            (file, index) =>
                index > 0 && ordered[index - 1].route === file.route,
        )
    )
        throw new TypeError('Transcript routes are missing or repeated.');
    // No part record is longer than one that lists the most files.
    const partRecordBytes = archive.encodeRecord(
        transcriptPartPurpose,
        Array.from({ length: maximumDependencies }, () => ordered[0].reference),
        unsigned16(0),
    ).bytes.byteLength;
    const fits = (
        part: PartDraft,
        records: ReadonlyMap<ProtocolHash, number>,
    ) => {
        let count = part.records.size + 1;
        let bytes = part.byteLength + partRecordBytes;
        for (const [identity, length] of records)
            if (!part.records.has(identity)) {
                count++;
                bytes += length;
            }
        return (
            part.files.length < maximumDependencies &&
            count <= limits.maximumRecords &&
            bytes <= limits.maximumTotalBytes
        );
    };
    const drafts: PartDraft[] = [];
    for (const file of ordered) {
        let part: PartDraft | undefined = drafts[drafts.length - 1];
        if (part === undefined || !fits(part, file.records)) {
            part = { files: [], records: new Map(), byteLength: 0 };
            if (!fits(part, file.records))
                throw new RangeError(
                    'A transcript file exceeds one retrieval.',
                );
            drafts.push(part);
        }
        part.files.push(file.reference);
        for (const [identity, length] of file.records)
            if (!part.records.has(identity)) {
                part.records.set(identity, length);
                part.byteLength += length;
            }
    }
    if (drafts.length > 0xffff)
        throw new RangeError('The transcript exceeds its part bound.');
    const distinct = new Map<ProtocolHash, number>();
    for (const file of ordered)
        for (const [identity, length] of file.records)
            distinct.set(identity, length);
    const parts: TranscriptPart[] = [];
    for (const [position, draft] of drafts.entries()) {
        const part = archive.encodeRecord(
            transcriptPartPurpose,
            draft.files,
            unsigned16(position),
        );
        await sink(part);
        distinct.set(part.reference.identity, part.reference.byteLength);
        parts.push({
            root: part.reference,
            records: draft.records.size + 1,
            byteLength: draft.byteLength + part.reference.byteLength,
        });
    }
    const payload = new Uint8Array(
        2 + parts.length * listedPartBytes + targetBody.length,
    );
    payload.set(unsigned16(parts.length));
    for (const [position, { root }] of parts.entries()) {
        const offset = 2 + position * listedPartBytes;
        payload.set(fromHexadecimal(root.identity), offset);
        payload.set(unsigned64(BigInt(root.byteLength)), offset + 64);
    }
    payload.set(targetBody, 2 + parts.length * listedPartBytes);
    const index = archive.encodeRecord(transcriptIndexPurpose, [], payload);
    await sink(index);
    distinct.set(index.reference.identity, index.reference.byteLength);
    let byteLength = 0;
    for (const length of distinct.values()) byteLength += length;
    return {
        index: index.reference,
        parts,
        records: distinct.size,
        byteLength,
    };
};

/** The parts an authenticated index lists, in order, and its target body. */
const readTranscriptIndex = (
    archive: PublicArchive,
    index: ArchiveReference,
    bytes: Uint8Array,
) => {
    const record = archive.readRecord(index, bytes);
    if (record.purpose !== transcriptIndexPurpose)
        throw new TypeError('The transcript index has another purpose.');
    if (record.dependencies.length !== 0)
        throw new TypeError('The transcript index has dependencies.');
    const payload = record.payload;
    const count = payload.length < 2 ? 0 : readUnsigned16(payload, 0);
    const end = 2 + count * listedPartBytes;
    if (count === 0 || payload.length < end)
        throw new TypeError('The transcript index is malformed.');
    const parts: ArchiveReference[] = [];
    for (let position = 0; position < count; position++) {
        const offset = 2 + position * listedPartBytes;
        const length = readUnsigned64(payload, offset + 64);
        if (length > BigInt(Number.MAX_SAFE_INTEGER))
            throw new TypeError('The transcript index is malformed.');
        parts.push({
            identity: hexadecimal(payload.subarray(offset, offset + 64)),
            byteLength: Number(length),
        });
    }
    return { parts, targetBody: payload.slice(end) };
};

// The checks a reader applies to a part at its position, to a file record
// and to a chunk before any of its bytes reach a verifier. Every chunk of a
// file is full but its last, which holds the rest, so a file has exactly one
// encoding.
const checkPart = (part: ArchiveRecord, position: number) => {
    if (part.purpose !== transcriptPartPurpose)
        throw new TypeError('A transcript part has another purpose.');
    if (part.dependencies.length === 0)
        throw new TypeError('A transcript part is empty.');
    if (
        part.payload.length !== 2 ||
        readUnsigned16(part.payload, 0) !== position
    )
        throw new TypeError('A transcript part has another position.');
};

const readFileRecord = (file: ArchiveRecord) => {
    if (file.purpose !== transcriptFilePurpose)
        throw new TypeError('A transcript file has another purpose.');
    if (file.payload.length <= 8)
        throw new TypeError('A transcript file is malformed.');
    const route = new TextDecoder('utf-8', { fatal: true }).decode(
        file.payload.subarray(8),
    );
    if (!isTranscriptRoute(route))
        throw new TypeError('Transcript route is not canonical.');
    const length = readUnsigned64(file.payload, 0);
    const chunkBytes = BigInt(transcriptChunkBytes);
    if (
        BigInt(file.dependencies.length) !==
        (length + chunkBytes - 1n) / chunkBytes
    )
        throw new TypeError('A transcript file has another length.');
    return { route, length };
};

const checkChunk = (
    chunk: ArchiveRecord,
    length: bigint,
    count: number,
    position: number,
) => {
    if (
        chunk.purpose !== transcriptChunkPurpose ||
        chunk.dependencies.length !== 0
    )
        throw new TypeError('A transcript chunk is malformed.');
    const expected =
        position < count - 1
            ? BigInt(transcriptChunkBytes)
            : length - BigInt(transcriptChunkBytes) * BigInt(count - 1);
    if (BigInt(chunk.payload.length) !== expected)
        throw new TypeError('A transcript file has another length.');
};

const readStored = async (
    archive: PublicArchive,
    store: PublicArchiveStore,
    reference: ArchiveReference,
) => {
    const bytes = await store.get(reference.identity);
    if (bytes === undefined)
        throw new Error('A retrieved archive record is missing.');
    return archive.readRecord(reference, bytes);
};

/**
 * Retrieves the index and every part it lists into the store, and returns each
 * part with the records and bytes its retrieval carried.
 */
export const retrieveTranscript = async (
    archive: PublicArchive,
    index: ArchiveReference,
    store: PublicArchiveStore,
    signal?: AbortSignal,
): Promise<TranscriptPart[]> => {
    await archive.retrieve(index, store, signal);
    const bytes = await store.get(index.identity);
    if (bytes === undefined)
        throw new Error('A retrieved archive record is missing.');
    const { parts } = readTranscriptIndex(archive, index, bytes);
    const retrieved: TranscriptPart[] = [];
    for (const root of parts) {
        const { recordCount, byteLength } = await archive.retrieve(
            root,
            store,
            signal,
        );
        retrieved.push({ root, records: recordCount, byteLength });
    }
    return retrieved;
};

/**
 * Reads every file of an authenticated index's parts from the store in
 * ascending route order, each through the writer `open` returns for its route.
 * Each record passes the archive decoder for its exact reference and context.
 * Returns the routes and the index's target body.
 */
export const readTranscript = async (
    archive: PublicArchive,
    index: ArchiveReference,
    store: PublicArchiveStore,
    open: (route: string) => Promise<TranscriptFileWriter>,
) => {
    const indexBytes = await store.get(index.identity);
    if (indexBytes === undefined)
        throw new Error('A retrieved archive record is missing.');
    const { parts, targetBody } = readTranscriptIndex(
        archive,
        index,
        indexBytes,
    );
    const routes: string[] = [];
    for (const [position, reference] of parts.entries()) {
        const part = await readStored(archive, store, reference);
        checkPart(part, position);
        for (const fileReference of part.dependencies) {
            const file = await readStored(archive, store, fileReference);
            const { route, length } = readFileRecord(file);
            if (
                routes.length > 0 &&
                byRoute(routes[routes.length - 1], route) >= 0
            )
                throw new TypeError(
                    'Transcript routes are not in ascending order.',
                );
            const writer = await open(route);
            try {
                for (const [
                    chunkPosition,
                    chunkReference,
                ] of file.dependencies.entries()) {
                    const chunk = await readStored(
                        archive,
                        store,
                        chunkReference,
                    );
                    checkChunk(
                        chunk,
                        length,
                        file.dependencies.length,
                        chunkPosition,
                    );
                    await writer.write(chunk.payload);
                }
            } finally {
                await writer.close();
            }
            routes.push(route);
        }
    }
    return { routes, targetBody };
};

/**
 * Opens an authenticated index for reading its files by route. The index,
 * every part and every file record come from the replicas one record at a
 * time, and each file's chunks when the file is read.
 */
export const openTranscript = async (
    archive: PublicArchive,
    index: ArchiveReference,
    signal?: AbortSignal,
) => {
    const { parts, targetBody } = readTranscriptIndex(
        archive,
        index,
        (await archive.fetch(index, signal)).bytes,
    );
    const files = new Map<
        string,
        Readonly<{
            length: bigint;
            chunks: readonly ArchiveReference[];
            reference: ArchiveReference;
        }>
    >();
    let previous: string | undefined;
    for (const [position, reference] of parts.entries()) {
        const { record: part } = await archive.fetch(reference, signal);
        checkPart(part, position);
        for (const fileReference of part.dependencies) {
            const { record: file } = await archive.fetch(fileReference, signal);
            const { route, length } = readFileRecord(file);
            if (previous !== undefined && byRoute(previous, route) >= 0)
                throw new TypeError(
                    'Transcript routes are not in ascending order.',
                );
            previous = route;
            files.set(route, {
                length,
                chunks: file.dependencies,
                reference: fileReference,
            });
        }
    }
    return {
        targetBody,
        // Content references only. Their reuse requires the caller's own
        // authenticated binding to an earlier verified input transcript.
        files: (): readonly TranscriptFile[] =>
            [...files].map(([route, file]) => ({
                route,
                reference: file.reference,
                records: new Map(
                    [file.reference, ...file.chunks].map((reference) => [
                        reference.identity,
                        reference.byteLength,
                    ]),
                ),
            })),
        /** The length a file declares, or nothing when no file has the route. */
        length: (route: string) => files.get(route)?.length,
        /** Passes one file's chunks in order and returns its length. */
        read: async (
            route: string,
            accept: (bytes: Uint8Array) => void | Promise<void>,
        ) => {
            const file = files.get(route);
            if (file === undefined)
                throw new RangeError('The transcript has no such file.');
            for (const [position, reference] of file.chunks.entries()) {
                const { record: chunk } = await archive.fetch(
                    reference,
                    signal,
                );
                checkChunk(chunk, file.length, file.chunks.length, position);
                await accept(chunk.payload);
            }
            return file.length;
        },
    };
};
