import { mkdir, open, readFile, rename } from 'node:fs/promises';
import path from 'node:path';

import type {
    PublicArchive,
    PublicArchiveStore,
} from '#packages/sdk/src/public-archive.js';
import {
    createTranscriptFileEncoder,
    encodeTranscriptIndex,
    readTranscript,
    transcriptChunkBytes,
    type TranscriptFile,
    type TranscriptLimits,
    type TranscriptSink,
} from '#packages/sdk/src/transcript-archive.js';
import type { ArchiveReference } from '#packages/wasm/src/index.js';

// The files of a verified public closure travel as an archived transcript
// whose routes name them below the ceremony or completion directory. Only
// the owning verifiers, run over the materialized files, accept protocol
// bytes.
export type ArchiveRoute = Readonly<{ route: string; file: string }>;

/** A directory of public archive bytes; every read is checked again. */
export const directoryArchiveStore = async (
    directory: string,
): Promise<PublicArchiveStore> => {
    await mkdir(directory, { recursive: true });
    return {
        get: async (identity) => {
            try {
                return await readFile(path.join(directory, identity));
            } catch (error) {
                if ((error as NodeJS.ErrnoException).code === 'ENOENT')
                    return undefined;
                throw error;
            }
        },
        put: async (identity, bytes) => {
            const file = path.join(directory, identity);
            const handle = await open(file + '.staged', 'w');
            try {
                await handle.writeFile(bytes);
                await handle.sync();
            } finally {
                await handle.close();
            }
            await rename(file + '.staged', file);
        },
    };
};

/**
 * Encodes each routed file, then the transcript's parts and index, into the
 * store. Returns the index, each part with its closure's size, and the number
 * and bytes of the distinct records the store received.
 */
export const encodeArchiveRoutes = async (
    archive: PublicArchive,
    routes: readonly ArchiveRoute[],
    targetBody: Uint8Array,
    store: PublicArchiveStore,
    limits: TranscriptLimits,
) => {
    const stored = new Set<string>();
    const sink: TranscriptSink = async ({ reference, bytes }) => {
        if (stored.has(reference.identity)) return;
        await store.put(reference.identity, bytes);
        stored.add(reference.identity);
    };
    const files: TranscriptFile[] = [];
    for (const { route, file } of routes) {
        const encoder = createTranscriptFileEncoder(archive, route, sink);
        const handle = await open(file, 'r');
        try {
            const buffer = Buffer.alloc(transcriptChunkBytes);
            for (;;) {
                const { bytesRead } = await handle.read(
                    buffer,
                    0,
                    transcriptChunkBytes,
                    null,
                );
                if (bytesRead === 0) break;
                await encoder.write(buffer.subarray(0, bytesRead));
            }
        } finally {
            await handle.close();
        }
        files.push(await encoder.finish());
    }
    return encodeTranscriptIndex(archive, files, targetBody, limits, sink);
};

/**
 * Writes every file of an authenticated index's parts below the directory and
 * returns the routes and the index's target body.
 */
export const materializeArchiveRoutes = (
    archive: PublicArchive,
    index: ArchiveReference,
    store: PublicArchiveStore,
    directory: string,
) =>
    readTranscript(archive, index, store, async (route) => {
        const target = path.join(directory, ...route.split('/'));
        await mkdir(path.dirname(target), { recursive: true });
        const handle = await open(target, 'wx');
        return {
            write: async (bytes) => {
                await handle.write(bytes);
            },
            close: async () => {
                try {
                    await handle.sync();
                } finally {
                    await handle.close();
                }
            },
        };
    });
