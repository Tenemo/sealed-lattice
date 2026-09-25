import assert from 'node:assert/strict';
import { mkdir, open, readFile, rename } from 'node:fs/promises';
import path from 'node:path';

import type {
    PublicArchive,
    PublicArchiveStore,
} from '#packages/sdk/src/public-archive.js';
import type { ArchiveReference } from '#packages/wasm/src/index.js';

// The route map of a verified public closure. Each dependency route becomes
// one record whose purpose is the route, whose payload is the file length and
// whose dependencies are its ordered chunk records, none for an empty file;
// one root lists the file records in ascending route order. Routes are
// transport labels: only the owning verifiers, run over the materialized
// files, accept protocol bytes.
export const archiveChunkPurpose = 'sealed-lattice/transcript-chunk/v1';
export const archiveRootPurpose = 'sealed-lattice/terminal-dependencies/v1';
const chunkBytes = 1_048_576;
const maximumDependencies = 4_096;

export type ArchiveRoute = Readonly<{ route: string; file: string }>;

// A route names a file below the ceremony or completion directory; no part
// starts with a dot, so none can leave it.
const isRoute = (route: string) =>
    Buffer.byteLength(route) <= 128 &&
    /^(?:ceremony|completion)(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)+$/u.test(route);

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

/** Encodes the routes into the store and returns the root with its bounds. */
export const encodeArchiveRoutes = async (
    archive: PublicArchive,
    routes: readonly ArchiveRoute[],
    rootPayload: Uint8Array,
    store: PublicArchiveStore,
) => {
    const ordered = [...routes].sort((left, right) =>
        left.route < right.route ? -1 : left.route > right.route ? 1 : 0,
    );
    assert.ok(ordered.length > 0 && ordered.length <= maximumDependencies);
    // Retrieval counts each distinct record once, and so does the encoder.
    const identities = new Set<string>();
    let byteLength = 0;
    const put = async (
        encoded: Readonly<{ reference: ArchiveReference; bytes: Uint8Array }>,
    ) => {
        if (!identities.has(encoded.reference.identity)) {
            await store.put(encoded.reference.identity, encoded.bytes);
            identities.add(encoded.reference.identity);
            byteLength += encoded.bytes.byteLength;
        }
        return encoded.reference;
    };
    const files: ArchiveReference[] = [];
    for (const [index, { route, file }] of ordered.entries()) {
        assert.ok(isRoute(route), 'Archive route is not canonical.');
        assert.ok(index === 0 || ordered[index - 1].route !== route);
        const chunks: ArchiveReference[] = [];
        let length = 0;
        const handle = await open(file, 'r');
        try {
            const buffer = Buffer.alloc(chunkBytes);
            for (;;) {
                const { bytesRead } = await handle.read(
                    buffer,
                    0,
                    chunkBytes,
                    length,
                );
                if (bytesRead === 0) break;
                chunks.push(
                    await put(
                        archive.encodeRecord(
                            archiveChunkPurpose,
                            [],
                            buffer.subarray(0, bytesRead),
                        ),
                    ),
                );
                length += bytesRead;
            }
        } finally {
            await handle.close();
        }
        assert.ok(chunks.length <= maximumDependencies);
        const size = Buffer.alloc(8);
        size.writeBigUInt64LE(BigInt(length));
        files.push(await put(archive.encodeRecord(route, chunks, size)));
    }
    const root = await put(
        archive.encodeRecord(archiveRootPurpose, files, rootPayload),
    );
    return { root, records: identities.size, byteLength };
};

/**
 * Writes every file of an authenticated closure below the directory. Each
 * record passes the archive decoder for its exact reference and context.
 */
export const materializeArchiveRoutes = async (
    archive: PublicArchive,
    root: ArchiveReference,
    store: PublicArchiveStore,
    directory: string,
) => {
    const read = async (reference: ArchiveReference) => {
        const bytes = await store.get(reference.identity);
        assert.ok(bytes, 'A retrieved archive record is missing.');
        return archive.readRecord(reference, bytes);
    };
    const top = await read(root);
    assert.equal(
        top.purpose,
        archiveRootPurpose,
        'The archive root has another purpose.',
    );
    const routes: string[] = [];
    for (const reference of top.dependencies) {
        const file = await read(reference);
        const route = file.purpose;
        assert.ok(isRoute(route), 'Archive route is not canonical.');
        assert.ok(
            routes.length === 0 || routes[routes.length - 1] < route,
            'Archive routes are not in ascending order.',
        );
        assert.equal(file.payload.byteLength, 8);
        const length = Buffer.from(file.payload).readBigUInt64LE();
        const target = path.join(directory, ...route.split('/'));
        await mkdir(path.dirname(target), { recursive: true });
        const handle = await open(target, 'wx');
        let written = 0n;
        try {
            for (const chunkReference of file.dependencies) {
                const chunk = await read(chunkReference);
                assert.equal(
                    chunk.purpose,
                    archiveChunkPurpose,
                    'An archive chunk has another purpose.',
                );
                assert.equal(chunk.dependencies.length, 0);
                assert.ok(chunk.payload.byteLength > 0);
                await handle.write(chunk.payload);
                written += BigInt(chunk.payload.byteLength);
            }
            await handle.sync();
        } finally {
            await handle.close();
        }
        assert.equal(written, length, 'Archived file length differs.');
        routes.push(route);
    }
    return { routes, payload: top.payload };
};
