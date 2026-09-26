import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    createPublicArchive,
    type PublicArchive,
    type PublicArchiveStore,
} from '#packages/sdk/dist/index.js';
import {
    retrieveTranscript,
    transcriptChunkBytes,
    transcriptChunkPurpose,
    transcriptFilePurpose,
    transcriptIndexPurpose,
    transcriptPartPurpose,
} from '#packages/sdk/src/transcript-archive.js';
import {
    encodeArchiveRoutes,
    materializeArchiveRoutes,
} from '#tools/ci/protocol-public-archive.js';

const context = '07'.repeat(64);
const otherContext = '08'.repeat(64);
const limits = { maximumRecords: 64, maximumTotalBytes: 8 << 20 };
// The client only encodes and reads records here, and retrieval finds every
// record already stored; no replica is contacted.
const verificationKeys = Array.from({ length: 3 }, () =>
    createPublicKey(generateKeyPairSync('ml-dsa-65').privateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-1952),
);
const client = (
    archiveContext: string,
    archiveLimits: Readonly<{
        maximumRecords: number;
        maximumTotalBytes: number;
    }> = limits,
) =>
    createPublicArchive({
        context: archiveContext,
        faultBound: 1,
        replicas: verificationKeys.map((verificationKey, position) => ({
            baseUrl: `http://127.0.0.1:9/replica/${String(position)}/`,
            verificationKey,
        })),
        ...archiveLimits,
    });
const memoryStore = () => {
    const records = new Map<string, Uint8Array>();
    const store: PublicArchiveStore = {
        get: (identity) => Promise.resolve(records.get(identity)),
        put: (identity, bytes) => {
            records.set(identity, Uint8Array.from(bytes));
            return Promise.resolve();
        },
    };
    return { records, store };
};

let directory: string;
let archive: PublicArchive;
const files: Record<string, Buffer> = {
    'completion/target.bin': Buffer.from('target'),
    // One byte past a chunk, so the file spans two chunk records.
    'ceremony/contribution-0/polynomial-02.bin': Buffer.alloc(
        (1 << 20) + 1,
        0x5a,
    ),
    'ceremony/close/intent.bin': Buffer.from('intent'),
    // A close without submissions has an empty index.
    'ceremony/close/submissions.txt': Buffer.alloc(0),
};
const routes = () =>
    Object.keys(files).map((route) => ({
        route,
        file: path.join(directory, 'source', ...route.split('/')),
    }));
const expectFiles = async (target: string) => {
    for (const [route, bytes] of Object.entries(files))
        expect(await readFile(path.join(target, ...route.split('/')))).toEqual(
            bytes,
        );
};

beforeAll(async () => {
    directory = await mkdtemp(path.resolve('temp/public-archive-route-'));
    for (const [route, bytes] of Object.entries(files)) {
        const file = path.join(directory, 'source', ...route.split('/'));
        await mkdir(path.dirname(file), { recursive: true });
        await writeFile(file, bytes, { flag: 'wx' });
    }
    archive = await client(context);
});
afterAll(async () => {
    await rm(directory, { recursive: true });
});

describe('archived transcript through the real scalar kernel', () => {
    it('reproduces every routed file from its authenticated chunks', async () => {
        const { records, store } = memoryStore();
        const encoded = await encodeArchiveRoutes(
            archive,
            routes(),
            Buffer.from('target body'),
            store,
            limits,
        );
        // Four file records, four chunk records, one part and the index.
        expect(encoded.parts).toHaveLength(1);
        expect(encoded.parts[0].records).toBe(9);
        expect(encoded.records).toBe(10);
        expect(records.size).toBe(10);
        const storedBytes = (identities: Iterable<string>) =>
            [...identities].reduce(
                (total, identity) => total + records.get(identity)!.byteLength,
                0,
            );
        expect(encoded.byteLength).toBe(storedBytes(records.keys()));
        expect(encoded.parts[0].byteLength).toBe(
            storedBytes(
                [...records.keys()].filter(
                    (identity) => identity !== encoded.index.identity,
                ),
            ),
        );
        expect(await retrieveTranscript(archive, encoded.index, store)).toEqual(
            encoded.parts,
        );
        const target = path.join(directory, 'round-trip');
        const materialized = await materializeArchiveRoutes(
            archive,
            encoded.index,
            store,
            target,
        );
        expect(materialized.routes).toEqual(Object.keys(files).sort());
        expect(Buffer.from(materialized.targetBody).toString()).toBe(
            'target body',
        );
        await expectFiles(target);
        // Another encoding of the same files reaches the same records.
        const again = memoryStore();
        expect(
            (
                await encodeArchiveRoutes(
                    archive,
                    routes().reverse(),
                    Buffer.from('target body'),
                    again.store,
                    limits,
                )
            ).index,
        ).toEqual(encoded.index);
        expect([...again.records.keys()].sort()).toEqual(
            [...records.keys()].sort(),
        );
    });

    it('splits a transcript beyond one retrieval into consecutive parts', async () => {
        // Four records per retrieval: the intent and the empty index with
        // their part, the two-chunk file with its part, and the target
        // with its part.
        const small = { maximumRecords: 4, maximumTotalBytes: 8 << 20 };
        const splitting = await client(context, small);
        const { records, store } = memoryStore();
        const encoded = await encodeArchiveRoutes(
            splitting,
            routes(),
            Buffer.from('target body'),
            store,
            small,
        );
        expect(encoded.parts.map((part) => part.records)).toEqual([4, 4, 3]);
        expect(encoded.records).toBe(records.size);
        expect(encoded.records - 1).toBeGreaterThan(small.maximumRecords);
        // Each part is one retrieval within the limits.
        expect(
            await retrieveTranscript(splitting, encoded.index, store),
        ).toEqual(encoded.parts);
        const target = path.join(directory, 'parts');
        const materialized = await materializeArchiveRoutes(
            splitting,
            encoded.index,
            store,
            target,
        );
        expect(materialized.routes).toEqual(Object.keys(files).sort());
        await expectFiles(target);
        // A file whose own closure exceeds one retrieval is refused.
        await expect(
            encodeArchiveRoutes(
                await client(context, { ...small, maximumRecords: 3 }),
                routes(),
                Buffer.from('target body'),
                memoryStore().store,
                { ...small, maximumRecords: 3 },
            ),
        ).rejects.toThrow('exceeds one retrieval');
    });

    it.each([
        'ceremony/../poll-definition.bin',
        'ceremony/./context.bin',
        '.hidden/context.bin',
        '/ceremony/context.bin',
        'ceremony/close/',
        'ceremony//close',
        'ceremony/' + 'a'.repeat(247),
    ])('refuses the noncanonical route %s', async (route) => {
        await expect(
            encodeArchiveRoutes(
                archive,
                [{ route, file: routes()[0].file }],
                Buffer.from('target body'),
                memoryStore().store,
                limits,
            ),
        ).rejects.toThrow('canonical');
    });

    it('refuses a repeated route', async () => {
        await expect(
            encodeArchiveRoutes(
                archive,
                [...routes(), routes()[0]],
                Buffer.from('target body'),
                memoryStore().store,
                limits,
            ),
        ).rejects.toThrow('repeated');
    });

    it('refuses changed, missing and other-poll records', async () => {
        const { records, store } = memoryStore();
        const encoded = await encodeArchiveRoutes(
            archive,
            routes(),
            Buffer.from('target body'),
            store,
            limits,
        );
        await expect(
            materializeArchiveRoutes(
                await client(otherContext),
                encoded.index,
                store,
                path.join(directory, 'other-context'),
            ),
        ).rejects.toThrow();
        const [identity, bytes] = [...records].find(
            ([key]) =>
                key !== encoded.index.identity &&
                key !== encoded.parts[0].root.identity,
        )!;
        const changed = Uint8Array.from(bytes);
        changed[changed.length - 1] ^= 1;
        records.set(identity, changed);
        await expect(
            materializeArchiveRoutes(
                archive,
                encoded.index,
                store,
                path.join(directory, 'changed'),
            ),
        ).rejects.toThrow();
        records.delete(identity);
        await expect(
            materializeArchiveRoutes(
                archive,
                encoded.index,
                store,
                path.join(directory, 'missing'),
            ),
        ).rejects.toThrow('missing');
    });

    it('refuses malformed files, unordered routes and parts, and foreign roots', async () => {
        const { store } = memoryStore();
        const put = async (
            purpose: string,
            dependencies: Parameters<PublicArchive['encodeRecord']>[1],
            payload: Uint8Array,
        ) => {
            const value = archive.encodeRecord(purpose, dependencies, payload);
            await store.put(value.reference.identity, value.bytes);
            return value.reference;
        };
        const header = (length: number, route: string) => {
            const bytes = Buffer.alloc(8);
            bytes.writeBigUInt64LE(BigInt(length));
            return Buffer.concat([bytes, Buffer.from(route)]);
        };
        const position = (value: number) => {
            const bytes = Buffer.alloc(2);
            bytes.writeUInt16LE(value);
            return bytes;
        };
        const listing = (
            parts: readonly Readonly<{
                identity: string;
                byteLength: number;
            }>[],
        ) => {
            const bytes = Buffer.alloc(2 + parts.length * 72);
            bytes.writeUInt16LE(parts.length);
            for (const [index, part] of parts.entries()) {
                bytes.write(part.identity, 2 + index * 72, 'hex');
                bytes.writeBigUInt64LE(
                    BigInt(part.byteLength),
                    2 + index * 72 + 64,
                );
            }
            return bytes;
        };
        const chunk = await put(transcriptChunkPurpose, [], Buffer.from('abc'));
        const full = await put(
            transcriptChunkPurpose,
            [],
            Buffer.alloc(transcriptChunkBytes, 1),
        );
        const empty = await put(transcriptChunkPurpose, [], Buffer.alloc(0));
        const file = (length: number, route: string, chunks = [chunk]) =>
            put(transcriptFilePurpose, chunks, header(length, route));
        const first = await file(3, 'ceremony/a.bin');
        const second = await file(3, 'ceremony/b.bin');
        const part = async (dependencies: Parameters<typeof put>[1], at = 0) =>
            put(transcriptPartPurpose, dependencies, position(at));
        const index = async (
            parts: Parameters<typeof listing>[0],
            dependencies: Parameters<typeof put>[1] = [],
        ) => put(transcriptIndexPurpose, dependencies, listing(parts));
        const single = async (
            fileReference: Parameters<typeof put>[1][number],
        ) => index([await part([fileReference])]);
        const firstPart = await part([first]);
        const secondPart = await part([second], 1);
        for (const [name, root, message] of [
            [
                'unordered',
                await index([await part([second, first])]),
                'ascending',
            ],
            [
                'repeated',
                await index([await part([first, first])]),
                'ascending',
            ],
            ['short', await single(await file(5, 'ceremony/c.bin')), 'length'],
            ['long', await single(await file(2, 'ceremony/d.bin')), 'length'],
            [
                'unfilled chunk',
                await single(
                    await file(transcriptChunkBytes + 3, 'ceremony/d1.bin', [
                        chunk,
                        full,
                    ]),
                ),
                'length',
            ],
            [
                'extra chunk',
                await single(await file(3, 'ceremony/d2.bin', [chunk, empty])),
                'length',
            ],
            [
                'empty chunk',
                await single(await file(0, 'ceremony/d3.bin', [empty])),
                'length',
            ],
            [
                'routeless',
                await single(
                    await put(transcriptFilePurpose, [chunk], header(3, '')),
                ),
                'malformed',
            ],
            [
                'escaping',
                await single(await file(3, 'ceremony/../e.bin')),
                'canonical',
            ],
            [
                'foreign file',
                await single(
                    await put(
                        'sealed-lattice/other-file/v1',
                        [chunk],
                        header(3, 'ceremony/f.bin'),
                    ),
                ),
                'purpose',
            ],
            [
                'chunk with dependencies',
                await single(
                    await file(3, 'ceremony/g.bin', [
                        await put(
                            transcriptChunkPurpose,
                            [chunk],
                            Buffer.from('abc'),
                        ),
                    ]),
                ),
                'malformed',
            ],
            ['empty part', await index([await part([])]), 'empty'],
            [
                'swapped parts',
                await index([secondPart, firstPart]),
                'another position',
            ],
            [
                'repeated part',
                await index([firstPart, firstPart]),
                'another position',
            ],
            [
                'routes across parts',
                await index([await part([second]), await part([first], 1)]),
                'ascending',
            ],
            ['no parts', await index([]), 'malformed'],
            [
                'index dependencies',
                await index([firstPart], [firstPart]),
                'dependencies',
            ],
            [
                'part as index',
                await put(transcriptPartPurpose, [], listing([firstPart])),
                'purpose',
            ],
            [
                'foreign part',
                await index([
                    await put(
                        'sealed-lattice/other-part/v1',
                        [first],
                        position(0),
                    ),
                ]),
                'purpose',
            ],
            [
                'foreign root',
                await put(
                    'sealed-lattice/other-root/v1',
                    [],
                    listing([firstPart]),
                ),
                'purpose',
            ],
        ] as const) {
            const target = path.join(directory, name.replace(/ /gu, '-'));
            await expect(
                retrieveTranscript(archive, root, store).then(() =>
                    materializeArchiveRoutes(archive, root, store, target),
                ),
            ).rejects.toThrow(message);
        }
    });
});
