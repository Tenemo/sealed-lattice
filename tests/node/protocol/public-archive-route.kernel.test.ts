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
    archiveChunkPurpose,
    archiveRootPurpose,
    encodeArchiveRoutes,
    materializeArchiveRoutes,
} from '#tools/ci/protocol-public-archive.js';

const context = '07'.repeat(64);
const otherContext = '08'.repeat(64);
// The client only encodes and reads records here; no replica is contacted.
const verificationKeys = Array.from({ length: 3 }, () =>
    createPublicKey(generateKeyPairSync('ml-dsa-65').privateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-1952),
);
const client = (archiveContext: string) =>
    createPublicArchive({
        context: archiveContext,
        faultBound: 1,
        replicas: verificationKeys.map((verificationKey, position) => ({
            baseUrl: `http://127.0.0.1:9/replica/${String(position)}/`,
            verificationKey,
        })),
        maximumRecords: 64,
        maximumTotalBytes: 8 << 20,
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

describe('public archive route map through the real scalar kernel', () => {
    it('reproduces every routed file from its authenticated chunks', async () => {
        const { records, store } = memoryStore();
        const encoded = await encodeArchiveRoutes(
            archive,
            routes(),
            Buffer.from('root'),
            store,
        );
        // Four file records, four chunk records and the root.
        expect(encoded.records).toBe(9);
        expect(records.size).toBe(9);
        expect(encoded.byteLength).toBe(
            [...records.values()].reduce(
                (total, bytes) => total + bytes.byteLength,
                0,
            ),
        );
        const target = path.join(directory, 'round-trip');
        const materialized = await materializeArchiveRoutes(
            archive,
            encoded.root,
            store,
            target,
        );
        expect(materialized.routes).toEqual(Object.keys(files).sort());
        expect(Buffer.from(materialized.payload).toString()).toBe('root');
        for (const [route, bytes] of Object.entries(files))
            expect(
                await readFile(path.join(target, ...route.split('/'))),
            ).toEqual(bytes);
    });

    it.each([
        'ceremony/../poll-definition.bin',
        'ceremony/./context.bin',
        'transcript/context.bin',
        'ceremony',
        'ceremony/close/',
    ])('refuses the noncanonical route %s', async (route) => {
        await expect(
            encodeArchiveRoutes(
                archive,
                [{ route, file: routes()[0].file }],
                Buffer.from('root'),
                memoryStore().store,
            ),
        ).rejects.toThrow('canonical');
    });

    it('refuses changed, missing and other-poll records', async () => {
        const { records, store } = memoryStore();
        const encoded = await encodeArchiveRoutes(
            archive,
            routes(),
            Buffer.from('root'),
            store,
        );
        await expect(
            materializeArchiveRoutes(
                await client(otherContext),
                encoded.root,
                store,
                path.join(directory, 'other-context'),
            ),
        ).rejects.toThrow();
        const [identity, bytes] = [...records].find(
            ([key]) => key !== encoded.root.identity,
        )!;
        const changed = Uint8Array.from(bytes);
        changed[changed.length - 1] ^= 1;
        records.set(identity, changed);
        await expect(
            materializeArchiveRoutes(
                archive,
                encoded.root,
                store,
                path.join(directory, 'changed'),
            ),
        ).rejects.toThrow();
        records.delete(identity);
        await expect(
            materializeArchiveRoutes(
                archive,
                encoded.root,
                store,
                path.join(directory, 'missing'),
            ),
        ).rejects.toThrow('missing');
    });

    it('refuses unordered routes, wrong lengths and a foreign root', async () => {
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
        const length = (value: number) => {
            const bytes = Buffer.alloc(8);
            bytes.writeBigUInt64LE(BigInt(value));
            return bytes;
        };
        const chunk = await put(archiveChunkPurpose, [], Buffer.from('abc'));
        const first = await put('ceremony/a.bin', [chunk], length(3));
        const second = await put('ceremony/b.bin', [chunk], length(3));
        const short = await put('ceremony/c.bin', [chunk], length(5));
        for (const [name, root, message] of [
            [
                'unordered',
                await put(archiveRootPurpose, [second, first], Buffer.alloc(0)),
                'ascending',
            ],
            [
                'repeated',
                await put(archiveRootPurpose, [first, first], Buffer.alloc(0)),
                'ascending',
            ],
            [
                'short',
                await put(archiveRootPurpose, [short], Buffer.alloc(0)),
                'length',
            ],
            [
                'foreign',
                await put(
                    'sealed-lattice/other-root/v1',
                    [first],
                    Buffer.alloc(0),
                ),
                'purpose',
            ],
        ] as const)
            await expect(
                materializeArchiveRoutes(
                    archive,
                    root,
                    store,
                    path.join(directory, name),
                ),
            ).rejects.toThrow(message);
    });
});
