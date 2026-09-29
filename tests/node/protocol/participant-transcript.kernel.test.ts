import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PublicInputFailure } from '#packages/sdk/src/participant/worker/context.js';
import {
    createTranscriptRecorder,
    discoverTranscripts,
    openArchive,
    openTranscriptSource,
} from '#packages/sdk/src/participant/worker/transcript.js';
import { transcriptChunkPurpose } from '#packages/sdk/src/transcript-archive.js';
import {
    createFoundationCeremonyRuntimeLoader,
    type FoundationCeremonyRuntime,
} from '#packages/wasm/src/index.js';
import { startPublicArchiveReplica } from '#tools/archive/public-archive-replica.js';

const poll = '07'.repeat(64);
// Fixed public test seeds in the seed-only PKCS#8 encoding used by OpenSSL.
// These keys never authenticate a real archive.
const keys = [4, 5, 6].map((seed) =>
    createPrivateKey({
        key: Buffer.concat([
            Buffer.from('3034020100300b060960864801650304031204228020', 'hex'),
            Buffer.alloc(32, seed),
        ]),
        type: 'pkcs8',
        format: 'der',
    }),
);
const verificationKeys = keys.map((key) =>
    createPublicKey(key)
        .export({ type: 'spki', format: 'der' })
        .subarray(-1952),
);
const kernel = new URL(
    '../../../packages/wasm/dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
// Records a participant's visit reads, some across chunk boundaries.
const records = new Map<string, Buffer>([
    [
        'registration/' + 'ab'.repeat(64) + '/registration-header.bin',
        Buffer.from('header'),
    ],
    ['contribution-0/polynomial-01.bin', Buffer.alloc((1 << 20) + 3, 0x5a)],
    ['close/intent.bin', Buffer.from('intent')],
    ['ballot-1/' + 'cd'.repeat(64) + '/body.bin', Buffer.alloc(0)],
]);

let directory: string;
let runtime: FoundationCeremonyRuntime;
let hosts: Awaited<ReturnType<typeof startPublicArchiveReplica>>[];
let kernelBytes: Buffer;
// The worker fetches the kernel as the application serves it.
const kernelServer = createServer((_request, response) => {
    response
        .writeHead(200, { 'Content-Type': 'application/wasm' })
        .end(kernelBytes);
});
const configuration = () => ({
    faultBound: 1,
    replicas: hosts.map((host, position) => ({
        baseUrl: host.baseUrl,
        verificationKey: verificationKeys[position].toString('hex'),
    })),
    kernel: `http://127.0.0.1:${String((kernelServer.address() as AddressInfo).port)}/sealed-lattice-kernel.wasm`,
    kernelSha256: createHash('sha256').update(kernelBytes).digest('hex'),
});

beforeAll(async () => {
    kernelBytes = await readFile(kernel);
    await new Promise<void>((resolve) => {
        kernelServer.listen(0, '127.0.0.1', resolve);
    });
    runtime = await createFoundationCeremonyRuntimeLoader(kernel, {
        expectedKernelSha256Hex: createHash('sha256')
            .update(kernelBytes)
            .digest('hex'),
    })();
    directory = await mkdtemp(path.resolve('temp/participant-transcript-'));
    hosts = await Promise.all(
        keys.map((privateKey, replicaPosition) =>
            startPublicArchiveReplica({
                directory: path.join(directory, String(replicaPosition)),
                context: poll,
                policy: { faultBound: 1, verificationKeys },
                replicaPosition,
                privateKey,
                runtime,
                maximumRecords: 64,
                maximumTotalBytes: 8 << 20,
                maximumStoredRecords: 64,
                maximumStoredBytes: 8 << 20,
            }),
        ),
    );
});
afterAll(async () => {
    for (const host of hosts) await host.close();
    await new Promise<void>((resolve) => {
        kernelServer.close(() => resolve());
    });
    await rm(directory, { recursive: true });
});

describe('participant transcript through the real scalar kernel and local replicas', () => {
    it('keeps both healthy holders while files are recorded concurrently', async () => {
        const opened = await openArchive(configuration(), poll);
        const firstChunk = opened.archive.encodeRecord(
            transcriptChunkPurpose,
            [],
            Uint8Array.of(7),
        );
        const secondChunk = opened.archive.encodeRecord(
            transcriptChunkPurpose,
            [],
            Uint8Array.of(8),
        );
        const gate = () => {
            let resolve!: () => void;
            const promise = new Promise<void>((ready) => {
                resolve = ready;
            });
            return { promise, resolve };
        };
        const first = gate();
        const second = [gate(), gate()];
        const firstStored = [gate(), gate()];
        const secondStored = gate();
        const recorder = createTranscriptRecorder({
            ...opened,
            replicas: opened.replicas.map((replica, position) => ({
                ...replica,
                store: async (record, signal) => {
                    if (position === 0)
                        throw new Error('One unavailable replica.');
                    if (
                        record.reference.identity ===
                        firstChunk.reference.identity
                    )
                        await first.promise;
                    if (
                        record.reference.identity ===
                        secondChunk.reference.identity
                    )
                        await second[position - 1].promise;
                    const result = await replica.store(record, signal);
                    if (
                        record.reference.identity ===
                        firstChunk.reference.identity
                    )
                        firstStored[position - 1].resolve();
                    if (
                        record.reference.identity ===
                            secondChunk.reference.identity &&
                        position === 1
                    )
                        secondStored.resolve();
                    return result;
                },
            })),
        });
        const firstFile = recorder.open('concurrent-a.bin');
        const secondFile = recorder.open('concurrent-b.bin');
        await firstFile.write(Uint8Array.of(7));
        await secondFile.write(Uint8Array.of(8));
        const finishing = Promise.all([
            firstFile.finish(),
            secondFile.finish(),
        ]).then(
            () => ({ error: undefined }),
            (error: unknown) => ({ error }),
        );
        first.resolve();
        await Promise.all(firstStored.map((value) => value.promise));
        await new Promise<void>((resolve) => setImmediate(resolve));
        second[0].resolve();
        await secondStored.promise;
        await new Promise<void>((resolve) => setImmediate(resolve));
        second[1].resolve();
        expect((await finishing).error).toBeUndefined();
        const archived = await recorder.archive();
        const reader = await openTranscriptSource(opened, archived.transcript);
        for (const [route, expected] of [
            ['concurrent-a.bin', 7],
            ['concurrent-b.bin', 8],
        ] as const) {
            const chunks: Uint8Array[] = [];
            await reader.read(route, 1, (bytes) => {
                chunks.push(bytes);
            });
            expect(Buffer.concat(chunks)).toEqual(Buffer.from([expected]));
        }
    }, 10_000);

    it('cancels an extra silent storage attempt once the complete candidate set holds every record', async () => {
        const opened = await openArchive(configuration(), poll);
        let cancelled = 0;
        const recorder = createTranscriptRecorder({
            ...opened,
            replicas: [
                ...opened.replicas,
                {
                    ...opened.replicas[0],
                    store: (_record, signal) =>
                        new Promise((_resolve, reject) => {
                            signal?.addEventListener(
                                'abort',
                                () => {
                                    cancelled++;
                                    reject(
                                        new Error(
                                            'The extra attempt was cancelled.',
                                        ),
                                    );
                                },
                                { once: true },
                            );
                        }),
                },
            ],
        });
        const file = recorder.open('bounded.bin');
        await file.write(Uint8Array.of(1, 2, 3));
        await file.finish();
        expect(cancelled).toBe(1);
        const archived = await recorder.archive();
        const reader = await openTranscriptSource(opened, archived.transcript);
        const chunks: Uint8Array[] = [];
        await reader.read('bounded.bin', 3, (bytes) => {
            chunks.push(bytes);
        });
        expect(Buffer.concat(chunks)).toEqual(Buffer.from([1, 2, 3]));
    }, 5_000);

    it('archives what a visit reads and serves it back by name from the replicas', async () => {
        // The third replica is down while the visit reads, so it is sent
        // nothing after its first refusal.
        await hosts[2].close();
        const archive = await openArchive(configuration(), poll);
        const recorder = createTranscriptRecorder(archive);
        const read = async (name: string, bytes: Uint8Array) => {
            const file = recorder.open(name);
            // The relay's pieces need not align with chunks.
            for (let offset = 0; offset < bytes.length; offset += 65_537)
                await file.write(bytes.subarray(offset, offset + 65_537));
            await file.finish();
        };
        for (const [name, bytes] of records) await read(name, bytes);
        // A record read twice with the same bytes is one file.
        await read('close/intent.bin', Buffer.from('intent'));
        await expect(
            read('close/intent.bin', Buffer.from('other')),
        ).rejects.toThrow(PublicInputFailure);
        const encoded = await recorder.archive();
        expect(encoded.parts).toBe(1);
        // Four files, four chunks, one part and the index.
        expect(encoded.records).toBe(10);
        const fetchedPurposes: string[] = [];
        const retained = createTranscriptRecorder({
            ...archive,
            archive: {
                ...archive.archive,
                fetch: async (reference, signal) => {
                    const fetched = await archive.archive.fetch(
                        reference,
                        signal,
                    );
                    fetchedPurposes.push(fetched.record.purpose);
                    return fetched;
                },
            },
        });
        await retained.reuse(encoded.transcript);
        const repeated = await retained.archive();
        expect(repeated).toEqual(encoded);
        // Index, part and file metadata suffice to retain the same closure;
        // the service still checks every transitive record before signing.
        expect(fetchedPurposes).toHaveLength(6);
        expect(fetchedPurposes).not.toContain(transcriptChunkPurpose);
        const chunk = archive.archive.encodeRecord(
            transcriptChunkPurpose,
            [],
            Buffer.from('intent'),
        );
        await rm(
            path.join(directory, '1', 'records', chunk.reference.identity),
        );
        await expect(retained.archive()).rejects.toThrow(PublicInputFailure);
        await archive.replicas[1].store(chunk);
        expect(await retained.archive()).toEqual(encoded);
        const changed = retained.open('close/intent.bin');
        await changed.write(Buffer.from('different'));
        await expect(changed.finish()).rejects.toThrow(
            'changed during the visit',
        );
        await expect(
            retained.reuse({
                ...encoded.transcript,
                identity: 'ff'.repeat(64),
            }),
        ).rejects.toThrow(PublicInputFailure);
        // Another replica is gone; the remaining one serves every record.
        await hosts[0].close();
        const reader = await openArchive(configuration(), poll);
        expect(
            (await discoverTranscripts(reader)).map((index) => index.identity),
        ).toContain(encoded.transcript.identity);
        const source = await openTranscriptSource(reader, encoded.transcript);
        for (const [name, bytes] of records) {
            const pieces: Uint8Array[] = [];
            expect(
                await source.read(name, bytes.length, (piece) => {
                    pieces.push(piece.slice());
                }),
            ).toBe(bytes.length);
            expect(Buffer.concat(pieces)).toEqual(bytes);
        }
        await expect(
            source.read('close/response-0.bin', 64, () => undefined),
        ).rejects.toThrow('unavailable');
        await expect(
            source.read('close/intent.bin', 5, () => undefined),
        ).rejects.toThrow('exceeds its bound');
        // A refusal by the consumer keeps its meaning.
        const refusal = new Error('The verifier refused the record.');
        await expect(
            source.read('close/intent.bin', 64, () => {
                throw refusal;
            }),
        ).rejects.toBe(refusal);
        // A reader of another poll refuses the transcript as public input.
        await expect(
            openTranscriptSource(
                await openArchive(configuration(), '08'.repeat(64)),
                encoded.transcript,
            ),
        ).rejects.toThrow(PublicInputFailure);
        // One replica is not more than the fault bound, so no new transcript
        // can be archived.
        const lone = createTranscriptRecorder(reader);
        const file = lone.open('close/intent.bin');
        await file.write(Buffer.from('intent'));
        await expect(file.finish()).rejects.toThrow(
            'Too few archive replicas hold the transcript.',
        );
    });

    it('refuses an archive configuration it cannot use as public input', async () => {
        await expect(
            openArchive({ ...configuration(), faultBound: 2 }, poll),
        ).rejects.toThrow(PublicInputFailure);
        await expect(
            openArchive(
                { ...configuration(), kernelSha256: '00'.repeat(32) },
                poll,
            ),
        ).rejects.toThrow(PublicInputFailure);
    });
});
