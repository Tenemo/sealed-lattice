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
        expect(encoded.parts).toHaveLength(1);
        // Four files, four chunks, one part and the index.
        expect(encoded.records).toBe(10);
        // Another replica is gone; the remaining one serves every record.
        await hosts[0].close();
        const reader = await openArchive(configuration(), poll);
        expect(
            (await discoverTranscripts(reader)).map((index) => index.identity),
        ).toContain(encoded.index.identity);
        const source = await openTranscriptSource(reader, encoded.index);
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
                encoded.index,
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
