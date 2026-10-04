import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
    pinBrowserProofChunks,
    serveBoundedBrowserInputs,
} from '#tools/ci/run-seed-sharing-browser.js';
import {
    createBrowserProofReader,
    createBrowserPredecessorReader,
    readBoundedBrowserResponse,
    seedSharingChunkBytes,
} from '#tools/ci/seed-sharing-browser-input.mjs';

const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');
const proofFixture = () => {
    const bytes = Uint8Array.from(
        { length: seedSharingChunkBytes + 17 },
        (_unused, index) => index % 251,
    );
    const chunks = [
        bytes.slice(0, seedSharingChunkBytes),
        bytes.slice(seedSharingChunkBytes),
    ];
    return {
        bytes,
        chunks,
        proof: {
            bytes: bytes.length,
            url: 'https://fixture.invalid/proof/',
            chunks: chunks.map((chunk, index) => ({
                offset: index * seedSharingChunkBytes,
                bytes: chunk.length,
                sha512: digest(chunk),
            })),
        },
    };
};

describe('authenticated browser proof transport', () => {
    it('reads across chunk boundaries with one cache and an independent copy', async () => {
        const fixture = proofFixture();
        const request = vi.fn<typeof fetch>((url) => {
            const address =
                typeof url === 'string'
                    ? url
                    : url instanceof URL
                      ? url.href
                      : url.url;
            const index = Number(address.split('/').pop());
            return Promise.resolve(new Response(fixture.chunks[index]));
        });
        const read = createBrowserProofReader(fixture.proof, request);
        const first = await read(10, 0);
        expect(first).toEqual(fixture.bytes.slice(0, 10));
        first[0] ^= 1;
        expect(await read(10, 0)).toEqual(fixture.bytes.slice(0, 10));
        expect(request).toHaveBeenCalledTimes(1);
        expect(await read(9, seedSharingChunkBytes - 4)).toEqual(
            fixture.bytes.slice(
                seedSharingChunkBytes - 4,
                seedSharingChunkBytes + 5,
            ),
        );
        expect(request).toHaveBeenCalledTimes(2);
        expect(await read(1, 0)).toEqual(fixture.bytes.slice(0, 1));
        expect(request).toHaveBeenCalledTimes(3);
    });

    it('rejects altered bytes before use and refuses out-of-bound reads before transfer', async () => {
        const fixture = proofFixture();
        const changed = fixture.chunks[0].slice();
        changed[17] ^= 1;
        const request = vi.fn<typeof fetch>(() =>
            Promise.resolve(new Response(changed)),
        );
        const read = createBrowserProofReader(fixture.proof, request);
        for (const [length, position] of [
            [0, 0],
            [-1, 0],
            [seedSharingChunkBytes + 1, 0],
            [1, -1],
            [1, fixture.bytes.length],
        ])
            await expect(read(length, position)).rejects.toThrow('outside');
        expect(request).not.toHaveBeenCalled();
        await expect(read(1, 0)).rejects.toThrow('pinned identity');
        expect(request).toHaveBeenCalledOnce();
        const malformed = createBrowserProofReader(
            {
                ...fixture.proof,
                chunks: [{ ...fixture.proof.chunks[0], offset: 1 }],
            },
            request,
        );
        await expect(malformed(1, 0)).rejects.toThrow('inventory');
        expect(request).toHaveBeenCalledOnce();
    });

    it('keeps only the active predecessor cache and clears it before the next proof', async () => {
        const bodies = [
            new Uint8Array([1, 2, 3, 4, 5]),
            new Uint8Array([6, 7, 8, 9, 10]),
        ];
        const predecessors = bodies.map((bytes, index) => ({
            bytes: bytes.length,
            url: 'https://fixture.invalid/predecessor/' + index + '/',
            chunks: [{ offset: 0, bytes: bytes.length, sha512: digest(bytes) }],
        }));
        const request = vi.fn<typeof fetch>((input) => {
            const url =
                typeof input === 'string'
                    ? input
                    : input instanceof URL
                      ? input.href
                      : input.url;
            const index = Number(new URL(url).pathname.split('/')[2]);
            return Promise.resolve(new Response(bodies[index]));
        });
        const reader = createBrowserPredecessorReader(predecessors, request);
        expect(await reader.read(0, 1, 0)).toEqual(new Uint8Array([1]));
        expect(await reader.read(0, 1, 1)).toEqual(new Uint8Array([2]));
        expect(request).toHaveBeenCalledTimes(1);
        expect(await reader.read(1, 1, 0)).toEqual(new Uint8Array([6]));
        expect(await reader.read(0, 1, 0)).toEqual(new Uint8Array([1]));
        expect(request).toHaveBeenCalledTimes(3);
        expect(await reader.read(0, 4, 1)).toEqual(
            new Uint8Array([2, 3, 4, 5]),
        );
        expect(await reader.read(0, 1, 0)).toEqual(new Uint8Array([1]));
        expect(request).toHaveBeenCalledTimes(4);
        reader.release();
        expect(await reader.read(0, 1, 0)).toEqual(new Uint8Array([1]));
        expect(request).toHaveBeenCalledTimes(5);
        await expect(reader.read(2, 1, 0)).rejects.toThrow('index');
        expect(request).toHaveBeenCalledTimes(5);
        const altered = createBrowserPredecessorReader(predecessors, () =>
            Promise.resolve(new Response(bodies[1])),
        );
        await expect(altered.read(0, 1, 0)).rejects.toThrow('pinned identity');
    });

    it('bounds streamed response length independently of HTTP headers', async () => {
        const fragmented = vi.fn<typeof fetch>(() =>
            Promise.resolve(
                new Response(
                    new ReadableStream<Uint8Array>({
                        start(controller) {
                            controller.enqueue(new Uint8Array([1]));
                            controller.enqueue(new Uint8Array([2, 3]));
                            controller.close();
                        },
                    }),
                ),
            ),
        );
        expect(
            await readBoundedBrowserResponse(
                'https://fixture.invalid/',
                3,
                3,
                fragmented,
            ),
        ).toEqual(new Uint8Array([1, 2, 3]));
        for (const body of [
            new Uint8Array([1, 2]),
            new Uint8Array([1, 2, 3, 4]),
        ]) {
            const response = vi.fn<typeof fetch>(() =>
                Promise.resolve(
                    new Response(body, { headers: { 'Content-Length': '3' } }),
                ),
            );
            await expect(
                readBoundedBrowserResponse(
                    'https://fixture.invalid/',
                    3,
                    3,
                    response,
                ),
            ).rejects.toThrow('declared length');
        }
        await expect(
            readBoundedBrowserResponse(
                'https://fixture.invalid/',
                4,
                3,
                fragmented,
            ),
        ).rejects.toThrow('bound');
        expect(fragmented).toHaveBeenCalledOnce();
    });

    it('serves only pinned assets and bounded chunks from its owned local server', async () => {
        await mkdir('temp', { recursive: true });
        const directory = await mkdtemp(
            path.resolve('temp/seed-sharing-browser-input-'),
        );
        const proofFile = path.join(directory, 'proof.data');
        const moduleFile = path.join(directory, 'module.data');
        const predecessorFile = path.join(directory, 'predecessor.data');
        const predecessorBytes = new Uint8Array([9, 8, 7]);
        await writeFile(predecessorFile, predecessorBytes);
        const bytes = new Uint8Array([1, 2, 3, 4, 5]);
        await writeFile(proofFile, bytes);
        await writeFile(moduleFile, bytes);
        let server:
            Awaited<ReturnType<typeof serveBoundedBrowserInputs>> | undefined;
        try {
            const proof = {
                name: 'synthetic',
                file: proofFile,
                bytes: bytes.length,
                sha512: digest(bytes),
            };
            const pinned = await pinBrowserProofChunks(proof);
            expect(pinned.chunks).toEqual([
                { offset: 0, bytes: bytes.length, sha512: proof.sha512 },
            ]);
            await expect(
                pinBrowserProofChunks({ ...proof, sha512: '0'.repeat(128) }),
            ).rejects.toThrow('changed');
            server = await serveBoundedBrowserInputs(
                path.resolve('.'),
                moduleFile,
                [pinned],
                undefined,
                [
                    await pinBrowserProofChunks({
                        name: 'predecessor',
                        file: predecessorFile,
                        bytes: predecessorBytes.length,
                        sha512: digest(predecessorBytes),
                    }),
                ],
            );
            expect(new URL(server.origin).port).not.toBe('80');
            for (const asset of [
                '/public-operator-scalar.mjs',
                '/scalar-module.mjs',
                '/bounded-output.mjs',
            ])
                expect((await fetch(server.origin + asset)).status).toBe(200);
            const response = await fetch(server.origin + '/proof/0/0');
            expect(response.status).toBe(200);
            expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
            const predecessorResponse = await fetch(
                server.origin + '/predecessor/0/0',
            );
            expect(predecessorResponse.status).toBe(200);
            expect(
                new Uint8Array(await predecessorResponse.arrayBuffer()),
            ).toEqual(predecessorBytes);
            for (const route of [
                '/predecessor/1/0',
                '/predecessor/0/1',
                '/proof/0/1',
                '/proof/1/0',
                '/proof/00/0',
                '/proof/0/0?offset=1',
                '/unknown',
            ])
                expect((await fetch(server.origin + route)).status).toBe(404);
            expect(
                (await fetch(server.origin + '/proof/0/0', { method: 'POST' }))
                    .status,
            ).toBe(400);
        } finally {
            await server?.close();
            expect(directory.startsWith(path.resolve('temp') + path.sep)).toBe(
                true,
            );
            await rm(directory, { recursive: true, force: true });
        }
    });
});
