import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';

import { describe, expect, it, vi } from 'vitest';

import { serveBoundedBrowserInputs } from '#tools/ci/run-seed-sharing-browser.js';
import {
    emitBrowserOutputChunk,
    seedSharingChunkBytes,
} from '#tools/ci/seed-sharing-browser-input.mjs';
import { createBrowserOutputSink } from '#tools/ci/seed-sharing-browser-sink.js';

const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');
const fixture = async () => {
    await mkdir('temp', { recursive: true });
    const directory = await mkdtemp(path.resolve('temp/browser-proof-sink-'));
    return {
        directory,
        file: path.join(directory, 'proof.data'),
        cleanup: async () => {
            expect(directory.startsWith(path.resolve('temp') + path.sep)).toBe(
                true,
            );
            await rm(directory, { recursive: true, force: true });
        },
    };
};

describe('browser bounded-output sink', () => {
    it('preserves the accepted prefix across invalid chunks and acknowledges completed writes', async () => {
        const files = await fixture();
        const sink = await createBrowserOutputSink(
            files.file,
            6,
            digest(new Uint8Array([1, 2, 3, 4, 5, 6])),
        );
        const first = new Uint8Array([1, 2, 3]);
        const second = new Uint8Array([4, 5, 6]);
        try {
            for (const [index, offset, length, hash, body] of [
                [1, 0, 3, digest(first), first],
                [0, 1, 3, digest(first), first],
                [0, 0, seedSharingChunkBytes + 1, digest(first), first],
                [0, 0, 3, digest(first), first.subarray(0, 2)],
                [0, 0, 2, digest(first), first],
                [0, 0, 3, digest(second), first],
            ] as const)
                await expect(
                    sink.receive(
                        index,
                        offset,
                        length,
                        hash,
                        Readable.from([body]),
                    ),
                ).rejects.toThrow();
            expect((await readFile(files.file)).length).toBe(0);
            expect(
                await sink.receive(
                    0,
                    0,
                    3,
                    digest(first),
                    Readable.from([first]),
                ),
            ).toMatchObject({ sha512: digest(first), nextOffset: 3 });
            expect(new Uint8Array(await readFile(files.file))).toEqual(first);
            await expect(
                sink.receive(0, 0, 3, digest(first), Readable.from([first])),
            ).rejects.toThrow('index');
            expect(() => sink.result()).toThrow('incomplete');
            await sink.receive(
                1,
                3,
                3,
                digest(second),
                Readable.from([second]),
            );
            const expected = new Uint8Array([1, 2, 3, 4, 5, 6]);
            expect(sink.result()).toMatchObject({
                file: files.file,
                bytes: 6,
                sha512: digest(expected),
            });
            expect(new Uint8Array(await readFile(files.file))).toEqual(
                expected,
            );
            await expect(
                sink.receive(
                    2,
                    6,
                    1,
                    digest(first.subarray(0, 1)),
                    Readable.from([first.subarray(0, 1)]),
                ),
            ).rejects.toThrow('bound');
        } finally {
            await sink.close();
            await files.cleanup();
        }
    });

    it('refuses a concurrent upload while an earlier chunk is still arriving', async () => {
        const files = await fixture();
        const sink = await createBrowserOutputSink(
            files.file,
            3,
            digest(new Uint8Array([1, 2, 3])),
        );
        const bytes = new Uint8Array([1, 2, 3]);
        let release: () => void = () => undefined;
        const ready = new Promise<void>((resolve) => {
            release = resolve;
        });
        const body = Readable.from(
            (async function* () {
                await ready;
                yield bytes;
            })(),
        );
        const pending = sink.receive(0, 0, 3, digest(bytes), body);
        try {
            await expect(
                sink.receive(0, 0, 3, digest(bytes), Readable.from([bytes])),
            ).rejects.toThrow('pending');
            release();
            await pending;
            expect(sink.result().bytes).toBe(3);
        } finally {
            release();
            await pending;
            await sink.close();
            await files.cleanup();
        }
    });

    it('waits for an exact HTTP write receipt before allowing the next prover action', async () => {
        const bytes = new Uint8Array([2, 7, 1]);
        const headers = {
            'X-Chunk-Sha512': digest(bytes),
            'X-Chunk-Index': '0',
            'X-Chunk-Offset': '0',
            'X-Chunk-Length': '3',
            'X-Next-Offset': '3',
        };
        let observed: () => void = () => undefined;
        const requested = new Promise<void>((resolve) => {
            observed = resolve;
        });
        let acknowledge: (response: Response) => void = () => undefined;
        const response = new Promise<Response>((resolve) => {
            acknowledge = resolve;
        });
        const request = vi.fn<typeof fetch>(() => {
            observed();
            return response;
        });
        let completed = false;
        const emitted = emitBrowserOutputChunk(
            'https://fixture.invalid/output/',
            0,
            0,
            bytes,
            request,
        ).then((receipt) => {
            completed = true;
            return receipt;
        });
        await requested;
        expect(completed).toBe(false);
        acknowledge(new Response(null, { status: 204, headers }));
        expect(await emitted).toEqual({ index: 0, offset: 0, length: 3 });
        expect(request).toHaveBeenCalledOnce();
        for (const altered of [
            { ...headers, 'X-Chunk-Sha512': '0'.repeat(128) },
            { ...headers, 'X-Chunk-Index': '1' },
            { ...headers, 'X-Chunk-Offset': '1' },
            { ...headers, 'X-Chunk-Length': '2' },
            { ...headers, 'X-Next-Offset': '4' },
            { ...headers, 'X-Chunk-Index': '' },
        ]) {
            const wrong = vi.fn<typeof fetch>(() =>
                Promise.resolve(
                    new Response(null, { status: 204, headers: altered }),
                ),
            );
            await expect(
                emitBrowserOutputChunk(
                    'https://fixture.invalid/output/',
                    0,
                    0,
                    bytes,
                    wrong,
                ),
            ).rejects.toThrow('sink');
        }
    });

    it('serves a real sequential POST sink only for the selected generated artifact', async () => {
        const files = await fixture();
        const moduleFile = path.join(files.directory, 'module.data');
        await writeFile(moduleFile, new Uint8Array([1, 2, 3]));
        let server:
            Awaited<ReturnType<typeof serveBoundedBrowserInputs>> | undefined;
        try {
            server = await serveBoundedBrowserInputs(
                path.resolve('.'),
                moduleFile,
                [],
                {
                    file: files.file,
                    expectedBytes: 5,
                    expectedSha512: digest(new Uint8Array([1, 2, 3, 4, 5])),
                },
            );
            expect(
                await emitBrowserOutputChunk(
                    server.origin + '/output/',
                    0,
                    0,
                    new Uint8Array([1, 2, 3]),
                ),
            ).toEqual({ index: 0, offset: 0, length: 3 });
            expect(() => server!.completedOutput()).toThrow('incomplete');
            expect(
                await emitBrowserOutputChunk(
                    server.origin + '/output/',
                    1,
                    3,
                    new Uint8Array([4, 5]),
                ),
            ).toEqual({ index: 1, offset: 3, length: 2 });
            const expected = new Uint8Array([1, 2, 3, 4, 5]);
            expect(server.completedOutput()).toMatchObject({
                file: files.file,
                bytes: 5,
                sha512: digest(expected),
            });
            expect(server.counters()).toMatchObject({
                receivedUploadPayloadBytes: 5,
                responsePayloadBytes: 0,
            });
            expect(
                new Uint8Array(
                    await (
                        await fetch(server.origin + '/module.wasm')
                    ).arrayBuffer(),
                ),
            ).toEqual(new Uint8Array([1, 2, 3]));
            expect(server.counters()).toMatchObject({
                receivedUploadPayloadBytes: 5,
                responsePayloadBytes: 3,
            });
            expect(new Uint8Array(await readFile(files.file))).toEqual(
                expected,
            );
            await expect(
                emitBrowserOutputChunk(
                    server.origin + '/output/',
                    0,
                    0,
                    new Uint8Array([1, 2, 3]),
                ),
            ).rejects.toThrow('acknowledge');
            expect(server.completedOutput().sha512).toBe(digest(expected));
        } finally {
            await server?.close();
            await files.cleanup();
        }
    });
});
