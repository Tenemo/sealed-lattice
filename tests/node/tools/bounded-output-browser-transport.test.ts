import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { readBoundedBrowserResponse } from '#tools/ci/bounded-output-browser-transport.mjs';
import { serveBoundedBrowserInputs } from '#tools/ci/bounded-output-browser.js';

const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');

describe('bounded browser transport', () => {
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

    it('serves only pinned assets and the output sink from its owned local server', async () => {
        await mkdir('temp', { recursive: true });
        const directory = await mkdtemp(
            path.resolve('temp/bounded-browser-transport-'),
        );
        const moduleFile = path.join(directory, 'module.data');
        const outputFile = path.join(directory, 'output.data');
        const bytes = new Uint8Array([1, 2, 3, 4, 5]);
        await writeFile(moduleFile, bytes);
        let server:
            Awaited<ReturnType<typeof serveBoundedBrowserInputs>> | undefined;
        try {
            server = await serveBoundedBrowserInputs(
                path.resolve('.'),
                moduleFile,
                {
                    file: outputFile,
                    expectedBytes: bytes.length,
                    expectedSha512: digest(bytes),
                },
            );
            expect(new URL(server.origin).port).not.toBe('80');
            for (const asset of [
                '/bounded-output-browser-worker.mjs',
                '/bounded-output-browser-transport.mjs',
                '/fhe-key-source-scalar.mjs',
                '/scalar-module.mjs',
                '/bounded-output.mjs',
            ])
                expect((await fetch(server.origin + asset)).status).toBe(200);
            const page = await fetch(server.origin + '/');
            expect(page.status).toBe(200);
            expect(await page.text()).toContain(
                "new Worker('/bounded-output-browser-worker.mjs'",
            );
            const module = await fetch(server.origin + '/module.wasm');
            expect(module.headers.get('Content-Type')).toBe('application/wasm');
            expect(new Uint8Array(await module.arrayBuffer())).toEqual(bytes);
            for (const route of [
                '/output/0/0',
                '/proof/0/0',
                '/predecessor/0/0',
                '/bounded-output-sink.mjs',
                '/module.wasm?offset=1',
                '/unknown',
            ])
                expect((await fetch(server.origin + route)).status).toBe(404);
            for (const route of ['/module.wasm', '/output/00/0', '/output/0'])
                expect(
                    (await fetch(server.origin + route, { method: 'POST' }))
                        .status,
                ).toBe(400);
            expect(() => server!.completedOutput()).toThrow('incomplete');
        } finally {
            await server?.close();
            expect(directory.startsWith(path.resolve('temp') + path.sep)).toBe(
                true,
            );
            await rm(directory, { recursive: true, force: true });
        }
    });
});
