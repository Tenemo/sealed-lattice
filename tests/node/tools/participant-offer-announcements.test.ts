import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';

import { expect, it } from 'vitest';

import { readOfferAnnouncements } from '#packages/sdk/src/participant/worker/relay/offer-discovery.js';
import {
    participantOfferAnnouncements,
    serveOfferAnnouncements,
} from '#tools/ci/participant-offer-announcements.js';

it('preserves concurrent untrusted announcements, deduplicates retries and paginates in insertion order', async () => {
    const scratch = path.resolve('temp');
    await mkdir(scratch, { recursive: true });
    const directory = await mkdtemp(path.join(scratch, 'offer-announcements-'));
    try {
        const store = participantOfferAnnouncements(directory);
        const identity = (number: number) => {
            const bytes = Buffer.alloc(64, 17);
            bytes.writeUInt32LE(number);
            return bytes;
        };
        expect(await store.page(2, 0)).toEqual(Buffer.alloc(12));
        // A malformed hint remains first; a different caller's later valid
        // hint is appended rather than replacing it or being locked out.
        await store.append(2, identity(999));
        await Promise.all(
            Array.from({ length: 70 }, (_, index) =>
                store.append(2, identity(index)),
            ),
        );
        await Promise.all(
            Array.from({ length: 20 }, () => store.append(2, identity(4))),
        );
        const first = await store.page(2, 0),
            second = await store.page(2, 64);
        expect(first.length).toBe(12 + 64 * 64);
        expect(first.readUInt32LE(8)).toBe(64);
        expect(first.readBigUInt64LE(0)).toBe(71n);
        expect(second.readUInt32LE(8)).toBe(7);
        expect(second.length).toBe(12 + 7 * 64);
        expect(
            Buffer.concat([first.subarray(12), second.subarray(12)]),
        ).toEqual(
            Buffer.concat([
                identity(999),
                ...Array.from({ length: 70 }, (_, index) => identity(index)),
            ]),
        );
        expect((await store.page(2, 71)).readUInt32LE(8)).toBe(0);
        expect((await store.page(2, 71)).readBigUInt64LE(0)).toBe(71n);
        expect(
            (await store.page(2, Number.MAX_SAFE_INTEGER)).readUInt32LE(8),
        ).toBe(0);
        expect(await store.page(1, 0)).toEqual(Buffer.alloc(12));
        const before = await readFile(path.join(directory, '2.bin'));
        for (const wrong of [
            Buffer.alloc(0),
            Buffer.alloc(63),
            Buffer.alloc(65),
        ])
            await expect(store.append(2, wrong)).rejects.toThrow(
                'one body identity',
            );
        for (const offset of [-1, 0.5, NaN])
            await expect(store.page(2, offset)).rejects.toThrow('cursor');
        await expect(store.append(-1, identity(1))).rejects.toThrow('position');
        expect(await readFile(path.join(directory, '2.bin'))).toEqual(before);
        const reopened = participantOfferAnnouncements(directory);
        await reopened.append(2, identity(0));
        expect(await reopened.page(2, 64)).toEqual(second);
    } finally {
        await rm(directory, { recursive: true });
    }
});

it('accepts cross-origin hints over HTTP and rejects malformed discovery pages in the real reader', async () => {
    const scratch = path.resolve('temp');
    await mkdir(scratch, { recursive: true });
    const directory = await mkdtemp(
        path.join(scratch, 'offer-discovery-http-'),
    );
    const store = participantOfferAnnouncements(directory);
    let malformed = Buffer.alloc(0);
    const server = createServer((request, response) => {
        const url = new URL(request.url ?? '/', 'http://localhost');
        if (url.pathname.startsWith('/malformed/')) {
            response.end(malformed);
            return;
        }
        void serveOfferAnnouncements(store, 4, request, response, url).catch(
            () => {
                response.writeHead(500);
                response.end();
            },
        );
    });
    try {
        await new Promise<void>((resolve) =>
            server.listen(0, '127.0.0.1', resolve),
        );
        const base = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}/`;
        const first = Buffer.alloc(64, 5),
            later = Buffer.alloc(64, 7);
        const append = (origin: string, body: Buffer) =>
            fetch(base + 'offers/2', {
                method: 'POST',
                headers: { Origin: origin },
                body: new Uint8Array(body),
            });
        expect(
            (await append('https://untrusted-first.example', first)).status,
        ).toBe(204);
        expect(
            (await append('https://original-author.example', later)).status,
        ).toBe(204);
        const retries = await Promise.all([
            append('https://another.example', first),
            append('https://original-author.example', later),
        ]);
        expect(retries.map((response) => response.status)).toEqual([204, 204]);
        expect(await readOfferAnnouncements({ base }, 2, 0)).toEqual({
            total: 2,
            identities: [new Uint8Array(first), new Uint8Array(later)],
        });
        expect(await readOfferAnnouncements({ base }, 1, 0)).toEqual({
            total: 0,
            identities: [],
        });
        expect(
            (await append('https://untrusted-first.example', Buffer.alloc(63)))
                .status,
        ).toBe(400);
        expect(
            (await append('https://untrusted-first.example', Buffer.alloc(65)))
                .status,
        ).toBe(400);
        for (const query of [
            'offset=-1',
            'offset=01',
            'offset=1.5',
            'offset=0&offset=1',
            'offset=0&extra=1',
        ])
            expect((await fetch(base + 'offers/2?' + query)).status).toBe(400);
        const wrongCount = Buffer.alloc(12);
        wrongCount.writeBigUInt64LE(65n);
        wrongCount.writeUInt32LE(65, 8);
        const truncated = Buffer.alloc(12 + 63);
        truncated.writeBigUInt64LE(1n);
        truncated.writeUInt32LE(1, 8);
        const trailing = Buffer.alloc(12 + 65);
        trailing.writeBigUInt64LE(1n);
        trailing.writeUInt32LE(1, 8);
        const unsafeTotal = Buffer.alloc(12);
        unsafeTotal.writeBigUInt64LE(BigInt(Number.MAX_SAFE_INTEGER) + 1n);
        const contradictory = Buffer.alloc(12 + 64);
        contradictory.writeUInt32LE(1, 8);
        for (const bytes of [
            Buffer.alloc(11),
            wrongCount,
            truncated,
            trailing,
            unsafeTotal,
            contradictory,
            Buffer.alloc(12 + 65 * 64),
        ]) {
            malformed = bytes;
            await expect(
                readOfferAnnouncements({ base: base + 'malformed/' }, 2, 0),
            ).rejects.toThrow();
        }
        expect(await readOfferAnnouncements({ base }, 2, 0)).toEqual({
            total: 2,
            identities: [new Uint8Array(first), new Uint8Array(later)],
        });
    } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
        );
        await rm(directory, { recursive: true });
    }
});
