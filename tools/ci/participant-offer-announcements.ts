import { mkdir, open, stat } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import path from 'node:path';

import { offerDiscoveryPageEntries } from '#packages/sdk/src/participant/worker/public.js';

const identityBytes = 64;

// Run-owned discovery hints, outside the immutable public-record routes.
// No signature, hash or proof is interpreted by this transport store.
export const participantOfferAnnouncements = (directory: string) => {
    const pending = new Map<number, Promise<void>>();
    const locked = async <Value>(
        position: number,
        action: (file: string) => Promise<Value>,
    ) => {
        if (!Number.isSafeInteger(position) || position < 0)
            throw new Error('Invalid offer announcement position.');
        const previous = pending.get(position);
        let unlock!: () => void;
        const released = new Promise<void>((resolve) => {
            unlock = resolve;
        });
        pending.set(position, released);
        await previous;
        try {
            return await action(
                path.join(directory, String(position) + '.bin'),
            );
        } finally {
            if (pending.get(position) === released) pending.delete(position);
            unlock();
        }
    };
    const size = async (file: string) => {
        const metadata = await stat(file).catch((error: unknown) => {
            if (
                error !== null &&
                typeof error === 'object' &&
                'code' in error &&
                error.code === 'ENOENT'
            )
                return undefined;
            throw error;
        });
        const bytes = metadata?.size ?? 0;
        if (!Number.isSafeInteger(bytes) || bytes % identityBytes !== 0)
            throw new Error('The offer announcement store is incomplete.');
        return bytes;
    };
    const read = async (
        handle: Awaited<ReturnType<typeof open>>,
        output: Buffer,
        offset: number,
    ) => {
        let consumed = 0;
        while (consumed < output.length) {
            const result = await handle.read(
                output,
                consumed,
                output.length - consumed,
                offset + consumed,
            );
            if (result.bytesRead === 0)
                throw new Error('An offer announcement disappeared.');
            consumed += result.bytesRead;
        }
    };
    return {
        append: async (position: number, identity: Uint8Array) => {
            if (identity.length !== identityBytes)
                throw new Error(
                    'An offer announcement must contain one body identity.',
                );
            const value = Buffer.from(identity);
            await locked(position, async (file) => {
                await mkdir(directory, { recursive: true });
                const length = await size(file);
                const handle = await open(file, 'a+');
                try {
                    const previous = Buffer.alloc(identityBytes);
                    for (
                        let offset = 0;
                        offset < length;
                        offset += identityBytes
                    ) {
                        await read(handle, previous, offset);
                        if (previous.equals(value)) return;
                    }
                    await handle.writeFile(value);
                    await handle.sync();
                } finally {
                    await handle.close();
                }
            });
        },
        page: async (position: number, offset: number) => {
            if (!Number.isSafeInteger(offset) || offset < 0)
                throw new Error('Invalid offer announcement cursor.');
            return locked(position, async (file) => {
                const total = (await size(file)) / identityBytes;
                const count = Math.min(
                    offerDiscoveryPageEntries,
                    Math.max(0, total - offset),
                );
                const bytes = Buffer.alloc(12 + count * identityBytes);
                bytes.writeBigUInt64LE(BigInt(total), 0);
                bytes.writeUInt32LE(count, 8);
                if (count !== 0) {
                    const handle = await open(file, 'r');
                    try {
                        await read(
                            handle,
                            bytes.subarray(12),
                            offset * identityBytes,
                        );
                    } finally {
                        await handle.close();
                    }
                }
                return bytes;
            });
        },
    };
};

// Public discovery accepts hints from every origin and performs no author
// authentication. The actual signed offer verifier owns that decision.
export const serveOfferAnnouncements = async (
    store: ReturnType<typeof participantOfferAnnouncements>,
    participants: number,
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
): Promise<Readonly<{ route: string; bytes: number }> | undefined> => {
    response.setHeader('Access-Control-Allow-Origin', '*');
    const invalid = () => {
        response.writeHead(400);
        response.end();
    };
    const route = /^\/offers\/(0|[1-9]\d*)$/u.exec(url.pathname);
    const position = route === null ? -1 : Number(route[1]);
    if (
        !Number.isSafeInteger(position) ||
        position < 0 ||
        position >= participants
    ) {
        invalid();
        return undefined;
    }
    if (request.method === 'POST' && url.search === '') {
        const chunks: Buffer[] = [];
        let length = 0;
        for await (const chunk of request as AsyncIterable<Buffer>) {
            length += chunk.length;
            if (length <= identityBytes) chunks.push(chunk);
        }
        if (length !== identityBytes) {
            invalid();
            return undefined;
        }
        await store.append(position, Buffer.concat(chunks));
        response.writeHead(204);
        response.end();
        return undefined;
    }
    const offset = url.searchParams.get('offset');
    if (
        request.method !== 'GET' ||
        offset === null ||
        !/^(0|[1-9]\d*)$/u.test(offset) ||
        !Number.isSafeInteger(Number(offset)) ||
        [...url.searchParams].length !== 1
    ) {
        invalid();
        return undefined;
    }
    const bytes = await store.page(position, Number(offset));
    response.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Cache-Control': 'no-store',
    });
    response.end(bytes);
    return { route: url.pathname.slice(1) + url.search, bytes: bytes.length };
};
