import { createPublicKey, sign, type KeyObject } from 'node:crypto';
import {
    mkdir,
    open,
    readFile,
    readdir,
    rename,
    stat,
    unlink,
} from 'node:fs/promises';
import { createServer, type IncomingMessage } from 'node:http';
import path from 'node:path';

import type {
    ArchivePolicy,
    ArchiveReference,
    ProtocolHash,
    PublicArchiveRuntime,
} from '#packages/wasm/src/index.js';
import { isProtocolHash } from '#packages/wasm/src/index.js';

const maximumRecordBytes = 1_572_864;

const body = async (
    request: IncomingMessage,
    maximum: number,
): Promise<Uint8Array> => {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const raw of request) {
        const chunk = Buffer.from(raw as Uint8Array);
        length += chunk.byteLength;
        if (length > maximum)
            throw new RangeError('Archive request exceeds its bound.');
        chunks.push(chunk);
    }
    return Buffer.concat(chunks, length);
};

const isReference = (value: unknown): value is ArchiveReference => {
    if (value === null || typeof value !== 'object') return false;
    const reference = value as Record<string, unknown>;
    return (
        isProtocolHash(reference.identity) &&
        typeof reference.byteLength === 'number' &&
        Number.isSafeInteger(reference.byteLength) &&
        reference.byteLength > 0 &&
        reference.byteLength <= maximumRecordBytes
    );
};

/** Local executable archive host. Distinct directories on this host do not
 * establish independent fault domains. Private replica keys stay with its owner. */
export const startPublicArchiveReplica = async (
    input: Readonly<{
        directory: string;
        context: ProtocolHash;
        policy: ArchivePolicy;
        replicaPosition: number;
        privateKey: KeyObject;
        runtime: PublicArchiveRuntime;
        maximumRecords: number;
        maximumTotalBytes: number;
    }>,
) => {
    const directory = path.resolve(input.directory);
    const context = input.context;
    if (
        !isProtocolHash(context) ||
        !Number.isSafeInteger(input.maximumRecords) ||
        input.maximumRecords < 1 ||
        input.maximumRecords > 65_536 ||
        !Number.isSafeInteger(input.maximumTotalBytes) ||
        input.maximumTotalBytes < 1 ||
        input.maximumTotalBytes > 4_294_967_291
    )
        throw new RangeError('Invalid archive host limits.');
    const key = createPublicKey(input.privateKey)
        .export({ type: 'spki', format: 'der' })
        .subarray(-1952);
    if (
        input.privateKey.asymmetricKeyType !== 'ml-dsa-65' ||
        !key.equals(
            Buffer.from(
                input.policy.verificationKeys[input.replicaPosition] ?? [],
            ),
        )
    )
        throw new Error(
            'Archive private key does not match its configured replica.',
        );
    input.runtime.archiveReceiptMessage(input.policy, context, {
        identity: context,
        byteLength: 1,
    });
    await mkdir(path.join(directory, 'records'), { recursive: true });
    await mkdir(path.join(directory, 'discovery', context), {
        recursive: true,
    });
    const storedLengths = new Map<string, number>();
    let storedBytes = 0;
    for (const name of await readdir(path.join(directory, 'records'))) {
        if (name.endsWith('.staged') && isProtocolHash(name.slice(0, -7))) {
            await unlink(path.join(directory, 'records', name));
            continue;
        }
        if (!isProtocolHash(name))
            throw new Error('Malformed archive storage entry.');
        const length = (await stat(path.join(directory, 'records', name))).size;
        if (
            length > maximumRecordBytes ||
            storedLengths.size >= input.maximumRecords ||
            length > input.maximumTotalBytes - storedBytes
        )
            throw new RangeError('Existing archive exceeds host limits.');
        storedLengths.set(name, length);
        storedBytes += length;
    }
    for (const name of await readdir(
        path.join(directory, 'discovery', context),
    )) {
        if (name.endsWith('.staged') && isProtocolHash(name.slice(0, -7)))
            await unlink(path.join(directory, 'discovery', context, name));
    }
    const readRecord = async (
        reference: ArchiveReference,
    ): Promise<Uint8Array> => {
        const file = path.join(directory, 'records', reference.identity);
        if ((await stat(file)).size !== reference.byteLength)
            throw new Error('Stored archive length does not match.');
        const bytes = await readFile(file);
        input.runtime.readArchiveRecord(context, reference, bytes);
        return bytes;
    };
    // No acknowledgement can precede successful flush and readback. A partial
    // write remains unacknowledged and can be replaced by the identical record.
    const persist = async (file: string, bytes: Uint8Array): Promise<void> => {
        const staged = file + '.staged';
        const handle = await open(staged, 'w');
        try {
            await handle.writeFile(bytes);
            await handle.sync();
        } finally {
            await handle.close();
        }
        if (!(await readFile(staged)).equals(Buffer.from(bytes)))
            throw new Error('Archive readback differs from written bytes.');
        await rename(staged, file);
    };
    const checkClosure = async (root: ArchiveReference): Promise<void> => {
        const seen = new Map<string, number>();
        const pending: ArchiveReference[] = [];
        let total = 0;
        const add = (reference: ArchiveReference): void => {
            const prior = seen.get(reference.identity);
            if (prior !== undefined) {
                if (prior !== reference.byteLength)
                    throw new Error('Conflicting archive lengths.');
                return;
            }
            if (
                seen.size >= input.maximumRecords ||
                reference.byteLength > input.maximumTotalBytes - total
            )
                throw new RangeError('Archive closure exceeds host limits.');
            seen.set(reference.identity, reference.byteLength);
            total += reference.byteLength;
            pending.push(reference);
        };
        add(root);
        for (let index = 0; index < pending.length; index++) {
            const reference = pending[index];
            const record = input.runtime.readArchiveRecord(
                context,
                reference,
                await readRecord(reference),
            );
            for (const dependency of record.dependencies) add(dependency);
        }
    };
    let serial = Promise.resolve();
    const server = createServer((request, response) => {
        const work = async (): Promise<void> => {
            try {
                const url = request.url ?? '';
                const recordMatch = /^\/records\/([a-f0-9]{128})$/u.exec(url);
                if (recordMatch !== null && request.method === 'PUT') {
                    const bytes = await body(request, maximumRecordBytes);
                    input.runtime.readArchiveRecord(
                        context,
                        {
                            identity: recordMatch[1],
                            byteLength: bytes.byteLength,
                        },
                        bytes,
                    );
                    const previousLength =
                        storedLengths.get(recordMatch[1]) ?? 0;
                    if (
                        (!storedLengths.has(recordMatch[1]) &&
                            storedLengths.size >= input.maximumRecords) ||
                        bytes.byteLength - previousLength >
                            input.maximumTotalBytes - storedBytes
                    )
                        throw new RangeError('Archive storage limit reached.');
                    await persist(
                        path.join(directory, 'records', recordMatch[1]),
                        bytes,
                    );
                    storedLengths.set(recordMatch[1], bytes.byteLength);
                    storedBytes += bytes.byteLength - previousLength;
                    response.writeHead(204).end();
                } else if (recordMatch !== null && request.method === 'GET') {
                    const file = path.join(
                        directory,
                        'records',
                        recordMatch[1],
                    );
                    const length = (await stat(file)).size;
                    if (length > maximumRecordBytes)
                        throw new RangeError(
                            'Stored record exceeds its bound.',
                        );
                    const bytes = await readRecord({
                        identity: recordMatch[1],
                        byteLength: length,
                    });
                    response
                        .writeHead(200, {
                            'Content-Type': 'application/octet-stream',
                            'Content-Length': bytes.byteLength,
                        })
                        .end(bytes);
                } else if (url === '/retain' && request.method === 'POST') {
                    const value: unknown = JSON.parse(
                        new TextDecoder('utf-8', { fatal: true }).decode(
                            await body(request, 512),
                        ),
                    );
                    if (value === null || typeof value !== 'object')
                        throw new Error('Malformed archive retention request.');
                    const requestBody = value as Record<string, unknown>;
                    if (
                        requestBody.context !== context ||
                        !isReference(requestBody.root)
                    )
                        throw new Error(
                            'Wrong archive retention context or root.',
                        );
                    const root = requestBody.root;
                    await checkClosure(root);
                    await persist(
                        path.join(
                            directory,
                            'discovery',
                            context,
                            root.identity,
                        ),
                        new TextEncoder().encode(JSON.stringify(root)),
                    );
                    const message = input.runtime.archiveReceiptMessage(
                        input.policy,
                        context,
                        root,
                    );
                    const signature = sign(null, message, {
                        key: input.privateKey,
                        context: Buffer.from(
                            'sealed-lattice/archive-retention/v1',
                        ),
                    });
                    response
                        .writeHead(200, {
                            'Content-Type': 'application/octet-stream',
                            'Content-Length': signature.byteLength,
                        })
                        .end(signature);
                } else if (
                    url === '/discovery/' + context &&
                    request.method === 'GET'
                ) {
                    const names = (
                        await readdir(
                            path.join(directory, 'discovery', context),
                        )
                    ).filter(
                        (name) =>
                            !(
                                name.endsWith('.staged') &&
                                isProtocolHash(name.slice(0, -7))
                            ),
                    );
                    if (names.length > input.maximumRecords)
                        throw new RangeError(
                            'Archive discovery exceeds host limits.',
                        );
                    const roots: ArchiveReference[] = [];
                    for (const name of names) {
                        if (!isProtocolHash(name))
                            throw new Error(
                                'Malformed stored discovery identity.',
                            );
                        const file = path.join(
                            directory,
                            'discovery',
                            context,
                            name,
                        );
                        if ((await stat(file)).size > 512)
                            throw new RangeError(
                                'Stored discovery entry exceeds its bound.',
                            );
                        const root: unknown = JSON.parse(
                            await readFile(file, 'utf8'),
                        );
                        if (!isReference(root) || root.identity !== name)
                            throw new Error('Malformed stored discovery root.');
                        await checkClosure(root);
                        roots.push(root);
                    }
                    response
                        .writeHead(200, { 'Content-Type': 'application/json' })
                        .end(JSON.stringify(roots));
                } else response.writeHead(404).end();
            } catch {
                // Reply with no filesystem, request-body, or credential details.
                response.writeHead(400).end();
            }
        };
        // Serialize writes with retention and readback; an in-flight duplicate
        // cannot truncate an acknowledged record during closure verification.
        serial = serial.then(work);
    });
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (address === null || typeof address === 'string')
        throw new Error('Archive listener has no TCP address.');
    return {
        baseUrl: `http://127.0.0.1:${String(address.port)}/`,
        close: async (): Promise<void> => {
            if (!server.listening) {
                await serial;
                return;
            }
            server.closeAllConnections();
            await new Promise<void>((resolve, reject) => {
                server.close((error) =>
                    error === undefined ? resolve() : reject(error),
                );
            });
            await serial;
        },
    };
};
