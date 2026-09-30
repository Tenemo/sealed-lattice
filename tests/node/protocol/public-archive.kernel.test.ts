import {
    createHash,
    createPrivateKey,
    createPublicKey,
    sign,
    verify,
} from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    readFile,
    realpath,
    rm,
    rmdir,
    unlink,
    writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

import { beforeAll, describe, expect, it, vi } from 'vitest';

import { createPublicArchive } from '#packages/sdk/dist/index.js';
import { openPublicArchive } from '#packages/sdk/src/public-archive.js';
import type { PublicArchiveStore } from '#packages/sdk/src/public-archive.js';
import {
    createFoundationCeremonyRuntimeLoader,
    FoundationKernelCommandError,
    type ArchiveAcknowledgement,
    type ArchivePolicy,
    type FoundationCeremonyRuntime,
} from '#packages/wasm/src/index.js';
import {
    archiveRecordByteLength,
    compilePublicArchiveResourceCensus,
} from '#tests/public-archive-resource-model.js';
import { startPublicArchiveReplica } from '#tools/archive/public-archive-replica.js';

const context = '07'.repeat(64);
// Fixed public test seeds in the seed-only PKCS#8 encoding used by OpenSSL.
// These keys never authenticate a real archive or participant.
const keys = [1, 2, 3].map((seed) =>
    createPrivateKey({
        key: Buffer.concat([
            Buffer.from('3034020100300b060960864801650304031204228020', 'hex'),
            Buffer.alloc(32, seed),
        ]),
        type: 'pkcs8',
        format: 'der',
    }),
);
const policy: ArchivePolicy = {
    faultBound: 1,
    verificationKeys: keys.map((key) =>
        createPublicKey(key)
            .export({ type: 'spki', format: 'der' })
            .subarray(-1952),
    ),
};
const kernelUrl = new URL(
    '../../../packages/wasm/dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
// A record identity as the foundation framing defines it, encoded here: the
// tuple header (schema 1, version 1, two items), the domain as an ASCII item
// (type 2) and the record as a raw-bytes item (type 1), each item's length
// before its inner length, hashed with SHAKE256 to 64 bytes.
const recordIdentity = (bytes: Uint8Array) => {
    const variable = (value: Uint8Array) => {
        const length = Buffer.alloc(4);
        length.writeUInt32LE(value.length);
        return Buffer.concat([length, value]);
    };
    const item = (tag: number, value: Uint8Array) => {
        const header = Buffer.alloc(6);
        header.writeUInt16LE(tag);
        header.writeUInt32LE(value.length, 2);
        return Buffer.concat([header, value]);
    };
    return createHash('shake256', { outputLength: 64 })
        .update(
            Buffer.concat([
                Buffer.from([1, 0, 1, 0, 2, 0, 0, 0]),
                item(
                    2,
                    variable(
                        Buffer.from('sealed-lattice/archive-record-id/v1'),
                    ),
                ),
                item(1, variable(bytes)),
            ]),
        )
        .digest('hex');
};
const receiptContext = Buffer.from('sealed-lattice/archive-retention/v1');
const store = () => {
    const records = new Map<string, Uint8Array>();
    const storage: PublicArchiveStore = {
        get: (identity) => Promise.resolve(records.get(identity)),
        put: (identity, bytes) => {
            records.set(identity, Uint8Array.from(bytes));
            return Promise.resolve();
        },
    };
    return { records, storage };
};
let runtime: FoundationCeremonyRuntime;
beforeAll(async () => {
    runtime = await createFoundationCeremonyRuntimeLoader(kernelUrl, {
        expectedKernelSha256Hex: createHash('sha256')
            .update(await readFile(kernelUrl))
            .digest('hex'),
    })();
});

describe('public archive through the real scalar kernel and local storage hosts', () => {
    it('retains identical concurrent publications without losing a staged file', async () => {
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-concurrent-'),
        );
        const workspace = await realpath(process.cwd());
        const resolved = await realpath(directory);
        if (!resolved.startsWith(path.join(workspace, 'temp') + path.sep))
            throw new Error('Archive fixture escaped the workspace.');
        const hosts = await Promise.all(
            keys.map((privateKey, replicaPosition) =>
                startPublicArchiveReplica({
                    directory: path.join(directory, String(replicaPosition)),
                    context,
                    policy,
                    replicaPosition,
                    privateKey,
                    runtime,
                    maximumRecords: 4,
                    maximumTotalBytes: 4 << 20,
                    maximumStoredRecords: 4,
                    maximumStoredBytes: 4 << 20,
                }),
            ),
        );
        try {
            const archive = openPublicArchive(runtime, {
                context,
                faultBound: 1,
                replicas: hosts.map((host, index) => ({
                    baseUrl: host.baseUrl,
                    verificationKey: policy.verificationKeys[index],
                })),
                maximumRecords: 4,
                maximumTotalBytes: 4 << 20,
            });
            const record = archive.encodeRecord(
                'shared-public-bytes',
                [],
                new Uint8Array(1 << 20),
            );
            const source = store();
            await source.storage.put(record.reference.identity, record.bytes);
            const publications = await Promise.all(
                Array.from({ length: 6 }, () =>
                    archive.publish(
                        record.reference,
                        source.storage,
                        AbortSignal.timeout(10_000),
                    ),
                ),
            );
            expect(
                publications.every(
                    (positions) => positions.length > policy.faultBound,
                ),
            ).toBe(true);
            expect((await archive.fetch(record.reference)).bytes).toEqual(
                record.bytes,
            );
        } finally {
            for (const host of hosts) await host.close();
            await rm(resolved, { recursive: true });
        }
    });

    it('hedges unavailable replicas, remembers only checked successes and cancels every remaining attempt', async () => {
        vi.useFakeTimers();
        const archive = openPublicArchive(runtime, {
            context,
            faultBound: 1,
            replicas: policy.verificationKeys.map(
                (verificationKey, position) => ({
                    baseUrl: `https://replica-${String(position)}.invalid/`,
                    verificationKey,
                }),
            ),
            maximumRecords: 8,
            maximumTotalBytes: 8 << 20,
        });
        const record = archive.encodeRecord(
            'payload',
            [],
            Uint8Array.of(1, 2, 3),
        );
        const damaged = record.bytes.slice();
        damaged[damaged.length - 1] ^= 1;
        const requested: number[] = [];
        const cancelled: number[] = [];
        let behavior: ('valid' | 'damaged' | 'silent')[] = [
            'valid',
            'valid',
            'valid',
        ];
        const mock = vi
            .spyOn(globalThis, 'fetch')
            .mockImplementation(async (input, init) => {
                const position = Number(
                    (typeof input === 'string'
                        ? input
                        : input instanceof URL
                          ? input.href
                          : input.url
                    ).match(/replica-(\d)/u)?.[1],
                );
                requested.push(position);
                if (behavior[position] === 'silent')
                    return new Promise<Response>((_resolve, reject) => {
                        init?.signal?.addEventListener(
                            'abort',
                            () => {
                                cancelled.push(position);
                                reject(new Error('Cancelled replica request.'));
                            },
                            { once: true },
                        );
                    });
                return new Response(
                    new Uint8Array(
                        behavior[position] === 'valid' ? record.bytes : damaged,
                    ),
                );
            });
        try {
            expect((await archive.fetch(record.reference)).bytes).toEqual(
                record.bytes,
            );
            expect(requested.splice(0)).toEqual([0]);
            expect(vi.getTimerCount()).toBe(0);
            // A served but wrong-hash record cannot be preferred or accepted.
            behavior = ['damaged', 'valid', 'valid'];
            expect((await archive.fetch(record.reference)).bytes).toEqual(
                record.bytes,
            );
            expect(requested.splice(0)).toEqual([0, 1]);
            expect((await archive.fetch(record.reference)).bytes).toEqual(
                record.bytes,
            );
            expect(requested.splice(0)).toEqual([1]);
            // The previously responsive source can disappear or never finish.
            behavior = ['damaged', 'silent', 'valid'];
            const pending = archive.fetch(record.reference);
            await vi.advanceTimersByTimeAsync(250);
            expect((await pending).bytes).toEqual(record.bytes);
            expect(requested.splice(0)).toEqual([1, 2]);
            expect(cancelled.splice(0)).toEqual([1]);
            expect(vi.getTimerCount()).toBe(0);
            behavior = ['damaged', 'damaged', 'damaged'];
            await expect(archive.fetch(record.reference)).rejects.toThrow();
            expect(requested.splice(0)).toEqual([2, 0, 1]);
            expect(vi.getTimerCount()).toBe(0);
            behavior = ['silent', 'silent', 'silent'];
            const controller = new AbortController();
            const interrupted = archive.fetch(
                record.reference,
                controller.signal,
            );
            const refusal = (async () => {
                await expect(interrupted).rejects.toThrow('Stopped retrieval.');
            })();
            controller.abort(new Error('Stopped retrieval.'));
            await refusal;
            await vi.advanceTimersByTimeAsync(1000);
            expect(requested.splice(0)).toEqual([2]);
            expect(cancelled.splice(0)).toEqual([2]);
            expect(vi.getTimerCount()).toBe(0);
            await expect(
                archive.fetch(record.reference, controller.signal),
            ).rejects.toThrow('Stopped retrieval.');
            expect(requested).toEqual([]);
        } finally {
            mock.mockRestore();
            vi.useRealTimers();
        }
    });

    it('keeps replica cursors separate and stops replayed discovery pages', async () => {
        const first = '01'.repeat(64),
            second = '02'.repeat(64),
            forged = 'ff'.repeat(64);
        const queries: string[][] = [[], [], []];
        const server = createServer((request, response) => {
            const url = new URL(request.url ?? '', 'http://127.0.0.1');
            const position = Number(url.pathname.split('/')[2]);
            const after = url.searchParams.get('after') ?? '';
            queries[position].push(after);
            const roots =
                position === 0
                    ? [{ identity: forged, byteLength: 100 }]
                    : position === 1 && after !== second
                      ? [
                            {
                                identity: after === '' ? first : second,
                                byteLength: 100,
                            },
                        ]
                      : [];
            response
                .writeHead(200, { 'Content-Type': 'application/json' })
                .end(JSON.stringify(roots));
        });
        await new Promise<void>((resolve) => {
            server.listen(0, '127.0.0.1', resolve);
        });
        const address = server.address();
        if (address === null || typeof address === 'string')
            throw new Error('Discovery fixture has no address.');
        try {
            const archive = await createPublicArchive({
                context,
                faultBound: 1,
                replicas: policy.verificationKeys.map(
                    (verificationKey, position) => ({
                        baseUrl: `http://127.0.0.1:${String(address.port)}/replica/${String(position)}/`,
                        verificationKey,
                    }),
                ),
                maximumRecords: 4,
                maximumTotalBytes: 4096,
            });
            const found: string[] = [];
            for await (const roots of archive.discover(
                AbortSignal.timeout(10_000),
            ))
                found.push(...roots.map((root) => root.identity));
            expect(found).toContain(first);
            expect(found).toContain(second);
            expect(queries).toEqual([['', forged], ['', first, second], ['']]);
        } finally {
            server.closeAllConnections();
            await new Promise<void>((resolve) => {
                server.close(() => resolve());
            });
        }
    });

    it('discovers a retained record across the maximum response boundary', async () => {
        const census = compilePublicArchiveResourceCensus();
        const record = (position: number) => {
            const payload = new Uint8Array(8);
            new DataView(payload.buffer).setBigUint64(
                0,
                BigInt(position),
                true,
            );
            return runtime.encodeArchiveRecord({
                context,
                purpose: 'public-record',
                dependencies: [],
                payload,
            });
        };
        const sample = record(0);
        const referenceBytes = Buffer.byteLength(
            JSON.stringify(sample.reference),
        );
        const count =
            Math.floor(
                (Number(census.maximumRecordBytes) - 1) / (referenceBytes + 1),
            ) + 1;
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-listing-'),
        );
        const recordsDirectory = path.join(directory, 'records'),
            discoveryDirectory = path.join(directory, 'discovery', context);
        await mkdir(recordsDirectory);
        await mkdir(discoveryDirectory, { recursive: true });
        const references: { identity: string; byteLength: number }[] = [];
        for (let offset = 0; offset < count; offset += 32) {
            await Promise.all(
                Array.from(
                    { length: Math.min(32, count - offset) },
                    async (_unused, index) => {
                        const value = record(offset + index);
                        references.push(value.reference);
                        await writeFile(
                            path.join(
                                recordsDirectory,
                                value.reference.identity,
                            ),
                            value.bytes,
                            { flag: 'wx' },
                        );
                        await writeFile(
                            path.join(
                                discoveryDirectory,
                                value.reference.identity,
                            ),
                            JSON.stringify(value.reference),
                            { flag: 'wx' },
                        );
                    },
                ),
            );
        }
        expect(Buffer.byteLength(JSON.stringify(references))).toBeGreaterThan(
            Number(census.maximumRecordBytes),
        );
        const host = await startPublicArchiveReplica({
            directory,
            context,
            policy: {
                faultBound: 0,
                verificationKeys: [policy.verificationKeys[0]],
            },
            replicaPosition: 0,
            privateKey: keys[0],
            runtime,
            maximumRecords: Number(census.maximumRecords),
            maximumTotalBytes: 4_294_967_291,
            maximumStoredRecords: Number(census.maximumRecords),
            maximumStoredBytes: 4_294_967_291,
        });
        let passed = false;
        try {
            const archive = await createPublicArchive({
                context,
                faultBound: 0,
                replicas: [
                    {
                        baseUrl: host.baseUrl,
                        verificationKey: policy.verificationKeys[0],
                    },
                ],
                maximumRecords: Number(census.maximumRecords),
                maximumTotalBytes: 4_294_967_291,
            });
            const control = record(count);
            references.push(control.reference);
            const source = store();
            await source.storage.put(control.reference.identity, control.bytes);
            expect(
                await archive.publish(control.reference, source.storage),
            ).toEqual([0]);
            source.records.clear();
            let pages = 0;
            const found = new Set<string>();
            for await (const page of archive.discover(
                AbortSignal.timeout(60_000),
            )) {
                pages++;
                expect(
                    Buffer.byteLength(JSON.stringify(page)),
                ).toBeLessThanOrEqual(Number(census.maximumRecordBytes));
                for (const reference of page) found.add(reference.identity);
            }
            expect(pages).toBe(2);
            expect(found).toEqual(
                new Set(references.map((reference) => reference.identity)),
            );
            expect(
                await archive.retrieve(control.reference, source.storage),
            ).toEqual({ recordCount: 1, byteLength: control.bytes.length });
            expect(source.records.get(control.reference.identity)).toEqual(
                control.bytes,
            );
            passed = true;
        } finally {
            await host.close();
            if (!passed)
                process.stderr.write(
                    `Public archive fixture retained at ${directory}\n`,
                );
        }
        const workspace = await realpath(process.cwd()),
            resolved = await realpath(directory);
        if (!resolved.startsWith(path.join(workspace, 'temp') + path.sep))
            throw new Error('Archive fixture cleanup escaped the workspace.');
        for (let offset = 0; offset < references.length; offset += 32)
            await Promise.all(
                references.slice(offset, offset + 32).map(async (reference) => {
                    await unlink(
                        path.join(discoveryDirectory, reference.identity),
                    );
                    await unlink(
                        path.join(recordsDirectory, reference.identity),
                    );
                }),
            );
        await rmdir(discoveryDirectory);
        await rmdir(path.dirname(discoveryDirectory));
        await rmdir(recordsDirectory);
        await rmdir(directory);
    });
    it('finishes publication, discovery and retrieval while one replica never replies', async () => {
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-silent-'),
        );
        const silent = createServer(() => {
            /* A permanently withheld response from one faulty domain. */
        });
        await new Promise<void>((resolve) => {
            silent.listen(0, '127.0.0.1', resolve);
        });
        const address = silent.address();
        if (address === null || typeof address === 'string')
            throw new Error('Silent fixture has no address.');
        const hosts = await Promise.all(
            keys.slice(0, 2).map((privateKey, replicaPosition) =>
                startPublicArchiveReplica({
                    directory: path.join(directory, String(replicaPosition)),
                    context,
                    policy,
                    replicaPosition,
                    privateKey,
                    runtime,
                    maximumRecords: 4,
                    maximumTotalBytes: 4096,
                    maximumStoredRecords: 4,
                    maximumStoredBytes: 4096,
                }),
            ),
        );
        try {
            const archive = await createPublicArchive({
                context,
                faultBound: 1,
                replicas: [
                    ...hosts.map((host, index) => ({
                        baseUrl: host.baseUrl,
                        verificationKey: policy.verificationKeys[index],
                    })),
                    {
                        baseUrl: `http://127.0.0.1:${String(address.port)}/`,
                        verificationKey: policy.verificationKeys[2],
                    },
                ],
                maximumRecords: 4,
                maximumTotalBytes: 4096,
            });
            const record = archive.encodeRecord(
                'empty-public-record',
                [],
                new Uint8Array(),
            );
            const source = store();
            await source.storage.put(record.reference.identity, record.bytes);
            expect(
                await archive.publish(
                    record.reference,
                    source.storage,
                    AbortSignal.timeout(10_000),
                ),
            ).toEqual([0, 1]);
            expect(
                await archive.retrieve(
                    record.reference,
                    store().storage,
                    AbortSignal.timeout(10_000),
                ),
            ).toEqual({ recordCount: 1, byteLength: record.bytes.byteLength });
            let discovered = false;
            for await (const roots of archive.discover(
                AbortSignal.timeout(10_000),
            )) {
                if (
                    roots.some(
                        (root) => root.identity === record.reference.identity,
                    )
                ) {
                    discovered = true;
                    break;
                }
            }
            expect(discovered).toBe(true);
        } finally {
            for (const host of hosts) await host.close();
            silent.closeAllConnections();
            await new Promise<void>((resolve) => {
                silent.close(() => resolve());
            });
        }
        await rm(directory, { recursive: true });
    });
    it('matches independent record bounds at empty and maximum payloads', () => {
        const census = compilePublicArchiveResourceCensus();
        for (const [purpose, dependencyCount, payloadLength] of [
            ['empty', 0, 0],
            ['x'.repeat(128), 4096, 1_048_576],
        ] as const) {
            const encoded = runtime.encodeArchiveRecord({
                context,
                purpose,
                dependencies: Array.from({ length: dependencyCount }, () => ({
                    identity: context,
                    byteLength: 100,
                })),
                payload: new Uint8Array(payloadLength),
            });
            expect(BigInt(encoded.bytes.length)).toBe(
                archiveRecordByteLength(
                    BigInt(purpose.length),
                    BigInt(dependencyCount),
                    BigInt(payloadLength),
                ),
            );
            expect(
                runtime.readArchiveRecord(
                    context,
                    encoded.reference,
                    encoded.bytes,
                ).payload.length,
            ).toBe(payloadLength);
        }
        expect(census.maximumEncodedRecordBytes).toBeLessThanOrEqual(
            census.maximumRecordBytes,
        );
        for (const payloadLength of [1_048_577])
            expect(() =>
                runtime.encodeArchiveRecord({
                    context,
                    purpose: 'x',
                    dependencies: [],
                    payload: new Uint8Array(payloadLength),
                }),
            ).toThrow();
    });
    it('matches independent SHAKE framing and OpenSSL receipt signatures', () => {
        const encoded = runtime.encodeArchiveRecord({
            context,
            purpose: 'ballot-body',
            dependencies: [],
            payload: Uint8Array.of(1, 2, 3),
        });
        expect(encoded.reference.identity).toBe(recordIdentity(encoded.bytes));
        const message = runtime.archiveReceiptMessage(
            policy,
            context,
            encoded.reference,
        );
        const signatures = keys.map((key, replicaPosition) => ({
            replicaPosition,
            signature: sign(null, message, {
                key,
                context: receiptContext,
            }),
        }));
        expect(
            verify(
                null,
                message,
                {
                    key: createPublicKey(keys[0]),
                    context: receiptContext,
                },
                signatures[0].signature,
            ),
        ).toBe(true);
        expect(
            runtime.authenticateArchiveAcknowledgements(
                policy,
                context,
                encoded.reference,
                signatures.slice(0, 2),
            ),
        ).toEqual([0, 1]);
        expect(() =>
            runtime.authenticateArchiveAcknowledgements(
                policy,
                context,
                encoded.reference,
                [signatures[0], signatures[0]],
            ),
        ).toThrow();
        signatures[0].signature[0] ^= 1;
        expect(
            runtime.authenticateArchiveAcknowledgements(
                policy,
                context,
                encoded.reference,
                signatures,
            ),
        ).toEqual([1, 2]);
        expect(() =>
            runtime.authenticateArchiveAcknowledgements(
                policy,
                '08'.repeat(64),
                encoded.reference,
                signatures,
            ),
        ).toThrow();
        expect(() =>
            runtime.readArchiveRecord(
                context,
                {
                    ...encoded.reference,
                    byteLength: encoded.reference.byteLength + 1,
                },
                encoded.bytes,
            ),
        ).toThrow();
        expect(() =>
            runtime.readArchiveRecord(
                '09'.repeat(64),
                encoded.reference,
                encoded.bytes,
            ),
        ).toThrow();
    });

    it('refuses changed records and acknowledgements without ending the kernel, and accepts only canonical records and genuine signers', () => {
        // Every case derives its choices from its label, so a failing case
        // replays from the label its failure names.
        const draws = (label: string) => {
            let block = 0;
            let words = Buffer.alloc(0);
            let offset = 0;
            return (bound: number) => {
                if (offset === words.length) {
                    words = createHash('shake256', { outputLength: 256 })
                        .update(label + '#' + String(block))
                        .digest();
                    block += 1;
                    offset = 0;
                }
                const value = words.readUInt32LE(offset);
                offset += 4;
                return value % bound;
            };
        };
        // A kernel call's result or refusal. A refusal is the kernel's command
        // error; any other failure ended the kernel instance and fails the
        // case.
        const attempt = <Value>(
            call: () => Value,
        ): Value | FoundationKernelCommandError => {
            try {
                return call();
            } catch (error) {
                if (error instanceof FoundationKernelCommandError) return error;
                throw error;
            }
        };
        const genuine = runtime.encodeArchiveRecord({
            context,
            purpose: 'ballot-body',
            dependencies: [1, 2, 3].map((index) => ({
                identity: String(index).padStart(2, '0').repeat(64),
                byteLength: 100 * index,
            })),
            payload: Uint8Array.from(
                { length: 300 },
                (_unused, offset) => offset % 251,
            ),
        });
        // Whether each changed record was refused, so that both the decoder's
        // acceptance and its refusals are exercised.
        const recordOutcomes = new Set<boolean>();
        for (let index = 0; index < 256; index += 1) {
            const label = 'record/' + String(index);
            const draw = draws(label);
            const bytes = Uint8Array.from(genuine.bytes);
            const changed =
                draw(3) === 0
                    ? bytes.subarray(0, 1 + draw(bytes.length - 1))
                    : draw(2) === 0
                      ? Buffer.concat([
                            bytes,
                            Buffer.alloc(1 + draw(64), draw(256)),
                        ])
                      : bytes;
            if (changed === bytes) bytes[draw(bytes.length)] ^= 1 + draw(255);
            // The reference names the changed bytes, so the kernel decodes
            // them.
            const record = attempt(() =>
                runtime.readArchiveRecord(
                    context,
                    {
                        identity: recordIdentity(changed),
                        byteLength: changed.length,
                    },
                    changed,
                ),
            );
            // A changed payload or purpose may still be a record, but only
            // one that encodes back to the same bytes.
            expect(
                record instanceof FoundationKernelCommandError ||
                    Buffer.from(
                        runtime.encodeArchiveRecord(record).bytes,
                    ).equals(Buffer.from(changed)),
                label,
            ).toBe(true);
            recordOutcomes.add(record instanceof FoundationKernelCommandError);
        }
        expect(recordOutcomes).toEqual(new Set([true, false]));
        expect(
            runtime.readArchiveRecord(
                context,
                genuine.reference,
                genuine.bytes,
            ),
        ).toMatchObject({ purpose: 'ballot-body' });
        const message = runtime.archiveReceiptMessage(
            policy,
            context,
            genuine.reference,
        );
        const signatures = keys.map((key, replicaPosition) => ({
            replicaPosition,
            signature: sign(null, message, { key, context: receiptContext }),
        }));
        // OpenSSL's verdict on an acknowledgement under the policy key at its
        // position.
        const verifies = ({
            replicaPosition,
            signature,
        }: ArchiveAcknowledgement) => {
            if (replicaPosition >= keys.length) return false;
            try {
                return verify(
                    null,
                    message,
                    {
                        key: createPublicKey(keys[replicaPosition]),
                        context: receiptContext,
                    },
                    signature,
                );
            } catch {
                return false;
            }
        };
        const acknowledgementOutcomes = new Set<boolean>();
        for (let index = 0; index < 64; index += 1) {
            const label = 'acknowledgement/' + String(index);
            const draw = draws(label);
            const acknowledgements = Array.from({ length: draw(6) }, () => {
                const { replicaPosition, signature } =
                    signatures[draw(signatures.length)];
                const copy = Uint8Array.from(signature);
                const change = draw(4);
                if (change === 1) copy[draw(copy.length)] ^= 1 + draw(255);
                return {
                    replicaPosition:
                        change === 2
                            ? [0, 1, 2, keys.length, 0xffff][draw(5)]
                            : replicaPosition,
                    signature:
                        change === 3
                            ? copy.subarray(0, draw(copy.length))
                            : copy,
                };
            });
            const signers = [
                ...new Set(
                    acknowledgements
                        .filter(verifies)
                        .map(({ replicaPosition }) => replicaPosition),
                ),
            ].sort((left, right) => left - right);
            // Too few signers are refused.
            const authenticated = attempt(() =>
                runtime.authenticateArchiveAcknowledgements(
                    policy,
                    context,
                    genuine.reference,
                    acknowledgements,
                ),
            );
            expect(
                authenticated instanceof FoundationKernelCommandError
                    ? 'refused'
                    : authenticated,
                label,
            ).toEqual(signers.length > policy.faultBound ? signers : 'refused');
            acknowledgementOutcomes.add(
                authenticated instanceof FoundationKernelCommandError,
            );
        }
        expect(acknowledgementOutcomes).toEqual(new Set([true, false]));
        expect(
            runtime.authenticateArchiveAcknowledgements(
                policy,
                context,
                genuine.reference,
                signatures,
            ),
        ).toEqual([0, 1, 2]);
    });

    it('retains the complete closure and retrieves it after author loss and replica restart', async () => {
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-test-'),
        );
        const maximumRecords = 12,
            maximumTotalBytes = 8 * 1_048_576;
        const inputs = keys.map((privateKey, replicaPosition) => ({
            directory: path.join(directory, String(replicaPosition)),
            context,
            policy,
            replicaPosition,
            privateKey,
            runtime,
            maximumRecords,
            maximumTotalBytes,
            maximumStoredRecords: maximumRecords,
            maximumStoredBytes: maximumTotalBytes,
        }));
        const hosts = await Promise.all(inputs.map(startPublicArchiveReplica));
        try {
            const configuration = () => ({
                context,
                faultBound: policy.faultBound,
                replicas: hosts.map((host, index) => ({
                    baseUrl: host.baseUrl,
                    verificationKey: policy.verificationKeys[index],
                })),
                maximumRecords,
                maximumTotalBytes,
            });
            const publisher = await createPublicArchive(configuration());
            const source = store();
            const leaves = [0, 1, 2].map((index) =>
                publisher.encodeRecord(
                    'ballot-body-chunk',
                    [],
                    Uint8Array.from(
                        { length: 1_048_576 },
                        (_unused, offset) => (index + offset) % 251,
                    ),
                ),
            );
            const root = publisher.encodeRecord(
                'ballot-body',
                leaves.map((leaf) => leaf.reference),
                new Uint8Array(),
            );
            for (const record of [...leaves, root])
                await source.storage.put(
                    record.reference.identity,
                    record.bytes,
                );
            const acknowledged = await publisher.publish(
                root.reference,
                source.storage,
                AbortSignal.timeout(20_000),
            );
            expect(acknowledged.length).toBeGreaterThan(policy.faultBound);
            // A partial retransmission cannot replace a previously completed file.
            await writeFile(
                path.join(
                    inputs[acknowledged[1]].directory,
                    'records',
                    leaves[0].reference.identity + '.staged',
                ),
                Uint8Array.of(9),
            );
            await writeFile(
                path.join(
                    inputs[acknowledged[1]].directory,
                    'discovery',
                    context,
                    root.reference.identity + '.staged',
                ),
                '{',
            );
            for (const host of hosts) await host.close();
            for (const position of acknowledged)
                hosts[position] = await startPublicArchiveReplica(
                    inputs[position],
                );
            // Remove the author and every participant cache; only two acknowledged
            // hosts return, and one of those subsequently loses a dependency.
            source.records.clear();
            await writeFile(
                path.join(
                    inputs[acknowledged[0]].directory,
                    'records',
                    leaves[0].reference.identity,
                ),
                Uint8Array.of(0),
            );
            const reader = await createPublicArchive(configuration());
            const destination = store();
            destination.records.set(root.reference.identity, Uint8Array.of(0));
            const recovered = await reader.retrieve(
                root.reference,
                destination.storage,
                AbortSignal.timeout(20_000),
            );
            expect(recovered).toEqual({
                recordCount: 4,
                byteLength: [...leaves, root].reduce(
                    (sum, record) => sum + record.bytes.byteLength,
                    0,
                ),
            });
            const initiallyRetrieved = [...leaves, root].map((record) => ({
                record,
                bytes: destination.records
                    .get(record.reference.identity)
                    ?.slice(),
            }));
            let discovered = false;
            for await (const roots of reader.discover(
                AbortSignal.timeout(10_000),
            )) {
                if (
                    roots.some(
                        (reference) =>
                            reference.identity === root.reference.identity,
                    )
                ) {
                    discovered = true;
                    break;
                }
            }
            expect(discovered).toBe(true);
            expect(
                await reader.retrieve(root.reference, destination.storage),
            ).toEqual(recovered);
            const limited = await createPublicArchive({
                ...configuration(),
                maximumRecords: 3,
            });
            await expect(
                limited.retrieve(
                    root.reference,
                    store().storage,
                    AbortSignal.timeout(10_000),
                ),
            ).rejects.toThrow('bound');
            // Large equality diagnostics block Node's shared event loop. Check
            // the bytes after network work so they cannot delay keepalive timers
            // while the next request is trying to reuse an idle connection.
            for (const { record, bytes } of initiallyRetrieved)
                expect(bytes).toEqual(record.bytes);
        } finally {
            for (const host of hosts) await host.close();
        }
        await rm(directory, { recursive: true });
    });

    it('does not acknowledge a missing dependency, accept a substitution, or publish from lost source state', async () => {
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-missing-'),
        );
        const host = await startPublicArchiveReplica({
            directory,
            context,
            policy: {
                faultBound: 0,
                verificationKeys: [policy.verificationKeys[0]],
            },
            replicaPosition: 0,
            privateKey: keys[0],
            runtime,
            maximumRecords: 4,
            maximumTotalBytes: 4096,
            maximumStoredRecords: 4,
            maximumStoredBytes: 4096,
        });
        try {
            const archive = await createPublicArchive({
                context,
                faultBound: 0,
                replicas: [
                    {
                        baseUrl: host.baseUrl,
                        verificationKey: policy.verificationKeys[0],
                    },
                ],
                maximumRecords: 4,
                maximumTotalBytes: 4096,
            });
            const leaf = archive.encodeRecord(
                'ballot-envelope',
                [],
                Uint8Array.of(5),
            );
            const root = archive.encodeRecord(
                'ballot-submission',
                [leaf.reference],
                new Uint8Array(),
            );
            expect(
                (
                    await fetch(
                        host.baseUrl + 'records/' + root.reference.identity,
                        { method: 'PUT', body: Uint8Array.from(root.bytes) },
                    )
                ).status,
            ).toBe(204);
            expect(
                (
                    await fetch(host.baseUrl + 'retain', {
                        method: 'POST',
                        body: JSON.stringify({ context, root: root.reference }),
                    })
                ).status,
            ).toBe(400);
            expect(
                (
                    await fetch(
                        host.baseUrl + 'records/' + leaf.reference.identity,
                        { method: 'PUT', body: Uint8Array.of(9) },
                    )
                ).status,
            ).toBe(400);
            await expect(
                archive.publish(root.reference, store().storage),
            ).rejects.toThrow('missing');
            const source = store();
            for (const record of [leaf, root])
                await source.storage.put(
                    record.reference.identity,
                    record.bytes,
                );
            expect(
                await archive.publish(root.reference, source.storage),
            ).toEqual([0]);
            // Failed later submissions do not revoke previously retained work.
            expect(
                (
                    await fetch(
                        host.baseUrl + 'records/' + root.reference.identity,
                        { method: 'PUT', body: Uint8Array.of(9) },
                    )
                ).status,
            ).toBe(400);
            expect(
                await archive.retrieve(root.reference, store().storage),
            ).toEqual({
                recordCount: 2,
                byteLength: leaf.bytes.byteLength + root.bytes.byteLength,
            });
        } finally {
            await host.close();
        }
        await rm(directory, { recursive: true });
    });

    it('bounds each retained closure by one retrieval and all stored records by the capacity', async () => {
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-capacity-'),
        );
        // One retrieval carries two records, and the host stores seven.
        const input = {
            directory,
            context,
            policy: {
                faultBound: 0,
                verificationKeys: [policy.verificationKeys[0]],
            },
            replicaPosition: 0,
            privateKey: keys[0],
            runtime,
            maximumRecords: 2,
            maximumTotalBytes: 4096,
            maximumStoredRecords: 7,
            maximumStoredBytes: 4096,
        };
        const host = await startPublicArchiveReplica(input);
        try {
            const configuration = (maximumRecords: number) => ({
                context,
                faultBound: 0,
                replicas: [
                    {
                        baseUrl: host.baseUrl,
                        verificationKey: policy.verificationKeys[0],
                    },
                ],
                maximumRecords,
                maximumTotalBytes: 4096,
            });
            const archive = await createPublicArchive(configuration(2));
            const source = store();
            const submission = async (values: readonly number[]) => {
                const leaves = values.map((value) =>
                    archive.encodeRecord(
                        'ballot-envelope',
                        [],
                        Uint8Array.of(value),
                    ),
                );
                const root = archive.encodeRecord(
                    'ballot-submission',
                    leaves.map((leaf) => leaf.reference),
                    new Uint8Array(),
                );
                for (const record of [...leaves, root])
                    await source.storage.put(
                        record.reference.identity,
                        record.bytes,
                    );
                return {
                    root: root.reference,
                    byteLength: [...leaves, root].reduce(
                        (sum, record) => sum + record.bytes.byteLength,
                        0,
                    ),
                };
            };
            // The host stores a closure beyond one retrieval but does not
            // acknowledge it.
            await expect(
                (await createPublicArchive(configuration(3))).publish(
                    (await submission([1, 2])).root,
                    source.storage,
                ),
            ).rejects.toThrow('unavailable');
            // Two more roots fill the capacity with seven records, more than
            // one retrieval carries.
            const retained = [await submission([3]), await submission([4])];
            for (const { root } of retained)
                expect(await archive.publish(root, source.storage)).toEqual([
                    0,
                ]);
            for (const { root, byteLength } of retained)
                expect(await archive.retrieve(root, store().storage)).toEqual({
                    recordCount: 2,
                    byteLength,
                });
            await expect(
                archive.publish((await submission([5])).root, source.storage),
            ).rejects.toThrow('unavailable');
        } finally {
            await host.close();
        }
        // A host whose capacity is below its stored records refuses to start.
        await expect(
            startPublicArchiveReplica({ ...input, maximumStoredRecords: 6 }),
        ).rejects.toThrow('exceeds host limits');
        await expect(
            startPublicArchiveReplica({ ...input, maximumStoredBytes: 0 }),
        ).rejects.toThrow('Invalid archive host limits');
        await rm(directory, { recursive: true });
    });

    it('sends a record only to replicas that lack it and acknowledges a closure they hold', async () => {
        const directory = await mkdtemp(
            path.resolve('temp/public-archive-store-'),
        );
        const hosts = await Promise.all(
            keys.slice(0, 2).map((privateKey, replicaPosition) =>
                startPublicArchiveReplica({
                    directory: path.join(directory, String(replicaPosition)),
                    context,
                    policy,
                    replicaPosition,
                    privateKey,
                    runtime,
                    maximumRecords: 4,
                    maximumTotalBytes: 4096,
                    maximumStoredRecords: 4,
                    maximumStoredBytes: 4096,
                }),
            ),
        );
        // The third replica reports the records it is told it holds and
        // refuses every upload, retention and read.
        const held = new Map<string, number>();
        const methods: string[] = [];
        const holding = createServer((request, response) => {
            methods.push(request.method ?? '');
            const length = held.get((request.url ?? '').split('/').pop() ?? '');
            if (request.method !== 'HEAD') response.writeHead(405).end();
            else if (length === undefined) response.writeHead(404).end();
            else response.writeHead(200, { 'Content-Length': length }).end();
        });
        await new Promise<void>((resolve) => {
            holding.listen(0, '127.0.0.1', resolve);
        });
        const address = holding.address();
        if (address === null || typeof address === 'string')
            throw new Error('Holding fixture has no address.');
        try {
            const archive = await createPublicArchive({
                context,
                faultBound: 1,
                replicas: [
                    ...hosts.map((host, index) => ({
                        baseUrl: host.baseUrl,
                        verificationKey: policy.verificationKeys[index],
                    })),
                    {
                        baseUrl: `http://127.0.0.1:${String(address.port)}/`,
                        verificationKey: policy.verificationKeys[2],
                    },
                ],
                maximumRecords: 4,
                maximumTotalBytes: 4096,
            });
            const leaf = archive.encodeRecord(
                'ballot-envelope',
                [],
                Uint8Array.of(7),
            );
            const root = archive.encodeRecord(
                'ballot-submission',
                [leaf.reference],
                new Uint8Array(),
            );
            // No replica holds the closure, so none acknowledges it.
            await expect(archive.retain(root.reference)).rejects.toThrow();
            held.set(leaf.reference.identity, leaf.reference.byteLength);
            methods.length = 0;
            expect(await archive.store(leaf)).toEqual([0, 1, 2]);
            expect(methods).toEqual(['HEAD']);
            expect(await archive.store(root)).toEqual([0, 1]);
            expect([...(await archive.retain(root.reference))].sort()).toEqual([
                0, 1,
            ]);
            expect((await archive.fetch(root.reference)).bytes).toEqual(
                root.bytes,
            );
            // Bytes that fail their own reference are never sent.
            methods.length = 0;
            await expect(
                archive.store({ reference: leaf.reference, bytes: root.bytes }),
            ).rejects.toThrow();
            expect(methods).toEqual([]);
            // One remaining replica is not more than the fault bound.
            await hosts[1].close();
            await expect(
                archive.store(
                    archive.encodeRecord(
                        'ballot-envelope',
                        [],
                        Uint8Array.of(8),
                    ),
                ),
            ).rejects.toThrow('Too few archive replicas');
        } finally {
            for (const host of hosts) await host.close();
            await new Promise<void>((resolve) => {
                holding.close(() => resolve());
            });
        }
        await rm(directory, { recursive: true });
    });
});
