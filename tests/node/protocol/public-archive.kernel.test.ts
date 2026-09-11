import {
    createHash,
    createPrivateKey,
    createPublicKey,
    sign,
    verify,
} from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { createPublicArchive } from '#packages/sdk/dist/index.js';
import type { PublicArchiveStore } from '#packages/sdk/src/public-archive.js';
import {
    createFoundationCeremonyRuntimeLoader,
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
        const variable = (bytes: Uint8Array) => {
            const length = Buffer.alloc(4);
            length.writeUInt32LE(bytes.length);
            return Buffer.concat([length, bytes]);
        };
        const item = (tag: number, value: Uint8Array) => {
            const header = Buffer.alloc(6);
            header.writeUInt16LE(tag);
            header.writeUInt32LE(value.length, 2);
            return Buffer.concat([header, value]);
        };
        const header = Buffer.from([1, 0, 1, 0, 2, 0, 0, 0]);
        const identity = createHash('shake256', { outputLength: 64 })
            .update(
                Buffer.concat([
                    header,
                    item(
                        2,
                        variable(
                            Buffer.from('sealed-lattice/archive-record-id/v1'),
                        ),
                    ),
                    item(1, variable(encoded.bytes)),
                ]),
            )
            .digest('hex');
        expect(encoded.reference.identity).toBe(identity);
        const message = runtime.archiveReceiptMessage(
            policy,
            context,
            encoded.reference,
        );
        const signatures = keys.map((key, replicaPosition) => ({
            replicaPosition,
            signature: sign(null, message, {
                key,
                context: Buffer.from('sealed-lattice/archive-retention/v1'),
            }),
        }));
        expect(
            verify(
                null,
                message,
                {
                    key: createPublicKey(keys[0]),
                    context: Buffer.from('sealed-lattice/archive-retention/v1'),
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
            for (const record of [...leaves, root])
                expect(
                    destination.records.get(record.reference.identity),
                ).toEqual(record.bytes);
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
        } finally {
            for (const host of hosts) await host.close();
        }
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
    });
});
