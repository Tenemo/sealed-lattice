import { afterEach, describe, expect, it } from 'vitest';

import {
    createProofWriter,
    proofLength,
    readProof,
} from '#packages/sdk/src/participant/worker/stages/contribution/contribution-proof.js';
import {
    openParticipantDatabase,
    readParticipantValue,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import {
    openRecord,
    sealRecord,
} from '#packages/sdk/src/participant/worker/storage/private-records.js';
import {
    fixtureRequest,
    writeFixtureStore,
} from '#packages/sdk/tests/browser-storage.js';

// Synthetic proof bytes isolate private storage framing and transport. Real
// AES-GCM and IndexedDB are exercised; no fixture asserts proof acceptance.
const recordBytes = 1_048_576;
const bounds = {
    minimumProofBytes: 17,
    maximumProofBytes: 3 * recordBytes + 37,
    bodyHeaderBytes: 8,
};
// Synthetic framing exercises storage only. Production headers come from
// the contribution-body codec in the Rust module.
const fixtureHeader = (length: number) => {
    const header = new Uint8Array(bounds.bodyHeaderBytes);
    new DataView(header.buffer).setBigUint64(0, BigInt(length), true);
    return header;
};
const expectedSlots = (length: number) =>
    Array.from({ length: Math.ceil(length / recordBytes) }, (_, index) => ({
        offset: index * recordBytes,
        length: Math.min(recordBytes, length - index * recordBytes),
    }));
type Slot = ReturnType<typeof expectedSlots>[number];
const databases: IDBDatabase[] = [];

const write = (
    database: IDBDatabase,
    change: (store: IDBObjectStore) => void,
) =>
    writeFixtureStore(database, 'contribution', change, {
        durability: 'strict',
    });
const proofBytes = (length: number) =>
    Uint8Array.from(
        { length },
        (_unused, index) => 1 + ((index * 17 + 3) % 251),
    );

const fixture = async () => {
    const database = await openParticipantDatabase(
        'proof-' + crypto.randomUUID(),
    );
    databases.push(database);
    const records = new Map<
        number,
        { key: Uint8Array; additionalData: Uint8Array }
    >();
    const writes: Slot[] = [];
    const reads: Slot[] = [];
    const writePlaintexts: Uint8Array[] = [];
    const readPlaintexts: Uint8Array[] = [];
    const store = async (slot: Slot, bytes: Uint8Array) => {
        writes.push({ ...slot });
        writePlaintexts.push(bytes);
        const additionalData = new TextEncoder().encode(
            `synthetic-contribution-proof/${slot.offset}/${slot.length}`,
        );
        const sealed = await sealRecord(additionalData, bytes);
        await write(database, (objects) => {
            objects.add(new Blob([new Uint8Array(sealed.ciphertext)]), [
                1,
                slot.offset,
            ]);
        });
        records.set(slot.offset, { key: sealed.key, additionalData });
    };
    const read = async (slot: Slot) => {
        reads.push({ ...slot });
        const record = records.get(slot.offset);
        if (record === undefined)
            throw new Error('Fixture record metadata is missing.');
        const bytes = await openRecord(
            database,
            'contribution',
            [1, slot.offset],
            record,
            slot.length,
        );
        readPlaintexts.push(bytes);
        return bytes;
    };
    const retain = async (bytes: Uint8Array, pieces: readonly number[]) => {
        const writer = createProofWriter(bounds, store);
        try {
            let offset = 0;
            let piece = 0;
            while (offset < bytes.length) {
                const end = Math.min(
                    bytes.length,
                    offset + pieces[piece % pieces.length],
                );
                await writer.append(bytes.subarray(offset, end));
                offset = end;
                piece++;
            }
            return fixtureHeader(await writer.finish());
        } finally {
            writer.close();
        }
    };
    return {
        database,
        records,
        writes,
        reads,
        writePlaintexts,
        readPlaintexts,
        store,
        read,
        retain,
    };
};

afterEach(async () => {
    for (const database of databases.splice(0)) {
        database.close();
        await fixtureRequest(indexedDB.deleteDatabase(database.name));
    }
});

describe('exact-length private contribution proof storage', () => {
    it.each(
        [
            17,
            recordBytes - 1,
            recordBytes,
            recordBytes + 1,
            2 * recordBytes + 7,
            bounds.maximumProofBytes,
        ].flatMap((length) => [
            {
                length,
                partition: 'split boundaries',
                pieces: [1, recordBytes - 1, 13, recordBytes + 17],
            },
            {
                length,
                partition: 'crossing boundaries',
                pieces: [recordBytes + 13, 7, 65_533],
            },
        ]),
    )(
        'stores only the required records for $length proof bytes and $partition',
        async ({ length, pieces }) => {
            const bytes = proofBytes(length);
            const retained = await fixture();
            const header = await retained.retain(bytes, pieces);
            expect(header.length).toBe(8);
            expect(
                new DataView(
                    header.buffer,
                    header.byteOffset,
                    header.byteLength,
                ).getBigUint64(0, true),
            ).toBe(BigInt(length));
            expect(proofLength(bounds, header)).toBe(length);
            expect(retained.writes).toEqual(expectedSlots(length));
            for (const slot of expectedSlots(length)) {
                const ciphertext = await readParticipantValue(
                    retained.database,
                    'contribution',
                    [1, slot.offset],
                );
                expect(ciphertext).toBeInstanceOf(Blob);
                expect((ciphertext as Blob).size).toBe(slot.length + 16);
            }
            const recovered = new Uint8Array(length);
            let consumed = 0;
            await readProof(bounds, header, retained.read, (offset, part) => {
                expect(offset).toBe(consumed);
                recovered.set(part, offset);
                consumed += part.length;
            });
            expect(consumed).toBe(length);
            expect(recovered).toEqual(bytes);
            expect(retained.reads).toEqual(expectedSlots(length));
            expect(
                retained.writePlaintexts.every((part) =>
                    part.every((byte) => byte === 0),
                ),
            ).toBe(true);
            expect(
                retained.readPlaintexts.every((part) =>
                    part.every((byte) => byte === 0),
                ),
            ).toBe(true);
        },
    );

    it.each([
        'missing',
        'ciphertext',
        'truncated',
        'extended',
        'reordered',
    ] as const)(
        'refuses %s required final records before completing a read',
        async (damage) => {
            const retained = await fixture();
            const length = recordBytes + 17;
            const header = await retained.retain(proofBytes(length), [
                recordBytes,
                17,
            ]);
            const slot = expectedSlots(length)[1];
            const key = [1, slot.offset];
            const original = await readParticipantValue(
                retained.database,
                'contribution',
                key,
            );
            if (!(original instanceof Blob)) throw new Error('Missing fixture');
            const ciphertext = new Uint8Array(await original.arrayBuffer());
            const first = await readParticipantValue(
                retained.database,
                'contribution',
                [1, 0],
            );
            await write(retained.database, (store) => {
                if (damage === 'missing') store.delete(key);
                if (damage === 'ciphertext') {
                    ciphertext[0] ^= 1;
                    store.put(new Blob([ciphertext]), key);
                }
                if (damage === 'truncated')
                    store.put(new Blob([ciphertext.slice(0, -1)]), key);
                if (damage === 'extended')
                    store.put(new Blob([ciphertext, Uint8Array.of(0)]), key);
                if (damage === 'reordered') store.put(first, key);
            });
            let consumed = 0;
            await expect(
                readProof(bounds, header, retained.read, (_offset, bytes) => {
                    consumed += bytes.length;
                }),
            ).rejects.toThrow();
            expect(consumed).toBe(recordBytes);
            expect(retained.reads).toEqual(expectedSlots(length));
            expect(
                retained.readPlaintexts.every((part) =>
                    part.every((byte) => byte === 0),
                ),
            ).toBe(true);
        },
    );

    it('propagates consumer and storage failures and clears the opened plaintext', async () => {
        const retained = await fixture();
        const header = await retained.retain(proofBytes(recordBytes + 3), [
            recordBytes + 3,
        ]);
        const failure = new Error('Consumer refused the proof prefix.');
        await expect(
            readProof(bounds, header, retained.read, () => {
                throw failure;
            }),
        ).rejects.toBe(failure);
        expect(retained.reads).toEqual([expectedSlots(recordBytes)[0]]);
        expect(retained.readPlaintexts[0].every((byte) => byte === 0)).toBe(
            true,
        );

        const pending = await fixture();
        const writeFailure = new Error('Final record storage is unavailable.');
        const writer = createProofWriter(bounds, async (slot, bytes) => {
            if (slot.offset === recordBytes) throw writeFailure;
            await pending.store(slot, bytes);
        });
        try {
            await writer.append(proofBytes(recordBytes + 17));
            await expect(writer.finish()).rejects.toBe(writeFailure);
        } finally {
            writer.close();
        }
        expect(pending.writes).toEqual([expectedSlots(recordBytes)[0]]);
        expect(
            pending.writePlaintexts.every((part) =>
                part.every((byte) => byte === 0),
            ),
        ).toBe(true);
        // No completed header can hide the missing
        // remainder. The original generation checkpoint is a separate owner.
        await expect(
            readProof(
                bounds,
                fixtureHeader(recordBytes + 17),
                pending.read,
                () => undefined,
            ),
        ).rejects.toThrow();
    });

    it('refuses malformed body framing before reading private records', async () => {
        const retained = await fixture();
        const header = await retained.retain(proofBytes(17), [17]);
        const shortProof = header.slice();
        new DataView(shortProof.buffer).setBigUint64(0, 16n, true);
        const tooLong = header.slice();
        new DataView(tooLong.buffer).setBigUint64(
            0,
            BigInt(bounds.maximumProofBytes) + 1n,
            true,
        );
        const overflowing = header.slice();
        new DataView(overflowing.buffer).setBigUint64(
            0,
            18_446_744_073_709_551_615n,
            true,
        );
        for (const malformed of [
            shortProof,
            tooLong,
            overflowing,
            header.subarray(0, 7),
            new Uint8Array(9),
        ])
            await expect(
                readProof(bounds, malformed, retained.read, () => undefined),
            ).rejects.toThrow();
        expect(retained.reads).toEqual([]);
    });
});
