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

// Synthetic proof bytes isolate private storage framing and transport. Real
// AES-GCM and IndexedDB are exercised; no fixture asserts proof acceptance.
const recordBytes = 1_048_576;
const bounds = {
    minimumProofBytes: 17,
    maximumProofBytes: 3 * recordBytes + 37,
    bodyHeaderBytes: 76,
};
// Synthetic framing exercises storage only. Production headers come from
// the original credential's source inventory in the Rust module.
const fixtureHeader = (length: number) => {
    const header = new Uint8Array(76).fill(43);
    header.set(new TextEncoder().encode('SCB2'));
    new DataView(header.buffer).setBigUint64(4, BigInt(length), true);
    return header;
};
const expectedSlots = [
    { offset: 0, length: recordBytes },
    { offset: recordBytes, length: recordBytes },
    { offset: 2 * recordBytes, length: recordBytes },
    { offset: 3 * recordBytes, length: 37 },
];
type Slot = (typeof expectedSlots)[number];
const databases: IDBDatabase[] = [];
const requestResult = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Fixture read failed.'));
    });
const write = (
    database: IDBDatabase,
    change: (store: IDBObjectStore) => void,
) =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction('contribution', 'readwrite', {
            durability: 'strict',
        });
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error('Fixture write failed.'));
        change(transaction.objectStore('contribution'));
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
        await requestResult(indexedDB.deleteDatabase(database.name));
    }
});

describe('fixed private contribution proof storage', () => {
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
        'keeps fixed slot traces for $length proof bytes and $partition',
        async ({ length, pieces }) => {
            const bytes = proofBytes(length);
            const fixed = await fixture();
            const header = await fixed.retain(bytes, pieces);
            expect(header.length).toBe(76);
            expect(new TextDecoder().decode(header.subarray(0, 4))).toBe(
                'SCB2',
            );
            expect(
                new DataView(
                    header.buffer,
                    header.byteOffset,
                    header.byteLength,
                ).getBigUint64(4, true),
            ).toBe(BigInt(length));
            expect(proofLength(bounds, header)).toBe(length);
            expect(fixed.writes).toEqual(expectedSlots);
            for (const slot of expectedSlots) {
                const ciphertext = await readParticipantValue(
                    fixed.database,
                    'contribution',
                    [1, slot.offset],
                );
                expect(ciphertext).toBeInstanceOf(Blob);
                expect((ciphertext as Blob).size).toBe(slot.length + 16);
            }
            const recovered = new Uint8Array(length);
            let consumed = 0;
            await readProof(bounds, header, fixed.read, (offset, part) => {
                expect(offset).toBe(consumed);
                recovered.set(part, offset);
                consumed += part.length;
            });
            expect(consumed).toBe(length);
            expect(recovered).toEqual(bytes);
            expect(fixed.reads).toEqual(expectedSlots);
            expect(
                fixed.writePlaintexts.every((part) =>
                    part.every((byte) => byte === 0),
                ),
            ).toBe(true);
            expect(
                fixed.readPlaintexts.every((part) =>
                    part.every((byte) => byte === 0),
                ),
            ).toBe(true);
        },
    );

    it('requires every padding record and authenticates its bytes before completing a read', async () => {
        for (const damage of [
            'missing',
            'ciphertext',
            'authenticated padding',
        ] as const) {
            const fixed = await fixture();
            const header = await fixed.retain(proofBytes(17), [7, 10]);
            const slot = expectedSlots[3];
            const key = [1, slot.offset];
            if (damage === 'missing')
                await write(fixed.database, (store) => store.delete(key));
            else if (damage === 'ciphertext') {
                const blob = await readParticipantValue(
                    fixed.database,
                    'contribution',
                    key,
                );
                if (!(blob instanceof Blob))
                    throw new Error('Fixture ciphertext is missing.');
                const ciphertext = new Uint8Array(await blob.arrayBuffer());
                ciphertext[ciphertext.length - 1] ^= 1;
                await write(fixed.database, (store) =>
                    store.put(new Blob([ciphertext]), key),
                );
            } else {
                // Valid AEAD cannot turn nonzero framing padding into a
                // canonical proof. Alter the final byte, not the proof prefix.
                const record = fixed.records.get(slot.offset)!;
                const padding = new Uint8Array(slot.length);
                padding[padding.length - 1] = 1;
                const sealed = await sealRecord(record.additionalData, padding);
                fixed.records.set(slot.offset, { ...record, key: sealed.key });
                await write(fixed.database, (store) =>
                    store.put(
                        new Blob([new Uint8Array(sealed.ciphertext)]),
                        key,
                    ),
                );
            }
            let consumed = 0;
            await expect(
                readProof(bounds, header, fixed.read, (_offset, bytes) => {
                    consumed += bytes.length;
                }),
            ).rejects.toThrow();
            expect(consumed).toBe(17);
            expect(fixed.reads).toEqual(expectedSlots);
            expect(
                fixed.readPlaintexts.every((part) =>
                    part.every((byte) => byte === 0),
                ),
            ).toBe(true);
        }
    });

    it('propagates consumer and storage failures and clears the opened plaintext', async () => {
        const fixed = await fixture();
        const header = await fixed.retain(proofBytes(recordBytes + 3), [
            recordBytes + 3,
        ]);
        const failure = new Error('Consumer refused the proof prefix.');
        await expect(
            readProof(bounds, header, fixed.read, () => {
                throw failure;
            }),
        ).rejects.toBe(failure);
        expect(fixed.reads).toEqual([expectedSlots[0]]);
        expect(fixed.readPlaintexts[0].every((byte) => byte === 0)).toBe(true);

        const pending = await fixture();
        const writeFailure = new Error('Padding storage is unavailable.');
        const writer = createProofWriter(bounds, async (slot, bytes) => {
            if (slot.offset === recordBytes) throw writeFailure;
            await pending.store(slot, bytes);
        });
        try {
            await writer.append(proofBytes(17));
            await expect(writer.finish()).rejects.toBe(writeFailure);
        } finally {
            writer.close();
        }
        expect(pending.writes).toEqual([expectedSlots[0]]);
        expect(
            pending.writePlaintexts.every((part) =>
                part.every((byte) => byte === 0),
            ),
        ).toBe(true);
        // No completed header or synthesized padding can hide the missing
        // remainder. The original generation checkpoint is a separate owner.
        await expect(
            readProof(bounds, fixtureHeader(17), pending.read, () => undefined),
        ).rejects.toThrow();
    });

    it('rejects malformed body framing before reading private records', async () => {
        const fixed = await fixture();
        const header = await fixed.retain(proofBytes(17), [17]);
        const wrongMagic = header.slice();
        wrongMagic[0] ^= 1;
        const shortProof = header.slice();
        new DataView(shortProof.buffer).setBigUint64(4, 16n, true);
        const tooLong = header.slice();
        new DataView(tooLong.buffer).setBigUint64(
            4,
            BigInt(bounds.maximumProofBytes) + 1n,
            true,
        );
        const overflowing = header.slice();
        new DataView(overflowing.buffer).setBigUint64(
            4,
            18_446_744_073_709_551_615n,
            true,
        );
        for (const malformed of [
            wrongMagic,
            shortProof,
            tooLong,
            overflowing,
            header.subarray(0, 75),
            new Uint8Array(77),
        ])
            await expect(
                readProof(bounds, malformed, fixed.read, () => undefined),
            ).rejects.toThrow();
        expect(fixed.reads).toEqual([]);
    });
});
