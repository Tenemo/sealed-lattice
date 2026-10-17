import { afterEach, describe, expect, it } from 'vitest';

import * as proofStorage from '#packages/sdk/src/participant/worker/stages/contribution/contribution-proof.js';
import {
    sealRecord,
    openSealedRecord,
} from '#packages/sdk/src/participant/worker/storage/private-records.js';
import { commitParticipantState } from '#packages/sdk/src/participant/worker/storage/state-transaction.js';
import {
    fixtureRequest,
    writeFixtureTransaction,
} from '#packages/sdk/tests/browser-storage.js';

const chunk = 1_048_576;
const bounds = {
    minimumProofBytes: 17,
    maximumProofBytes: 3 * chunk + 37,
    bodyHeaderBytes: 8,
};
type RecordEntry = { offset: number; length: number; key: Uint8Array };
type Head = {
    generation: number;
    key: Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<ArrayBuffer>;
};
const opened: IDBDatabase[] = [];
const encoder = new TextEncoder();
const context = encoder.encode('contribution-proof-transaction');
const originalIntent = Uint8Array.of(1, 7, 19, 31);
const payload = (length: number) =>
    Uint8Array.from(
        { length },
        (_unused, index) => 1 + ((index * 17 + 3) % 251),
    );
const checksum = async (bytes: Uint8Array) =>
    Array.from(
        new Uint8Array(
            await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
        ),
        (value) => value.toString(16).padStart(2, '0'),
    ).join('');
const frame = (length: number) => {
    const bytes = new Uint8Array(bounds.bodyHeaderBytes);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(length), true);
    return bytes;
};
const associated = (offset: number, length: number) =>
    encoder.encode(`contribution-proof-transaction/${offset}/${length}`);
const openDatabase = async (name: string) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
        for (const store of ['head', 'records', 'checkpoint'])
            request.result.createObjectStore(store);
    };
    const database = await fixtureRequest(request);
    opened.push(database);
    return database;
};
const fixture = async () => {
    const name = 'contribution-proof-transaction-' + crypto.randomUUID();
    let database = await openDatabase(name);
    const checkpointContext = encoder.encode(
        'contribution-proof-transaction/checkpoint',
    );
    const checkpoint = await sealRecord(
        checkpointContext,
        Uint8Array.of(5, 11),
    );
    const intentBytes = encoder.encode(
        JSON.stringify({
            seed: [...originalIntent],
            checkpointKey: [...checkpoint.key],
        }),
    );
    const sealedIntent = await sealRecord(context, intentBytes);
    await writeFixtureTransaction(
        database,
        ['head', 'checkpoint'],
        (transaction) => {
            transaction
                .objectStore('head')
                .put({ generation: 6, ...sealedIntent }, 0);
            transaction
                .objectStore('checkpoint')
                .put(new Blob([checkpoint.ciphertext]), 0);
        },
        { durability: 'strict' },
    );
    const get = (store: string, key: IDBValidKey): Promise<unknown> =>
        fixtureRequest(database.transaction(store).objectStore(store).get(key));
    const intent = async () => {
        const head = (await get('head', 0)) as Head;
        expect(head.generation).toBe(6);
        const original = await openSealedRecord(
            head.key,
            context,
            head.ciphertext,
        );
        expect(original).toEqual(intentBytes);
        const retained = JSON.parse(new TextDecoder().decode(original)) as {
            checkpointKey: number[];
        };
        expect(
            await openSealedRecord(
                Uint8Array.from(retained.checkpointKey),
                checkpointContext,
                new Uint8Array(
                    await ((await get('checkpoint', 0)) as Blob).arrayBuffer(),
                ),
            ),
        ).toEqual(Uint8Array.of(5, 11));
    };
    const stage = async (bytes: Uint8Array, failAt = -1) => {
        const inventory: RecordEntry[] = [];
        const writer = proofStorage.createProofWriter(
            bounds,
            async (slot, plaintext) => {
                if (inventory.length === failAt)
                    throw new Error('Injected staged write failure');
                const sealed = await sealRecord(
                    associated(slot.offset, slot.length),
                    plaintext,
                );
                await writeFixtureTransaction(
                    database,
                    ['records'],
                    (transaction) => {
                        transaction
                            .objectStore('records')
                            .put(new Blob([sealed.ciphertext]), slot.offset);
                    },
                    { durability: 'strict' },
                );
                inventory.push({ ...slot, key: sealed.key });
            },
        );
        for (let offset = 0; offset < bytes.length; offset += 65_533)
            await writer.append(
                bytes.subarray(offset, Math.min(offset + 65_533, bytes.length)),
            );
        const length = await writer.finish();
        const header = frame(length);
        const manifest = encoder.encode(
            JSON.stringify({
                header: [...header],
                inventory: inventory.map((record) => ({
                    ...record,
                    key: [...record.key],
                })),
            }),
        );
        const completed = await sealRecord(context, manifest);
        return { inventory, header, completed };
    };
    const commit = async (
        staged: Awaited<ReturnType<typeof stage>>,
        fail = false,
    ) => {
        await commitParticipantState({
            database,
            stores: ['head', 'checkpoint', 'records'],
            timeoutMilliseconds: 30_000,
            validate: async (reader) => {
                const previous = (await reader.get('head', 0)) as {
                    generation: number;
                    key: Uint8Array;
                    ciphertext: Uint8Array<ArrayBuffer>;
                };
                expect(previous.generation).toBe(6);
                const original = await openSealedRecord(
                    previous.key,
                    context,
                    previous.ciphertext,
                );
                expect(original).toEqual(intentBytes);
                const retained = JSON.parse(
                    new TextDecoder().decode(original),
                ) as { checkpointKey: number[] };
                const storedCheckpoint = await reader.get('checkpoint', 0);
                if (
                    !(storedCheckpoint instanceof Blob) ||
                    storedCheckpoint.size !== 18
                )
                    throw new Error('Missing original checkpoint');
                expect(
                    await openSealedRecord(
                        Uint8Array.from(retained.checkpointKey),
                        checkpointContext,
                        new Uint8Array(await storedCheckpoint.arrayBuffer()),
                    ),
                ).toEqual(Uint8Array.of(5, 11));
                expect(await reader.count('records')).toBe(
                    staged.inventory.length,
                );
                for (const record of staged.inventory) {
                    const value = await reader.get('records', record.offset);
                    if (
                        !(value instanceof Blob) ||
                        value.size !== record.length + 16
                    )
                        throw new Error(
                            'Missing or truncated required proof record',
                        );
                    const plaintext = await openSealedRecord(
                        record.key,
                        associated(record.offset, record.length),
                        new Uint8Array(await value.arrayBuffer()),
                    );
                    plaintext.fill(0);
                }
            },
            write: (transaction) => {
                transaction
                    .objectStore('head')
                    .put({ generation: 7, ...staged.completed }, 0);
                transaction.objectStore('checkpoint').clear();
                if (fail) throw new Error('Injected completion failure');
            },
        });
    };
    const read = async () => {
        const head = (await get('head', 0)) as Head;
        if (head.generation !== 7)
            throw new Error('No completed proof authority');
        const decoded = JSON.parse(
            new TextDecoder().decode(
                await openSealedRecord(head.key, context, head.ciphertext),
            ),
        ) as {
            header: number[];
            inventory: { offset: number; length: number; key: number[] }[];
        };
        const result = new Uint8Array(
            new DataView(Uint8Array.from(decoded.header).buffer).getUint32(
                0,
                true,
            ),
        );
        let consumed = 0;
        await proofStorage.readProof(
            bounds,
            Uint8Array.from(decoded.header),
            async (slot, index) => {
                const record = decoded.inventory[index];
                if (
                    !record ||
                    record.offset !== slot.offset ||
                    record.length !== slot.length
                )
                    throw new Error('Changed proof inventory');
                const value = await get('records', slot.offset);
                if (!(value instanceof Blob) || value.size !== slot.length + 16)
                    throw new Error('Missing or truncated proof record');
                return openSealedRecord(
                    Uint8Array.from(record.key),
                    associated(slot.offset, slot.length),
                    new Uint8Array(await value.arrayBuffer()),
                );
            },
            (offset, bytes) => {
                expect(offset).toBe(consumed);
                result.set(bytes, offset);
                consumed += bytes.length;
            },
        );
        expect(consumed).toBe(result.length);
        return result;
    };
    return {
        name,
        get,
        intent,
        stage,
        commit,
        read,
        mutate: (change: (transaction: IDBTransaction) => void) =>
            writeFixtureTransaction(
                database,
                ['head', 'records', 'checkpoint'],
                change,
                { durability: 'strict' },
            ),
        reopen: async () => {
            database.close();
            database = await openDatabase(name);
        },
    };
};
afterEach(async () => {
    const names = new Set(opened.map((database) => database.name));
    for (const database of opened.splice(0)) database.close();
    for (const name of names)
        await fixtureRequest(indexedDB.deleteDatabase(name));
});

// An encrypted component intent exercises the real transaction implementation.
// Whole participant authority and proof validity are checked by the guarded recovery lane.
describe('contribution proof completion transactions', () => {
    it('keeps original intent after final-record write failure and replays the same bytes', async () => {
        const stored = await fixture();
        const bytes = payload(chunk + 7);
        await expect(stored.stage(bytes, 1)).rejects.toThrow('staged write');
        await stored.reopen();
        await stored.intent();
        await expect(stored.read()).rejects.toThrow('No completed');
        await stored.mutate((transaction) =>
            transaction.objectStore('records').clear(),
        );
        const staged = await stored.stage(bytes);
        await stored.commit(staged);
        expect(await checksum(await stored.read())).toBe(await checksum(bytes));
    });
    it('rolls back a failed completed-body transaction and authenticates the original intent', async () => {
        const stored = await fixture();
        const bytes = payload(chunk + 7);
        const staged = await stored.stage(bytes);
        await expect(stored.commit(staged, true)).rejects.toThrow(
            'completion failure',
        );
        await stored.reopen();
        await stored.intent();
        await stored.commit(staged);
        expect(await checksum(await stored.read())).toBe(await checksum(bytes));
    });
    it.each(['missing', 'altered'] as const)(
        'refuses an %s original checkpoint before retiring it',
        async (fault) => {
            const stored = await fixture();
            const staged = await stored.stage(payload(chunk + 7));
            const ciphertext = new Uint8Array(
                await (
                    (await stored.get('checkpoint', 0)) as Blob
                ).arrayBuffer(),
            );
            ciphertext[0] ^= 1;
            await stored.mutate((transaction) => {
                if (fault === 'missing')
                    transaction.objectStore('checkpoint').delete(0);
                else
                    transaction
                        .objectStore('checkpoint')
                        .put(new Blob([ciphertext]), 0);
            });
            await expect(stored.commit(staged)).rejects.toThrow();
            expect(((await stored.get('head', 0)) as Head).generation).toBe(6);
        },
    );
});
