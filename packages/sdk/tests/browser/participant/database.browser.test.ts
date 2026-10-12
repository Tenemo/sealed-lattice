import { afterEach, describe, expect, it, vi } from 'vitest';

import { StorageFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import {
    addParticipantRecords,
    openParticipantDatabase,
    participantDatabaseName,
    readParticipantValue,
    recordBytes,
    snapshotParticipant,
} from '#packages/sdk/src/participant/worker/storage/database.js';

const databases: IDBDatabase[] = [];
const names: string[] = [];
const openDatabase = async () => {
    const namespace = 'storage-' + crypto.randomUUID();
    names.push(participantDatabaseName(namespace));
    const database = await openParticipantDatabase(namespace);
    databases.push(database);
    return database;
};

afterEach(async () => {
    vi.restoreAllMocks();
    for (const database of databases.splice(0)) database.close();
    for (const name of names.splice(0))
        await new Promise<void>((resolve, reject) => {
            const request = indexedDB.deleteDatabase(name);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error ?? new Error(name));
        });
});

describe('participant storage failures', () => {
    it('reports reads on a connection the browser closed as storage failures', async () => {
        const database = await openDatabase();
        database.close();
        await expect(
            readParticipantValue(database, 'data', [0, 0]),
        ).rejects.toBeInstanceOf(StorageFailure);
        await expect(snapshotParticipant(database)).rejects.toBeInstanceOf(
            StorageFailure,
        );
    });

    it('adds nothing and reports a storage failure when the browser aborts a staged write', async () => {
        const database = await openDatabase();
        const staged = { key: [1, 0], bytes: Uint8Array.of(1, 2, 3) };
        await addParticipantRecords(database, 'contribution', [staged]);
        // Adding an existing key makes the browser abort the whole
        // transaction, as a quota failure does.
        await expect(
            addParticipantRecords(database, 'contribution', [
                { key: [1, 1], bytes: Uint8Array.of(4) },
                staged,
            ]),
        ).rejects.toBeInstanceOf(StorageFailure);
        expect((await snapshotParticipant(database)).counts.contribution).toBe(
            1,
        );
    });

    it('reports an unreadable record as a storage failure and a refused allocation as itself', async () => {
        const record = new Blob([Uint8Array.of(7, 9)]);
        const refused = new RangeError('Array buffer allocation failed');
        vi.spyOn(Blob.prototype, 'arrayBuffer')
            .mockRejectedValueOnce(
                new DOMException(
                    'The requested file could not be read.',
                    'NotReadableError',
                ),
            )
            .mockRejectedValueOnce(refused);
        await expect(recordBytes(record)).rejects.toBeInstanceOf(
            StorageFailure,
        );
        await expect(recordBytes(record)).rejects.toBe(refused);
        await expect(recordBytes(record)).resolves.toEqual(Uint8Array.of(7, 9));
    });
});
