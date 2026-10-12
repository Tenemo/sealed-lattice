import {
    awaitLater,
    requestResult,
    transactionCompletion,
} from './database.js';

// Whether a readback confirmed the stop marker's strict write.
export type StopPersistence = 'confirmed' | 'unconfirmed';

// This reports local persistence only. It grants no protocol authority, and an
// unconfirmed write never permits continuation of the failed invocation.
export async function stopParticipant(
    database: IDBDatabase,
): Promise<StopPersistence> {
    try {
        const write = database.transaction('stopped', 'readwrite', {
            durability: 'strict',
        });
        const written = awaitLater(transactionCompletion(write));
        if (write.durability === 'strict')
            write.objectStore('stopped').put(true, 0);
        else write.abort();
        await written;
        const read = database.transaction('stopped', 'readonly');
        const readDone = awaitLater(transactionCompletion(read));
        const [marker] = await Promise.all([
            requestResult<unknown>(read.objectStore('stopped').get(0)),
            readDone,
        ]);
        return marker === true ? 'confirmed' : 'unconfirmed';
    } catch {
        // A committed marker can still exist when readback fails.
        return 'unconfirmed';
    }
}
