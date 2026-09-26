// This reports local persistence only. It grants no protocol authority, and an
// unconfirmed write never permits continuation of the failed invocation.
export async function stopParticipant(database: IDBDatabase): Promise<{
    refused: true;
    stopped: boolean;
    stopPersistence: 'confirmed' | 'unconfirmed';
}> {
    let stopped = false;
    try {
        await new Promise<void>((resolve, reject) => {
            const transaction = database.transaction('stopped', 'readwrite', {
                durability: 'strict',
            });
            transaction.oncomplete = () => resolve();
            transaction.onabort = () =>
                reject(new Error('Stop write aborted.'));
            transaction.onerror = () => {};
            if (transaction.durability !== 'strict') {
                transaction.abort();
                return;
            }
            transaction.objectStore('stopped').put(true, 0);
        });
        stopped = await new Promise<boolean>((resolve, reject) => {
            const transaction = database.transaction('stopped', 'readonly');
            let marker: unknown;
            transaction.oncomplete = () => resolve(marker === true);
            transaction.onabort = () =>
                reject(new Error('Stop readback aborted.'));
            transaction.onerror = () => {};
            const request = transaction.objectStore('stopped').get(0);
            request.onsuccess = () => {
                marker = request.result;
            };
        });
    } catch {
        // A committed marker can still exist when readback fails.
    }
    return {
        refused: true,
        stopped,
        stopPersistence: stopped ? 'confirmed' : 'unconfirmed',
    };
}
