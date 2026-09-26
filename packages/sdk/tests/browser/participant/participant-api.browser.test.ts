import { describe, expect, it } from 'vitest';

import { openParticipant } from 'sealed-lattice';

const requestResult = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error('Failed.'));
    });

// Counts every store of a namespace's participant database.
const storeCounts = async (name: string) => {
    const database = await requestResult(indexedDB.open(name));
    try {
        const stores = [...database.objectStoreNames];
        const transaction = database.transaction(stores, 'readonly');
        return Object.fromEntries(
            await Promise.all(
                stores.map(
                    async (store) =>
                        [
                            store,
                            await requestResult(
                                transaction.objectStore(store).count(),
                            ),
                        ] as const,
                ),
            ),
        );
    } finally {
        database.close();
    }
};

describe('participant API', () => {
    it('refuses operations on an empty namespace and leaves it empty', async () => {
        const namespace = `empty-${crypto.randomUUID()}`;
        const name = `sealed-lattice-participant/${namespace}`;
        const participant = openParticipant({
            namespace,
            relay: location.origin + '/',
        });
        try {
            for (const request of [
                { operation: 'status' },
                { operation: 'contribute' },
                { operation: 'ballot', parameters: { scores: [1, 1] } },
            ] as const)
                expect(await participant.run(request)).toEqual({
                    status: 'refused',
                });
            // The worker checked the packaged module and recomputed the
            // runtime identity before it opened the namespace's database, and
            // no refusal wrote a stop marker.
            const counts = await storeCounts(name);
            expect(Object.keys(counts).sort()).toEqual([
                'ballot',
                'checkpoint',
                'close',
                'contribution',
                'data',
                'head',
                'key',
                'release',
                'root',
                'stopped',
            ]);
            expect(Object.values(counts).every((count) => count === 0)).toBe(
                true,
            );
        } finally {
            await requestResult(indexedDB.deleteDatabase(name));
        }
    });
});
