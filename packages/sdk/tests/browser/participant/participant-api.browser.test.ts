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

// Writes a participant database for a namespace, with a root key, a sealed
// root of arbitrary bytes and the given head, beside empty record stores.
const participantStores = [
    'key',
    'root',
    'head',
    'stopped',
    'data',
    'contribution',
    'checkpoint',
    'ballot',
    'close',
    'release',
];
const writeParticipant = async (name: string, head: unknown) => {
    const opening = indexedDB.open(name, 1);
    opening.onupgradeneeded = () => {
        for (const store of participantStores)
            opening.result.createObjectStore(store);
    };
    const database = await requestResult(opening);
    try {
        const key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
        const transaction = database.transaction(
            ['key', 'root', 'head'],
            'readwrite',
        );
        const written = new Promise<void>((resolve, reject) => {
            transaction.oncomplete = () => resolve();
            transaction.onabort = () =>
                reject(transaction.error ?? new Error('Aborted.'));
        });
        transaction.objectStore('key').put(key, 0);
        transaction
            .objectStore('root')
            .put(crypto.getRandomValues(new Uint8Array(96)), 0);
        if (head !== undefined) transaction.objectStore('head').put(head, 0);
        await written;
    } finally {
        database.close();
    }
};
const otherRuntime = 'b3'.repeat(64);
const rootHash = 'e1'.repeat(64);

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
                    reason: 'no participant',
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

    it('refuses a participant that another runtime created and leaves its state unchanged', async () => {
        for (const [head, refusal] of [
            [
                { generation: 5, hash: rootHash, runtime: otherRuntime },
                {
                    status: 'refused',
                    reason: 'another runtime',
                    runtime: otherRuntime,
                },
            ],
            // A head that a runtime before the head named its runtime wrote.
            [
                { generation: 5, hash: rootHash },
                { status: 'refused', reason: 'another runtime' },
            ],
        ] as const) {
            const namespace = `another-${crypto.randomUUID()}`;
            const name = `sealed-lattice-participant/${namespace}`;
            try {
                await writeParticipant(name, head);
                const participant = openParticipant({
                    namespace,
                    relay: location.origin + '/',
                });
                for (const request of [
                    { operation: 'status' },
                    { operation: 'result' },
                ] as const)
                    expect(await participant.run(request)).toEqual(refusal);
                const counts = await storeCounts(name);
                expect(counts.key).toBe(1);
                expect(counts.root).toBe(1);
                expect(counts.head).toBe(1);
                expect(counts.stopped).toBe(0);
            } finally {
                await requestResult(indexedDB.deleteDatabase(name));
            }
        }
    });

    it('stops a participant whose authority is damaged, and it stays stopped', async () => {
        for (const head of [
            undefined,
            { generation: 5, hash: rootHash, runtime: 'not a runtime' },
        ]) {
            const namespace = `damaged-${crypto.randomUUID()}`;
            const name = `sealed-lattice-participant/${namespace}`;
            try {
                await writeParticipant(name, head);
                const participant = openParticipant({
                    namespace,
                    relay: location.origin + '/',
                });
                for (let visit = 0; visit < 2; visit++)
                    expect(
                        await participant.run({ operation: 'status' }),
                    ).toEqual({
                        status: 'stopped',
                        reason: 'Missing or inconsistent participant authority.',
                        stopPersistence: 'confirmed',
                    });
                expect((await storeCounts(name)).stopped).toBe(1);
            } finally {
                await requestResult(indexedDB.deleteDatabase(name));
            }
        }
    });
});
