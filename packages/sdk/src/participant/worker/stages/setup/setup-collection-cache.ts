import type { OfferDiscoveryProgress } from '../../relay/offer-discovery.js';
import { StorageFailure } from '../../shared/failures.js';
import {
    requestResult,
    transactionCompletion,
} from '../../storage/database.js';

const storeName = 'collection';
export type CollectionKind = 'offer' | 'sum' | 'job' | 'proof';

export const writeCollection = async (
    cache: IDBDatabase,
    write: (store: IDBObjectStore) => void,
) => {
    try {
        const transaction = cache.transaction(storeName, 'readwrite', {
            durability: 'strict',
        });
        const done = transactionCompletion(transaction);
        write(transaction.objectStore(storeName));
        await done;
    } catch {
        throw new StorageFailure('The setup collection cache refused a write.');
    }
};

export const clearCollectionKind = (cache: IDBDatabase, kind: CollectionKind) =>
    writeCollection(cache, (store) =>
        store.delete(IDBKeyRange.bound([kind], [kind, []])),
    );

export const collectionBlob = async (cache: IDBDatabase, key: IDBValidKey) => {
    let value: unknown;
    try {
        const transaction = cache.transaction(storeName, 'readonly');
        [value] = await Promise.all([
            requestResult<unknown>(transaction.objectStore(storeName).get(key)),
            transactionCompletion(transaction),
        ]);
    } catch {
        throw new StorageFailure('The setup collection cache refused a read.');
    }
    if (value === undefined) return undefined;
    if (!(value instanceof Blob))
        throw new StorageFailure('A setup collection record is malformed.');
    return value;
};

export const collectionBytes = async (
    cache: IDBDatabase,
    key: IDBValidKey,
    length: number,
) => {
    const value = await collectionBlob(cache, key);
    if (value?.size !== length)
        throw new StorageFailure('A setup collection record is missing.');
    return collectionBuffer(value);
};

export const collectionBuffer = async (value: Blob) => {
    try {
        return new Uint8Array(await value.arrayBuffer());
    } catch {
        throw new StorageFailure('The setup collection cache refused a read.');
    }
};

export const readDiscoveryProgress = async (
    cache: IDBDatabase,
    authors: number,
): Promise<OfferDiscoveryProgress | undefined> => {
    const blob = await collectionBlob(cache, 'discovery');
    if (blob?.size !== 4 + 17 * authors) return undefined;
    const bytes = await collectionBuffer(blob);
    const view = new DataView(bytes.buffer);
    const nextPosition = view.getUint32(0, true);
    if (nextPosition >= authors) return undefined;
    const positions = [];
    for (let index = 0; index < authors; index++) {
        const start = 4 + 17 * index;
        const initialized = view.getUint8(start);
        const offset = Number(view.getBigUint64(start + 1, true));
        const total = Number(view.getBigUint64(start + 9, true));
        if (
            !Number.isSafeInteger(offset) ||
            !Number.isSafeInteger(total) ||
            initialized > 1 ||
            offset > total ||
            (initialized === 0 && (offset !== 0 || total !== 0))
        )
            return undefined;
        positions.push({ offset, ...(initialized === 0 ? {} : { total }) });
    }
    return { nextPosition, authors: positions };
};

export const saveDiscoveryProgress = async (
    cache: IDBDatabase,
    progress: OfferDiscoveryProgress,
) => {
    const bytes = new Uint8Array(4 + 17 * progress.authors.length);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, progress.nextPosition, true);
    for (const [index, author] of progress.authors.entries()) {
        const start = 4 + 17 * index;
        view.setUint8(start, author.total === undefined ? 0 : 1);
        view.setBigUint64(start + 1, BigInt(author.offset), true);
        view.setBigUint64(start + 9, BigInt(author.total ?? 0), true);
    }
    await writeCollection(cache, (store) =>
        store.put(new Blob([bytes]), 'discovery'),
    );
};

export const collectionWriter = (
    cache: IDBDatabase,
    key: (offset: number) => IDBValidKey,
    capacity: number,
    maximum: number,
) => {
    const buffer = new Uint8Array(capacity);
    let used = 0,
        offset = 0;
    const flush = async () => {
        const bytes = new Blob([buffer.subarray(0, used)]);
        await writeCollection(cache, (store) => store.put(bytes, key(offset)));
        offset += used;
        used = 0;
    };
    return {
        append: async (bytes: Uint8Array) => {
            if (bytes.length > maximum - offset - used)
                throw new StorageFailure(
                    'The setup collection record exceeds its bound.',
                );
            for (let index = 0; index < bytes.length;) {
                const count = Math.min(bytes.length - index, capacity - used);
                buffer.set(bytes.subarray(index, index + count), used);
                used += count;
                index += count;
                if (used === capacity) await flush();
            }
        },
        finish: async () => {
            if (used > 0) await flush();
            return offset;
        },
    };
};

export const moveCollectedAggregate = async (
    cache: IDBDatabase,
    source: IDBValidKey,
    target: IDBValidKey,
    value: Blob,
) => {
    try {
        const transaction = cache.transaction(
            [storeName, 'aggregate'],
            'readwrite',
            { durability: 'strict' },
        );
        const done = transactionCompletion(transaction);
        transaction.objectStore('aggregate').put(value, target);
        transaction.objectStore(storeName).delete(source);
        await done;
    } catch {
        throw new StorageFailure(
            'The collected aggregate could not be retained.',
        );
    }
};
