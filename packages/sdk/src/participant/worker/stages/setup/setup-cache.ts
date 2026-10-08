import type { PublicProfileContext } from '../../module/context.js';
import { PublicInputFailure, ResourceFailure } from '../../shared/failures.js';
import {
    namespacedName,
    requestResult,
    setupCacheName,
    transactionCompletion,
} from '../../storage/database.js';

// The public aggregate cache. It supplies only bytes that the owning Rust
// verifiers check against their exact verified predecessors, and a cache
// failure leaves the participant pending, like any other public input.

const cacheStore = 'aggregate';

// The aggregate cache holds only public bytes; a cache failure leaves the
// participant pending, like any other public input.
export const openSetupCache = async (namespace: string) => {
    const opened = indexedDB.open(namespacedName(setupCacheName, namespace), 1);
    opened.onupgradeneeded = () => opened.result.createObjectStore(cacheStore);
    try {
        return await requestResult(opened);
    } catch {
        throw new PublicInputFailure('The setup cache is unavailable.');
    }
};

export const writeCache = async (
    cache: IDBDatabase,
    write: (store: IDBObjectStore) => void,
) => {
    try {
        const transaction = cache.transaction(cacheStore, 'readwrite', {
            durability: 'strict',
        });
        const done = transactionCompletion(transaction);
        write(transaction.objectStore(cacheStore));
        await done;
    } catch {
        throw new PublicInputFailure('The setup cache refused a write.');
    }
};

// The chunk capacity of one body polynomial, as setup verification streams
// and caches its aggregate: the whole coefficients that fit the module's
// setup chunk capacity.
export const aggregateCapacity = (
    context: PublicProfileContext,
    polynomial: Readonly<{ bytes: number; coefficients: number }>,
) => {
    const width = polynomial.bytes / polynomial.coefficients;
    return Math.floor(context.module.setup_chunk_capacity() / width) * width;
};

// The chunks of an aggregate of the given length: each but the last fills
// the capacity.
type AggregateChunk = Readonly<{ offset: number; length: number }>;

const aggregateChunks = (capacity: number, bytes: number) => {
    const chunks: AggregateChunk[] = [];
    for (let offset = 0; offset < bytes; offset += capacity)
        chunks.push({ offset, length: Math.min(capacity, bytes - offset) });
    return chunks;
};

// Discards every cached aggregate. The next operation that needs the setup then
// verifies it again, which rewrites the cache.
const discardSetupCache = async (namespace: string) => {
    const cache = await openSetupCache(namespace);
    try {
        await writeCache(cache, (store) => store.clear());
    } finally {
        cache.close();
    }
};

// Whether the cache holds a chunk of the final aggregate at every offset
// setup verification writes one. Each consumer checks the bytes it reads
// against the retained setup reference.
export const holdsFinalAggregate = async (context: PublicProfileContext) => {
    const { profile } = context;
    const accepted = profile.setupContributorCount - 1;
    const expected = new Set<string>();
    for (const polynomial of profile.contribution.polynomials)
        for (const { offset } of aggregateChunks(
            aggregateCapacity(context, polynomial),
            polynomial.bytes,
        ))
            expected.add(
                String(polynomial.expandedIndex) + ':' + String(offset),
            );
    const cache = await openSetupCache(context.namespace);
    try {
        const transaction = cache.transaction(cacheStore, 'readonly');
        const range = IDBKeyRange.bound(
            [accepted],
            [accepted + 1],
            false,
            true,
        );
        const [keys] = await Promise.all([
            requestResult(
                transaction.objectStore(cacheStore).getAllKeys(range),
            ),
            transactionCompletion(transaction),
        ]);
        return (
            keys.length === expected.size &&
            keys.every((key) => {
                if (!Array.isArray(key) || key.length !== 3) return false;
                const [, index, offset] = key as unknown[];
                return expected.has(String(index) + ':' + String(offset));
            })
        );
    } catch {
        throw new PublicInputFailure('The setup cache refused a read.');
    } finally {
        cache.close();
    }
};

// Delivers cached final aggregate bytes into the module. Missing or refused
// bytes are not the ones the retained setup reference names, so the cache
// is discarded and the next operation verifies the setup again, which rewrites
// it.
export const deliverFinalAggregate = async (
    context: PublicProfileContext,
    deliver: () => Promise<void>,
) => {
    try {
        await deliver();
    } catch (error) {
        if (!(error instanceof ResourceFailure))
            await discardSetupCache(context.namespace);
        throw error;
    }
};

// Reads one coefficient-aligned chunk. Neither cache rebuild nor a private
// consumer materializes a complete polynomial's encoded bytes in JavaScript.
export const readCachedAggregateChunk = async (
    cache: IDBDatabase,
    accepted: number,
    expandedIndex: number,
    chunk: AggregateChunk,
) => {
    let value: unknown;
    try {
        const transaction = cache.transaction(cacheStore, 'readonly');
        const store = transaction.objectStore(cacheStore);
        [value] = await Promise.all([
            requestResult<unknown>(
                store.get([accepted, expandedIndex, chunk.offset]),
            ),
            transactionCompletion(transaction),
        ]);
    } catch {
        throw new PublicInputFailure('The setup cache refused a read.');
    }
    if (!(value instanceof Blob) || value.size !== chunk.length)
        throw new PublicInputFailure('A cached aggregate chunk is missing.');
    return new Uint8Array(await value.arrayBuffer());
};

// Streams the final public aggregate of one body polynomial from the cache
// in the whole-coefficient chunks setup verification wrote. The consumer
// checks the bytes against the retained setup reference.
export const readFinalAggregate = async (
    context: PublicProfileContext,
    expandedIndex: number,
    consume: (offset: number, bytes: Uint8Array) => void,
) => {
    const { profile } = context;
    const polynomial = profile.contribution.polynomials.find(
        (value) => value.expandedIndex === expandedIndex,
    );
    if (polynomial === undefined)
        throw new Error('No body polynomial has this index.');
    const chunks = aggregateChunks(
        aggregateCapacity(context, polynomial),
        polynomial.bytes,
    );
    const cache = await openSetupCache(context.namespace);
    try {
        for (const chunk of chunks)
            consume(
                chunk.offset,
                await readCachedAggregateChunk(
                    cache,
                    profile.setupContributorCount - 1,
                    expandedIndex,
                    chunk,
                ),
            );
    } finally {
        cache.close();
    }
};
