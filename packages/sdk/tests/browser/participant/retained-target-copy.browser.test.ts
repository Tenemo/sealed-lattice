import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ProfileContext } from '#packages/sdk/src/participant/worker/context.js';
import {
    ModuleFailure,
    ResourceFailure,
} from '#packages/sdk/src/participant/worker/kernel.js';
import { chunkBytes } from '#packages/sdk/src/participant/worker/root.js';
import {
    evaluatedTargetName,
    namespacedName,
} from '#packages/sdk/src/participant/worker/storage.js';
import {
    restoreEvaluation,
    retainEvaluation,
} from '#packages/sdk/src/participant/worker/target.js';

const databases: IDBDatabase[] = [];
const names: string[] = [];
const result = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Fixture read failed.'));
    });
const storeCopy = (database: IDBDatabase, bytes: Blob) =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction('target', 'readwrite');
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error('Fixture write failed.'));
        transaction.objectStore('target').put(bytes, 0);
    });
const storedCopy = (database: IDBDatabase) =>
    result<unknown>(
        database.transaction('target').objectStore('target').get(0),
    );

// Transport stand-ins, not target verification: they record the actual
// begin/append/finish calls and copied bytes. Only the real Rust lifecycle
// gate can establish RET1 authentication or a verified evaluation capability.
const fixture = async (length = 2 * chunkBytes + 37) => {
    const namespace = 'retained-target-' + crypto.randomUUID();
    const name = namespacedName(evaluatedTargetName, namespace);
    names.push(name);
    const opening = indexedDB.open(name, 1);
    opening.onupgradeneeded = () => opening.result.createObjectStore('target');
    const database = await result(opening);
    databases.push(database);
    const bytes = Uint8Array.from(
        { length },
        (_, index) => (index * 17 + 3) % 251,
    );
    bytes.set(new TextEncoder().encode('RET1'));
    const memory = new WebAssembly.Memory({
        initial: Math.ceil((length + 32) / 65536),
    });
    new Uint8Array(memory.buffer, 32, length).set(bytes);
    const calls: [number, number][] = [];
    let copied = 0;
    let equal = true;
    const restore = vi.fn((operation: number, count: number) => {
        calls.push([operation, count]);
        if (operation === 0) {
            copied = 0;
            equal = true;
            return Number(count !== bytes.length);
        }
        if (operation === 1) {
            const incoming = new Uint8Array(memory.buffer, 32, count);
            equal &&= incoming.every(
                (byte, index) => byte === bytes[copied + index],
            );
            copied += count;
            return 0;
        }
        return Number(
            operation !== 2 || count !== 0 || copied !== bytes.length || !equal,
        );
    });
    const kernel = {
        memory,
        retain_evaluation: () => 0,
        contribution_output_pointer: () => 32,
        contribution_output_length: () => bytes.length,
        input_pointer: () => 32,
        input_capacity: () => chunkBytes,
        restore_evaluation: restore,
    };
    const context = { namespace, kernel } as unknown as ProfileContext;
    await storeCopy(database, new Blob([bytes]));
    return { context, database, bytes, kernel, calls, copied: () => copied };
};

afterEach(async () => {
    vi.restoreAllMocks();
    for (const database of databases.splice(0)) database.close();
    for (const name of names.splice(0))
        await result(indexedDB.deleteDatabase(name));
});

describe('retained target bounded copies', () => {
    it('assembles identical immutable bytes from bounded Wasm views at the existing key', async () => {
        const fixed = await fixture();
        const sizes: number[] = [];
        const OriginalBlob = Blob;
        class ObservedBlob extends OriginalBlob {
            constructor(parts: BlobPart[] = [], options?: BlobPropertyBag) {
                for (const part of parts)
                    if (ArrayBuffer.isView(part)) sizes.push(part.byteLength);
                super(parts, options);
            }
        }
        vi.stubGlobal('Blob', ObservedBlob);
        try {
            await retainEvaluation(fixed.context);
        } finally {
            vi.unstubAllGlobals();
        }
        new Uint8Array(fixed.kernel.memory.buffer).fill(0);
        const stored = await storedCopy(fixed.database);
        expect(stored).toBeInstanceOf(Blob);
        expect(new Uint8Array(await (stored as Blob).arrayBuffer())).toEqual(
            fixed.bytes,
        );
        expect(sizes).toEqual([chunkBytes, chunkBytes, 37]);
        const keys = await result(
            fixed.database
                .transaction('target')
                .objectStore('target')
                .getAllKeys(),
        );
        expect(keys).toEqual([0]);
    });

    it('reads one bounded slice at a time from the original immutable snapshot', async () => {
        const fixed = await fixture();
        const sizes: number[] = [];
        vi.spyOn(Blob.prototype, 'arrayBuffer').mockImplementation(
            async function (this: Blob) {
                sizes.push(this.size);
                expect(this.size).toBeLessThanOrEqual(chunkBytes);
                expect(fixed.copied()).toBe(
                    sizes.slice(0, -1).reduce((sum, size) => sum + size, 0),
                );
                if (sizes.length === 1)
                    await storeCopy(
                        fixed.database,
                        new Blob([Uint8Array.of(99)]),
                    );
                return new Response(this).arrayBuffer();
            },
        );
        await expect(restoreEvaluation(fixed.context)).resolves.toBe(true);
        expect(sizes).toEqual([chunkBytes, chunkBytes, 37]);
        expect(fixed.calls).toEqual([
            [0, fixed.bytes.length],
            [1, chunkBytes],
            [1, chunkBytes],
            [1, 37],
            [2, 0],
        ]);
    });

    it('rejects an excessive length before reading or appending any bytes', async () => {
        const fixed = await fixture();
        await storeCopy(
            fixed.database,
            new Blob([fixed.bytes, Uint8Array.of(1)]),
        );
        const read = vi.spyOn(Blob.prototype, 'arrayBuffer');
        await expect(restoreEvaluation(fixed.context)).resolves.toBe(false);
        expect(read).not.toHaveBeenCalled();
        expect(fixed.calls).toEqual([[0, fixed.bytes.length + 1]]);
        expect(await storedCopy(fixed.database)).toBeUndefined();
    });

    it('refuses host sizes that would wrap the Wasm ABI without starting or reading the copy', async () => {
        for (const size of [
            2 ** 32,
            2 ** 32 + 37,
            Number.MAX_SAFE_INTEGER + 1,
            -1,
            1.5,
            Number.NaN,
        ]) {
            const fixed = await fixture(37);
            // Override only the reported size; no enormous payload is
            // materialized. The stored value is still a real immutable Blob.
            const length = vi
                .spyOn(Blob.prototype, 'size', 'get')
                .mockReturnValue(size);
            const slice = vi.spyOn(Blob.prototype, 'slice');
            const read = vi.spyOn(Blob.prototype, 'arrayBuffer');
            await expect(restoreEvaluation(fixed.context)).resolves.toBe(false);
            expect(fixed.calls).toEqual([]);
            expect(slice).not.toHaveBeenCalled();
            expect(read).not.toHaveBeenCalled();
            expect(await storedCopy(fixed.database)).toBeUndefined();
            length.mockRestore();
            slice.mockRestore();
            read.mockRestore();
        }
    });

    it('finishes and discards an incomplete copy when a later Blob slice cannot be read', async () => {
        const fixed = await fixture();
        let reads = 0;
        vi.spyOn(Blob.prototype, 'arrayBuffer').mockImplementation(function (
            this: Blob,
        ) {
            if (++reads === 2)
                return Promise.reject(new DOMException('Unreadable slice.'));
            return new Response(this).arrayBuffer();
        });
        await expect(restoreEvaluation(fixed.context)).resolves.toBe(false);
        expect(fixed.calls).toEqual([
            [0, fixed.bytes.length],
            [1, chunkBytes],
            [2, 0],
        ]);
        expect(await storedCopy(fixed.database)).toBeUndefined();
    });

    it('finishes an incomplete copy after a nonterminal host failure', async () => {
        const fixed = await fixture();
        const failure = new Error('The host input copy failed.');
        fixed.kernel.input_capacity = () => {
            throw failure;
        };
        await expect(restoreEvaluation(fixed.context)).rejects.toBe(failure);
        expect(fixed.calls).toEqual([
            [0, fixed.bytes.length],
            [2, 0],
        ]);
    });

    it('does not finalize after a terminal failure while reading a slice', async () => {
        for (const failure of [
            new ModuleFailure('Module failed during transfer.'),
            new ResourceFailure('Transfer exhausted its bound.'),
        ]) {
            const fixed = await fixture();
            const read = vi
                .spyOn(Blob.prototype, 'arrayBuffer')
                .mockRejectedValue(failure);
            await expect(restoreEvaluation(fixed.context)).rejects.toBe(
                failure,
            );
            expect(fixed.calls).toEqual([[0, fixed.bytes.length]]);
            read.mockRestore();
        }
    });

    it('never re-enters a terminal module and preserves its failure over cache cleanup', async () => {
        for (const failure of [
            new ModuleFailure('Module failed.'),
            new ResourceFailure('Bound exhausted.'),
        ]) {
            const fixed = await fixture();
            fixed.kernel.restore_evaluation.mockImplementation(
                (operation, length) => {
                    fixed.calls.push([operation, length]);
                    if (operation === 1) throw failure;
                    return 0;
                },
            );
            await expect(restoreEvaluation(fixed.context)).rejects.toBe(
                failure,
            );
            expect(fixed.calls).toEqual([
                [0, fixed.bytes.length],
                [1, chunkBytes],
            ]);
            expect((await storedCopy(fixed.database)) instanceof Blob).toBe(
                failure instanceof ResourceFailure,
            );
        }
        const fixed = await fixture();
        const failure = new ModuleFailure('Module failed before cleanup.');
        fixed.kernel.restore_evaluation.mockImplementation(() => {
            throw failure;
        });
        const transaction = fixed.database.transaction.bind(fixed.database);
        const refused = vi
            .spyOn(IDBDatabase.prototype, 'transaction')
            .mockImplementation(
                (...arguments_: Parameters<IDBDatabase['transaction']>) => {
                    if (arguments_[1] === 'readwrite')
                        throw new DOMException('Cache unavailable.');
                    return transaction(...arguments_);
                },
            );
        await expect(restoreEvaluation(fixed.context)).rejects.toBe(failure);
        expect(fixed.kernel.restore_evaluation).toHaveBeenCalledTimes(1);
        refused.mockRestore();
    });

    it('observes request-error and transaction-abort cleanup failures without hiding the terminal cause', async () => {
        for (const synchronous of [false, true]) {
            const fixed = await fixture(37);
            const failure = new ModuleFailure(
                'Module failed before an aborted cleanup.',
            );
            fixed.kernel.restore_evaluation.mockImplementation(() => {
                throw failure;
            });
            const events: string[] = [];
            let aborted: Promise<void> | undefined;
            const original = Object.getOwnPropertyDescriptor(
                IDBObjectStore.prototype,
                'clear',
            )?.value as
                ((this: IDBObjectStore) => IDBRequest<undefined>) | undefined;
            if (original === undefined)
                throw new Error('No native clear implementation.');
            const clear = vi.spyOn(IDBObjectStore.prototype, 'clear');
            clear.mockImplementation(function (this: IDBObjectStore) {
                const request = original.call(this);
                request.addEventListener('error', () =>
                    events.push('request error'),
                );
                aborted = new Promise<void>((resolve) => {
                    this.transaction.addEventListener('abort', () => {
                        events.push('transaction abort');
                        resolve();
                    });
                });
                this.transaction.abort();
                if (synchronous)
                    throw new Error(
                        'The request factory failed after queuing work.',
                    );
                return request;
            });
            const unhandled = vi.fn();
            window.addEventListener('unhandledrejection', unhandled);
            try {
                await expect(restoreEvaluation(fixed.context)).rejects.toBe(
                    failure,
                );
                await aborted;
                // Give the browser its rejection-reporting checkpoint after
                // the real request error and transaction abort have fired.
                await new Promise<void>((resolve) => setTimeout(resolve, 0));
                expect(events).toEqual(['request error', 'transaction abort']);
                expect(unhandled).not.toHaveBeenCalled();
                expect(fixed.kernel.restore_evaluation).toHaveBeenCalledTimes(
                    1,
                );
            } finally {
                window.removeEventListener('unhandledrejection', unhandled);
                clear.mockRestore();
            }
            expect(await storedCopy(fixed.database)).toBeInstanceOf(Blob);
        }
    });
});
