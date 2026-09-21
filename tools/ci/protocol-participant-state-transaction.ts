export interface ParticipantTransactionReader {
    get(store: string, key: IDBValidKey): Promise<unknown>;
    count(store: string): Promise<number>;
}

// WebCrypto and Blob reads complete outside IDB request tasks. Keep the write
// transaction alive, and dispatch every read/write from an active request
// callback. Validation is private state consistency, not protocol acceptance.
// The validator must await all its work and the writer must be synchronous.
// A rejected call is not proof of rollback: continuation must authenticate the
// exact predecessor independently, including after uncertain browser failures.
export async function commitParticipantState({
    database,
    stores,
    validate,
    write,
    timeoutMilliseconds,
}: {
    database: IDBDatabase;
    stores: readonly string[];
    validate: (reader: ParticipantTransactionReader) => Promise<void>;
    write: (transaction: IDBTransaction) => void;
    timeoutMilliseconds: number;
}): Promise<void> {
    if (
        !stores.includes('head') ||
        !Number.isSafeInteger(timeoutMilliseconds) ||
        timeoutMilliseconds <= 0
    )
        throw new Error('Invalid participant transaction bounds.');
    const transaction = database.transaction([...stores], 'readwrite', {
        durability: 'strict',
    });
    let finished = false,
        validated = false,
        written = false,
        failure: Error | undefined,
        pendingReads = 0;
    const queue: (() => void)[] = [];
    const asError = (error: unknown) =>
        error instanceof Error
            ? error
            : new Error('Participant transaction failed.');
    const abort = (error: unknown) => {
        failure ??= asError(error);
        if (finished) return;
        try {
            transaction.abort();
        } catch (caught) {
            if (
                !(caught instanceof DOMException) ||
                caught.name !== 'InvalidStateError'
            )
                throw caught;
        }
    };
    const requests = new Set<(error: unknown) => void>();
    const read = <Value>(
        operation: () => IDBRequest<Value>,
    ): Promise<Value> => {
        const result = new Promise<Value>((resolve, reject) => {
            if (finished) {
                reject(failure ?? new Error('Participant transaction ended.'));
                return;
            }
            if (validated || written) {
                const error = new Error(
                    'Participant validation already ended.',
                );
                reject(error);
                abort(error);
                return;
            }
            requests.add(reject);
            queue.push(() => {
                try {
                    const request = operation();
                    pendingReads++;
                    request.onsuccess = () => {
                        pendingReads--;
                        requests.delete(reject);
                        resolve(request.result);
                    };
                    request.onerror = () => {
                        pendingReads--;
                        requests.delete(reject);
                        reject(asError(request.error));
                        abort(request.error);
                    };
                } catch (error) {
                    requests.delete(reject);
                    reject(asError(error));
                    abort(error);
                }
            });
        });
        // The transaction owns error propagation even if validation discards
        // a read promise. Observing it here preserves rejection for awaiters.
        void result.catch(() => {});
        return result;
    };
    const reader: ParticipantTransactionReader = {
        get: (store, key) =>
            read(() => transaction.objectStore(store).get(key)),
        count: (store) => read(() => transaction.objectStore(store).count()),
    };
    const done = new Promise<void>((resolve, reject) => {
        const finish = () => {
            finished = true;
            queue.length = 0;
            for (const rejectRead of requests)
                rejectRead(
                    failure ?? new Error('Participant transaction ended.'),
                );
            requests.clear();
        };
        transaction.oncomplete = () => {
            finish();
            if (!written || failure)
                reject(
                    failure ??
                        new Error('Participant transaction committed early.'),
                );
            else resolve();
        };
        transaction.onabort = () => {
            finish();
            reject(
                failure ?? new Error('Participant state transaction aborted.'),
            );
        };
        transaction.onerror = () => abort(transaction.error);
    });
    const timer = setTimeout(
        () => abort(new Error('Participant state validation deadline.')),
        timeoutMilliseconds,
    );
    const pump = () => {
        if (finished || failure) return;
        try {
            const heartbeat = transaction.objectStore('head').get(0);
            heartbeat.onerror = () => abort(heartbeat.error);
            heartbeat.onsuccess = () => {
                if (finished || failure) return;
                while (queue.length && !failure) queue.shift()!();
                if (failure) return;
                if (validated && pendingReads === 0 && queue.length === 0) {
                    try {
                        // This bounds validation, not the browser's commit
                        // operation. oncomplete remains authoritative after
                        // writes have been queued and commit may have begun.
                        clearTimeout(timer);
                        written = true;
                        const result: unknown = write(transaction);
                        if (result !== undefined) {
                            void Promise.resolve(result).catch(() => {});
                            throw new Error(
                                'Participant writes must be synchronous.',
                            );
                        }
                    } catch (error) {
                        abort(error);
                    }
                } else pump();
            };
        } catch (error) {
            abort(error);
        }
    };
    if (transaction.durability !== 'strict')
        abort(new Error('Strict participant durability unavailable.'));
    else {
        pump();
        void Promise.resolve()
            .then(() => validate(reader))
            .then(() => {
                validated = true;
            }, abort);
    }
    try {
        await done;
    } finally {
        clearTimeout(timer);
    }
}
