import { describe, expect, it } from 'vitest';

import {
    openUntrustedStorageTransactionStore,
    UntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAtomicMutation,
    type UntrustedStorageAuthenticator,
    type UntrustedStorageRepairReport,
    type UntrustedStorageTransactionErrorCode,
    type UntrustedStorageTransactionLimits,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
import { authenticatedRepairProtectionForTestAdapter } from '#packages/protocol/tests/support/runtime-storage-test-support';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const bytesEqual = (
    left: Uint8Array | undefined,
    right: Uint8Array | undefined,
): boolean => {
    if (left === undefined || right === undefined) {
        return left === right;
    }
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }

    return true;
};

class DeterministicInMemoryStorageAdapter implements UntrustedStorageAdapter {
    #values = new Map<string, Uint8Array>();
    public afterNextAtomicMutation: (() => void) | undefined;
    public beforeNextAtomicMutation: (() => void) | undefined;
    public beforeNextUnreferencedObjectDeletion: (() => void) | undefined;
    public failNextAtomicMutationCount = 0;
    public failNextDeleteCount = 0;
    public forceNextAtomicConflict = false;
    public returnAliasedReads = false;
    public returnSubviewReads = false;
    #mostRecentlyReturnedBuffer: Uint8Array | undefined;

    public read(key: string): Promise<Uint8Array | undefined> {
        const storedValue = this.#values.get(key);
        let returnedValue = this.returnAliasedReads
            ? storedValue
            : storedValue?.slice();
        if (this.returnSubviewReads && returnedValue !== undefined) {
            const paddedValue = new Uint8Array(returnedValue.byteLength + 2);
            paddedValue.set(returnedValue, 1);
            returnedValue = paddedValue.subarray(1, paddedValue.byteLength - 1);
        }
        this.#mostRecentlyReturnedBuffer = returnedValue;
        return Promise.resolve(returnedValue);
    }

    public write(key: string, value: Uint8Array): Promise<void> {
        this.#values.set(key, value.slice());
        return Promise.resolve();
    }

    public delete(key: string): Promise<void> {
        if (this.failNextDeleteCount > 0) {
            this.failNextDeleteCount -= 1;
            return Promise.reject(new Error('injected delete failure'));
        }
        this.#values.delete(key);
        return Promise.resolve();
    }

    public listKeys(prefix: string): Promise<readonly string[]> {
        return Promise.resolve(
            [...this.#values.keys()]
                .filter((key) => key.startsWith(prefix))
                .sort(),
        );
    }

    public deleteUnreferencedObjects(input: {
        indexPrefix: string;
        objectKeys: readonly string[];
    }): Promise<boolean> {
        const beforeDeletion = this.beforeNextUnreferencedObjectDeletion;
        this.beforeNextUnreferencedObjectDeletion = undefined;
        beforeDeletion?.();
        const referencedObjectKeys = new Set(
            [...this.#values.entries()]
                .filter(([key]) => key.startsWith(input.indexPrefix))
                .map(([, value]) => textDecoder.decode(value)),
        );
        if (
            input.objectKeys.some((objectKey) =>
                referencedObjectKeys.has(objectKey),
            )
        ) {
            return Promise.resolve(false);
        }
        for (const objectKey of input.objectKeys) {
            this.#values.delete(objectKey);
        }
        return Promise.resolve(true);
    }

    public applyAtomicMutation(
        mutation: UntrustedStorageAtomicMutation,
    ): Promise<boolean> {
        const beforeMutation = this.beforeNextAtomicMutation;
        this.beforeNextAtomicMutation = undefined;
        beforeMutation?.();

        if (this.failNextAtomicMutationCount > 0) {
            this.failNextAtomicMutationCount -= 1;
            return Promise.reject(
                new Error('injected atomic mutation failure'),
            );
        }
        if (this.forceNextAtomicConflict) {
            this.forceNextAtomicConflict = false;
            return Promise.resolve(false);
        }
        for (const expectedValue of mutation.expectedValues) {
            if (
                !bytesEqual(
                    this.#values.get(expectedValue.key),
                    expectedValue.value,
                )
            ) {
                return Promise.resolve(false);
            }
        }

        const nextValues = new Map<string, Uint8Array>(
            [...this.#values.entries()].map(
                ([key, value]) => [key, value.slice()] as const,
            ),
        );
        for (const key of mutation.deletes) {
            nextValues.delete(key);
        }
        for (const write of mutation.writes) {
            nextValues.set(write.key, write.value.slice());
        }
        this.#values = nextValues;

        const afterMutation = this.afterNextAtomicMutation;
        this.afterNextAtomicMutation = undefined;
        afterMutation?.();

        return Promise.resolve(true);
    }

    public keys(): readonly string[] {
        return [...this.#values.keys()].sort();
    }

    public rawDelete(key: string): void {
        this.#values.delete(key);
    }

    public rawRead(key: string): Uint8Array | undefined {
        return this.#values.get(key)?.slice();
    }

    public rawWrite(key: string, value: Uint8Array): void {
        this.#values.set(key, value.slice());
    }
    public mutateMostRecentlyReturnedBuffer(bytes: Uint8Array): void {
        if (this.#mostRecentlyReturnedBuffer === undefined) {
            throw new Error('no adapter-returned buffer is available');
        }
        if (this.#mostRecentlyReturnedBuffer.byteLength !== bytes.byteLength) {
            throw new Error('replacement bytes have the wrong length');
        }
        this.#mostRecentlyReturnedBuffer.set(bytes);
    }
}

const defaultLimits: UntrustedStorageTransactionLimits = {
    maximumActiveTransactionCount: 4,
    maximumLeaseByteLength: 1_024,
    maximumLeaseCountPerTransaction: 4,
    maximumOwnedRecordCount: 64,
    maximumStoredValueByteLength: 16_384,
    maximumTransactionByteLength: 2_048,
    maximumTransactionLifetimeMilliseconds: 1_000,
};

const createDeterministicIdentifierFactory = (
    factoryIdentifier = 0,
): ((kind: 'lease' | 'transaction') => string) => {
    const counts = {
        lease: 0,
        transaction: 0,
    };

    return (kind: 'lease' | 'transaction'): string => {
        counts[kind] += 1;
        const kindCode = kind === 'transaction' ? '01' : '02';
        return `${kindCode}${factoryIdentifier
            .toString(16)
            .padStart(30, '0')}${counts[kind].toString(16).padStart(32, '0')}`;
    };
};

const identifierFilledWithByte = (byte: number): string =>
    byte.toString(16).padStart(2, '0').repeat(32);

const createQueuedIdentifierFactory = (input: {
    lease: readonly string[];
    transaction: readonly string[];
}): ((kind: 'lease' | 'transaction') => string) => {
    const identifiers = {
        lease: [...input.lease],
        transaction: [...input.transaction],
    };

    return (kind) => {
        const identifier = identifiers[kind].shift();
        if (identifier === undefined) {
            throw new Error(`no deterministic ${kind} identifier remains`);
        }

        return identifier;
    };
};

const openTestStore = async (input?: {
    adapter?: DeterministicInMemoryStorageAdapter;
    createIdentifier?: (kind: 'lease' | 'transaction') => string;
    limits?: Partial<UntrustedStorageTransactionLimits>;
    monotonicClockMilliseconds?: () => number;
    namespace?: string;
}): Promise<{
    adapter: DeterministicInMemoryStorageAdapter;
    repairReport: UntrustedStorageRepairReport;
    store: UntrustedStorageTransactionStore;
}> => {
    const adapter = input?.adapter ?? new DeterministicInMemoryStorageAdapter();
    const namespace = input?.namespace ?? 'test-runtime';
    const result = await openUntrustedStorageTransactionStore({
        adapter,
        authenticatedRepairProtection:
            await authenticatedRepairProtectionForTestAdapter(
                adapter,
                namespace,
            ),
        createIdentifier:
            input?.createIdentifier ?? createDeterministicIdentifierFactory(),
        limits: { ...defaultLimits, ...input?.limits },
        monotonicClockMilliseconds:
            input?.monotonicClockMilliseconds ?? (() => 0),
        namespace,
    });

    return { adapter, ...result };
};

const exactAuthenticator =
    (
        expectedLogicalRecordKey: string,
        expectedBytes: Uint8Array,
        invocationCounter?: { count: number },
    ): UntrustedStorageAuthenticator =>
    ({ bytes, logicalRecordKey }) => {
        if (invocationCounter !== undefined) {
            invocationCounter.count += 1;
        }
        if (logicalRecordKey !== expectedLogicalRecordKey) {
            throw new Error('logical record key mismatch');
        }
        if (!bytesEqual(bytes, expectedBytes)) {
            throw new Error('stored byte authentication mismatch');
        }
    };

const expectStorageError = async (
    operation: Promise<unknown>,
    code: UntrustedStorageTransactionErrorCode,
): Promise<void> => {
    await expect(operation).rejects.toMatchObject({
        code,
        name: 'UntrustedStorageTransactionError',
    });
};

const requiredRawValue = (
    adapter: DeterministicInMemoryStorageAdapter,
    key: string,
): Uint8Array => {
    const value = adapter.rawRead(key);
    if (value === undefined) {
        throw new Error(`expected raw storage value for ${key}`);
    }

    return value;
};

const writeRecord = async (
    store: UntrustedStorageTransactionStore,
    logicalRecordKey: string,
    bytes: Uint8Array,
): Promise<void> => {
    const transaction = await store.beginTransaction({
        lifetimeMilliseconds: 100,
    });
    const lease = await transaction.issueWriteLease({
        declaredByteLength: bytes.byteLength,
        logicalRecordKey,
    });
    await lease.write(bytes);
    await lease.seal(exactAuthenticator(logicalRecordKey, bytes));
    await transaction.commit();
};

const indexKey = (namespace: string, logicalRecordKey: string): string =>
    `sealed-lattice-runtime-store/${namespace}/indices/${Array.from(
        textEncoder.encode(logicalRecordKey),
        (byte) => byte.toString(16).padStart(2, '0'),
    ).join('')}`;

const maximumIndexValueByteLength = (namespace: string): number =>
    textEncoder.encode(`sealed-lattice-runtime-store/${namespace}/objects/`)
        .byteLength +
    64 +
    1 +
    64;

describe('untrusted storage transaction store', () => {
    it('publishes authenticated copy-on-write bytes and preserves copy boundaries', async () => {
        const { adapter, store } = await openTestStore();
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 4,
            logicalRecordKey: 'checkpoint/manifest',
        });
        const sourceBytes = new Uint8Array([1, 2, 3, 4]);
        const expectedBytes = sourceBytes.slice();
        const authenticationInvocations = { count: 0 };

        await lease.write(sourceBytes);
        sourceBytes.fill(99);
        await lease.seal(
            exactAuthenticator(
                'checkpoint/manifest',
                expectedBytes,
                authenticationInvocations,
            ),
        );
        expect(lease.state()).toBe('sealed');

        await transaction.commit();
        expect(lease.state()).toBe('consumed');
        expect(authenticationInvocations.count).toBe(3);
        await transaction.commit();

        const restoredBytes = await store.readAuthenticated({
            authenticate: exactAuthenticator(
                'checkpoint/manifest',
                expectedBytes,
                authenticationInvocations,
            ),
            logicalRecordKey: 'checkpoint/manifest',
        });
        expect(restoredBytes).toEqual(expectedBytes);
        restoredBytes?.fill(88);
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'checkpoint/manifest',
                    expectedBytes,
                ),
                logicalRecordKey: 'checkpoint/manifest',
            }),
        ).toEqual(expectedBytes);
        expect(authenticationInvocations.count).toBe(4);
        expect(
            adapter.keys().filter((key) => key.includes('/objects/')),
        ).toHaveLength(1);
        await expectStorageError(transaction.abort(), 'InvalidState');
    });

    it('consumes an authenticated owned record without a return copy and rechecks its coordinate', async () => {
        const { adapter, store } = await openTestStore();
        const firstBytes = new Uint8Array([1, 2, 3, 4]);
        await writeRecord(store, 'record-a', firstBytes);
        await writeRecord(store, 'record-b', new Uint8Array([8, 7, 6]));
        const secondObjectKey = textDecoder.decode(
            requiredRawValue(adapter, indexKey('test-runtime', 'record-b')),
        );
        let consumedBytes: Uint8Array | undefined;

        await expectStorageError(
            store.consumeAuthenticated({
                consume: ({ bytes, logicalRecordKey }) => {
                    expect(logicalRecordKey).toBe('record-a');
                    expect(bytes).toEqual(firstBytes);
                    expect(bytes.byteOffset).toBe(0);
                    expect(bytes.byteLength).toBe(bytes.buffer.byteLength);
                    consumedBytes = bytes;
                    structuredClone(bytes.buffer, { transfer: [bytes.buffer] });
                    adapter.rawWrite(
                        indexKey('test-runtime', 'record-a'),
                        textEncoder.encode(secondObjectKey),
                    );
                },
                logicalRecordKey: 'record-a',
            }),
            'Conflict',
        );
        expect(consumedBytes?.byteLength).toBe(0);
    });

    it('rejects an authenticated consumer that retains or receives non-owned adapter bytes', async () => {
        const first = await openTestStore({ namespace: 'retained-consumer' });
        await writeRecord(first.store, 'record', new Uint8Array([1, 2, 3, 4]));
        let retainedBytes: Uint8Array | undefined;
        await expectStorageError(
            first.store.consumeAuthenticated({
                consume: ({ bytes }) => {
                    retainedBytes = bytes;
                },
                logicalRecordKey: 'record',
            }),
            'AuthenticationFailed',
        );
        expect(retainedBytes?.byteLength).toBe(0);

        const second = await openTestStore({ namespace: 'subview-adapter' });
        await writeRecord(second.store, 'record', new Uint8Array([4, 3, 2, 1]));
        second.adapter.returnSubviewReads = true;
        await expectStorageError(
            second.store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'record',
                    new Uint8Array([4, 3, 2, 1]),
                ),
                logicalRecordKey: 'record',
            }),
            'AdapterFailure',
        );
    });

    it('replaces and deletes records without exposing old physical objects', async () => {
        const { adapter, store } = await openTestStore();
        await writeRecord(store, 'record-a', new Uint8Array([1, 2]));
        const firstObjectKey = textDecoder.decode(
            requiredRawValue(adapter, indexKey('test-runtime', 'record-a')),
        );

        await writeRecord(store, 'record-a', new Uint8Array([7, 8, 9]));
        const secondObjectKey = textDecoder.decode(
            requiredRawValue(adapter, indexKey('test-runtime', 'record-a')),
        );
        expect(secondObjectKey).not.toBe(firstObjectKey);
        expect(adapter.rawRead(firstObjectKey)).toBeUndefined();
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'record-a',
                    new Uint8Array([7, 8, 9]),
                ),
                logicalRecordKey: 'record-a',
            }),
        ).toEqual(new Uint8Array([7, 8, 9]));

        const deleteTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await deleteTransaction.stageDeletion('record-a');
        await deleteTransaction.commit();
        await deleteTransaction.commit();
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'record-a',
                    new Uint8Array([7, 8, 9]),
                ),
                logicalRecordKey: 'record-a',
            }),
        ).toBeUndefined();
        expect(adapter.rawRead(secondObjectKey)).toBeUndefined();

        const missingDeleteTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await missingDeleteTransaction.stageDeletion('record-a');
        await missingDeleteTransaction.commit();
    });

    it('cancels and aborts leases idempotently while releasing reservations', async () => {
        const { adapter, store } = await openTestStore({
            limits: {
                maximumLeaseByteLength: 5,
                maximumTransactionByteLength: 5,
            },
        });
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const cancelledLease = await transaction.issueWriteLease({
            declaredByteLength: 5,
            logicalRecordKey: 'cancelled',
        });
        await cancelledLease.write(new Uint8Array([1, 2, 3, 4, 5]));
        await cancelledLease.cancel();
        await cancelledLease.cancel();
        expect(cancelledLease.state()).toBe('cancelled');

        const replacementLease = await transaction.issueWriteLease({
            declaredByteLength: 5,
            logicalRecordKey: 'replacement',
        });
        await replacementLease.write(new Uint8Array([5, 4, 3, 2, 1]));
        await transaction.abort();
        await transaction.abort();
        expect(replacementLease.state()).toBe('cancelled');
        expect(
            adapter.keys().filter((key) => key.includes('/objects/')),
        ).toEqual([]);
        await expectStorageError(transaction.commit(), 'InvalidState');
    });

    it('rejects tampering at seal, before atomic publication, and during atomic publication', async () => {
        const { adapter, store } = await openTestStore();
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 3,
            logicalRecordKey: 'tamper-before-seal',
        });
        await lease.write(new Uint8Array([1, 2, 3]));
        const stagedObjectKey = adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        expect(stagedObjectKey).toBeDefined();
        adapter.rawWrite(stagedObjectKey ?? '', new Uint8Array([3, 2, 1]));
        await expectStorageError(
            lease.seal(
                exactAuthenticator(
                    'tamper-before-seal',
                    new Uint8Array([1, 2, 3]),
                ),
            ),
            'AuthenticationFailed',
        );
        await transaction.abort();

        const precommitTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const precommitLease = await precommitTransaction.issueWriteLease({
            declaredByteLength: 3,
            logicalRecordKey: 'tamper-before-commit',
        });
        await precommitLease.write(new Uint8Array([4, 5, 6]));
        await precommitLease.seal(
            exactAuthenticator(
                'tamper-before-commit',
                new Uint8Array([4, 5, 6]),
            ),
        );
        const precommitObjectKey = adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        adapter.rawWrite(precommitObjectKey ?? '', new Uint8Array([6, 5, 4]));
        await expectStorageError(
            precommitTransaction.commit(),
            'AuthenticationFailed',
        );
        await precommitTransaction.abort();

        const atomicTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const atomicLease = await atomicTransaction.issueWriteLease({
            declaredByteLength: 3,
            logicalRecordKey: 'tamper-during-commit',
        });
        await atomicLease.write(new Uint8Array([7, 8, 9]));
        await atomicLease.seal(
            exactAuthenticator(
                'tamper-during-commit',
                new Uint8Array([7, 8, 9]),
            ),
        );
        const atomicObjectKey = adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        adapter.beforeNextAtomicMutation = () => {
            adapter.rawWrite(atomicObjectKey ?? '', new Uint8Array([9, 8, 7]));
        };
        await expectStorageError(atomicTransaction.commit(), 'Conflict');
        expect(atomicLease.state()).toBe('sealed');
        await atomicTransaction.abort();
    });

    it('keeps a committed transaction uncleaned until publication authentication succeeds', async () => {
        const { adapter, store } = await openTestStore();
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const expectedBytes = new Uint8Array([10, 11, 12]);
        const lease = await transaction.issueWriteLease({
            declaredByteLength: expectedBytes.byteLength,
            logicalRecordKey: 'post-publication',
        });
        await lease.write(expectedBytes);
        await lease.seal(exactAuthenticator('post-publication', expectedBytes));
        const stagedObjectKey = adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        adapter.afterNextAtomicMutation = () => {
            adapter.rawWrite(
                stagedObjectKey ?? '',
                new Uint8Array([12, 11, 10]),
            );
        };

        await expectStorageError(transaction.commit(), 'AuthenticationFailed');
        expect(lease.state()).toBe('claimed');
        await expectStorageError(transaction.abort(), 'InvalidState');

        adapter.rawWrite(stagedObjectKey ?? '', expectedBytes);
        await transaction.commit();
        expect(lease.state()).toBe('consumed');
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'post-publication',
                    expectedBytes,
                ),
                logicalRecordKey: 'post-publication',
            }),
        ).toEqual(expectedBytes);
    });

    it('releases failed wrapper ownership after post-commit authentication and abort cleanup failures', async () => {
        const postCommitStore = await openTestStore({
            namespace: 'close-post-commit',
        });
        const postCommitTransaction =
            await postCommitStore.store.beginTransaction({
                lifetimeMilliseconds: 100,
            });
        const expectedBytes = new Uint8Array([21, 22, 23]);
        const postCommitLease = await postCommitTransaction.issueWriteLease({
            declaredByteLength: expectedBytes.byteLength,
            logicalRecordKey: 'post-commit-failure',
        });
        await postCommitLease.write(expectedBytes);
        await postCommitLease.seal(
            exactAuthenticator('post-commit-failure', expectedBytes),
        );
        const stagedObjectKey = postCommitStore.adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        postCommitStore.adapter.afterNextAtomicMutation = () => {
            postCommitStore.adapter.rawWrite(
                stagedObjectKey ?? '',
                new Uint8Array([23, 22, 21]),
            );
        };

        await expectStorageError(
            postCommitTransaction.commit(),
            'AuthenticationFailed',
        );
        const postCommitPublicationDispositions: string[] = [];
        await postCommitTransaction.closeAfterFailure((disposition) => {
            postCommitPublicationDispositions.push(disposition);
        });
        await postCommitTransaction.closeAfterFailure((disposition) => {
            postCommitPublicationDispositions.push(disposition);
        });
        expect(postCommitPublicationDispositions).toEqual([
            'published-or-indeterminate',
            'published-or-indeterminate',
        ]);
        await expectStorageError(
            postCommitTransaction.commit(),
            'InvalidState',
        );
        await expect(postCommitStore.store.repair()).resolves.toMatchObject({
            retainedObjectCount: 1,
        });

        const abortStore = await openTestStore({
            namespace: 'close-abort-cleanup',
        });
        const abortTransaction = await abortStore.store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const abortLease = await abortTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'abort-cleanup-failure',
        });
        await abortLease.write(new Uint8Array([7]));
        await abortLease.seal(
            exactAuthenticator('abort-cleanup-failure', new Uint8Array([7])),
        );
        abortStore.adapter.failNextDeleteCount = 1;

        await expectStorageError(
            abortTransaction.closeAfterFailure(),
            'CleanupFailed',
        );
        await expect(abortStore.store.repair()).resolves.toMatchObject({
            removedUnreferencedObjectCount: 1,
            retainedObjectCount: 0,
        });
        await expectStorageError(abortTransaction.commit(), 'InvalidState');
    });

    it('binds atomic publication to the owned bytes authenticated before commit', async () => {
        const { adapter, store } = await openTestStore();
        const expectedBytes = new Uint8Array([4, 5, 6]);
        let authenticationInvocationCount = 0;
        const authenticator: UntrustedStorageAuthenticator = async (input) => {
            authenticationInvocationCount += 1;
            await exactAuthenticator('aliased-lease', expectedBytes)(input);
            if (authenticationInvocationCount === 2) {
                await Promise.resolve();
                adapter.mutateMostRecentlyReturnedBuffer(
                    new Uint8Array([6, 5, 4]),
                );
            }
        };
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: expectedBytes.byteLength,
            logicalRecordKey: 'aliased-lease',
        });
        await lease.write(expectedBytes);
        await lease.seal(authenticator);
        adapter.returnAliasedReads = true;

        await expectStorageError(transaction.commit(), 'AuthenticationFailed');
        expect(lease.state()).toBe('sealed');
        expect(
            adapter.rawRead(indexKey('test-runtime', 'aliased-lease')),
        ).toBeUndefined();
        await transaction.abort();
    });

    it('resolves competing copy-on-write transactions with compare-and-swap conflict detection', async () => {
        const { store } = await openTestStore();
        await writeRecord(store, 'shared-record', new Uint8Array([1]));

        const firstTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const secondTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const firstLease = await firstTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'shared-record',
        });
        const secondLease = await secondTransaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'shared-record',
        });
        await firstLease.write(new Uint8Array([2]));
        await firstLease.seal(
            exactAuthenticator('shared-record', new Uint8Array([2])),
        );
        await secondLease.write(new Uint8Array([3]));
        await secondLease.seal(
            exactAuthenticator('shared-record', new Uint8Array([3])),
        );

        await firstTransaction.commit();
        await expectStorageError(secondTransaction.commit(), 'Conflict');
        expect(secondLease.state()).toBe('sealed');
        await secondTransaction.abort();
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'shared-record',
                    new Uint8Array([2]),
                ),
                logicalRecordKey: 'shared-record',
            }),
        ).toEqual(new Uint8Array([2]));
    });

    it('fails closed when another store instance advances the authenticated head', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const { store: firstStore } = await openTestStore({
            adapter,
            createIdentifier: createDeterministicIdentifierFactory(1),
        });
        const { store: secondStore } = await openTestStore({
            adapter,
            createIdentifier: createDeterministicIdentifierFactory(2),
        });

        await expect(
            secondStore.readAuthenticated({
                authenticate: exactAuthenticator(
                    'shared-record',
                    new Uint8Array(),
                ),
                logicalRecordKey: 'shared-record',
            }),
        ).resolves.toBeUndefined();
        await writeRecord(firstStore, 'shared-record', new Uint8Array([1]));

        await expectStorageError(
            secondStore.beginTransaction({ lifetimeMilliseconds: 100 }),
            'AuthenticationFailed',
        );
        await expectStorageError(
            secondStore.readAuthenticated({
                authenticate: exactAuthenticator(
                    'shared-record',
                    new Uint8Array([1]),
                ),
                logicalRecordKey: 'shared-record',
            }),
            'AuthenticationFailed',
        );
        const { store: reopenedStore } = await openTestStore({
            adapter,
            createIdentifier: createDeterministicIdentifierFactory(3),
        });
        await expect(
            reopenedStore.readAuthenticated({
                authenticate: exactAuthenticator(
                    'shared-record',
                    new Uint8Array([1]),
                ),
                logicalRecordKey: 'shared-record',
            }),
        ).resolves.toEqual(new Uint8Array([1]));
    });

    it('publishes multi-record changes atomically when one expected index conflicts', async () => {
        const { store } = await openTestStore();
        await writeRecord(store, 'record-one', new Uint8Array([1]));
        await writeRecord(store, 'record-two', new Uint8Array([2]));

        const candidate = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const candidateOne = await candidate.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'record-one',
        });
        const candidateTwo = await candidate.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'record-two',
        });

        const competitor = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const competitorOne = await competitor.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'record-one',
        });
        await candidateOne.write(new Uint8Array([10]));
        await candidateOne.seal(
            exactAuthenticator('record-one', new Uint8Array([10])),
        );
        await candidateTwo.write(new Uint8Array([20]));
        await candidateTwo.seal(
            exactAuthenticator('record-two', new Uint8Array([20])),
        );
        await competitorOne.write(new Uint8Array([11]));
        await competitorOne.seal(
            exactAuthenticator('record-one', new Uint8Array([11])),
        );
        await competitor.commit();

        await expectStorageError(candidate.commit(), 'Conflict');
        await candidate.abort();
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'record-one',
                    new Uint8Array([11]),
                ),
                logicalRecordKey: 'record-one',
            }),
        ).toEqual(new Uint8Array([11]));
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'record-two',
                    new Uint8Array([2]),
                ),
                logicalRecordKey: 'record-two',
            }),
        ).toEqual(new Uint8Array([2]));
    });

    it('enforces lease, transaction, count, active, and declared-length quotas', async () => {
        const { store } = await openTestStore({
            limits: {
                maximumActiveTransactionCount: 2,
                maximumLeaseByteLength: 5,
                maximumLeaseCountPerTransaction: 2,
                maximumTransactionByteLength: 7,
            },
        });
        const firstTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await expectStorageError(
            firstTransaction.issueWriteLease({
                declaredByteLength: 6,
                logicalRecordKey: 'too-large-lease',
            }),
            'QuotaExceeded',
        );
        const firstLease = await firstTransaction.issueWriteLease({
            declaredByteLength: 5,
            logicalRecordKey: 'first',
        });
        await expectStorageError(
            firstTransaction.issueWriteLease({
                declaredByteLength: 3,
                logicalRecordKey: 'too-large-transaction',
            }),
            'QuotaExceeded',
        );
        const secondLease = await firstTransaction.issueWriteLease({
            declaredByteLength: 2,
            logicalRecordKey: 'second',
        });
        await expectStorageError(
            firstTransaction.stageDeletion('third-change'),
            'QuotaExceeded',
        );
        await expectStorageError(
            firstLease.write(new Uint8Array([1, 2, 3, 4])),
            'MalformedLength',
        );

        const secondTransaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await expectStorageError(
            store.beginTransaction({ lifetimeMilliseconds: 100 }),
            'QuotaExceeded',
        );
        await expectStorageError(
            store.beginTransaction({ lifetimeMilliseconds: 1_001 }),
            'MalformedLength',
        );

        await firstLease.write(new Uint8Array([1, 2, 3, 4, 5]));
        await secondLease.write(new Uint8Array([6, 7]));
        await firstTransaction.abort();
        await secondTransaction.abort();
    });

    it('rejects lone UTF-16 surrogates without rejecting valid supplementary characters', async () => {
        const { store } = await openTestStore();
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        for (const malformedLogicalRecordKey of [
            '\ud800',
            '\udc00',
            'prefix-\ud800-suffix',
            '\ud800\ud800',
        ]) {
            await expectStorageError(
                transaction.issueWriteLease({
                    declaredByteLength: 1,
                    logicalRecordKey: malformedLogicalRecordKey,
                }),
                'MalformedLength',
            );
        }

        const validLogicalRecordKey = 'supplementary-\ud83d\ude42';
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: validLogicalRecordKey,
        });
        await lease.write(new Uint8Array([7]));
        await lease.seal(
            exactAuthenticator(validLogicalRecordKey, new Uint8Array([7])),
        );
        await transaction.commit();
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    validLogicalRecordKey,
                    new Uint8Array([7]),
                ),
                logicalRecordKey: validLogicalRecordKey,
            }),
        ).toEqual(new Uint8Array([7]));
    });

    it('expires only after the exact deadline and cleans staged objects idempotently', async () => {
        let currentTimeMilliseconds = 0.25;
        const { adapter, store } = await openTestStore({
            monotonicClockMilliseconds: () => currentTimeMilliseconds,
        });
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 10,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 2,
            logicalRecordKey: 'expiring',
        });
        await lease.write(new Uint8Array([1, 2]));

        currentTimeMilliseconds = 10.25;
        await lease.seal(
            exactAuthenticator('expiring', new Uint8Array([1, 2])),
        );
        currentTimeMilliseconds = 10.251;
        await expectStorageError(transaction.commit(), 'Expired');
        expect(await store.cleanupExpiredTransactions()).toBe(1);
        expect(await store.cleanupExpiredTransactions()).toBe(0);
        expect(lease.state()).toBe('cancelled');
        expect(
            adapter.keys().filter((key) => key.includes('/objects/')),
        ).toEqual([]);
    });

    it('retries visible post-commit cleanup failures without rolling back publication', async () => {
        const { adapter, store } = await openTestStore();
        await writeRecord(store, 'replace-cleanup', new Uint8Array([1]));
        const oldObjectKey = textDecoder.decode(
            requiredRawValue(
                adapter,
                indexKey('test-runtime', 'replace-cleanup'),
            ),
        );
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'replace-cleanup',
        });
        await lease.write(new Uint8Array([2]));
        await lease.seal(
            exactAuthenticator('replace-cleanup', new Uint8Array([2])),
        );
        adapter.failNextDeleteCount = 1;

        await expectStorageError(transaction.commit(), 'CleanupFailed');
        expect(lease.state()).toBe('consumed');
        expect(adapter.rawRead(oldObjectKey)).toEqual(new Uint8Array([1]));
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'replace-cleanup',
                    new Uint8Array([2]),
                ),
                logicalRecordKey: 'replace-cleanup',
            }),
        ).toEqual(new Uint8Array([2]));

        await transaction.commit();
        await transaction.commit();
        expect(adapter.rawRead(oldObjectKey)).toBeUndefined();
    });

    it('restores retryable transaction state when atomic publication throws', async () => {
        const { adapter, store } = await openTestStore();
        await writeRecord(store, 'retry-after-throw', new Uint8Array([1]));
        const oldObjectKey = textDecoder.decode(
            requiredRawValue(
                adapter,
                indexKey('test-runtime', 'retry-after-throw'),
            ),
        );
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'retry-after-throw',
        });
        await lease.write(new Uint8Array([2]));
        await lease.seal(
            exactAuthenticator('retry-after-throw', new Uint8Array([2])),
        );
        adapter.failNextAtomicMutationCount = 1;

        await expect(transaction.commit()).rejects.toThrow(
            'injected atomic mutation failure',
        );
        expect(lease.state()).toBe('sealed');
        expect(adapter.rawRead(oldObjectKey)).toEqual(new Uint8Array([1]));
        expect(
            textDecoder.decode(
                requiredRawValue(
                    adapter,
                    indexKey('test-runtime', 'retry-after-throw'),
                ),
            ),
        ).toBe(oldObjectKey);

        await transaction.commit();
        expect(lease.state()).toBe('consumed');
        expect(adapter.rawRead(oldObjectKey)).toBeUndefined();
        expect(
            await store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'retry-after-throw',
                    new Uint8Array([2]),
                ),
                logicalRecordKey: 'retry-after-throw',
            }),
        ).toEqual(new Uint8Array([2]));
    });

    it('rejects oversized hostile index and retained object values before decoding or authentication', async () => {
        const oversizedIndexStore = await openTestStore({
            namespace: 'oversized-index',
        });
        oversizedIndexStore.adapter.rawWrite(
            indexKey('oversized-index', 'record'),
            new Uint8Array(maximumIndexValueByteLength('oversized-index') + 1),
        );
        await expectStorageError(
            oversizedIndexStore.store.readAuthenticated({
                authenticate: exactAuthenticator('record', new Uint8Array()),
                logicalRecordKey: 'record',
            }),
            'CorruptIndex',
        );
        await expectStorageError(
            openTestStore({
                adapter: oversizedIndexStore.adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: defaultLimits,
                monotonicClockMilliseconds: () => 0,
                namespace: 'oversized-index',
            }),
            'AuthenticationFailed',
        );

        const oversizedObjectStore = await openTestStore({
            limits: { maximumLeaseByteLength: 4 },
            namespace: 'oversized-object',
        });
        await writeRecord(
            oversizedObjectStore.store,
            'record',
            new Uint8Array([1, 2, 3, 4]),
        );
        await expectStorageError(
            openTestStore({
                adapter: oversizedObjectStore.adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: { ...defaultLimits, maximumLeaseByteLength: 3 },
                monotonicClockMilliseconds: () => 0,
                namespace: 'oversized-object',
            }),
            'MalformedLength',
        );
    });

    it('fails repair when retained storage exceeds the configured total quota', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const namespace = 'over-total-quota';
        const { store } = await openTestStore({ adapter, namespace });
        await writeRecord(store, 'record', new Uint8Array([1]));
        const maximumIndividualValueByteLength = Math.max(
            ...adapter
                .keys()
                .map((key) => requiredRawValue(adapter, key).byteLength),
        );

        await expectStorageError(
            openTestStore({
                adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: {
                    ...defaultLimits,
                    maximumStoredValueByteLength:
                        maximumIndividualValueByteLength,
                },
                monotonicClockMilliseconds: () => 0,
                namespace,
            }),
            'QuotaExceeded',
        );
    });

    it('bounds hostile owned-key enumeration before repair builds record maps', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const namespace = 'owned-record-cap';
        const objectKey =
            `sealed-lattice-runtime-store/${namespace}/objects/` +
            `${identifierFilledWithByte(7)}/${identifierFilledWithByte(8)}`;
        adapter.rawWrite(objectKey, new Uint8Array([1]));
        adapter.rawWrite(
            indexKey(namespace, 'record'),
            textEncoder.encode(objectKey),
        );

        await expectStorageError(
            openTestStore({
                adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: { ...defaultLimits, maximumOwnedRecordCount: 1 },
                monotonicClockMilliseconds: () => 0,
                namespace,
            }),
            'QuotaExceeded',
        );

        const longKeyAdapter = new DeterministicInMemoryStorageAdapter();
        longKeyAdapter.rawWrite(
            `sealed-lattice-runtime-store/${namespace}/indices/${'a'.repeat(2_049)}`,
            new Uint8Array([1]),
        );
        await expectStorageError(
            openTestStore({
                adapter: longKeyAdapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: defaultLimits,
                monotonicClockMilliseconds: () => 0,
                namespace,
            }),
            'AdapterFailure',
        );
    });

    it('does not delete an object that becomes committed after the repair listing', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const namespace = 'repair-publication-race';
        const objectKey =
            `sealed-lattice-runtime-store/${namespace}/objects/` +
            `${identifierFilledWithByte(9)}/${identifierFilledWithByte(10)}`;
        const committedIndexKey = indexKey(namespace, 'newly-committed');
        adapter.rawWrite(objectKey, new Uint8Array([4, 5, 6]));
        adapter.beforeNextUnreferencedObjectDeletion = () => {
            adapter.rawWrite(committedIndexKey, textEncoder.encode(objectKey));
        };

        await expectStorageError(
            openTestStore({
                adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: defaultLimits,
                monotonicClockMilliseconds: () => 0,
                namespace,
            }),
            'Conflict',
        );
        expect(adapter.rawRead(objectKey)).toEqual(new Uint8Array([4, 5, 6]));
        expect(adapter.rawRead(committedIndexKey)).toEqual(
            textEncoder.encode(objectKey),
        );
    });

    it('repairs abandoned writes but fails closed on corrupt, dangling, or aliased committed indices', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const crashedStore = await openTestStore({ adapter });
        const abandonedTransaction = await crashedStore.store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const abandonedLease = await abandonedTransaction.issueWriteLease({
            declaredByteLength: 3,
            logicalRecordKey: 'abandoned',
        });
        await abandonedLease.write(new Uint8Array([9, 9, 9]));

        const afterCrash = await openTestStore({ adapter });
        expect(afterCrash.repairReport).toMatchObject({
            removedUnreferencedObjectCount: 1,
            retainedObjectCount: 0,
        });

        await writeRecord(
            afterCrash.store,
            'aliased-record',
            new Uint8Array([1]),
        );
        await writeRecord(
            afterCrash.store,
            'retained-record',
            new Uint8Array([2]),
        );
        const aliasedObjectKey = textDecoder.decode(
            requiredRawValue(
                adapter,
                indexKey('test-runtime', 'aliased-record'),
            ),
        );
        const rootPrefix = 'sealed-lattice-runtime-store/test-runtime/';
        const missingObjectKey =
            `${rootPrefix}objects/` +
            `${identifierFilledWithByte(7)}/${identifierFilledWithByte(8)}`;
        const orphanObjectKey =
            `${rootPrefix}objects/` +
            `${identifierFilledWithByte(9)}/${identifierFilledWithByte(10)}`;
        adapter.rawWrite(
            indexKey('test-runtime', 'alias-copy'),
            textEncoder.encode(aliasedObjectKey),
        );
        adapter.rawWrite(
            indexKey('test-runtime', 'malformed'),
            new Uint8Array([0xff]),
        );
        adapter.rawWrite(
            indexKey('test-runtime', 'dangling'),
            textEncoder.encode(missingObjectKey),
        );
        adapter.rawWrite(orphanObjectKey, new Uint8Array([7, 7]));

        await expectStorageError(
            openTestStore({ adapter }),
            'AuthenticationFailed',
        );
        expect(
            adapter.rawRead(indexKey('test-runtime', 'aliased-record')),
        ).toBeDefined();
        expect(
            adapter.rawRead(indexKey('test-runtime', 'alias-copy')),
        ).toBeDefined();
        expect(adapter.rawRead(indexKey('test-runtime', 'malformed'))).toEqual(
            new Uint8Array([0xff]),
        );
        expect(
            adapter.rawRead(indexKey('test-runtime', 'dangling')),
        ).toBeDefined();
        expect(adapter.rawRead(aliasedObjectKey)).toEqual(new Uint8Array([1]));
        expect(adapter.rawRead(orphanObjectKey)).toEqual(
            new Uint8Array([7, 7]),
        );
    });

    it('detects index changes that race an authenticated read', async () => {
        const { adapter, store } = await openTestStore();
        await writeRecord(store, 'racing-read', new Uint8Array([1, 2, 3]));
        const recordIndexKey = indexKey('test-runtime', 'racing-read');

        await expectStorageError(
            store.readAuthenticated({
                authenticate: async ({ bytes, logicalRecordKey }) => {
                    await exactAuthenticator(
                        'racing-read',
                        new Uint8Array([1, 2, 3]),
                    )({ bytes, logicalRecordKey });
                    adapter.rawDelete(recordIndexKey);
                },
                logicalRecordKey: 'racing-read',
            }),
            'Conflict',
        );
    });

    it('rejects wrong-length, non-hexadecimal, and noncanonical injected identifiers', async () => {
        const malformedIdentifiers = [
            'a'.repeat(63),
            'a'.repeat(65),
            'A'.repeat(64),
            'g'.repeat(64),
            `${'a'.repeat(63)}-`,
        ];

        for (
            let identifierIndex = 0;
            identifierIndex < malformedIdentifiers.length;
            identifierIndex += 1
        ) {
            const malformedIdentifier = malformedIdentifiers[identifierIndex];
            if (malformedIdentifier === undefined) {
                throw new Error('malformed identifier fixture is missing');
            }
            const { store } = await openTestStore({
                createIdentifier: () => malformedIdentifier,
                namespace: `invalid-transaction-identifier-${identifierIndex}`,
            });
            await expectStorageError(
                store.beginTransaction({ lifetimeMilliseconds: 100 }),
                'AdapterFailure',
            );
        }

        const { store } = await openTestStore({
            createIdentifier: (kind) =>
                kind === 'transaction'
                    ? identifierFilledWithByte(11)
                    : 'B'.repeat(64),
            namespace: 'invalid-lease-identifier',
        });
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await expectStorageError(
            transaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: 'invalid-lease',
            }),
            'AdapterFailure',
        );
        await transaction.abort();

        const coercibleIdentifier = {
            toString: () => identifierFilledWithByte(22),
        };
        const coercibleIdentifierFactory = (() =>
            coercibleIdentifier) as unknown as (
            kind: 'lease' | 'transaction',
        ) => string;
        const coercibleStore = await openTestStore({
            createIdentifier: coercibleIdentifierFactory,
            namespace: 'coercible-identifier',
        });
        await expectStorageError(
            coercibleStore.store.beginTransaction({
                lifetimeMilliseconds: 100,
            }),
            'AdapterFailure',
        );
    });

    it('classifies injected entropy failure without issuing a reusable identifier', async () => {
        const entropyFailure = new Error('injected entropy failure');
        const { store } = await openTestStore({
            createIdentifier: () => {
                throw entropyFailure;
            },
            namespace: 'identifier-entropy-failure',
        });

        await expect(
            store.beginTransaction({ lifetimeMilliseconds: 100 }),
        ).rejects.toMatchObject({
            code: 'AdapterFailure',
            failureCause: entropyFailure,
            name: 'UntrustedStorageTransactionError',
        });
    });

    it('never reissues a transaction identifier after abort', async () => {
        const transactionIdentifier = identifierFilledWithByte(12);
        const { store } = await openTestStore({
            createIdentifier: createQueuedIdentifierFactory({
                lease: [],
                transaction: [transactionIdentifier, transactionIdentifier],
            }),
            namespace: 'retired-after-abort',
        });
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await transaction.abort();

        await expectStorageError(
            store.beginTransaction({ lifetimeMilliseconds: 100 }),
            'AdapterFailure',
        );
    });

    it('retires transaction and lease identifiers that collide with stored objects', async () => {
        const transactionIdentifier = identifierFilledWithByte(18);
        const existingLeaseIdentifier = identifierFilledWithByte(19);
        const transactionCollision = await openTestStore({
            createIdentifier: createQueuedIdentifierFactory({
                lease: [],
                transaction: [transactionIdentifier, transactionIdentifier],
            }),
            namespace: 'transaction-storage-collision',
        });
        const collidingTransactionObjectKey =
            'sealed-lattice-runtime-store/transaction-storage-collision/objects/' +
            `${transactionIdentifier}/${existingLeaseIdentifier}`;
        transactionCollision.adapter.rawWrite(
            collidingTransactionObjectKey,
            new Uint8Array([1]),
        );
        await expect(
            transactionCollision.store.beginTransaction({
                lifetimeMilliseconds: 100,
            }),
        ).rejects.toMatchObject({
            code: 'AdapterFailure',
            message: 'transaction identifier collides with stored objects.',
        });
        transactionCollision.adapter.rawDelete(collidingTransactionObjectKey);
        await expect(
            transactionCollision.store.beginTransaction({
                lifetimeMilliseconds: 100,
            }),
        ).rejects.toMatchObject({
            code: 'AdapterFailure',
            message:
                "transaction identifier was reused during this store's lifetime.",
        });

        const leaseIdentifier = identifierFilledWithByte(20);
        const transactionForLeaseCollision = identifierFilledWithByte(21);
        const leaseCollision = await openTestStore({
            createIdentifier: createQueuedIdentifierFactory({
                lease: [leaseIdentifier, leaseIdentifier],
                transaction: [transactionForLeaseCollision],
            }),
            namespace: 'lease-storage-collision',
        });
        const transaction = await leaseCollision.store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const collidingLeaseObjectKey =
            'sealed-lattice-runtime-store/lease-storage-collision/objects/' +
            `${transactionForLeaseCollision}/${leaseIdentifier}`;
        leaseCollision.adapter.rawWrite(
            collidingLeaseObjectKey,
            new Uint8Array([1]),
        );
        await expect(
            transaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: 'first-collision',
            }),
        ).rejects.toMatchObject({
            code: 'AdapterFailure',
            message: 'lease identifier collides with a stored object.',
        });
        leaseCollision.adapter.rawDelete(collidingLeaseObjectKey);
        await expect(
            transaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: 'retired-collision',
            }),
        ).rejects.toMatchObject({
            code: 'AdapterFailure',
            message:
                "lease identifier was reused during this store's lifetime.",
        });
        await transaction.abort();
    });
});
