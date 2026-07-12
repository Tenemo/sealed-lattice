import { describe, expect, it } from 'vitest';

import {
    openUntrustedStorageTransactionStore,
    UntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAtomicMutation,
    type UntrustedStorageAuthenticator,
    type UntrustedStorageRecoveryReport,
    type UntrustedStorageTransactionErrorCode,
    type UntrustedStorageTransactionLimits,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';

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
    public failNextAtomicMutationCount = 0;
    public failNextDeleteCount = 0;
    public forceNextAtomicConflict = false;
    public returnAliasedReads = false;
    #mostRecentlyReturnedBuffer: Uint8Array | undefined;

    public read(key: string): Promise<Uint8Array | undefined> {
        const storedValue = this.#values.get(key);
        const returnedValue = this.returnAliasedReads
            ? storedValue
            : storedValue?.slice();
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
    maximumStoredValueByteLength: 16_384,
    maximumTransactionByteLength: 2_048,
    maximumTransactionLifetimeMilliseconds: 1_000,
};

const createDeterministicIdentifierFactory = (): ((
    kind: 'lease' | 'transaction',
) => string) => {
    const counts = {
        lease: 0,
        transaction: 0,
    };

    return (kind: 'lease' | 'transaction'): string => {
        counts[kind] += 1;
        return `${kind}-${counts[kind].toString().padStart(16, '0')}`;
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
    recoveryReport: UntrustedStorageRecoveryReport;
    store: UntrustedStorageTransactionStore;
}> => {
    const adapter = input?.adapter ?? new DeterministicInMemoryStorageAdapter();
    const result = await openUntrustedStorageTransactionStore({
        adapter,
        createIdentifier:
            input?.createIdentifier ?? createDeterministicIdentifierFactory(),
        limits: { ...defaultLimits, ...input?.limits },
        monotonicClockMilliseconds:
            input?.monotonicClockMilliseconds ?? (() => 0),
        namespace: input?.namespace ?? 'test-runtime',
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
    128 +
    1 +
    128;

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

    it('keeps every lease claimed until a multi-record publication is fully verified', async () => {
        const { adapter, store } = await openTestStore();
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const firstLease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'publication-first',
        });
        const secondLease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'publication-second',
        });
        await firstLease.write(new Uint8Array([1]));
        await firstLease.seal(
            exactAuthenticator('publication-first', new Uint8Array([1])),
        );
        await secondLease.write(new Uint8Array([2]));
        await secondLease.seal(
            exactAuthenticator('publication-second', new Uint8Array([2])),
        );
        const stagedObjectKeys = adapter
            .keys()
            .filter((key) => key.includes('/objects/'));
        const secondObjectKey = stagedObjectKeys[1];
        expect(secondObjectKey).toBeDefined();
        adapter.afterNextAtomicMutation = () => {
            adapter.rawWrite(secondObjectKey ?? '', new Uint8Array([3]));
        };

        await expectStorageError(transaction.commit(), 'AuthenticationFailed');
        expect(firstLease.state()).toBe('claimed');
        expect(secondLease.state()).toBe('claimed');

        adapter.rawWrite(secondObjectKey ?? '', new Uint8Array([2]));
        await transaction.commit();
        expect(firstLease.state()).toBe('consumed');
        expect(secondLease.state()).toBe('consumed');
    });

    it('owns adapter buffers across asynchronous authentication', async () => {
        const { adapter, store } = await openTestStore();
        const expectedBytes = new Uint8Array([1, 2, 3]);
        await writeRecord(store, 'aliased-read', expectedBytes);
        adapter.returnAliasedReads = true;

        const restoredBytes = await store.readAuthenticated({
            authenticate: async ({ bytes, logicalRecordKey }) => {
                await Promise.resolve();
                adapter.mutateMostRecentlyReturnedBuffer(
                    new Uint8Array([9, 9, 9]),
                );
                await exactAuthenticator(
                    'aliased-read',
                    expectedBytes,
                )({
                    bytes,
                    logicalRecordKey,
                });
            },
            logicalRecordKey: 'aliased-read',
        });
        expect(restoredBytes).toEqual(expectedBytes);
        await expectStorageError(
            store.readAuthenticated({
                authenticate: exactAuthenticator('aliased-read', expectedBytes),
                logicalRecordKey: 'aliased-read',
            }),
            'AuthenticationFailed',
        );
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

        await expectStorageError(transaction.commit(), 'Conflict');
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

    it('conflicts when indexed object bytes change in place after staging', async () => {
        const { adapter, store } = await openTestStore();
        await writeRecord(store, 'shared-record', new Uint8Array([1]));
        const sharedRecordIndexKey = indexKey('test-runtime', 'shared-record');
        const sharedRecordIndexValue = requiredRawValue(
            adapter,
            sharedRecordIndexKey,
        );
        const sharedRecordObjectKey = textDecoder.decode(
            sharedRecordIndexValue,
        );
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            expectedCurrentValue: new Uint8Array([1]),
            logicalRecordKey: 'shared-record',
        });
        await lease.write(new Uint8Array([2]));
        await lease.seal(
            exactAuthenticator('shared-record', new Uint8Array([2])),
        );

        adapter.rawWrite(sharedRecordObjectKey, new Uint8Array([9]));

        await expectStorageError(transaction.commit(), 'Conflict');
        expect(lease.state()).toBe('sealed');
        expect(adapter.rawRead(sharedRecordIndexKey)).toEqual(
            sharedRecordIndexValue,
        );
        expect(adapter.rawRead(sharedRecordObjectKey)).toEqual(
            new Uint8Array([9]),
        );
        await transaction.abort();
    });

    it('binds staged mutations to bytes inspected through another store instance', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const createFirstStoreIdentifier =
            createDeterministicIdentifierFactory();
        const createSecondStoreIdentifier =
            createDeterministicIdentifierFactory();
        const { store: firstStore } = await openTestStore({
            adapter,
            createIdentifier: (kind) =>
                `first-${createFirstStoreIdentifier(kind)}`,
        });
        const { store: secondStore } = await openTestStore({
            adapter,
            createIdentifier: (kind) =>
                `second-${createSecondStoreIdentifier(kind)}`,
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

        const staleAbsentTransaction = await secondStore.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await expectStorageError(
            staleAbsentTransaction.issueWriteLease({
                declaredByteLength: 1,
                expectedCurrentValue: null,
                logicalRecordKey: 'shared-record',
            }),
            'Conflict',
        );
        await staleAbsentTransaction.abort();

        const inspectedBytes = await secondStore.readAuthenticated({
            authenticate: exactAuthenticator(
                'shared-record',
                new Uint8Array([1]),
            ),
            logicalRecordKey: 'shared-record',
        });
        if (inspectedBytes === undefined) {
            throw new Error('The shared record unexpectedly disappeared.');
        }
        await writeRecord(firstStore, 'shared-record', new Uint8Array([2]));

        const staleReplacementTransaction = await secondStore.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await expectStorageError(
            staleReplacementTransaction.issueWriteLease({
                declaredByteLength: 1,
                expectedCurrentValue: inspectedBytes,
                logicalRecordKey: 'shared-record',
            }),
            'Conflict',
        );
        await staleReplacementTransaction.abort();

        const staleDeletionTransaction = await secondStore.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await expectStorageError(
            staleDeletionTransaction.stageDeletion(
                'shared-record',
                inspectedBytes,
            ),
            'Conflict',
        );
        await staleDeletionTransaction.abort();
        await expect(
            secondStore.readAuthenticated({
                authenticate: exactAuthenticator(
                    'shared-record',
                    new Uint8Array([2]),
                ),
                logicalRecordKey: 'shared-record',
            }),
        ).resolves.toEqual(new Uint8Array([2]));
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

    it('accepts an exact storage reservation and rejects one byte beyond it', async () => {
        const namespace = 'quota-exact';
        const objectKey =
            `sealed-lattice-runtime-store/${namespace}/objects/` +
            'transaction-0000000000000001/lease-0000000000000001';
        const exactStoredValueByteLength =
            textEncoder.encode(objectKey).byteLength + 3;
        const exactStore = await openTestStore({
            limits: {
                maximumStoredValueByteLength: exactStoredValueByteLength,
            },
            namespace,
        });
        const exactTransaction = await exactStore.store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        const exactLease = await exactTransaction.issueWriteLease({
            declaredByteLength: 3,
            logicalRecordKey: 'exact',
        });
        await exactLease.write(new Uint8Array([1, 2, 3]));
        await exactLease.seal(
            exactAuthenticator('exact', new Uint8Array([1, 2, 3])),
        );
        await exactTransaction.commit();

        const constrainedStore = await openTestStore({
            limits: {
                maximumStoredValueByteLength: exactStoredValueByteLength - 1,
            },
            namespace,
        });
        const constrainedTransaction =
            await constrainedStore.store.beginTransaction({
                lifetimeMilliseconds: 100,
            });
        await expectStorageError(
            constrainedTransaction.issueWriteLease({
                declaredByteLength: 3,
                logicalRecordKey: 'exact',
            }),
            'QuotaExceeded',
        );
        await constrainedTransaction.abort();
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
            openUntrustedStorageTransactionStore({
                adapter: oversizedIndexStore.adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: defaultLimits,
                monotonicClockMilliseconds: () => 0,
                namespace: 'oversized-index',
            }),
            'CorruptIndex',
        );

        const oversizedObjectStore = await openTestStore({
            limits: { maximumLeaseByteLength: 3 },
            namespace: 'oversized-object',
        });
        const oversizedObjectKey =
            'sealed-lattice-runtime-store/oversized-object/objects/' +
            'transaction-oversized-0001/lease-oversized-0000001';
        oversizedObjectStore.adapter.rawWrite(
            oversizedObjectKey,
            new Uint8Array([1, 2, 3, 4]),
        );
        oversizedObjectStore.adapter.rawWrite(
            indexKey('oversized-object', 'record'),
            textEncoder.encode(oversizedObjectKey),
        );
        await expectStorageError(
            oversizedObjectStore.store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'record',
                    new Uint8Array([1, 2, 3, 4]),
                ),
                logicalRecordKey: 'record',
            }),
            'MalformedLength',
        );
        await expectStorageError(
            openUntrustedStorageTransactionStore({
                adapter: oversizedObjectStore.adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: { ...defaultLimits, maximumLeaseByteLength: 3 },
                monotonicClockMilliseconds: () => 0,
                namespace: 'oversized-object',
            }),
            'MalformedLength',
        );
    });

    it('fails recovery when retained storage exceeds the configured total quota', async () => {
        const adapter = new DeterministicInMemoryStorageAdapter();
        const namespace = 'over-total-quota';
        const objectKey =
            `sealed-lattice-runtime-store/${namespace}/objects/` +
            'transaction-overquota-0001/lease-overquota-000001';
        adapter.rawWrite(objectKey, new Uint8Array([1]));
        adapter.rawWrite(
            indexKey(namespace, 'record'),
            textEncoder.encode(objectKey),
        );

        await expectStorageError(
            openUntrustedStorageTransactionStore({
                adapter,
                createIdentifier: createDeterministicIdentifierFactory(),
                limits: {
                    ...defaultLimits,
                    maximumStoredValueByteLength: 1,
                },
                monotonicClockMilliseconds: () => 0,
                namespace,
            }),
            'QuotaExceeded',
        );
    });

    it('recovers abandoned writes and corrupt, dangling, aliased storage indices', async () => {
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
        expect(afterCrash.recoveryReport).toMatchObject({
            removedCorruptIndexCount: 0,
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
            'transaction-dangling-0001/lease-dangling-0000001';
        const orphanObjectKey =
            `${rootPrefix}objects/` +
            'transaction-orphan-00001/lease-orphan-00000001';
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

        const recovered = await openTestStore({ adapter });
        expect(recovered.recoveryReport).toMatchObject({
            removedCorruptIndexCount: 4,
            removedUnreferencedObjectCount: 2,
            retainedObjectCount: 1,
        });
        expect(
            await recovered.store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'aliased-record',
                    new Uint8Array([1]),
                ),
                logicalRecordKey: 'aliased-record',
            }),
        ).toBeUndefined();
        expect(
            await recovered.store.readAuthenticated({
                authenticate: exactAuthenticator(
                    'retained-record',
                    new Uint8Array([2]),
                ),
                logicalRecordKey: 'retained-record',
            }),
        ).toEqual(new Uint8Array([2]));
        expect(adapter.rawRead(orphanObjectKey)).toBeUndefined();
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

    it('rejects reused identifiers before they can alias transaction resources', async () => {
        let transactionCount = 0;
        const createIdentifier = (kind: 'lease' | 'transaction'): string => {
            if (kind === 'transaction') {
                transactionCount += 1;
                return `transaction-${transactionCount
                    .toString()
                    .padStart(16, '0')}`;
            }

            return 'lease-reused-0000000001';
        };
        const { store } = await openTestStore({ createIdentifier });
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 100,
        });
        await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'first',
        });
        await expectStorageError(
            transaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: 'second',
            }),
            'AdapterFailure',
        );
        await transaction.abort();
    });
});
