import { hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    AuthenticatedCheckpointStore,
    type AuthenticatedCheckpointExclusiveLock,
    type AuthenticatedCheckpointRecordContext,
    type AuthenticatedCheckpointScope,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAtomicMutation,
    type UntrustedStorageTransactionLimits,
    type UntrustedStorageTransactionStore,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const storageNamespace = 'checkpoint-tests';
const authenticationTagByteLength = 64;
let openedStoreCount = 0;

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

const hexToBytes = (hex: string): Uint8Array =>
    Uint8Array.from({ length: hex.length / 2 }, (_, byteIndex) =>
        Number.parseInt(hex.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
    );

const encodeUnsigned32 = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

class TestCheckpointExclusiveLock {
    readonly #tails = new Map<string, Promise<void>>();
    readonly #requestCountWaiters: {
        expectedRequestCount: number;
        resolve(): void;
    }[] = [];
    public activeOperationCount = 0;
    public maximumActiveOperationCount = 0;
    public requestCount = 0;

    public readonly withExclusiveCheckpointLock: AuthenticatedCheckpointExclusiveLock =
        async <Result>(input: {
            lockName: string;
            operation: () => Promise<Result>;
        }): Promise<Result> => {
            this.requestCount += 1;
            this.#resolveRequestCountWaiters();
            const previousOperation =
                this.#tails.get(input.lockName) ?? Promise.resolve();
            let releaseOperation: (() => void) | undefined;
            const currentOperation = new Promise<void>((resolve) => {
                releaseOperation = resolve;
            });
            this.#tails.set(input.lockName, currentOperation);
            await previousOperation;
            this.activeOperationCount += 1;
            this.maximumActiveOperationCount = Math.max(
                this.maximumActiveOperationCount,
                this.activeOperationCount,
            );
            try {
                return await input.operation();
            } finally {
                this.activeOperationCount -= 1;
                releaseOperation?.();
                if (this.#tails.get(input.lockName) === currentOperation) {
                    this.#tails.delete(input.lockName);
                }
            }
        };

    public waitForRequestCount(expectedRequestCount: number): Promise<void> {
        if (this.requestCount >= expectedRequestCount) {
            return Promise.resolve();
        }

        return new Promise<void>((resolve) => {
            this.#requestCountWaiters.push({ expectedRequestCount, resolve });
        });
    }

    #resolveRequestCountWaiters(): void {
        for (
            let waiterIndex = this.#requestCountWaiters.length - 1;
            waiterIndex >= 0;
            waiterIndex -= 1
        ) {
            const waiter = this.#requestCountWaiters[waiterIndex];
            if (
                waiter !== undefined &&
                this.requestCount >= waiter.expectedRequestCount
            ) {
                this.#requestCountWaiters.splice(waiterIndex, 1);
                waiter.resolve();
            }
        }
    }
}

const sharedCheckpointExclusiveLock = new TestCheckpointExclusiveLock();

class InMemoryStorageAdapter implements UntrustedStorageAdapter {
    #values = new Map<string, Uint8Array>();
    public afterRead: ((key: string) => void) | undefined;

    public read(key: string): Promise<Uint8Array | undefined> {
        const value = this.#values.get(key)?.slice();
        this.afterRead?.(key);

        return Promise.resolve(value);
    }

    public write(key: string, value: Uint8Array): Promise<void> {
        this.#values.set(key, value.slice());
        return Promise.resolve();
    }

    public delete(key: string): Promise<void> {
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
        const nextValues = new Map(
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
}

class TestCheckpointCryptography {
    readonly #bindContext: boolean;
    readonly #openCountByLogicalRecordKey = new Map<string, number>();
    public failFourthManifestOpen = false;
    public failFourthStateChunkOpen = false;
    public onSeal:
        | ((context: AuthenticatedCheckpointRecordContext) => void)
        | undefined;

    public constructor(bindContext = true) {
        this.#bindContext = bindContext;
    }

    public readonly sealRecord = (input: {
        context: AuthenticatedCheckpointRecordContext;
        plaintext: Uint8Array;
    }): Uint8Array => {
        this.onSeal?.(input.context);
        const tag = this.#authenticationTag(input.context, input.plaintext);
        const sealedBytes = new Uint8Array(
            tag.byteLength + input.plaintext.byteLength,
        );
        sealedBytes.set(tag, 0);
        sealedBytes.set(input.plaintext, tag.byteLength);

        return sealedBytes;
    };

    public readonly openRecord = (input: {
        context: AuthenticatedCheckpointRecordContext;
        sealedBytes: Uint8Array;
    }): Uint8Array => {
        const invocationCount =
            (this.#openCountByLogicalRecordKey.get(
                input.context.logicalRecordKey,
            ) ?? 0) + 1;
        this.#openCountByLogicalRecordKey.set(
            input.context.logicalRecordKey,
            invocationCount,
        );
        if (
            invocationCount === 4 &&
            ((input.context.recordKind === 'manifest' &&
                this.failFourthManifestOpen) ||
                (input.context.recordKind === 'stateChunk' &&
                    this.failFourthStateChunkOpen))
        ) {
            throw new Error('injected checkpoint open failure');
        }
        if (input.sealedBytes.byteLength < authenticationTagByteLength) {
            throw new Error('sealed checkpoint record is truncated');
        }
        const observedTag = input.sealedBytes.slice(
            0,
            authenticationTagByteLength,
        );
        const plaintext = input.sealedBytes.slice(authenticationTagByteLength);
        const expectedTag = this.#authenticationTag(input.context, plaintext);
        if (!bytesEqual(observedTag, expectedTag)) {
            throw new Error('sealed checkpoint authentication failed');
        }

        return plaintext;
    };

    #authenticationTag(
        context: AuthenticatedCheckpointRecordContext,
        plaintext: Uint8Array,
    ): Uint8Array {
        const parts: Uint8Array[] = [];
        if (this.#bindContext) {
            parts.push(
                textEncoder.encode(context.recordKind),
                textEncoder.encode(context.checkpointIdentifier),
                textEncoder.encode(context.logicalRecordKey),
                context.attemptIdentifier,
                context.resumeBindingDigest,
            );
            if (context.recordKind === 'stateChunk') {
                parts.push(
                    encodeUnsigned32(context.chunkIndex),
                    encodeUnsigned32(context.chunkByteLength),
                    context.chunkDigest,
                );
            }
        }
        parts.push(plaintext);

        return hexToBytes(
            hash512Hex('sealed-lattice/test/checkpoint-record-seal/v1', parts),
        );
    }
}

const storageLimits: UntrustedStorageTransactionLimits = {
    maximumActiveTransactionCount: 4,
    maximumLeaseByteLength: 2_048,
    maximumLeaseCountPerTransaction: 12,
    maximumStoredValueByteLength: 65_536,
    maximumTransactionByteLength: 8_192,
    maximumTransactionLifetimeMilliseconds: 5_000,
};

const checkpointLimits = {
    checkpointChunkByteLength: 4,
    maximumCheckpointByteLength: 16,
    maximumCheckpointChunkCount: 4,
    maximumSealedRecordByteLength: 1_024,
    transactionLifetimeMilliseconds: 1_000,
} as const;

const createIdentifierFactory = (
    storeIdentifier: number,
): ((kind: 'lease' | 'transaction') => string) => {
    const counts = { lease: 0, transaction: 0 };

    return (kind) => {
        counts[kind] += 1;
        const kindCode = kind === 'transaction' ? '01' : '02';
        return `${kindCode}${storeIdentifier
            .toString(16)
            .padStart(30, '0')}${counts[kind].toString(16).padStart(32, '0')}`;
    };
};

const openStorage = async (
    adapter = new InMemoryStorageAdapter(),
): Promise<{
    adapter: InMemoryStorageAdapter;
    store: UntrustedStorageTransactionStore;
}> => {
    openedStoreCount += 1;
    const opened = await openUntrustedStorageTransactionStore({
        adapter,
        createIdentifier: createIdentifierFactory(openedStoreCount),
        limits: storageLimits,
        monotonicClockMilliseconds: () => 0,
        namespace: storageNamespace,
    });

    return { adapter, store: opened.store };
};

const createCheckpointStore = (
    store: UntrustedStorageTransactionStore,
    cryptography = new TestCheckpointCryptography(),
    exclusiveLock: TestCheckpointExclusiveLock = sharedCheckpointExclusiveLock,
): AuthenticatedCheckpointStore =>
    new AuthenticatedCheckpointStore({
        withExclusiveCheckpointLock: exclusiveLock.withExclusiveCheckpointLock,
        limits: checkpointLimits,
        openRecord: cryptography.openRecord,
        sealRecord: cryptography.sealRecord,
        store,
    });

const createScope = (seed: number): AuthenticatedCheckpointScope => ({
    attemptIdentifier: new Uint8Array(32).fill(seed),
    checkpointIdentifier: `checkpoint-${seed.toString().padStart(16, '0')}`,
    resumeBindingDigest: new Uint8Array(64).fill(seed + 64),
});

const restoreBytes = async (
    checkpointStore: AuthenticatedCheckpointStore,
    scope: AuthenticatedCheckpointScope,
): Promise<Uint8Array | undefined> => {
    const chunks: Uint8Array[] = [];

    return checkpointStore.resumeCheckpoint({
        restorer: {
            acceptChunk: ({ bytes, chunkIndex }) => {
                expect(chunkIndex).toBe(chunks.length);
                chunks.push(bytes.slice());
            },
            complete: (descriptor) => {
                const bytes = new Uint8Array(descriptor.totalByteLength);
                let offset = 0;
                for (const chunk of chunks) {
                    bytes.set(chunk, offset);
                    offset += chunk.byteLength;
                }
                expect(offset).toBe(descriptor.totalByteLength);

                return bytes;
            },
            discard: () => {
                chunks.length = 0;
            },
        },
        scope,
    });
};

const indexKey = (logicalRecordKey: string): string =>
    `sealed-lattice-runtime-store/${storageNamespace}/indices/${Array.from(
        textEncoder.encode(logicalRecordKey),
        (byte) => byte.toString(16).padStart(2, '0'),
    ).join('')}`;

const logicalRecordKeyFromIndexKey = (key: string): string => {
    const prefix = `sealed-lattice-runtime-store/${storageNamespace}/indices/`;
    if (!key.startsWith(prefix)) {
        throw new Error('storage key is not an index key');
    }
    const hex = key.slice(prefix.length);
    const bytes = hexToBytes(hex);

    return fatalTextDecoder.decode(bytes);
};

const indexedLogicalRecordKeys = (
    adapter: InMemoryStorageAdapter,
): readonly string[] =>
    adapter
        .keys()
        .filter((key) => key.includes('/indices/'))
        .map(logicalRecordKeyFromIndexKey)
        .sort();

const requiredRawValue = (
    adapter: InMemoryStorageAdapter,
    key: string,
): Uint8Array => {
    const value = adapter.rawRead(key);
    if (value === undefined) {
        throw new Error(`missing raw test value for ${key}`);
    }

    return value;
};

const objectKeyForLogicalRecord = (
    adapter: InMemoryStorageAdapter,
    logicalRecordKey: string,
): string =>
    fatalTextDecoder.decode(
        requiredRawValue(adapter, indexKey(logicalRecordKey)),
    );

describe('authenticated checkpoint store', () => {
    it('rejects limits that cannot contain the bounded manifest', async () => {
        const { store } = await openStorage();

        expect(
            () =>
                new AuthenticatedCheckpointStore({
                    withExclusiveCheckpointLock: () =>
                        Promise.reject(
                            new Error('unexpected checkpoint lock request'),
                        ),
                    limits: {
                        ...checkpointLimits,
                        maximumSealedRecordByteLength: 512,
                    },
                    openRecord: ({ sealedBytes }) => sealedBytes,
                    sealRecord: ({ plaintext }) => plaintext,
                    store,
                }),
        ).toThrowError(
            expect.objectContaining({
                code: 'InvalidConfiguration',
                name: 'AuthenticatedCheckpointError',
            }),
        );
    });

    it('publishes chunks before one authenticated manifest and resumes them in order', async () => {
        const { adapter, store } = await openStorage();
        const cryptography = new TestCheckpointCryptography();
        let observedCommittedChunksBeforeManifest = false;
        cryptography.onSeal = (context) => {
            if (context.recordKind !== 'manifest') {
                return;
            }
            const logicalRecordKeys = indexedLogicalRecordKeys(adapter);
            observedCommittedChunksBeforeManifest =
                logicalRecordKeys.filter((key) => key.includes('/chunks/'))
                    .length === 3 &&
                logicalRecordKeys.some((key) =>
                    key.endsWith('/interrupted-publication'),
                ) &&
                !logicalRecordKeys.some((key) => key.endsWith('/manifest'));
        };
        const checkpointStore = createCheckpointStore(store, cryptography);
        const scope = createScope(1);
        const descriptor = await checkpointStore.replaceCheckpoint({
            scope,
            stateChunks: [
                new Uint8Array([1, 2, 3, 4]),
                new Uint8Array([5, 6, 7, 8]),
                new Uint8Array([9, 10]),
            ],
        });

        expect(descriptor).toMatchObject({
            chunkCount: 3,
            totalByteLength: 10,
        });
        expect(descriptor.orderedStateDigest).toHaveLength(64);
        expect(observedCommittedChunksBeforeManifest).toBe(true);
        expect(await restoreBytes(checkpointStore, scope)).toEqual(
            new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        );
        const logicalRecordKeys = indexedLogicalRecordKeys(adapter);
        expect(
            logicalRecordKeys.filter((key) => key.endsWith('/manifest')),
        ).toHaveLength(1);
        expect(
            logicalRecordKeys.filter((key) => key.includes('/chunks/')),
        ).toHaveLength(3);
        expect(
            logicalRecordKeys.some((key) =>
                key.endsWith('/interrupted-publication'),
            ),
        ).toBe(false);
    });

    it('holds one cross-instance lock across replacement publication and eviction', async () => {
        const { store } = await openStorage();
        const exclusiveLock = new TestCheckpointExclusiveLock();
        const firstCheckpointStore = createCheckpointStore(
            store,
            new TestCheckpointCryptography(),
            exclusiveLock,
        );
        const secondCheckpointStore = createCheckpointStore(
            store,
            new TestCheckpointCryptography(),
            exclusiveLock,
        );
        const scope = createScope(91);
        let signalSourceEntered: (() => void) | undefined;
        const sourceEntered = new Promise<void>((resolve) => {
            signalSourceEntered = resolve;
        });
        let releaseSource: (() => void) | undefined;
        const sourceRelease = new Promise<void>((resolve) => {
            releaseSource = resolve;
        });
        const replacement = firstCheckpointStore.replaceCheckpoint({
            scope,
            stateChunks: (async function* (): AsyncGenerator<Uint8Array> {
                signalSourceEntered?.();
                await sourceRelease;
                yield new Uint8Array([1, 2, 3, 4]);
                yield new Uint8Array([5, 6]);
            })(),
        });
        await sourceEntered;

        let evictionSettled = false;
        const eviction = secondCheckpointStore.evictCheckpoint(scope);
        void eviction.then(
            () => {
                evictionSettled = true;
            },
            () => {
                evictionSettled = true;
            },
        );
        await exclusiveLock.waitForRequestCount(2);
        expect(exclusiveLock.activeOperationCount).toBe(1);
        expect(exclusiveLock.maximumActiveOperationCount).toBe(1);
        expect(evictionSettled).toBe(false);

        releaseSource?.();
        await expect(replacement).resolves.toMatchObject({
            chunkCount: 2,
            totalByteLength: 6,
        });
        await expect(eviction).resolves.toEqual({ removedChunkCount: 2 });
        expect(await restoreBytes(firstCheckpointStore, scope)).toBeUndefined();
        expect(exclusiveLock.maximumActiveOperationCount).toBe(1);
    });

    it('aborts invisible staged chunks when the source fails before publication', async () => {
        const { adapter, store } = await openStorage();
        const checkpointStore = createCheckpointStore(store);
        const source = function* (): Generator<Uint8Array> {
            yield new Uint8Array([1, 2, 3, 4]);
            yield new Uint8Array([5, 6, 7, 8]);
            throw new Error('injected checkpoint source failure');
        };

        await expect(
            checkpointStore.replaceCheckpoint({
                scope: createScope(14),
                stateChunks: source(),
            }),
        ).rejects.toThrow('injected checkpoint source failure');
        expect(adapter.keys()).toEqual([]);
    });

    it('refuses a different attempt or resume binding even with context-insensitive sealing', async () => {
        const { store } = await openStorage();
        const cryptography = new TestCheckpointCryptography(false);
        const checkpointStore = createCheckpointStore(store, cryptography);
        const scope = createScope(5);
        await checkpointStore.replaceCheckpoint({
            scope,
            stateChunks: [new Uint8Array([1, 2])],
        });

        await expect(
            restoreBytes(checkpointStore, {
                ...scope,
                attemptIdentifier: new Uint8Array(32).fill(77),
            }),
        ).rejects.toMatchObject({
            code: 'ResumeMismatch',
            name: 'AuthenticatedCheckpointError',
        });
        await expect(
            restoreBytes(checkpointStore, {
                ...scope,
                resumeBindingDigest: new Uint8Array(64).fill(88),
            }),
        ).rejects.toMatchObject({
            code: 'ResumeMismatch',
            name: 'AuthenticatedCheckpointError',
        });
    });

    it('refuses an authenticated manifest whose hostile count exceeds the configured bound', async () => {
        const { adapter, store } = await openStorage();
        const cryptography = new TestCheckpointCryptography();
        const checkpointStore = createCheckpointStore(store, cryptography);
        const scope = createScope(6);
        await checkpointStore.replaceCheckpoint({
            scope,
            stateChunks: [new Uint8Array([1, 2, 3])],
        });
        const logicalRecordKey = `authenticated-checkpoints/${scope.checkpointIdentifier}/manifest`;
        const objectKey = objectKeyForLogicalRecord(adapter, logicalRecordKey);
        const context: AuthenticatedCheckpointRecordContext = {
            attemptIdentifier: scope.attemptIdentifier,
            checkpointIdentifier: scope.checkpointIdentifier,
            logicalRecordKey,
            recordKind: 'manifest',
            resumeBindingDigest: scope.resumeBindingDigest,
        };
        const plaintext = cryptography.openRecord({
            context,
            sealedBytes: requiredRawValue(adapter, objectKey),
        });
        const identifierByteLength = new DataView(
            plaintext.buffer,
            plaintext.byteOffset,
            plaintext.byteLength,
        ).getUint16(6, true);
        const chunkCountOffset = 8 + identifierByteLength + 32 + 64 + 4;
        new DataView(
            plaintext.buffer,
            plaintext.byteOffset,
            plaintext.byteLength,
        ).setUint32(chunkCountOffset, 0xffff_ffff, true);
        adapter.rawWrite(
            objectKey,
            cryptography.sealRecord({ context, plaintext }),
        );

        await expect(
            restoreBytes(checkpointStore, scope),
        ).rejects.toMatchObject({
            code: 'BoundsExceeded',
            name: 'AuthenticatedCheckpointError',
        });
    });

    it('refuses tampered, missing, and reordered chunk records without completing restore', async () => {
        const { adapter, store } = await openStorage();
        const checkpointStore = createCheckpointStore(store);
        const scope = createScope(7);
        const chunks = [
            new Uint8Array([1, 2, 3, 4]),
            new Uint8Array([5, 6, 7, 8]),
            new Uint8Array([9]),
        ];
        await checkpointStore.replaceCheckpoint({ scope, stateChunks: chunks });
        const chunkLogicalRecordKeys = indexedLogicalRecordKeys(adapter).filter(
            (key) => key.includes('/chunks/'),
        );
        const secondChunkLogicalRecordKey = chunkLogicalRecordKeys[1];
        if (secondChunkLogicalRecordKey === undefined) {
            throw new Error('second chunk record was not published');
        }
        adapter.rawDelete(indexKey(secondChunkLogicalRecordKey));
        const acceptedChunkIndices: number[] = [];
        let completed = false;
        let discarded = false;

        await expect(
            checkpointStore.resumeCheckpoint({
                restorer: {
                    acceptChunk: ({ chunkIndex }) => {
                        acceptedChunkIndices.push(chunkIndex);
                    },
                    complete: () => {
                        completed = true;
                    },
                    discard: () => {
                        discarded = true;
                    },
                },
                scope,
            }),
        ).rejects.toMatchObject({
            code: 'MissingChunk',
            name: 'AuthenticatedCheckpointError',
        });
        expect(acceptedChunkIndices).toEqual([0]);
        expect(completed).toBe(false);
        expect(discarded).toBe(true);

        await checkpointStore.replaceCheckpoint({ scope, stateChunks: chunks });
        const reorderedChunkKeys = indexedLogicalRecordKeys(adapter).filter(
            (key) => key.includes('/chunks/'),
        );
        const firstIndexKey = indexKey(reorderedChunkKeys[0] ?? '');
        const secondIndexKey = indexKey(reorderedChunkKeys[1] ?? '');
        const firstIndexValue = requiredRawValue(adapter, firstIndexKey);
        const secondIndexValue = requiredRawValue(adapter, secondIndexKey);
        adapter.rawWrite(firstIndexKey, secondIndexValue);
        adapter.rawWrite(secondIndexKey, firstIndexValue);

        await expect(
            restoreBytes(checkpointStore, scope),
        ).rejects.toMatchObject({
            code: 'AuthenticationFailed',
        });
    });

    it('recovers an interrupted replacement and retains the last published attempt state', async () => {
        const { adapter, store } = await openStorage();
        const initialCryptography = new TestCheckpointCryptography();
        const checkpointStore = createCheckpointStore(
            store,
            initialCryptography,
        );
        const scope = createScope(10);
        const sharedChunk = new Uint8Array([1, 2, 3, 4]);
        const initialBytes = new Uint8Array([1, 2, 3, 4, 5]);
        await checkpointStore.replaceCheckpoint({
            scope,
            stateChunks: [sharedChunk, new Uint8Array([5])],
        });
        initialCryptography.failFourthStateChunkOpen = true;

        await expect(
            checkpointStore.replaceCheckpoint({
                scope,
                stateChunks: [sharedChunk, new Uint8Array([9])],
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(
            indexedLogicalRecordKeys(adapter).some((key) =>
                key.endsWith('/interrupted-publication'),
            ),
        ).toBe(true);

        const reopenedStorage = await openStorage(adapter);
        const recoveredCheckpointStore = createCheckpointStore(
            reopenedStorage.store,
        );
        expect(
            await recoveredCheckpointStore.cleanupInterruptedPublication(scope),
        ).toEqual({ removedChunkCount: 1 });
        expect(await restoreBytes(recoveredCheckpointStore, scope)).toEqual(
            initialBytes,
        );
        expect(
            await recoveredCheckpointStore.cleanupInterruptedPublication(scope),
        ).toEqual({ removedChunkCount: 0 });
        expect(
            indexedLogicalRecordKeys(adapter).some((key) =>
                key.endsWith('/interrupted-publication'),
            ),
        ).toBe(false);
    });

    it('evicts published and interrupted records deterministically and idempotently', async () => {
        const { adapter, store } = await openStorage();
        const checkpointStore = createCheckpointStore(store);
        const scope = createScope(12);
        await checkpointStore.replaceCheckpoint({
            scope,
            stateChunks: [new Uint8Array([1, 2, 3, 4]), new Uint8Array([5])],
        });

        expect(await checkpointStore.evictCheckpoint(scope)).toEqual({
            removedChunkCount: 2,
        });
        expect(await checkpointStore.evictCheckpoint(scope)).toEqual({
            removedChunkCount: 0,
        });
        expect(await restoreBytes(checkpointStore, scope)).toBeUndefined();
        expect(indexedLogicalRecordKeys(adapter)).toEqual([]);
    });

    it('discards parser state if completion fails and preserves the parser failure', async () => {
        const { store } = await openStorage();
        const checkpointStore = createCheckpointStore(store);
        const scope = createScope(13);
        await checkpointStore.replaceCheckpoint({
            scope,
            stateChunks: [new Uint8Array([1, 2, 3])],
        });
        let discardedFailure: unknown;

        await expect(
            checkpointStore.resumeCheckpoint({
                restorer: {
                    acceptChunk: () => undefined,
                    complete: () => {
                        throw new Error('parser completion failed');
                    },
                    discard: (failure) => {
                        discardedFailure = failure;
                    },
                },
                scope,
            }),
        ).rejects.toMatchObject({
            code: 'RestoreFailed',
            name: 'AuthenticatedCheckpointError',
        });
        expect(discardedFailure).toMatchObject({
            code: 'RestoreFailed',
            name: 'AuthenticatedCheckpointError',
        });
    });
});
