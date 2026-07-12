import { hash512Hex } from '@sealed-lattice/crypto';
import { afterEach, describe, expect, it } from 'vitest';

import {
    AuthenticatedCheckpointStore,
    createAuthenticatedCheckpointWebLock,
    type AuthenticatedCheckpointExclusiveLock,
    type AuthenticatedCheckpointRecordContext,
    type AuthenticatedCheckpointScope,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import {
    openWebLockOwnedStorageTransactionStore,
    type WebLockOwnedStorageTransactionStore,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';

const authenticationTagByteLength = 64;
const textEncoder = new TextEncoder();
const openedHandles: WebLockOwnedStorageTransactionStore[] = [];
const databaseNames = new Set<string>();
const webLocksAvailable = typeof navigator.locks?.request === 'function';

const storageLimits = {
    maximumActiveTransactionCount: 4,
    maximumLeaseByteLength: 2_048,
    maximumLeaseCountPerTransaction: 12,
    maximumStoredValueByteLength: 65_536,
    maximumTransactionByteLength: 8_192,
    maximumTransactionLifetimeMilliseconds: 5_000,
} as const;

const checkpointLimits = {
    checkpointChunkByteLength: 4,
    maximumCheckpointByteLength: 16,
    maximumCheckpointChunkCount: 4,
    maximumSealedRecordByteLength: 1_024,
    transactionLifetimeMilliseconds:
        storageLimits.maximumTransactionLifetimeMilliseconds,
} as const;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
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

class BrowserCheckpointExclusiveLock {
    readonly #requestCountWaiters: {
        expectedRequestCount: number;
        resolve(): void;
    }[] = [];
    readonly #webLock = createAuthenticatedCheckpointWebLock(navigator.locks);
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

            return this.#webLock({
                lockName: input.lockName,
                operation: async () => {
                    this.activeOperationCount += 1;
                    this.maximumActiveOperationCount = Math.max(
                        this.maximumActiveOperationCount,
                        this.activeOperationCount,
                    );
                    try {
                        return await input.operation();
                    } finally {
                        this.activeOperationCount -= 1;
                    }
                },
            });
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

const sharedCheckpointExclusiveLock = new BrowserCheckpointExclusiveLock();

const hexToBytes = (hex: string): Uint8Array =>
    Uint8Array.from({ length: hex.length / 2 }, (_, byteIndex) =>
        Number.parseInt(hex.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
    );

const encodeUnsigned32 = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

class BrowserCheckpointCryptography {
    readonly #openCountByLogicalRecordKey = new Map<string, number>();
    public failFourthStateChunkOpen = false;

    public readonly sealRecord = (input: {
        context: AuthenticatedCheckpointRecordContext;
        plaintext: Uint8Array;
    }): Uint8Array => {
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
            input.context.recordKind === 'stateChunk' &&
            this.failFourthStateChunkOpen
        ) {
            throw new Error('injected browser checkpoint open failure');
        }
        if (input.sealedBytes.byteLength < authenticationTagByteLength) {
            throw new Error('sealed browser checkpoint is truncated');
        }
        const observedTag = input.sealedBytes.slice(
            0,
            authenticationTagByteLength,
        );
        const plaintext = input.sealedBytes.slice(authenticationTagByteLength);
        const expectedTag = this.#authenticationTag(input.context, plaintext);
        if (!bytesEqual(observedTag, expectedTag)) {
            throw new Error('browser checkpoint authentication failed');
        }

        return plaintext;
    };

    #authenticationTag(
        context: AuthenticatedCheckpointRecordContext,
        plaintext: Uint8Array,
    ): Uint8Array {
        const parts = [
            textEncoder.encode(context.recordKind),
            textEncoder.encode(context.checkpointIdentifier),
            textEncoder.encode(context.logicalRecordKey),
            context.attemptIdentifier,
            context.resumeBindingDigest,
        ];
        if (context.recordKind === 'stateChunk') {
            parts.push(
                encodeUnsigned32(context.chunkIndex),
                encodeUnsigned32(context.chunkByteLength),
                context.chunkDigest,
            );
        }
        parts.push(plaintext);

        return hexToBytes(
            hash512Hex(
                'sealed-lattice/test/browser-checkpoint-record-seal/v1',
                parts,
            ),
        );
    }
}

const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    const suffix = Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');

    return `sealed-lattice-checkpoint-browser-test-${suffix}`;
};

const createScope = (seed: number): AuthenticatedCheckpointScope => ({
    attemptIdentifier: new Uint8Array(32).fill(seed),
    checkpointIdentifier: `browser-checkpoint-${seed
        .toString()
        .padStart(16, '0')}`,
    resumeBindingDigest: new Uint8Array(64).fill(seed + 64),
});

const openOwnedStore = async (
    databaseName: string,
): Promise<WebLockOwnedStorageTransactionStore> => {
    databaseNames.add(databaseName);
    const handle = await openWebLockOwnedStorageTransactionStore({
        databaseName,
        limits: storageLimits,
        namespace: 'authenticated-checkpoints',
    });
    openedHandles.push(handle);

    return handle;
};

const createCheckpointStore = (
    handle: WebLockOwnedStorageTransactionStore,
    cryptography = new BrowserCheckpointCryptography(),
    exclusiveLock: BrowserCheckpointExclusiveLock = sharedCheckpointExclusiveLock,
): AuthenticatedCheckpointStore =>
    new AuthenticatedCheckpointStore({
        withExclusiveCheckpointLock: exclusiveLock.withExclusiveCheckpointLock,
        limits: checkpointLimits,
        openRecord: cryptography.openRecord,
        sealRecord: cryptography.sealRecord,
        store: handle.store,
    });

const restoreBytes = async (
    checkpointStore: AuthenticatedCheckpointStore,
    scope: AuthenticatedCheckpointScope,
): Promise<Uint8Array | undefined> => {
    const chunks: Uint8Array[] = [];

    return checkpointStore.resumeCheckpoint({
        restorer: {
            acceptChunk: ({ bytes }) => {
                chunks.push(bytes.slice());
            },
            complete: ({ totalByteLength }) => {
                const bytes = new Uint8Array(totalByteLength);
                let offset = 0;
                for (const chunk of chunks) {
                    bytes.set(chunk, offset);
                    offset += chunk.byteLength;
                }

                return bytes;
            },
            discard: () => {
                chunks.length = 0;
            },
        },
        scope,
    });
};

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error('checkpoint test database deletion failed'),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () =>
                reject(
                    new Error(
                        'checkpoint test database deletion was blocked by a leaked connection',
                    ),
                ),
            { once: true },
        );
    });

afterEach(async () => {
    for (const handle of openedHandles.splice(0).reverse()) {
        try {
            await handle.close();
        } catch {
            // A failed owned handle has already closed its adapter.
        }
    }
    for (const databaseName of databaseNames) {
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe.skipIf(!webLocksAvailable)(
    'Authenticated checkpoint store in browsers',
    () => {
        it('fails closed for unavailable or unbounded Web Locks and releases after rejection', async () => {
            expect(() =>
                createAuthenticatedCheckpointWebLock(null),
            ).toThrowError(
                expect.objectContaining({ code: 'InvalidConfiguration' }),
            );
            const webLock = createAuthenticatedCheckpointWebLock(
                navigator.locks,
            );
            let invalidOperationInvoked = false;
            await expect(
                webLock({
                    lockName: `caller-selected-${'x'.repeat(512)}`,
                    operation: () => {
                        invalidOperationInvoked = true;
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
            expect(invalidOperationInvoked).toBe(false);

            const lockName =
                'sealed-lattice-authenticated-checkpoint-browser-checkpoint-lock-01';
            const operationFailure = new Error(
                'injected checkpoint operation rejection',
            );
            await expect(
                webLock({
                    lockName,
                    operation: () => Promise.reject(operationFailure),
                }),
            ).rejects.toBe(operationFailure);
            await expect(
                webLock({
                    lockName,
                    operation: () => Promise.resolve(17),
                }),
            ).resolves.toBe(17);

            const requestFailure = new Error(
                'injected Web Lock request failure',
            );
            const failingLockManager = {
                request: () => Promise.reject(requestFailure),
            } as unknown as LockManager;
            await expect(
                createAuthenticatedCheckpointWebLock(failingLockManager)({
                    lockName,
                    operation: () => Promise.resolve(),
                }),
            ).rejects.toMatchObject({
                code: 'LockUnavailable',
                failureCause: requestFailure,
            });

            const postOperationRequestFailure = new Error(
                'injected post-operation Web Lock failure',
            );
            const postOperationFailingLockManager = {
                request: async (
                    grantedLockName: string,
                    _options: unknown,
                    callback: (lock: Lock | null) => Promise<unknown>,
                ): Promise<never> => {
                    await callback({
                        mode: 'exclusive',
                        name: grantedLockName,
                    });
                    throw postOperationRequestFailure;
                },
            } as unknown as LockManager;
            let postOperationCompleted = false;
            await expect(
                createAuthenticatedCheckpointWebLock(
                    postOperationFailingLockManager,
                )({
                    lockName,
                    operation: () => {
                        postOperationCompleted = true;
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({
                code: 'LockUnavailable',
                failureCause: postOperationRequestFailure,
            });
            expect(postOperationCompleted).toBe(true);
        });

        it('persists and resumes authenticated state after browser storage reopen', async () => {
            const databaseName = createDatabaseName();
            const scope = createScope(1);
            const firstHandle = await openOwnedStore(databaseName);
            const firstCheckpointStore = createCheckpointStore(firstHandle);
            await firstCheckpointStore.replaceCheckpoint({
                scope,
                stateChunks: [
                    new Uint8Array([1, 2, 3, 4]),
                    new Uint8Array([5, 6, 7, 8]),
                    new Uint8Array([9]),
                ],
            });
            await firstHandle.close();

            const secondHandle = await openOwnedStore(databaseName);
            const secondCheckpointStore = createCheckpointStore(secondHandle);
            expect(await restoreBytes(secondCheckpointStore, scope)).toEqual(
                new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]),
            );
            expect(await secondCheckpointStore.evictCheckpoint(scope)).toEqual({
                removedChunkCount: 3,
            });
            expect(
                await restoreBytes(secondCheckpointStore, scope),
            ).toBeUndefined();
        });

        it('holds the browser lock across a multi-instance replacement and eviction', async () => {
            const databaseName = createDatabaseName();
            const handle = await openOwnedStore(databaseName);
            const exclusiveLock = new BrowserCheckpointExclusiveLock();
            const firstCheckpointStore = createCheckpointStore(
                handle,
                new BrowserCheckpointCryptography(),
                exclusiveLock,
            );
            const secondCheckpointStore = createCheckpointStore(
                handle,
                new BrowserCheckpointCryptography(),
                exclusiveLock,
            );
            const scope = createScope(21);
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
                    yield new Uint8Array([2, 4, 6, 8]);
                    yield new Uint8Array([10]);
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
                totalByteLength: 5,
            });
            await expect(eviction).resolves.toEqual({
                removedChunkCount: 2,
            });
            expect(
                await restoreBytes(firstCheckpointStore, scope),
            ).toBeUndefined();
            expect(exclusiveLock.maximumActiveOperationCount).toBe(1);
        });

        it('cleans an interrupted chunk generation after close and storage recovery', async () => {
            const databaseName = createDatabaseName();
            const scope = createScope(2);
            const firstHandle = await openOwnedStore(databaseName);
            const failingCryptography = new BrowserCheckpointCryptography();
            const firstCheckpointStore = createCheckpointStore(
                firstHandle,
                failingCryptography,
            );
            const publishedBytes = new Uint8Array([1, 3, 5]);
            await firstCheckpointStore.replaceCheckpoint({
                scope,
                stateChunks: [publishedBytes],
            });
            failingCryptography.failFourthStateChunkOpen = true;

            await expect(
                firstCheckpointStore.replaceCheckpoint({
                    scope,
                    stateChunks: [new Uint8Array([2, 4, 6])],
                }),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
            await firstHandle.close();

            const secondHandle = await openOwnedStore(databaseName);
            const secondCheckpointStore = createCheckpointStore(secondHandle);
            expect(
                await secondCheckpointStore.cleanupInterruptedPublication(
                    scope,
                ),
            ).toEqual({ removedChunkCount: 1 });
            expect(await restoreBytes(secondCheckpointStore, scope)).toEqual(
                publishedBytes,
            );
            expect(
                await secondCheckpointStore.cleanupInterruptedPublication(
                    scope,
                ),
            ).toEqual({ removedChunkCount: 0 });
        });
    },
);
