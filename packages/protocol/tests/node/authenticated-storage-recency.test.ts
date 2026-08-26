import { describe, expect, it } from 'vitest';

import {
    AuthenticatedStorageRecencyCoordinator,
    authenticatedStorageRecencyCoordinateByteLength,
} from '#packages/protocol/src/runtime/authenticated-storage-recency';
import type { UntrustedStorageTransactionStore } from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
import {
    InMemoryAuthenticatedStorageRecencyAnchor,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const commitRecord = async (
    store: UntrustedStorageTransactionStore,
    logicalRecordKey: string,
    value: Uint8Array,
): Promise<void> => {
    const transaction = await store.beginTransaction({
        lifetimeMilliseconds: 1_000,
    });
    try {
        const lease = await transaction.issueWriteLease({
            declaredByteLength: value.byteLength,
            logicalRecordKey,
        });
        await lease.write(value);
        await lease.seal(({ bytes }) => {
            expect(bytes).toEqual(value);
        });
        await transaction.commit();
    } catch (error) {
        await transaction.closeAfterFailure();
        throw error;
    }
};

const snapshotAdapter = (
    adapter: InMemoryRuntimeStorageAdapter,
): ReadonlyMap<string, Uint8Array> =>
    new Map(
        adapter.keys().map((key) => {
            const value = adapter.rawRead(key);
            if (value === undefined) {
                throw new Error('Adapter key disappeared during snapshot.');
            }
            return [key, value] as const;
        }),
    );

const restoreAdapter = (
    adapter: InMemoryRuntimeStorageAdapter,
    snapshot: ReadonlyMap<string, Uint8Array>,
): void => {
    for (const key of adapter.keys()) {
        adapter.rawDelete(key);
    }
    for (const [key, value] of snapshot) {
        adapter.rawWrite(key, value);
    }
};

describe('authenticated storage recency', () => {
    it('initializes one exact empty coordinate and preserves read-only state', async () => {
        const { store } = await openRuntimeTestStore({
            namespace: 'recency-empty-coordinate',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store,
        });

        await coordinator.reconcile();
        const initializedBytes = anchor.copyBytes();
        expect(initializedBytes).toHaveLength(
            authenticatedStorageRecencyCoordinateByteLength,
        );
        await expect(
            coordinator.runRead(() => Promise.resolve('read result')),
        ).resolves.toBe('read result');
        expect(anchor.copyBytes()).toEqual(initializedBytes);
        expect(anchor.compareAndSetCallCount).toBe(1);
    });

    it('advances once per mutation and accepts the exact reopened coordinate', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-mutation',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();
        const emptyCoordinate = anchor.copyBytes();

        await expect(
            coordinator.runMutation(async () => {
                await commitRecord(
                    opened.store,
                    'first-record',
                    new Uint8Array([1, 2, 3]),
                );
                return 17;
            }),
        ).resolves.toBe(17);
        const firstCoordinate = anchor.copyBytes();
        expect(firstCoordinate).not.toEqual(emptyCoordinate);

        const reopened = await openRuntimeTestStore({
            adapter: opened.adapter,
            namespace: 'recency-mutation',
        });
        const reopenedCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: reopened.store,
        });
        await expect(reopenedCoordinator.reconcile()).resolves.toBeUndefined();
        expect(anchor.copyBytes()).toEqual(firstCoordinate);
    });

    it('repairs exactly one committed transition after an interrupted anchor update', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-one-transition-repair',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const firstCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await firstCoordinator.reconcile();
        const emptyCoordinate = anchor.copyBytes();

        await commitRecord(
            opened.store,
            'interrupted-record',
            new Uint8Array([4, 5, 6]),
        );
        expect(anchor.copyBytes()).toEqual(emptyCoordinate);

        const resumedCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await expect(resumedCoordinator.reconcile()).resolves.toBeUndefined();
        expect(anchor.copyBytes()).not.toEqual(emptyCoordinate);
        expect(anchor.compareAndSetCallCount).toBe(2);
    });

    it('refuses an adjacent-sequence head whose predecessor is an unanchored fork', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-adjacent-fork',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();
        await coordinator.runMutation(() =>
            commitRecord(
                opened.store,
                'shared-predecessor',
                new Uint8Array([1]),
            ),
        );
        const sharedPredecessorSnapshot = snapshotAdapter(opened.adapter);
        await coordinator.runMutation(() =>
            commitRecord(
                opened.store,
                'anchored-second-transition',
                new Uint8Array([2]),
            ),
        );
        const anchoredCoordinate = anchor.copyBytes();

        restoreAdapter(opened.adapter, sharedPredecessorSnapshot);
        const forkIdentifierCounts = { lease: 100, transaction: 100 };
        const forked = await openRuntimeTestStore({
            adapter: opened.adapter,
            createIdentifier: (kind) => {
                forkIdentifierCounts[kind] += 1;
                const kindByte = kind === 'transaction' ? '01' : '02';
                return `${kindByte}${forkIdentifierCounts[kind]
                    .toString(16)
                    .padStart(62, '0')}`;
            },
            namespace: 'recency-adjacent-fork',
        });
        await commitRecord(
            forked.store,
            'forked-second-transition',
            new Uint8Array([3]),
        );
        await commitRecord(
            forked.store,
            'forked-third-transition',
            new Uint8Array([4]),
        );
        const forkedHead = await forked.store.authenticateCurrentHead();
        expect(forkedHead.namespaceSequence).toBe(3n);

        const forkedCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: forked.store,
        });
        await expect(forkedCoordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });
        expect(anchor.copyBytes()).toEqual(anchoredCoordinate);
    });

    it('retires on a skipped transition and remains retired', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-skipped-transition',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const firstCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await firstCoordinator.reconcile();
        await commitRecord(
            opened.store,
            'first-unanchored-record',
            new Uint8Array([7]),
        );
        await commitRecord(
            opened.store,
            'second-unanchored-record',
            new Uint8Array([8]),
        );

        const resumedCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await expect(resumedCoordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });
        await expect(resumedCoordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });
    });

    it('detects an authenticated local rollback behind the external anchor', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-local-rollback',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();
        const emptyStorageSnapshot = snapshotAdapter(opened.adapter);

        await coordinator.runMutation(() =>
            commitRecord(opened.store, 'newer-record', new Uint8Array([9, 10])),
        );
        const newerAnchor = anchor.copyBytes();
        restoreAdapter(opened.adapter, emptyStorageSnapshot);

        const rolledBack = await openRuntimeTestStore({
            adapter: opened.adapter,
            namespace: 'recency-local-rollback',
        });
        const rolledBackCoordinator =
            new AuthenticatedStorageRecencyCoordinator({
                anchor,
                store: rolledBack.store,
            });
        await expect(rolledBackCoordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });
        expect(anchor.copyBytes()).toEqual(newerAnchor);
    });

    it('retires on same-sequence anchor replacement and malformed anchor bytes', async () => {
        const firstOpened = await openRuntimeTestStore({
            namespace: 'recency-replaced-anchor',
        });
        const replacedAnchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const firstCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor: replacedAnchor,
            store: firstOpened.store,
        });
        await firstCoordinator.reconcile();
        const changedBytes = replacedAnchor.copyBytes();
        if (changedBytes === undefined) {
            throw new Error('Expected an initialized anchor.');
        }
        changedBytes[changedBytes.byteLength - 1] ^= 0x01;
        replacedAnchor.replaceBytes(changedBytes);
        await expect(firstCoordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });

        const secondOpened = await openRuntimeTestStore({
            namespace: 'recency-malformed-anchor',
        });
        const malformedAnchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        malformedAnchor.replaceBytes(new Uint8Array([1, 2, 3]));
        const secondCoordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor: malformedAnchor,
            store: secondOpened.store,
        });
        await expect(secondCoordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });
    });

    it('keeps transient anchor failures retryable without exposing a mutation', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-transient-anchor',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        anchor.failNextReadCount = 1;
        await expect(coordinator.reconcile()).rejects.toMatchObject({
            code: 'AnchorFailure',
        });
        await expect(coordinator.reconcile()).resolves.toBeUndefined();

        anchor.failNextCompareAndSetCount = 1;
        await expect(
            coordinator.runMutation(() =>
                commitRecord(
                    opened.store,
                    'committed-before-anchor-failure',
                    new Uint8Array([11]),
                ),
            ),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        await expect(coordinator.reconcile()).resolves.toBeUndefined();
        await expect(
            coordinator.runRead(() => Promise.resolve('safe after repair')),
        ).resolves.toBe('safe after repair');
    });

    it('reconciles a committed throwing mutation but preserves its original failure', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-throwing-mutation',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();
        const operationFailure = new Error('Injected post-commit failure.');

        await expect(
            coordinator.runMutation(async () => {
                await commitRecord(
                    opened.store,
                    'committed-then-thrown',
                    new Uint8Array([12]),
                );
                throw operationFailure;
            }),
        ).rejects.toBe(operationFailure);
        await expect(coordinator.reconcile()).resolves.toBeUndefined();
    });

    it('does not advance for a failed pre-commit mutation or a successful no-op', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-mutation-outcomes',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();
        const emptyCoordinate = anchor.copyBytes();
        const operationFailure = new Error('Injected pre-commit failure.');

        await expect(
            coordinator.runMutation(() => Promise.reject(operationFailure)),
        ).rejects.toBe(operationFailure);
        expect(anchor.copyBytes()).toEqual(emptyCoordinate);
        await expect(
            coordinator.runMutation(() => Promise.resolve('no mutation')),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        expect(anchor.copyBytes()).toEqual(emptyCoordinate);
    });

    it('does not mistake non-error rejections for successful operations', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-non-error-rejection',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();
        const emptyCoordinate = anchor.copyBytes();
        const nonErrorFailure = undefined as unknown as Error;

        await expect(
            coordinator.runRead(() => Promise.reject(nonErrorFailure)),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await expect(
            coordinator.runMutation(() => Promise.reject(nonErrorFailure)),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(anchor.copyBytes()).toEqual(emptyCoordinate);
        await expect(coordinator.reconcile()).resolves.toBeUndefined();
    });

    it('retires when a read-only callback mutates authenticated storage', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-read-mutation',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();

        await expect(
            coordinator.runRead(async () => {
                await commitRecord(
                    opened.store,
                    'forbidden-read-write',
                    new Uint8Array([13]),
                );
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(coordinator.reconcile()).rejects.toMatchObject({
            code: 'Conflict',
        });
    });

    it('serializes concurrent mutations into consecutive anchored transitions', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'recency-concurrent-mutations',
        });
        const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
        const coordinator = new AuthenticatedStorageRecencyCoordinator({
            anchor,
            store: opened.store,
        });
        await coordinator.reconcile();

        await Promise.all([
            coordinator.runMutation(() =>
                commitRecord(
                    opened.store,
                    'concurrent-first',
                    new Uint8Array([14]),
                ),
            ),
            coordinator.runMutation(() =>
                commitRecord(
                    opened.store,
                    'concurrent-second',
                    new Uint8Array([15]),
                ),
            ),
        ]);
        const snapshot = await opened.store.authenticateCurrentHead();
        expect(snapshot.namespaceSequence).toBe(2n);
        await expect(coordinator.reconcile()).resolves.toBeUndefined();
        expect(anchor.compareAndSetCallCount).toBe(3);
    });
});
