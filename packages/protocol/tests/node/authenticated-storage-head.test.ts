import { describe, expect, it } from 'vitest';

import { createRuntimeRecordAuthenticatedRepairProtection } from '#packages/protocol/src/runtime/authenticated-runtime-record';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageTransactionLimits,
    type UntrustedStorageTransactionStore,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
import {
    generateRuntimeStorageRootKey,
    InMemoryRuntimeStorageAdapter,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const authenticatedStoreLimits: UntrustedStorageTransactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 1_024,
    maximumLeaseCountPerTransaction: 4,
    maximumOwnedRecordCount: 32,
    maximumStoredValueByteLength: 16_384,
    maximumTransactionByteLength: 4_096,
    maximumTransactionLifetimeMilliseconds: 1_000,
};

const deterministicIdentifierFactory = (): ((
    kind: 'lease' | 'transaction',
) => string) => {
    const counts = { lease: 0, transaction: 0 };
    return (kind) => {
        counts[kind] += 1;
        const kindByte = kind === 'transaction' ? '01' : '02';
        return `${kindByte}${counts[kind].toString(16).padStart(62, '0')}`;
    };
};

const writeRecords = async (
    store: UntrustedStorageTransactionStore,
    records: readonly Readonly<{ key: string; value: Uint8Array }>[],
): Promise<void> => {
    const transaction = await store.beginTransaction({
        lifetimeMilliseconds: 1_000,
    });
    try {
        for (const record of records) {
            const lease = await transaction.issueWriteLease({
                declaredByteLength: record.value.byteLength,
                logicalRecordKey: record.key,
            });
            await lease.write(record.value);
            await lease.seal(({ bytes, logicalRecordKey }) => {
                expect(logicalRecordKey).toBe(record.key);
                expect(bytes).toEqual(record.value);
            });
        }
        await transaction.commit();
    } catch (error) {
        await transaction.closeAfterFailure();
        throw error;
    }
};

describe('authenticated storage head', () => {
    it('binds repair authority to the candidate, runtime, and namespace', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const rootKey = await generateRuntimeStorageRootKey();
        const createProtection = (
            namespace: string,
            authorityContext = runtimeAuthorityContext(),
        ) =>
            createRuntimeRecordAuthenticatedRepairProtection({
                authorityContext,
                maximumRecordSealingCount: 64,
                namespace,
                rootKey,
            });
        const firstProtection = createProtection('authority-first');
        const secondNamespaceProtection = createProtection('authority-second');
        const secondCandidateProtection = createProtection(
            'authority-first',
            runtimeAuthorityContext({
                candidateIdentity: new Uint8Array(64).fill(0x91),
            }),
        );
        const secondRuntimeProtection = createProtection(
            'authority-first',
            runtimeAuthorityContext({
                runtimeManifestHash: new Uint8Array(64).fill(0x92),
            }),
        );

        expect(
            new Set(
                [
                    firstProtection,
                    secondNamespaceProtection,
                    secondCandidateProtection,
                    secondRuntimeProtection,
                ].map((protection) =>
                    Array.from(protection.repairIdentity).join(','),
                ),
            ).size,
        ).toBe(4);

        const openWith = (
            namespace: string,
            authenticatedRepairProtection: typeof firstProtection,
        ) =>
            openUntrustedStorageTransactionStore({
                adapter,
                authenticatedRepairProtection,
                createIdentifier: deterministicIdentifierFactory(),
                limits: authenticatedStoreLimits,
                monotonicClockMilliseconds: () => 0,
                namespace,
            });
        const firstStore = await openWith('authority-first', firstProtection);
        await writeRecords(firstStore.store, [
            {
                key: 'authority-record',
                value: new Uint8Array([0x11, 0x22]),
            },
        ]);
        const firstHeadKey =
            'sealed-lattice-runtime-store/authority-first/repair/current-head';
        const copiedHead = adapter.rawRead(firstHeadKey);
        if (copiedHead === undefined) {
            throw new Error('The first authenticated head is missing.');
        }
        adapter.rawWrite(
            'sealed-lattice-runtime-store/authority-second/repair/current-head',
            copiedHead,
        );

        await expect(
            openWith('authority-second', secondNamespaceProtection),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await expect(
            openWith('authority-first', secondCandidateProtection),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await expect(
            openWith('authority-first', secondRuntimeProtection),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

        await firstProtection.close();
        await firstProtection.close();
        await expect(
            openWith('authority-first', firstProtection),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await Promise.all([
            secondNamespaceProtection.close(),
            secondCandidateProtection.close(),
            secondRuntimeProtection.close(),
        ]);
    });

    it('binds the authorized empty coordinate to the storage identity and namespace', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const first = await openRuntimeTestStore({
            adapter,
            namespace: 'head-coordinate-first',
        });
        const second = await openRuntimeTestStore({
            adapter,
            namespace: 'head-coordinate-second',
        });

        const firstSnapshot = await first.store.authenticateCurrentHead();
        const repeatedSnapshot = await first.store.authenticateCurrentHead();
        const secondSnapshot = await second.store.authenticateCurrentHead();

        expect(firstSnapshot.namespaceSequence).toBe(0n);
        expect(
            firstSnapshot.predecessorAuthenticatedHeadDigest,
        ).toBeUndefined();
        expect(firstSnapshot.storageInstanceIdentity).toHaveLength(64);
        expect(firstSnapshot.authenticatedHeadDigest).toHaveLength(64);
        expect(repeatedSnapshot).toEqual(firstSnapshot);
        expect(repeatedSnapshot.authenticatedHeadDigest).not.toBe(
            firstSnapshot.authenticatedHeadDigest,
        );
        expect(first.store.copyStorageInstanceIdentity()).toEqual(
            firstSnapshot.storageInstanceIdentity,
        );
        expect(secondSnapshot.storageInstanceIdentity).not.toEqual(
            firstSnapshot.storageInstanceIdentity,
        );
        expect(secondSnapshot.authenticatedHeadDigest).not.toEqual(
            firstSnapshot.authenticatedHeadDigest,
        );
    });

    it('advances once per committed transaction and reproduces the exact coordinate after reopening', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const namespace = 'head-coordinate-transitions';
        const opened = await openRuntimeTestStore({ adapter, namespace });
        const emptySnapshot = await opened.store.authenticateCurrentHead();

        await writeRecords(opened.store, [
            { key: 'first', value: new Uint8Array([1, 2, 3]) },
        ]);
        const firstTransition = await opened.store.authenticateCurrentHead();
        await writeRecords(opened.store, [
            { key: 'second', value: new Uint8Array([4, 5]) },
            { key: 'third', value: new Uint8Array([6, 7, 8, 9]) },
        ]);
        const secondTransition = await opened.store.authenticateCurrentHead();

        expect(firstTransition.namespaceSequence).toBe(1n);
        expect(secondTransition.namespaceSequence).toBe(2n);
        expect(firstTransition.predecessorAuthenticatedHeadDigest).toEqual(
            new Uint8Array(64),
        );
        expect(secondTransition.predecessorAuthenticatedHeadDigest).toEqual(
            firstTransition.authenticatedHeadDigest,
        );
        expect(firstTransition.authenticatedHeadDigest).not.toEqual(
            emptySnapshot.authenticatedHeadDigest,
        );
        expect(secondTransition.authenticatedHeadDigest).not.toEqual(
            firstTransition.authenticatedHeadDigest,
        );

        const reopened = await openRuntimeTestStore({ adapter, namespace });
        expect(await reopened.store.authenticateCurrentHead()).toEqual(
            secondTransition,
        );
    });

    it('does not advance on rollback and detects an externally replaced head', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const namespace = 'head-coordinate-conflict';
        const { store } = await openRuntimeTestStore({ adapter, namespace });
        const emptySnapshot = await store.authenticateCurrentHead();
        const transaction = await store.beginTransaction({
            lifetimeMilliseconds: 1_000,
        });
        const lease = await transaction.issueWriteLease({
            declaredByteLength: 1,
            logicalRecordKey: 'conflicting',
        });
        await lease.write(new Uint8Array([1]));
        await lease.seal(() => undefined);
        adapter.forceNextAtomicConflict = true;
        await expect(transaction.commit()).rejects.toMatchObject({
            code: 'Conflict',
        });
        await transaction.abort();
        expect(await store.authenticateCurrentHead()).toEqual(emptySnapshot);

        await writeRecords(store, [
            { key: 'committed', value: new Uint8Array([9]) },
        ]);
        const repairHeadKey = `sealed-lattice-runtime-store/${namespace}/repair/current-head`;
        const replacedHead = adapter.rawRead(repairHeadKey);
        expect(replacedHead).toBeDefined();
        replacedHead![0] ^= 1;
        adapter.rawWrite(repairHeadKey, replacedHead!);

        await expect(store.authenticateCurrentHead()).rejects.toMatchObject({
            code: 'AuthenticationFailed',
        });
    });

    it('stores one bounded binary repair representation and rejects hostile binary variants after authentication', async () => {
        const adapter = new InMemoryRuntimeStorageAdapter();
        const namespace = 'binary-repair-head';
        const protection = createRuntimeRecordAuthenticatedRepairProtection({
            authorityContext: runtimeAuthorityContext(),
            maximumRecordSealingCount: 32,
            namespace,
            rootKey: await generateRuntimeStorageRootKey(),
        });
        const openStore = () =>
            openUntrustedStorageTransactionStore({
                adapter,
                authenticatedRepairProtection: protection,
                createIdentifier: deterministicIdentifierFactory(),
                limits: authenticatedStoreLimits,
                monotonicClockMilliseconds: () => 0,
                namespace,
            });
        const opened = await openStore();
        await writeRecords(opened.store, [
            { key: 'first', value: Uint8Array.of(1, 2, 3) },
            { key: 'second', value: Uint8Array.of(4, 5) },
        ]);
        const repairHeadKey = `sealed-lattice-runtime-store/${namespace}/repair/current-head`;
        const originalSealedHead = adapter.rawRead(repairHeadKey);
        expect(originalSealedHead).toBeDefined();
        const canonicalHead = await protection.open(
            originalSealedHead!.slice(),
        );
        expect([...canonicalHead.slice(0, 4)]).toEqual([
            0x53, 0x4c, 0x52, 0x48,
        ]);
        expect(() => {
            JSON.parse(new TextDecoder().decode(canonicalHead));
        }).toThrow();

        const wrongMagic = canonicalHead.slice();
        wrongMagic[0] ^= 0xff;
        const wrongVersion = canonicalHead.slice();
        new DataView(
            wrongVersion.buffer,
            wrongVersion.byteOffset,
            wrongVersion.byteLength,
        ).setUint16(4, 2, true);
        const zeroSequence = canonicalHead.slice();
        new DataView(
            zeroSequence.buffer,
            zeroSequence.byteOffset,
            zeroSequence.byteLength,
        ).setBigUint64(6, 0n, true);
        const tooManyRecords = canonicalHead.slice();
        new DataView(
            tooManyRecords.buffer,
            tooManyRecords.byteOffset,
            tooManyRecords.byteLength,
        ).setUint32(
            174,
            authenticatedStoreLimits.maximumOwnedRecordCount + 1,
            true,
        );
        const trailingByte = new Uint8Array(canonicalHead.byteLength + 1);
        trailingByte.set(canonicalHead);
        const truncated = canonicalHead.slice(0, canonicalHead.byteLength - 1);

        for (const hostileHead of [
            wrongMagic,
            wrongVersion,
            zeroSequence,
            tooManyRecords,
            trailingByte,
            truncated,
        ]) {
            adapter.rawWrite(repairHeadKey, await protection.seal(hostileHead));
            await expect(openStore()).rejects.toMatchObject({
                code: 'AuthenticationFailed',
            });
        }

        adapter.rawWrite(repairHeadKey, originalSealedHead!);
        expect(await openStore()).toMatchObject({
            repairReport: { retainedObjectCount: 2 },
        });
        canonicalHead.fill(0);
    });
});
