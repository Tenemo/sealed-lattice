import { describe, expect, it } from 'vitest';

import {
    createRuntimeRecordProtection,
    createRuntimeRecordProtectionFromSession,
    maximumRuntimeRecordDerivationCount,
    readRuntimeRecord,
    releaseRuntimeRecordProtection,
    runtimeRecordEnvelopeOverheadByteLength,
    sampleRuntimeIdentifier,
    sealRuntimeRecord,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtectionSession,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import {
    generateRuntimeStorageRootKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const repeatedSaltCryptoProvider = (): Crypto =>
    ({
        getRandomValues: <Value extends ArrayBufferView>(
            value: Value,
        ): Value => {
            new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
            ).fill(0x5a);
            return value;
        },
        subtle: globalThis.crypto.subtle,
    }) as Crypto;

describe('authenticated runtime records', () => {
    it('requires one nonextractable HKDF root and a bounded derivation count', async () => {
        const aesGcmKey = await globalThis.crypto.subtle.generateKey(
            { length: 256, name: 'AES-GCM' },
            false,
            ['decrypt', 'encrypt'],
        );
        const deriveBitsOnlyRootKey = await globalThis.crypto.subtle.importKey(
            'raw',
            new Uint8Array(32).fill(0x41),
            'HKDF',
            false,
            ['deriveBits'],
        );
        const validRootKey = await generateRuntimeStorageRootKey();
        for (const invalidInput of [
            { maximumRecordSealingCount: 1, rootKey: aesGcmKey },
            {
                maximumRecordSealingCount: 1,
                rootKey: deriveBitsOnlyRootKey,
            },
            {
                maximumRecordSealingCount:
                    maximumRuntimeRecordDerivationCount + 1,
                rootKey: validRootKey,
            },
        ]) {
            expect(() =>
                createRuntimeRecordProtection({
                    authorityContext: runtimeAuthorityContext(),
                    ...invalidInput,
                }),
            ).toThrowError(
                expect.objectContaining({ code: 'InvalidConfiguration' }),
            );
        }
    });

    it('rejects malformed UTF-16 in authenticated text fields', async () => {
        const rootKey = await generateRuntimeStorageRootKey();
        const protection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            maximumRecordSealingCount: 4,
            rootKey,
        });
        for (const malformedInput of [
            {
                logicalRecordKey: 'record-\ud800',
                operationDomain: 'sealed-lattice/test/runtime-record/v1',
            },
            {
                logicalRecordKey: 'valid-record',
                operationDomain: 'sealed-lattice/test/\udc00/v1',
            },
        ]) {
            await expect(
                sealRuntimeRecord({
                    ...malformedInput,
                    plaintext: new Uint8Array([1]),
                    protection,
                }),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        }
    });

    it('rejects key-derivation salt reuse across protection instances sharing one root key', async () => {
        const rootKey = await generateRuntimeStorageRootKey();
        const firstProtection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            cryptoProvider: repeatedSaltCryptoProvider(),
            maximumRecordSealingCount: 2,
            rootKey,
        });
        const secondProtection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            cryptoProvider: repeatedSaltCryptoProvider(),
            maximumRecordSealingCount: 2,
            rootKey,
        });

        const sealed = await sealRuntimeRecord({
            logicalRecordKey: 'salt-registry/first',
            operationDomain: 'sealed-lattice/test/runtime-record/v1',
            plaintext: new Uint8Array([1, 2, 3]),
            protection: firstProtection,
        });
        expect(sealed.byteLength).toBeGreaterThan(3);

        await releaseRuntimeRecordProtection(firstProtection);
        await expect(
            sealRuntimeRecord({
                logicalRecordKey: 'salt-registry/released',
                operationDomain: 'sealed-lattice/test/runtime-record/v1',
                plaintext: new Uint8Array([7, 8, 9]),
                protection: firstProtection,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });

        await expect(
            sealRuntimeRecord({
                logicalRecordKey: 'salt-registry/second',
                operationDomain: 'sealed-lattice/test/runtime-record/v1',
                plaintext: new Uint8Array([4, 5, 6]),
                protection: secondProtection,
            }),
        ).rejects.toMatchObject({ code: 'EntropyFailure' });
    });

    it('delegates exact canonical inputs and releases the owned session once', async () => {
        const recordedAssociatedData: Uint8Array[] = [];
        const recordedPlaintexts: Uint8Array[] = [];
        const delegatedInputReferences: Uint8Array[] = [];
        let closeCount = 0;
        const session: RuntimeRecordProtectionSession = Object.freeze({
            close: () => {
                closeCount += 1;
            },
            openCanonicalEnvelope: () =>
                Promise.reject(new Error('Not used by this test.')),
            sampleIdentifier: ({ byteLength }) =>
                new Uint8Array(byteLength).fill(0x3c),
            sealPlaintext: ({ associatedData, plaintext }) => {
                recordedAssociatedData.push(associatedData.slice());
                recordedPlaintexts.push(plaintext.slice());
                delegatedInputReferences.push(associatedData, plaintext);
                return Promise.resolve(
                    new Uint8Array(
                        plaintext.byteLength +
                            runtimeRecordEnvelopeOverheadByteLength,
                    ).fill(7),
                );
            },
        });
        const protection = createRuntimeRecordProtectionFromSession({
            authorityContext: runtimeAuthorityContext(),
            session,
        });

        const firstEnvelope = await sealRuntimeRecord({
            logicalRecordKey: 'first-record',
            operationDomain: 'sealed-lattice/test/delegated-record/v1',
            plaintext: new Uint8Array([1, 2, 3]),
            protection,
        });
        const secondEnvelope = await sealRuntimeRecord({
            logicalRecordKey: 'second-record',
            operationDomain: 'sealed-lattice/test/delegated-record/v1',
            plaintext: new Uint8Array([4, 5, 6]),
            protection,
        });

        expect(firstEnvelope).toEqual(
            new Uint8Array(3 + runtimeRecordEnvelopeOverheadByteLength).fill(7),
        );
        expect(secondEnvelope).toEqual(firstEnvelope);
        expect(recordedPlaintexts).toEqual([
            new Uint8Array([1, 2, 3]),
            new Uint8Array([4, 5, 6]),
        ]);
        expect(recordedAssociatedData[0]).not.toEqual(
            recordedAssociatedData[1],
        );
        expect(
            delegatedInputReferences.every((bytes) =>
                bytes.every((byte) => byte === 0),
            ),
        ).toBe(true);

        const firstRelease = releaseRuntimeRecordProtection(protection);
        const secondRelease = releaseRuntimeRecordProtection(protection);
        await expect(firstRelease).resolves.toBeUndefined();
        await expect(secondRelease).resolves.toBeUndefined();
        expect(closeCount).toBe(1);
        await expect(
            sealRuntimeRecord({
                logicalRecordKey: 'released-record',
                operationDomain: 'sealed-lattice/test/delegated-record/v1',
                plaintext: new Uint8Array([9]),
                protection,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('retries failed session cleanup while keeping record protection unavailable', async () => {
        let closeAttemptCount = 0;
        const protection = createRuntimeRecordProtectionFromSession({
            authorityContext: runtimeAuthorityContext(),
            session: Object.freeze({
                close: () => {
                    closeAttemptCount += 1;
                    return closeAttemptCount === 1
                        ? Promise.reject(
                              new Error('Injected session cleanup failure.'),
                          )
                        : Promise.resolve();
                },
                openCanonicalEnvelope: () =>
                    Promise.reject(new Error('Not used by this test.')),
                sampleIdentifier: ({ byteLength }) =>
                    new Uint8Array(byteLength).fill(0x4d),
                sealPlaintext: () => Promise.resolve(new Uint8Array([1])),
            }),
        });

        await expect(
            releaseRuntimeRecordProtection(protection),
        ).rejects.toThrow('Injected session cleanup failure.');
        expect(() =>
            sampleRuntimeIdentifier(
                protection,
                new Set<string>(),
                'unavailable identifier',
            ),
        ).toThrowError(expect.objectContaining({ code: 'InvalidState' }));

        await expect(
            releaseRuntimeRecordProtection(protection),
        ).resolves.toBeUndefined();
        expect(closeAttemptCount).toBe(2);
    });

    it('rejects invalid worker-session outputs without retaining them', async () => {
        let invalidIdentifier: Uint8Array | undefined;
        const protection = createRuntimeRecordProtectionFromSession({
            authorityContext: runtimeAuthorityContext(),
            session: Object.freeze({
                close: () => undefined,
                openCanonicalEnvelope: () =>
                    Promise.reject(new Error('Not used by this test.')),
                sampleIdentifier: () => {
                    invalidIdentifier = new Uint8Array([1, 2, 3]);
                    return invalidIdentifier;
                },
                sealPlaintext: () => Promise.resolve(new Uint8Array([1])),
            }),
        });

        expect(() =>
            sampleRuntimeIdentifier(
                protection,
                new Set<string>(),
                'delegated identifier',
            ),
        ).toThrow(expect.objectContaining({ code: 'EntropyFailure' }));
        expect(invalidIdentifier).toEqual(new Uint8Array([0, 0, 0]));
        await expect(
            sealRuntimeRecord({
                logicalRecordKey: 'invalid-envelope',
                operationDomain: 'sealed-lattice/test/delegated-record/v1',
                plaintext: new Uint8Array([1]),
                protection,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        await releaseRuntimeRecordProtection(protection);
    });

    it('does not mistake a non-error storage rejection for a missing record', async () => {
        const opened = await openRuntimeTestStore({
            namespace: 'runtime-record-non-error-rejection',
        });
        const protection = createRuntimeRecordProtection({
            authorityContext: runtimeAuthorityContext(),
            maximumRecordSealingCount: 2,
            rootKey: await generateRuntimeStorageRootKey(),
        });
        const transaction = await opened.store.beginTransaction({
            lifetimeMilliseconds: 1_000,
        });
        await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: null,
            logicalRecordKey: 'rejected-read',
            operationDomain: 'sealed-lattice/test/rejected-read/v1',
            plaintext: new Uint8Array([1, 2, 3]),
            protection,
            transaction,
        });
        await transaction.commit();
        opened.adapter.rejectNextReadWith(undefined);

        await expect(
            readRuntimeRecord({
                logicalRecordKey: 'rejected-read',
                operationDomain: 'sealed-lattice/test/rejected-read/v1',
                protection,
                store: opened.store,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
    });
});
