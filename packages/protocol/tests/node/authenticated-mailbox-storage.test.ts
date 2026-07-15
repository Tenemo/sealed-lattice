import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    AuthenticatedMailboxStorageError,
    createBrowserLocalAuthenticatedMailboxStorage,
    type AuthenticatedMailboxStorageLimits,
    type BrowserLocalAuthenticatedMailboxStorage,
} from '#packages/protocol/src/index';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const textDecoder = new TextDecoder();

const mailboxStorageLimits: AuthenticatedMailboxStorageLimits = {
    maximumCarrierByteLength: 16 * 1_024,
    maximumMailboxByteLength: foundationProfile.streamChunkByteLength * 3,
    maximumRecordSealingCount: 10_000,
    transactionLifetimeMilliseconds: 5_000,
};

const hashHex = (byte: number): ProtocolHash =>
    Array.from(hashFilledWith(byte), (value) =>
        value.toString(16).padStart(2, '0'),
    ).join('');

const producerSlot = (input: {
    direction: 'inbound' | 'outbound';
    producerSequence?: string;
}) => ({
    actionContextHash: hashHex(0x33),
    ceremonyContextHash: hashHex(0x22),
    payloadType: 2 as const,
    producerSequence: input.producerSequence ?? '7',
    recipientParticipantId:
        input.direction === 'inbound' ? hashHex(0x44) : hashHex(0x77),
    rosterHash: hashHex(0x66),
    sourceParticipantId:
        input.direction === 'outbound' ? hashHex(0x44) : hashHex(0x77),
    suiteId: hashHex(0x11),
});

const carrier = (byte = 0xa1) => ({
    canonicalEnvelopeBytes: new Uint8Array([
        byte,
        byte ^ 0xff,
        0x03,
        0x04,
        0x05,
    ]),
});

const arrayBufferFrom = (bytes: Uint8Array): ArrayBuffer => {
    const copied = new Uint8Array(new ArrayBuffer(bytes.byteLength));
    copied.set(bytes);

    return copied.buffer;
};

const deterministicBytes = (byteLength: number, offset: number): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
        bytes[byteIndex] = (byteIndex * 29 + offset) & 0xff;
    }

    return bytes;
};

const decodeLogicalRecordKey = (indexKey: string): string | undefined => {
    const marker = '/indices/';
    const markerOffset = indexKey.indexOf(marker);
    if (markerOffset < 0) {
        return undefined;
    }
    const encoded = indexKey.slice(markerOffset + marker.length);
    if (encoded.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(encoded)) {
        return undefined;
    }
    const bytes = new Uint8Array(encoded.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            encoded.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return textDecoder.decode(bytes);
};

const tamperLogicalRecord = (
    adapter: InMemoryRuntimeStorageAdapter,
    logicalRecordKeyFragment: string,
): void => {
    const indexKey = adapter
        .keys()
        .find((key) =>
            decodeLogicalRecordKey(key)?.includes(logicalRecordKeyFragment),
        );
    if (indexKey === undefined) {
        throw new Error('Expected logical record index was not found.');
    }
    const indexValue = adapter.rawRead(indexKey);
    if (indexValue === undefined) {
        throw new Error('Expected logical record index value was not found.');
    }
    const objectKey = textDecoder.decode(indexValue);
    const objectValue = adapter.rawRead(objectKey);
    if (objectValue === undefined) {
        throw new Error('Expected logical record object was not found.');
    }
    objectValue[Math.floor(objectValue.byteLength / 2)] ^= 0x80;
    adapter.rawWrite(objectKey, objectValue);
};

const logicalRecordKeys = (
    adapter: InMemoryRuntimeStorageAdapter,
): readonly string[] =>
    adapter
        .keys()
        .map(decodeLogicalRecordKey)
        .filter((key): key is string => key !== undefined);

const requiredIndexKey = (
    adapter: InMemoryRuntimeStorageAdapter,
    logicalRecordKeyFragment: string,
): string => {
    const key = adapter
        .keys()
        .find((candidate) =>
            decodeLogicalRecordKey(candidate)?.includes(
                logicalRecordKeyFragment,
            ),
        );
    if (key === undefined) {
        throw new Error('Expected logical record index was not found.');
    }

    return key;
};

const requiredObjectKey = (
    adapter: InMemoryRuntimeStorageAdapter,
    indexKey: string,
): string => {
    const indexValue = adapter.rawRead(indexKey);
    if (indexValue === undefined) {
        throw new Error('Expected logical record index value was not found.');
    }

    return textDecoder.decode(indexValue);
};

const createHarness = async (input?: {
    encryptionKey?: CryptoKey;
    runtimeBuildManifestByte?: number;
    storeHarness?: Awaited<ReturnType<typeof openRuntimeTestStore>>;
}): Promise<{
    adapter: InMemoryRuntimeStorageAdapter;
    encryptionKey: CryptoKey;
    storage: BrowserLocalAuthenticatedMailboxStorage;
    storeHarness: Awaited<ReturnType<typeof openRuntimeTestStore>>;
}> => {
    const storeHarness =
        input?.storeHarness ??
        (await openRuntimeTestStore({ namespace: 'mailbox-storage-test' }));
    const encryptionKey =
        input?.encryptionKey ?? (await generateRuntimeStorageEncryptionKey());
    const storage = createBrowserLocalAuthenticatedMailboxStorage({
        authorityContext: runtimeAuthorityContext({
            runtimeBuildManifestHash: hashFilledWith(
                input?.runtimeBuildManifestByte ?? 0x55,
            ),
        }),
        encryptionKey,
        limits: mailboxStorageLimits,
        store: storeHarness.store,
    });

    return {
        adapter: storeHarness.adapter,
        encryptionKey,
        storage,
        storeHarness,
    };
};

describe('Browser-local authenticated mailbox storage', () => {
    it('publishes outbound chunks through an authenticated manifest and reuses only the exact cached slot', async () => {
        const { storage } = await createHarness();
        const totalByteLength = foundationProfile.streamChunkByteLength + 37;
        const firstChunk = deterministicBytes(
            foundationProfile.streamChunkByteLength,
            0x13,
        );
        const secondChunk = deterministicBytes(37, 0x71);
        const slot = producerSlot({ direction: 'outbound' });
        const lease = await storage.outboundCache.reserve({
            plaintextByteLength: totalByteLength,
            producerSlot: slot,
        });

        expect(lease.disposition).toBe('fresh');
        await lease.stageChunk({
            bytes: arrayBufferFrom(firstChunk),
            chunkIndex: 0,
        });
        await lease.stageChunk({
            bytes: arrayBufferFrom(secondChunk),
            chunkIndex: 1,
        });
        await expect(
            lease.pullChunk({
                chunkIndex: 0,
                expectedByteLength: firstChunk.byteLength,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        const signedCarrier = carrier();
        await lease.commit(signedCarrier);

        expect(
            new Uint8Array(
                (await lease.pullChunk({
                    chunkIndex: 0,
                    expectedByteLength: firstChunk.byteLength,
                }))!,
            ),
        ).toEqual(firstChunk);
        expect(
            new Uint8Array(
                (await lease.pullChunk({
                    chunkIndex: 1,
                    expectedByteLength: secondChunk.byteLength,
                }))!,
            ),
        ).toEqual(secondChunk);
        await expect(
            lease.pullChunk({ chunkIndex: 2, expectedByteLength: 0 }),
        ).resolves.toBeUndefined();

        const cachedLease = await storage.outboundCache.reserve({
            plaintextByteLength: totalByteLength,
            producerSlot: slot,
        });
        expect(cachedLease.disposition).toBe('cached');
        await expect(cachedLease.cachedCarrier()).resolves.toEqual({
            canonicalEnvelopeBytes: signedCarrier.canonicalEnvelopeBytes,
        });
        expect(
            new Uint8Array(
                (await cachedLease.pullChunk({
                    chunkIndex: 1,
                    expectedByteLength: secondChunk.byteLength,
                }))!,
            ),
        ).toEqual(secondChunk);
        await expect(
            storage.outboundCache.reserve({
                plaintextByteLength: totalByteLength + 1,
                producerSlot: slot,
            }),
        ).rejects.toMatchObject({
            code: 'Equivocation',
        });
    });

    it('durably reserves outbound slots before chunk consumption and repairs abandoned journals', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({
            direction: 'outbound',
            producerSequence: '11',
        });
        const firstLease = await firstHarness.storage.outboundCache.reserve({
            plaintextByteLength: 23,
            producerSlot: slot,
        });
        await expect(
            firstHarness.storage.outboundCache.reserve({
                plaintextByteLength: 23,
                producerSlot: slot,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await firstLease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(23, 0x42)),
            chunkIndex: 0,
        });

        const restartedHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const repairedLease =
            await restartedHarness.storage.outboundCache.reserve({
                plaintextByteLength: 23,
                producerSlot: slot,
            });
        expect(repairedLease.disposition).toBe('fresh');
        await repairedLease.cancel();

        expect(
            restartedHarness.adapter
                .keys()
                .map(decodeLogicalRecordKey)
                .filter((key) => key?.includes('/outbound/')),
        ).toEqual([]);
    });

    it('does not publish cancelled outbound chunks and removes every journal-owned record', async () => {
        const { adapter, storage } = await createHarness();
        const lease = await storage.outboundCache.reserve({
            plaintextByteLength: 31,
            producerSlot: producerSlot({
                direction: 'outbound',
                producerSequence: '12',
            }),
        });
        await lease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(31, 0x19)),
            chunkIndex: 0,
        });
        await lease.cancel();
        await lease.cancel();

        expect(logicalRecordKeys(adapter)).toEqual([]);
        await expect(lease.cachedCarrier()).rejects.toMatchObject({
            code: 'InvalidState',
        });
    });

    it('retains the outbound journal when cleanup fails so a restarted authority can finish it', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({
            direction: 'outbound',
            producerSequence: '13',
        });
        const lease = await firstHarness.storage.outboundCache.reserve({
            plaintextByteLength: 17,
            producerSlot: slot,
        });
        await lease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(17, 0x63)),
            chunkIndex: 0,
        });
        firstHarness.adapter.failAtomicMutationAfter(1);
        await expect(lease.cancel()).rejects.toMatchObject({
            code: 'CleanupFailed',
        });
        expect(
            firstHarness.adapter
                .keys()
                .map(decodeLogicalRecordKey)
                .some((key) => key?.includes('/outbound/journal/')),
        ).toBe(true);

        const restartedHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const repairedLease =
            await restartedHarness.storage.outboundCache.reserve({
                plaintextByteLength: 17,
                producerSlot: slot,
            });
        expect(repairedLease.disposition).toBe('fresh');
        await repairedLease.cancel();
        expect(logicalRecordKeys(restartedHarness.adapter)).toEqual([]);
    });

    it('keeps outbound and staging leases cleanable when transaction acquisition is unavailable', async () => {
        const harness = await createHarness();
        const outboundLease = await harness.storage.outboundCache.reserve({
            plaintextByteLength: 21,
            producerSlot: producerSlot({
                direction: 'outbound',
                producerSequence: '14',
            }),
        });
        await outboundLease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(21, 0x39)),
            chunkIndex: 0,
        });
        const outboundBlockingTransactions = await Promise.all(
            Array.from({ length: 8 }, () =>
                harness.storeHarness.store.beginTransaction({
                    lifetimeMilliseconds: 5_000,
                }),
            ),
        );
        const uncommittedCarrier = carrier(0xa2);
        await expect(
            outboundLease.commit(uncommittedCarrier),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
        await Promise.all(
            outboundBlockingTransactions.map((transaction) =>
                transaction.abort(),
            ),
        );
        await expect(outboundLease.cancel()).resolves.toBeUndefined();
        expect(logicalRecordKeys(harness.adapter)).toEqual([]);

        const envelopeHash = hashHex(0x94);
        const stagingLease = await harness.storage.stagingBoundary.open({
            envelopeHash,
            totalByteLength: 27,
        });
        await stagingLease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(27, 0x51)),
            chunkIndex: 0,
        });
        const stagingBlockingTransactions = await Promise.all(
            Array.from({ length: 8 }, () =>
                harness.storeHarness.store.beginTransaction({
                    lifetimeMilliseconds: 5_000,
                }),
            ),
        );
        await expect(stagingLease.seal()).rejects.toMatchObject({
            code: 'ResourceLimit',
        });
        await Promise.all(
            stagingBlockingTransactions.map((transaction) =>
                transaction.abort(),
            ),
        );
        await expect(stagingLease.dispose()).resolves.toBeUndefined();
        expect(logicalRecordKeys(harness.adapter)).toEqual([]);

        const replacementLease = await harness.storage.stagingBoundary.open({
            envelopeHash,
            totalByteLength: 29,
        });
        await replacementLease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(29, 0x72)),
            chunkIndex: 0,
        });
        await replacementLease.seal();
        await replacementLease.dispose();
        expect(logicalRecordKeys(harness.adapter)).toEqual([]);
    });

    it('commits staging before reread and preserves evidence after authenticated chunk tampering', async () => {
        const { adapter, storage } = await createHarness();
        const totalByteLength = foundationProfile.streamChunkByteLength + 19;
        const firstChunk = deterministicBytes(
            foundationProfile.streamChunkByteLength,
            0x28,
        );
        const secondChunk = deterministicBytes(19, 0x81);
        const envelopeHash = hashHex(0x91);
        const lease = await storage.stagingBoundary.open({
            envelopeHash,
            totalByteLength,
        });

        await expect(
            lease.pullChunk({
                chunkIndex: 0,
                expectedByteLength: firstChunk.byteLength,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        await lease.stageChunk({
            bytes: arrayBufferFrom(firstChunk),
            chunkIndex: 0,
        });
        await lease.stageChunk({
            bytes: arrayBufferFrom(secondChunk),
            chunkIndex: 1,
        });
        await lease.seal();
        expect(
            new Uint8Array(
                (await lease.pullChunk({
                    chunkIndex: 0,
                    expectedByteLength: firstChunk.byteLength,
                }))!,
            ),
        ).toEqual(firstChunk);
        await expect(
            lease.pullChunk({ chunkIndex: 2, expectedByteLength: 0 }),
        ).resolves.toBeUndefined();

        tamperLogicalRecord(adapter, '/staging/chunk/');
        await expect(
            lease.pullChunk({
                chunkIndex: 0,
                expectedByteLength: firstChunk.byteLength,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await expect(lease.dispose()).rejects.toMatchObject({
            code: 'CleanupFailed',
        });
        expect(
            logicalRecordKeys(adapter).some((key) =>
                key.includes('/staging/chunk/'),
            ),
        ).toBe(true);
    });

    it('rejects out-of-order and wrong-length staging chunks without publishing a manifest', async () => {
        const { adapter, storage } = await createHarness();
        const initialKeys = adapter.keys();
        const lease = await storage.stagingBoundary.open({
            envelopeHash: hashHex(0x92),
            totalByteLength: 29,
        });

        await expect(
            lease.stageChunk({
                bytes: arrayBufferFrom(deterministicBytes(29, 0x32)),
                chunkIndex: 1,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(
            lease.stageChunk({
                bytes: arrayBufferFrom(deterministicBytes(28, 0x32)),
                chunkIndex: 0,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        await expect(lease.seal()).rejects.toMatchObject({
            code: 'InvalidState',
        });
        await lease.dispose();
        expect(adapter.keys()).toEqual(initialKeys);
    });

    it('repairs a sealed staging lease after restart before accepting replacement chunks', async () => {
        const firstHarness = await createHarness();
        const envelopeHash = hashHex(0x93);
        const abandonedLease = await firstHarness.storage.stagingBoundary.open({
            envelopeHash,
            totalByteLength: 41,
        });
        await abandonedLease.stageChunk({
            bytes: arrayBufferFrom(deterministicBytes(41, 0x37)),
            chunkIndex: 0,
        });
        await abandonedLease.seal();

        const restartedHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const replacementLease =
            await restartedHarness.storage.stagingBoundary.open({
                envelopeHash,
                totalByteLength: 43,
            });
        const replacementChunk = deterministicBytes(43, 0x83);
        await replacementLease.stageChunk({
            bytes: arrayBufferFrom(replacementChunk),
            chunkIndex: 0,
        });
        await replacementLease.seal();
        expect(
            new Uint8Array(
                (await replacementLease.pullChunk({
                    chunkIndex: 0,
                    expectedByteLength: replacementChunk.byteLength,
                }))!,
            ),
        ).toEqual(replacementChunk);
        await replacementLease.dispose();
        expect(logicalRecordKeys(restartedHarness.adapter)).toEqual([]);
    });

    it('classifies inbound retransmission, active reuse, and signed-slot equivocation exactly', async () => {
        const { storage } = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xb1);
        const first = await storage.inboundSlotAuthority.reserve({
            ...signedCarrier,
            producerSlot: slot,
        });
        expect(first.isValid).toBe(true);
        if (!first.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        expect(first.value.disposition).toBe('fresh');

        await expect(
            storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            }),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'consumedState',
        });
        await expect(
            storage.inboundSlotAuthority.reserve({
                canonicalEnvelopeBytes: new Uint8Array([0x99]),
                producerSlot: slot,
            }),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'equivocation',
        });
        await first.value.commit();

        const retransmission = await storage.inboundSlotAuthority.reserve({
            ...signedCarrier,
            producerSlot: slot,
        });
        expect(retransmission.isValid).toBe(true);
        if (!retransmission.isValid) {
            throw new Error('Expected an exact inbound retransmission.');
        }
        expect(retransmission.value.disposition).toBe(
            'byteIdenticalRetransmission',
        );
        await expect(
            storage.inboundSlotAuthority.reserve({
                canonicalEnvelopeBytes: new Uint8Array([0x10, 0x20]),
                producerSlot: slot,
            }),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'equivocation',
        });
    });

    it('makes a failed inbound commit terminal without corrupting a later reservation', async () => {
        const harness = await createHarness();
        const slot = producerSlot({
            direction: 'inbound',
            producerSequence: '15',
        });
        const signedCarrier = carrier(0xb9);
        const reservation = await harness.storage.inboundSlotAuthority.reserve({
            ...signedCarrier,
            producerSlot: slot,
        });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        harness.adapter.failAtomicMutationAfter(1);
        await expect(reservation.value.commit()).rejects.toMatchObject({
            code: 'StorageFailure',
        });
        await expect(reservation.value.commit()).rejects.toMatchObject({
            code: 'InvalidState',
        });

        const replacement = await harness.storage.inboundSlotAuthority.reserve({
            ...signedCarrier,
            producerSlot: slot,
        });
        expect(replacement.isValid).toBe(true);
        if (!replacement.isValid) {
            throw new Error('Expected a replacement inbound reservation.');
        }
        expect(replacement.value.disposition).toBe('fresh');
        await replacement.value.commit();

        const retransmission =
            await harness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        expect(retransmission).toMatchObject({
            isValid: true,
            value: { disposition: 'byteIdenticalRetransmission' },
        });
    });

    it('refuses restart without deleting a malformed committed inbound index', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xb3);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();
        const indexKey = requiredIndexKey(
            firstHarness.adapter,
            '/inbound/slot/',
        );
        const objectKey = requiredObjectKey(firstHarness.adapter, indexKey);
        firstHarness.adapter.rawWrite(indexKey, new Uint8Array([0xff]));

        await expect(
            openRuntimeTestStore({
                adapter: firstHarness.adapter,
                namespace: 'mailbox-storage-test',
            }),
        ).rejects.toMatchObject({ code: 'CorruptIndex' });
        expect(firstHarness.adapter.rawRead(indexKey)).toEqual(
            new Uint8Array([0xff]),
        );
        expect(firstHarness.adapter.rawRead(objectKey)).toBeDefined();
    });

    it('uses the authenticated head to reject a missing committed index after restart', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xb4);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();
        const indexKey = requiredIndexKey(
            firstHarness.adapter,
            '/inbound/slot/',
        );
        const objectKey = requiredObjectKey(firstHarness.adapter, indexKey);
        firstHarness.adapter.rawDelete(indexKey);
        await expect(
            openRuntimeTestStore({
                adapter: firstHarness.adapter,
                namespace: 'mailbox-storage-test',
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(firstHarness.adapter.rawRead(objectKey)).toBeDefined();
    });

    it('refuses to replace or delete live objects whose bytes no longer match the authenticated head', async () => {
        const harness = await createHarness();
        const writeRecord = async (
            logicalRecordKey: string,
            bytes: Uint8Array,
        ): Promise<void> => {
            const transaction =
                await harness.storeHarness.store.beginTransaction({
                    lifetimeMilliseconds: 5_000,
                });
            const lease = await transaction.issueWriteLease({
                declaredByteLength: bytes.byteLength,
                logicalRecordKey,
            });
            await lease.write(bytes);
            await lease.seal(({ bytes: storedBytes }) => {
                expect(storedBytes).toEqual(bytes);
            });
            await transaction.commit();
        };
        const deletionRecordKey = 'mailbox/live-tamper-delete';
        const replacementRecordKey = 'mailbox/live-tamper-replace';
        await writeRecord(deletionRecordKey, new Uint8Array([1, 3, 5, 7, 9]));
        await writeRecord(
            replacementRecordKey,
            new Uint8Array([2, 4, 6, 8, 10]),
        );
        const deletionIndexKey = requiredIndexKey(
            harness.adapter,
            deletionRecordKey,
        );
        const replacementIndexKey = requiredIndexKey(
            harness.adapter,
            replacementRecordKey,
        );
        const deletionObjectKey = requiredObjectKey(
            harness.adapter,
            deletionIndexKey,
        );
        const replacementObjectKey = requiredObjectKey(
            harness.adapter,
            replacementIndexKey,
        );
        const deletionBytes = harness.adapter.rawRead(deletionObjectKey);
        const replacementBytes = harness.adapter.rawRead(replacementObjectKey);
        if (deletionBytes === undefined || replacementBytes === undefined) {
            throw new Error('Expected committed generic record bytes.');
        }
        deletionBytes[1] ^= 0x80;
        replacementBytes[3] ^= 0x40;
        harness.adapter.rawWrite(deletionObjectKey, deletionBytes);
        harness.adapter.rawWrite(replacementObjectKey, replacementBytes);
        const headKey = harness.adapter
            .keys()
            .find((key) => key.endsWith('/repair/current-head'));
        if (headKey === undefined) {
            throw new Error('Expected authenticated repair head.');
        }
        const headBeforeRefusedMutations = harness.adapter.rawRead(headKey);

        const deletionTransaction =
            await harness.storeHarness.store.beginTransaction({
                lifetimeMilliseconds: 5_000,
            });
        await expect(
            deletionTransaction.stageDeletion(deletionRecordKey),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await deletionTransaction.closeAfterFailure();

        const replacementTransaction =
            await harness.storeHarness.store.beginTransaction({
                lifetimeMilliseconds: 5_000,
            });
        await expect(
            replacementTransaction.issueWriteLease({
                declaredByteLength: 5,
                logicalRecordKey: replacementRecordKey,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await replacementTransaction.closeAfterFailure();

        expect(harness.adapter.rawRead(deletionIndexKey)).toBeDefined();
        expect(harness.adapter.rawRead(replacementIndexKey)).toBeDefined();
        expect(harness.adapter.rawRead(deletionObjectKey)).toEqual(
            deletionBytes,
        );
        expect(harness.adapter.rawRead(replacementObjectKey)).toEqual(
            replacementBytes,
        );
        expect(harness.adapter.rawRead(headKey)).toEqual(
            headBeforeRefusedMutations,
        );
    });

    it('adopts an intact authenticated head and cleans only abandoned pre-commit objects after restart', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xb7);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();
        const committedIndexKey = requiredIndexKey(
            firstHarness.adapter,
            '/inbound/slot/',
        );
        const committedObjectKey = requiredObjectKey(
            firstHarness.adapter,
            committedIndexKey,
        );
        const abandonedTransaction =
            await firstHarness.storeHarness.store.beginTransaction({
                lifetimeMilliseconds: 5_000,
            });
        const abandonedLease = await abandonedTransaction.issueWriteLease({
            declaredByteLength: 4,
            logicalRecordKey: 'mailbox/abandoned-pre-commit-object',
        });
        await abandonedLease.write(new Uint8Array([9, 8, 7, 6]));
        await abandonedLease.seal(() => undefined);
        const abandonedObjectKey = firstHarness.adapter
            .keys()
            .find(
                (key) =>
                    key.includes('/objects/') && key !== committedObjectKey,
            );
        if (abandonedObjectKey === undefined) {
            throw new Error('Expected an abandoned pre-commit object.');
        }

        const reopenedStore = await openRuntimeTestStore({
            adapter: firstHarness.adapter,
            namespace: 'mailbox-storage-test',
        });
        expect(
            firstHarness.adapter.rawRead(abandonedObjectKey),
        ).toBeUndefined();
        const restartedHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: reopenedStore,
        });
        const retransmission =
            await restartedHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });

        expect(retransmission.isValid).toBe(true);
        if (!retransmission.isValid) {
            throw new Error('Expected an exact inbound retransmission.');
        }
        expect(retransmission.value.disposition).toBe(
            'byteIdenticalRetransmission',
        );
        expect(
            firstHarness.adapter.rawRead(abandonedObjectKey),
        ).toBeUndefined();
        expect(firstHarness.adapter.rawRead(committedObjectKey)).toBeDefined();
    });

    it('rejects a missing committed object and preserves its index for diagnosis', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xb5);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();
        const indexKey = requiredIndexKey(
            firstHarness.adapter,
            '/inbound/slot/',
        );
        const objectKey = requiredObjectKey(firstHarness.adapter, indexKey);
        firstHarness.adapter.rawDelete(objectKey);

        await expect(
            openRuntimeTestStore({
                adapter: firstHarness.adapter,
                namespace: 'mailbox-storage-test',
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(firstHarness.adapter.rawRead(indexKey)).toBeDefined();
    });

    it('authenticates the current head before adopting committed mailbox state after restart', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xb6);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();
        const headKey = firstHarness.adapter
            .keys()
            .find((key) => key.endsWith('/repair/current-head'));
        if (headKey === undefined) {
            throw new Error('Expected authenticated repair head.');
        }
        const headBytes = firstHarness.adapter.rawRead(headKey);
        if (headBytes === undefined) {
            throw new Error('Expected authenticated repair head bytes.');
        }
        headBytes[Math.floor(headBytes.byteLength / 2)] ^= 0x80;
        firstHarness.adapter.rawWrite(headKey, headBytes);
        await expect(
            openRuntimeTestStore({
                adapter: firstHarness.adapter,
                namespace: 'mailbox-storage-test',
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('rejects committed mailbox records under a different encryption key', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({
            direction: 'inbound',
            producerSequence: '16',
        });
        const signedCarrier = carrier(0xba);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();
        const differentEncryptionKey =
            await generateRuntimeStorageEncryptionKey();

        const wrongKeyHarness = await createHarness({
            encryptionKey: differentEncryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        await expect(
            wrongKeyHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

        const retransmission =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        expect(retransmission).toMatchObject({
            isValid: true,
            value: { disposition: 'byteIdenticalRetransmission' },
        });
    });

    it('rejects substitution of older committed bytes at the current object key after restart', async () => {
        const firstHarness = await createHarness();
        const logicalRecordKey = 'mailbox/digest-substitution-regression';
        const writeGenericRecord = async (
            bytes: Uint8Array,
            expectedCurrentValue?: Uint8Array,
        ): Promise<void> => {
            const transaction =
                await firstHarness.storeHarness.store.beginTransaction({
                    lifetimeMilliseconds: 5_000,
                });
            const lease = await transaction.issueWriteLease({
                declaredByteLength: bytes.byteLength,
                ...(expectedCurrentValue === undefined
                    ? {}
                    : { expectedCurrentValue }),
                logicalRecordKey,
            });
            await lease.write(bytes);
            await lease.seal(({ bytes: observedBytes }) => {
                expect(observedBytes).toEqual(bytes);
            });
            await transaction.commit();
        };
        const firstValue = new Uint8Array([1, 3, 5, 7, 9]);
        const secondValue = new Uint8Array([2, 4, 6, 8, 10]);
        await writeGenericRecord(firstValue);
        const indexKey = requiredIndexKey(
            firstHarness.adapter,
            logicalRecordKey,
        );
        const firstObjectKey = requiredObjectKey(
            firstHarness.adapter,
            indexKey,
        );
        const olderCommittedBytes =
            firstHarness.adapter.rawRead(firstObjectKey);
        if (olderCommittedBytes === undefined) {
            throw new Error('Expected first committed object bytes.');
        }
        await writeGenericRecord(secondValue, firstValue);
        const currentObjectKey = requiredObjectKey(
            firstHarness.adapter,
            indexKey,
        );
        firstHarness.adapter.rawWrite(currentObjectKey, olderCommittedBytes);
        await expect(
            openRuntimeTestStore({
                adapter: firstHarness.adapter,
                namespace: 'mailbox-storage-test',
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(firstHarness.adapter.rawRead(currentObjectKey)).toEqual(
            olderCommittedBytes,
        );
    });

    it('binds inbound records to the runtime build and rejects a wrong local authority context', async () => {
        const firstHarness = await createHarness();
        const slot = producerSlot({ direction: 'inbound' });
        const signedCarrier = carrier(0xc1);
        const reservation =
            await firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            });
        if (!reservation.isValid) {
            throw new Error('Expected a fresh inbound mailbox reservation.');
        }
        await reservation.value.commit();

        const wrongContextHarness = await createHarness({
            encryptionKey: firstHarness.encryptionKey,
            runtimeBuildManifestByte: 0x56,
            storeHarness: firstHarness.storeHarness,
        });
        await expect(
            wrongContextHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: slot,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        await expect(
            firstHarness.storage.inboundSlotAuthority.reserve({
                ...signedCarrier,
                producerSlot: {
                    ...slot,
                    actionContextHash: hashHex(0xdd),
                },
            }),
        ).rejects.toMatchObject({
            code: 'InvalidInput',
            name: AuthenticatedMailboxStorageError.name,
        });
    });
});
