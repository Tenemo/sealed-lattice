import type {
    AuthenticatedMailboxPlaintextCapability,
    AuthenticatedMailboxPlaintextSinkLease,
    AuthenticatedMailboxProducerSlot,
    SetupMailboxSlot,
} from '@sealed-lattice/crypto';
import {
    foundationProfile,
    recipientPrivateVssShareMailboxPayloadType,
    type ProtocolHash,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createRecipientVssAuthenticatedMailboxPlaintextSink as createAuthorityBoundRecipientVssAuthenticatedMailboxPlaintextSink,
    type AuthenticatedMailboxStorageLimits,
} from '#packages/protocol/src/index';
import { createRecipientVssAuthenticatedMailboxPlaintextSinkWithConsumer as createRecipientVssAuthenticatedMailboxPlaintextSink } from '#packages/protocol/src/runtime/recipient-vss-authenticated-mailbox-sink/runtime';
import type { RecipientVssAuthenticatedPlaintextConsumer } from '#packages/protocol/src/runtime/recipient-vss-authenticated-mailbox-sink/records';
import { createRuntimeRecordProtection } from '#packages/protocol/src/runtime/authenticated-runtime-record';
import {
    generateRuntimeStorageEncryptionKey,
    hashFilledWith,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const textDecoder = new TextDecoder();

it('requires a live worker-issued aggregate recipient authority', async () => {
    const harness = await openRuntimeTestStore({
        namespace: 'recipient-vss-forged-authority-test',
    });
    const encryptionKey = await generateRuntimeStorageEncryptionKey();
    expect(() =>
        createAuthorityBoundRecipientVssAuthenticatedMailboxPlaintextSink({
            authority: Object.freeze({
                release: () => undefined,
            }) as never,
            expectedSetupMailboxSlot,
            expectedSetupMailboxSlotHash: hashHex(0x99),
            limits: storageLimits,
            protection: createRuntimeRecordProtection({
                authorityContext: runtimeAuthorityContext(),
                encryptionKey,
                maximumRecordSealingCount:
                    storageLimits.maximumRecordSealingCount,
            }),
            store: harness.store,
        }),
    ).toThrowError(/consumedState/u);
});

const storageLimits: AuthenticatedMailboxStorageLimits = {
    maximumCarrierByteLength: 16 * 1_024,
    maximumMailboxByteLength: foundationProfile.streamChunkByteLength * 3,
    maximumRecordSealingCount: 10_000,
    transactionLifetimeMilliseconds: 5_000,
};

const hashHex = (byte: number): ProtocolHash =>
    Array.from(hashFilledWith(byte), (value) =>
        value.toString(16).padStart(2, '0'),
    ).join('');

const expectedSetupMailboxSlot: SetupMailboxSlot = Object.freeze({
    actionContextHash: hashHex(0x33),
    ceremonyContextHash: hashHex(0x22),
    orderedMaterialRoots: Object.freeze([hashHex(0x91)]),
    payloadType: recipientPrivateVssShareMailboxPayloadType,
    producerSequence: '7',
    recipientParticipantId: hashHex(0x44),
    rosterHash: hashHex(0x66),
    sourceParticipantId: hashHex(0x77),
    statementHash: hashHex(0x88),
    suiteId: hashHex(0x11),
});

const producerSlot: AuthenticatedMailboxProducerSlot = Object.freeze({
    actionContextHash: expectedSetupMailboxSlot.actionContextHash,
    ceremonyContextHash: expectedSetupMailboxSlot.ceremonyContextHash,
    payloadType: expectedSetupMailboxSlot.payloadType,
    producerSequence: expectedSetupMailboxSlot.producerSequence,
    recipientParticipantId: expectedSetupMailboxSlot.recipientParticipantId,
    rosterHash: expectedSetupMailboxSlot.rosterHash,
    sourceParticipantId: expectedSetupMailboxSlot.sourceParticipantId,
    suiteId: expectedSetupMailboxSlot.suiteId,
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

const splitPlaintext = (plaintext: Uint8Array): readonly Uint8Array[] => {
    const chunks: Uint8Array[] = [];
    for (
        let byteOffset = 0;
        byteOffset < plaintext.byteLength;
        byteOffset += foundationProfile.streamChunkByteLength
    ) {
        chunks.push(
            plaintext.slice(
                byteOffset,
                Math.min(
                    plaintext.byteLength,
                    byteOffset + foundationProfile.streamChunkByteLength,
                ),
            ),
        );
    }
    return chunks;
};

const stagePlaintext = async (
    lease: AuthenticatedMailboxPlaintextSinkLease,
    plaintext: Uint8Array,
): Promise<void> => {
    const chunks = splitPlaintext(plaintext);
    for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += 1) {
        await lease.stageChunk({
            bytes: arrayBufferFrom(chunks[chunkIndex]),
            chunkIndex,
        });
    }
};

const createCapability = (): Readonly<{
    capability: AuthenticatedMailboxPlaintextCapability;
    releaseCount(): number;
}> => {
    let released = false;
    let releaseCount = 0;
    const capability: AuthenticatedMailboxPlaintextCapability = Object.freeze({
        release: () => {
            if (released) {
                throw new Error(
                    'The test authenticated-plaintext capability was already consumed.',
                );
            }
            released = true;
            releaseCount += 1;
        },
    });
    return Object.freeze({ capability, releaseCount: () => releaseCount });
};

const createConsumer = (): Readonly<{
    consumedEnvelopes: Uint8Array[];
    consumedPlaintexts: Uint8Array[];
    consumer: RecipientVssAuthenticatedPlaintextConsumer;
    retirementFailures: unknown[];
}> => {
    const consumedEnvelopes: Uint8Array[] = [];
    const consumedPlaintexts: Uint8Array[] = [];
    const retirementFailures: unknown[] = [];
    return {
        consumedEnvelopes,
        consumedPlaintexts,
        consumer: Object.freeze({
            consumeAuthenticatedPlaintext: async ({
                authenticatedPlaintextCapability,
                canonicalPlaintextBytes,
                canonicalSignedEnvelopeBytes,
            }) => {
                consumedEnvelopes.push(canonicalSignedEnvelopeBytes.slice());
                consumedPlaintexts.push(canonicalPlaintextBytes.slice());
                authenticatedPlaintextCapability.release();
            },
            retireAfterUncertainConsumption: async (failure) => {
                retirementFailures.push(failure);
            },
        }),
        retirementFailures,
    };
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

const createHarness = async (input?: {
    consumer?: ReturnType<typeof createConsumer>;
    encryptionKey?: CryptoKey;
    storeHarness?: Awaited<ReturnType<typeof openRuntimeTestStore>>;
}) => {
    const storeHarness =
        input?.storeHarness ??
        (await openRuntimeTestStore({
            namespace: 'recipient-vss-mailbox-sink-test',
        }));
    const encryptionKey =
        input?.encryptionKey ?? (await generateRuntimeStorageEncryptionKey());
    const consumer = input?.consumer ?? createConsumer();
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        encryptionKey,
        maximumRecordSealingCount: storageLimits.maximumRecordSealingCount,
    });
    const sink = createRecipientVssAuthenticatedMailboxPlaintextSink({
        consumer: consumer.consumer,
        expectedSetupMailboxSlot,
        expectedSetupMailboxSlotHash: hashHex(0x99),
        limits: storageLimits,
        protection,
        store: storeHarness.store,
    });
    return { consumer, encryptionKey, sink, storeHarness };
};

const reservation = (input: {
    canonicalEnvelopeBytes: Uint8Array;
    envelopeHash: ProtocolHash;
    plaintextByteLength: number;
}) => ({
    canonicalEnvelopeBytes: input.canonicalEnvelopeBytes,
    envelopeHash: input.envelopeHash,
    plaintextByteLength: input.plaintextByteLength,
    producerSlot,
});

describe('recipient VSS authenticated mailbox plaintext sink', () => {
    it('reauthenticates prepared and restarted committed plaintext before worker-local consumption', async () => {
        const plaintext = deterministicBytes(
            foundationProfile.streamChunkByteLength + 37,
            0x31,
        );
        const canonicalEnvelopeBytes = deterministicBytes(113, 0x82);
        const envelopeHash = hashHex(0xa1);
        const firstHarness = await createHarness();
        const firstLease = await firstHarness.sink.plaintextSinkBoundary.reserve(
            reservation({
                canonicalEnvelopeBytes,
                envelopeHash,
                plaintextByteLength: plaintext.byteLength,
            }),
        );
        expect(firstLease.disposition).toBe('fresh');
        expect(firstLease.authenticationRequirement).toBe('authenticate');
        await stagePlaintext(firstLease, plaintext);
        const abandonedCapability = createCapability();
        await firstLease.seal(abandonedCapability.capability);
        await firstLease.release();
        expect(abandonedCapability.releaseCount()).toBe(1);
        expect(firstHarness.consumer.consumedPlaintexts).toEqual([]);

        const preparedConsumer = createConsumer();
        const preparedHarness = await createHarness({
            consumer: preparedConsumer,
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const preparedLease =
            await preparedHarness.sink.plaintextSinkBoundary.reserve(
                reservation({
                    canonicalEnvelopeBytes,
                    envelopeHash,
                    plaintextByteLength: plaintext.byteLength,
                }),
            );
        expect(preparedLease.disposition).toBe('prepared');
        expect(preparedLease.authenticationRequirement).toBe('authenticate');
        await stagePlaintext(preparedLease, plaintext);
        const preparedCapability = createCapability();
        await preparedLease.seal(preparedCapability.capability);
        await preparedLease.commit();
        expect(preparedCapability.releaseCount()).toBe(1);
        expect(preparedConsumer.consumedEnvelopes).toEqual([
            canonicalEnvelopeBytes,
        ]);
        expect(preparedConsumer.consumedPlaintexts).toEqual([plaintext]);
        expect(preparedConsumer.retirementFailures).toEqual([]);

        const liveCommittedLease =
            await preparedHarness.sink.plaintextSinkBoundary.reserve(
                reservation({
                    canonicalEnvelopeBytes,
                    envelopeHash,
                    plaintextByteLength: plaintext.byteLength,
                }),
            );
        expect(liveCommittedLease.disposition).toBe('committed');
        expect(liveCommittedLease.authenticationRequirement).toBe('none');
        await liveCommittedLease.commit();
        expect(preparedConsumer.consumedPlaintexts).toHaveLength(1);

        const restartedConsumer = createConsumer();
        const restartedHarness = await createHarness({
            consumer: restartedConsumer,
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const restartedLease =
            await restartedHarness.sink.plaintextSinkBoundary.reserve(
                reservation({
                    canonicalEnvelopeBytes,
                    envelopeHash,
                    plaintextByteLength: plaintext.byteLength,
                }),
            );
        expect(restartedLease.disposition).toBe('committed');
        expect(restartedLease.authenticationRequirement).toBe('authenticate');
        await stagePlaintext(restartedLease, plaintext);
        const restartedCapability = createCapability();
        await restartedLease.seal(restartedCapability.capability);
        await restartedLease.commit();
        expect(restartedCapability.releaseCount()).toBe(1);
        expect(restartedConsumer.consumedEnvelopes).toEqual([
            canonicalEnvelopeBytes,
        ]);
        expect(restartedConsumer.consumedPlaintexts).toEqual([plaintext]);
        expect(restartedConsumer.retirementFailures).toEqual([]);
    });

    it('retires the one-shot capability and consumer when protected staged plaintext is corrupted', async () => {
        const plaintext = deterministicBytes(257, 0x53);
        const canonicalEnvelopeBytes = deterministicBytes(97, 0x72);
        const envelopeHash = hashHex(0xb2);
        const firstHarness = await createHarness();
        const firstLease = await firstHarness.sink.plaintextSinkBoundary.reserve(
            reservation({
                canonicalEnvelopeBytes,
                envelopeHash,
                plaintextByteLength: plaintext.byteLength,
            }),
        );
        await stagePlaintext(firstLease, plaintext);
        const abandonedCapability = createCapability();
        await firstLease.seal(abandonedCapability.capability);
        await firstLease.release();
        tamperLogicalRecord(firstHarness.storeHarness.adapter, '/chunk/');

        const restartedConsumer = createConsumer();
        const restartedHarness = await createHarness({
            consumer: restartedConsumer,
            encryptionKey: firstHarness.encryptionKey,
            storeHarness: firstHarness.storeHarness,
        });
        const restartedLease =
            await restartedHarness.sink.plaintextSinkBoundary.reserve(
                reservation({
                    canonicalEnvelopeBytes,
                    envelopeHash,
                    plaintextByteLength: plaintext.byteLength,
                }),
            );
        await stagePlaintext(restartedLease, plaintext);
        const restartedCapability = createCapability();
        await restartedLease.seal(restartedCapability.capability);
        await expect(restartedLease.commit()).rejects.toMatchObject({
            code: 'AuthenticationFailed',
        });
        expect(restartedCapability.releaseCount()).toBe(1);
        expect(restartedConsumer.consumedPlaintexts).toEqual([]);
        expect(restartedConsumer.retirementFailures).toHaveLength(1);
        await expect(
            restartedHarness.sink.plaintextSinkBoundary.reserve(
                reservation({
                    canonicalEnvelopeBytes,
                    envelopeHash,
                    plaintextByteLength: plaintext.byteLength,
                }),
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });
});
