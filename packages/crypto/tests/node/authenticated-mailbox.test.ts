import { sha384 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    AuthenticatedMailboxCleanupError,
    openAuthenticatedMailbox,
    sealAuthenticatedMailbox,
    type AuthenticatedMailboxCarrier,
    type AuthenticatedMailboxGcmRuntime,
    type AuthenticatedMailboxInboundSlotAuthority,
    type AuthenticatedMailboxKernel,
    type AuthenticatedMailboxOutboundCache,
    type AuthenticatedMailboxProducerSlot,
    type AuthenticatedMailboxStagingBoundary,
    type AuthenticatedMailboxStreamBoundary,
    type MailboxAssociatedData,
    type MailboxAssociatedDataExpectation,
    type MailboxKeyScheduleInput,
    type SignedMailboxEnvelope,
    type UnsignedMailboxEnvelope,
} from '#packages/crypto/src/authenticated-mailbox';
import {
    canonicalJson,
    hash512Hex,
    openBrowserLocalExternalKeyProvider,
} from '#packages/crypto/src/index';
import { createBrowserLocalKeyOperations } from '#packages/crypto/tests/support/browser-local-key-operations';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const mailboxSignatureContext = textEncoder.encode(
    'sealed-lattice/mailbox-signature/v1',
);

const canonicalBytesHex = (value: unknown): string =>
    bytesToHex(textEncoder.encode(canonicalJson(value)));

const objectHash = (domain: string, value: unknown): ProtocolHash =>
    hash512Hex(domain, [textEncoder.encode(canonicalJson(value))]);

const unsignedEnvelope = (
    envelope: SignedMailboxEnvelope,
): UnsignedMailboxEnvelope => {
    const { sourceSignatureHex: _sourceSignatureHex, ...unsigned } = envelope;
    return unsigned;
};

const keyScheduleValue = (
    value: MailboxKeyScheduleInput | MailboxAssociatedData,
): MailboxKeyScheduleInput => ({
    suiteId: value.suiteId,
    ceremonyContextHash: value.ceremonyContextHash,
    actionContextHash: value.actionContextHash,
    rosterHash: value.rosterHash,
    sourceParticipantId: value.sourceParticipantId,
    recipientParticipantId: value.recipientParticipantId,
    producerSequence: value.producerSequence,
    envelopeAttemptIdentifierHex: value.envelopeAttemptIdentifierHex,
    payloadType: value.payloadType,
    statementHash: value.statementHash,
    orderedMaterialRoots: value.orderedMaterialRoots,
    kemCiphertextHash: value.kemCiphertextHash,
});

const kernel: AuthenticatedMailboxKernel = {
    encodeMailboxKeyScheduleInput: (value) => {
        const keySchedule = keyScheduleValue(value);
        return {
            canonicalBytesHex: canonicalBytesHex(keySchedule),
            hkdfExtractSaltHex: objectHash(
                'test/mailbox-hkdf-salt',
                keySchedule,
            ).slice(0, 96),
        };
    },
    encodeMailboxAssociatedData: (value) => ({
        canonicalBytesHex: canonicalBytesHex(value),
        hkdfExtractSaltHex: objectHash('test/mailbox-hkdf-salt', value).slice(
            0,
            96,
        ),
    }),
    encodeSignedMailboxEnvelope: (value) => ({
        canonicalBytesHex: canonicalBytesHex(value),
        envelopeHash: objectHash(
            'test/mailbox-envelope',
            unsignedEnvelope(value),
        ),
    }),
    decodeSignedMailboxEnvelope: (input) => {
        const value = JSON.parse(
            textDecoder.decode(hexToBytes(input.canonicalBytesHex)),
        ) as SignedMailboxEnvelope;
        return {
            value,
            envelopeHash: objectHash(
                'test/mailbox-envelope',
                unsignedEnvelope(value),
            ),
        };
    },
    deriveMailboxKemCiphertextHash: (input) =>
        hash512Hex('test/mailbox-kem-ciphertext', [
            hexToBytes(input.kemCiphertextHex),
        ]),
    deriveMailboxEnvelopeHash: (value) =>
        objectHash('test/mailbox-envelope', value),
    deriveSetupMailboxSlotHash: (value) =>
        objectHash('test/setup-mailbox-slot', value),
};

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

const slotKey = (slot: AuthenticatedMailboxProducerSlot): string =>
    canonicalJson(slot);

type TestLeaseState =
    | 'active'
    | 'authenticating'
    | 'cancelled'
    | 'completed'
    | 'decrypting'
    | 'failed';

const makeStreamBoundary = (): AuthenticatedMailboxStreamBoundary => ({
    openWriter: ({ totalByteLength }) => {
        const chunkCount = Math.ceil(
            totalByteLength / foundationProfile.streamChunkByteLength,
        );
        const chunkDigests: ProtocolHash[] = [];
        let state: TestLeaseState = 'active';
        return {
            absorbChunk: (chunkIndex, bytes) => {
                if (state !== 'active' || chunkIndex !== chunkDigests.length) {
                    state = 'failed';
                    throw Object.assign(new Error('invalid stream order'), {
                        refusalReason: 'wrongTypeOrLength' as const,
                    });
                }
                chunkDigests.push(
                    hash512Hex('test/mailbox-stream-chunk', [
                        new Uint8Array(bytes),
                    ]),
                );
            },
            cancel: () => {
                if (state === 'active') {
                    state = 'cancelled';
                }
            },
            chunkCount,
            finish: () => {
                if (state !== 'active' || chunkDigests.length !== chunkCount) {
                    state = 'failed';
                    throw Object.assign(new Error('incomplete stream'), {
                        refusalReason: 'wrongTypeOrLength' as const,
                    });
                }
                state = 'completed';
                return {
                    totalByteLength: String(totalByteLength),
                    orderedChunkDigests: chunkDigests,
                };
            },
            state: () => state,
            totalByteLength,
        };
    },
    openVerifier: ({ descriptor }) => {
        const totalByteLength = Number(descriptor.totalByteLength);
        const chunkCount = descriptor.orderedChunkDigests.length;
        const observedChunkDigests: ProtocolHash[] = [];
        let state: TestLeaseState = 'active';
        return {
            absorbChunk: (chunkIndex, bytes) => {
                if (
                    state !== 'active' ||
                    chunkIndex !== observedChunkDigests.length
                ) {
                    state = 'failed';
                    throw Object.assign(new Error('invalid stream order'), {
                        refusalReason: 'wrongTypeOrLength' as const,
                    });
                }
                const observedDigest = hash512Hex('test/mailbox-stream-chunk', [
                    new Uint8Array(bytes),
                ]);
                if (
                    observedDigest !==
                    descriptor.orderedChunkDigests[chunkIndex]
                ) {
                    state = 'failed';
                    throw Object.assign(new Error('stream digest mismatch'), {
                        refusalReason: 'wrongHashOrRoot' as const,
                    });
                }
                observedChunkDigests.push(observedDigest);
            },
            cancel: () => {
                if (state === 'active') {
                    state = 'cancelled';
                }
            },
            chunkCount,
            finish: () => {
                if (
                    state !== 'active' ||
                    observedChunkDigests.length !== chunkCount ||
                    observedChunkDigests.some(
                        (digest, chunkIndex) =>
                            digest !==
                            descriptor.orderedChunkDigests[chunkIndex],
                    )
                ) {
                    state = 'failed';
                    throw Object.assign(new Error('stream digest mismatch'), {
                        refusalReason: 'wrongHashOrRoot' as const,
                    });
                }
                state = 'completed';
            },
            state: () => state,
            totalByteLength,
        };
    },
});

type GcmRuntimeObservation = {
    authenticationFinished: boolean;
};

const makeGcmRuntime = (
    observation: GcmRuntimeObservation,
): AuthenticatedMailboxGcmRuntime => {
    const initialHash = (
        key: Uint8Array,
        nonce: Uint8Array,
        associatedData: Uint8Array,
    ) => {
        const hash = sha384.create();
        hash.update(key);
        hash.update(nonce);
        hash.update(associatedData);
        return hash;
    };
    const applyKeystream = (
        bytes: Uint8Array,
        key: Uint8Array,
        nonce: Uint8Array,
        startingOffset: number,
    ): void => {
        for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
            const offset = startingOffset + byteIndex;
            bytes[byteIndex] ^=
                key[offset % key.byteLength] ^
                nonce[offset % nonce.byteLength] ^
                (offset & 0xff);
        }
    };

    return {
        openEncryptor: (input) => {
            const key = input.key.slice();
            const nonce = input.nonce.slice();
            const hash = initialHash(key, nonce, input.associatedData);
            let processedByteLength = 0;
            let state: TestLeaseState = 'active';
            return {
                cancel: () => {
                    if (state === 'active') {
                        state = 'cancelled';
                    }
                    key.fill(0);
                    nonce.fill(0);
                    hash.destroy();
                },
                encryptChunk: (buffer) => {
                    if (state !== 'active') {
                        throw new Error('encryptor is inactive');
                    }
                    const bytes = new Uint8Array(buffer);
                    applyKeystream(bytes, key, nonce, processedByteLength);
                    processedByteLength += bytes.byteLength;
                    hash.update(bytes);
                },
                finish: () => {
                    if (
                        state !== 'active' ||
                        processedByteLength !== input.totalByteLength
                    ) {
                        state = 'failed';
                        throw Object.assign(new Error('wrong GCM length'), {
                            refusalReason: 'wrongTypeOrLength' as const,
                        });
                    }
                    state = 'completed';
                    const tag = hash.digest().slice(0, 16);
                    key.fill(0);
                    nonce.fill(0);
                    return tag;
                },
                state: () => state,
            };
        },
        openVerifier: (input) => {
            const key = input.key.slice();
            const nonce = input.nonce.slice();
            const hash = initialHash(key, nonce, input.associatedData);
            let authenticatedByteLength = 0;
            let decryptedByteLength = 0;
            let state: TestLeaseState = 'authenticating';
            return {
                authenticateChunk: (buffer) => {
                    if (state !== 'authenticating') {
                        throw new Error('verifier is not authenticating');
                    }
                    const bytes = new Uint8Array(buffer);
                    authenticatedByteLength += bytes.byteLength;
                    hash.update(bytes);
                },
                cancel: () => {
                    if (state !== 'completed' && state !== 'failed') {
                        state = 'cancelled';
                    }
                    key.fill(0);
                    nonce.fill(0);
                    hash.destroy();
                },
                decryptChunk: (buffer) => {
                    if (state !== 'decrypting') {
                        throw new Error('verifier is not decrypting');
                    }
                    const bytes = new Uint8Array(buffer);
                    applyKeystream(bytes, key, nonce, decryptedByteLength);
                    decryptedByteLength += bytes.byteLength;
                },
                finishAuthentication: (tag) => {
                    if (
                        state !== 'authenticating' ||
                        authenticatedByteLength !== input.totalByteLength
                    ) {
                        state = 'failed';
                        throw Object.assign(new Error('wrong GCM length'), {
                            refusalReason: 'wrongTypeOrLength' as const,
                        });
                    }
                    const expectedTag = hash.digest().slice(0, 16);
                    if (!bytesEqual(tag, expectedTag)) {
                        state = 'failed';
                        throw Object.assign(new Error('invalid GCM tag'), {
                            refusalReason: 'invalidArithmeticRelation' as const,
                        });
                    }
                    observation.authenticationFinished = true;
                    state = 'decrypting';
                },
                finishDecryption: () => {
                    if (
                        state !== 'decrypting' ||
                        decryptedByteLength !== input.totalByteLength
                    ) {
                        state = 'failed';
                        throw new Error('incomplete GCM decryption');
                    }
                    state = 'completed';
                    key.fill(0);
                    nonce.fill(0);
                },
                state: () => state,
            };
        },
    };
};

type CachedMailbox = {
    carrier: AuthenticatedMailboxCarrier;
    chunks: Uint8Array[];
};

const makeOutboundCache = (): {
    cache: AuthenticatedMailboxOutboundCache;
    records: Map<string, CachedMailbox>;
} => {
    const records = new Map<string, CachedMailbox>();
    return {
        cache: {
            reserve: (input) => {
                const key = slotKey(input.producerSlot);
                const chunkCount = Math.ceil(
                    input.plaintextByteLength /
                        foundationProfile.streamChunkByteLength,
                );
                const cached = records.get(key);
                const stagedChunks: Uint8Array[] = [];
                let cancelled = false;
                return Promise.resolve({
                    disposition: cached === undefined ? 'fresh' : 'cached',
                    cachedCarrier: () => {
                        if (cached === undefined) {
                            return Promise.reject(
                                new Error('No cached carrier is available.'),
                            );
                        }
                        return Promise.resolve({
                            canonicalEnvelopeBytes:
                                cached.carrier.canonicalEnvelopeBytes.slice(),
                            envelopeHash: cached.carrier.envelopeHash,
                        });
                    },
                    stageChunk: ({ bytes, chunkIndex }) => {
                        if (
                            cached !== undefined ||
                            cancelled ||
                            chunkIndex !== stagedChunks.length
                        ) {
                            return Promise.reject(
                                new Error('Invalid cache staging state.'),
                            );
                        }
                        stagedChunks.push(new Uint8Array(bytes).slice());
                        return Promise.resolve();
                    },
                    commit: (carrier) => {
                        if (
                            cached !== undefined ||
                            cancelled ||
                            stagedChunks.length !== chunkCount
                        ) {
                            return Promise.reject(
                                new Error('Invalid cache commit state.'),
                            );
                        }
                        records.set(key, {
                            carrier: {
                                canonicalEnvelopeBytes:
                                    carrier.canonicalEnvelopeBytes.slice(),
                                envelopeHash: carrier.envelopeHash,
                            },
                            chunks: stagedChunks.map((chunk) => chunk.slice()),
                        });
                        return Promise.resolve();
                    },
                    pullChunk: ({ chunkIndex, expectedByteLength }) => {
                        const record = cached ?? records.get(key);
                        const chunk = record?.chunks[chunkIndex];
                        if (expectedByteLength === 0) {
                            return Promise.resolve(undefined);
                        }
                        return Promise.resolve(chunk?.slice().buffer);
                    },
                    cancel: () => {
                        cancelled = true;
                        for (const chunk of stagedChunks) {
                            chunk.fill(0);
                        }
                        return Promise.resolve();
                    },
                });
            },
        },
        records,
    };
};

const makeInboundSlotAuthority =
    (): AuthenticatedMailboxInboundSlotAuthority => {
        const accepted = new Map<
            string,
            { canonicalEnvelopeBytes: Uint8Array; envelopeHash: ProtocolHash }
        >();
        const reserved = new Set<string>();
        return {
            reserve: (input) => {
                const key = slotKey(input.producerSlot);
                const existing = accepted.get(key);
                if (existing !== undefined) {
                    if (
                        existing.envelopeHash !== input.envelopeHash ||
                        !bytesEqual(
                            existing.canonicalEnvelopeBytes,
                            input.canonicalEnvelopeBytes,
                        )
                    ) {
                        return Promise.resolve({
                            isValid: false,
                            refusalReason: 'equivocation',
                        });
                    }
                    return Promise.resolve({
                        isValid: true,
                        value: {
                            disposition: 'byteIdenticalRetransmission',
                            cancel: () => Promise.resolve(),
                            commit: () => Promise.resolve(),
                        },
                    });
                }
                if (reserved.has(key)) {
                    return Promise.resolve({
                        isValid: false,
                        refusalReason: 'equivocation',
                    });
                }
                reserved.add(key);
                let terminal = false;
                return Promise.resolve({
                    isValid: true,
                    value: {
                        disposition: 'fresh',
                        cancel: () => {
                            if (!terminal) {
                                terminal = true;
                                reserved.delete(key);
                            }
                            return Promise.resolve();
                        },
                        commit: () => {
                            if (terminal) {
                                return Promise.reject(
                                    new Error(
                                        'Inbound slot lease is terminal.',
                                    ),
                                );
                            }
                            terminal = true;
                            reserved.delete(key);
                            accepted.set(key, {
                                canonicalEnvelopeBytes:
                                    input.canonicalEnvelopeBytes.slice(),
                                envelopeHash: input.envelopeHash,
                            });
                            return Promise.resolve();
                        },
                    },
                });
            },
        };
    };

const makeStagingBoundary = (input?: {
    readonly failDispose?: boolean;
    readonly mutateFirstRead?: boolean;
}): {
    readonly boundary: AuthenticatedMailboxStagingBoundary;
    readonly observation: { disposeCount: number };
} => {
    const observation = { disposeCount: 0 };
    return {
        boundary: {
            open: ({ totalByteLength }) => {
                const chunkCount = Math.ceil(
                    totalByteLength / foundationProfile.streamChunkByteLength,
                );
                const chunks: Uint8Array[] = [];
                let disposed = false;
                let sealed = false;
                return Promise.resolve({
                    stageChunk: ({ bytes, chunkIndex }) => {
                        if (
                            disposed ||
                            sealed ||
                            chunkIndex !== chunks.length
                        ) {
                            return Promise.reject(
                                new Error('Invalid staging state.'),
                            );
                        }
                        chunks.push(new Uint8Array(bytes).slice());
                        return Promise.resolve();
                    },
                    seal: () => {
                        if (disposed || chunks.length !== chunkCount) {
                            return Promise.reject(
                                new Error('Incomplete staging lease.'),
                            );
                        }
                        sealed = true;
                        return Promise.resolve();
                    },
                    pullChunk: ({ chunkIndex, expectedByteLength }) => {
                        if (disposed || !sealed) {
                            return Promise.reject(
                                new Error('Staging lease is unreadable.'),
                            );
                        }
                        if (expectedByteLength === 0) {
                            return Promise.resolve(undefined);
                        }
                        const chunk = chunks[chunkIndex]?.slice();
                        if (
                            input?.mutateFirstRead === true &&
                            chunkIndex === 0 &&
                            chunk !== undefined
                        ) {
                            chunk[0] ^= 1;
                        }
                        return Promise.resolve(chunk?.buffer);
                    },
                    dispose: () => {
                        observation.disposeCount += 1;
                        disposed = true;
                        for (const chunk of chunks) {
                            chunk.fill(0);
                        }
                        return input?.failDispose === true
                            ? Promise.reject(
                                  new Error(
                                      'Injected staging cleanup failure.',
                                  ),
                              )
                            : Promise.resolve();
                    },
                });
            },
        },
        observation,
    };
};

const sourceFromChunks =
    (chunks: readonly Uint8Array[]) =>
    ({
        chunkIndex,
        expectedByteLength,
    }: {
        readonly chunkIndex: number;
        readonly expectedByteLength: number;
    }): Promise<ArrayBuffer | undefined> => {
        if (expectedByteLength === 0) {
            return Promise.resolve(undefined);
        }
        const chunk = chunks[chunkIndex];
        return Promise.resolve(chunk?.slice().buffer);
    };

const sourceFromBytes =
    (bytes: Uint8Array) =>
    ({
        chunkIndex,
        expectedByteLength,
    }: {
        readonly chunkIndex: number;
        readonly expectedByteLength: number;
    }): Promise<ArrayBuffer | undefined> => {
        if (expectedByteLength === 0) {
            return Promise.resolve(undefined);
        }
        const start = chunkIndex * foundationProfile.streamChunkByteLength;
        return Promise.resolve(
            bytes.slice(start, start + expectedByteLength).buffer,
        );
    };

const deterministicEntropy = (initialValue: number) => {
    let nextValue = initialValue;
    return (byteLength: number): Uint8Array => {
        const output = new Uint8Array(byteLength).fill(nextValue);
        nextValue = (nextValue + 1) & 0xff;
        return output;
    };
};

const keyPair = (seedValue: number) => ({
    signing: ml_dsa65.keygen(
        new Uint8Array(ml_dsa65.lengths.seed!).fill(seedValue),
    ),
    mailbox: ml_kem768.keygen(
        new Uint8Array(ml_kem768.lengths.seed!).fill(seedValue + 1),
    ),
});

const associatedData = Object.freeze({
    suiteId: '11'.repeat(64),
    ceremonyContextHash: '22'.repeat(64),
    actionContextHash: '33'.repeat(64),
    rosterHash: '44'.repeat(64),
    sourceParticipantId: '55'.repeat(64),
    recipientParticipantId: '66'.repeat(64),
    producerSequence: '7',
    payloadType: 2 as const,
    statementHash: '77'.repeat(64),
    orderedMaterialRoots: ['88'.repeat(64)],
});

const resignEnvelope = (
    envelope: SignedMailboxEnvelope,
    signingSecretKey: Uint8Array,
): AuthenticatedMailboxCarrier => {
    const envelopeHash = kernel.deriveMailboxEnvelopeHash(
        unsignedEnvelope(envelope),
    );
    const signature = ml_dsa65.sign(
        hexToBytes(envelopeHash),
        signingSecretKey,
        {
            context: mailboxSignatureContext,
            extraEntropy: false,
        },
    );
    const encoded = kernel.encodeSignedMailboxEnvelope({
        ...envelope,
        sourceSignatureHex: bytesToHex(signature),
    });
    signature.fill(0);
    return {
        canonicalEnvelopeBytes: hexToBytes(encoded.canonicalBytesHex),
        envelopeHash,
    };
};

const flipLastHexByte = (value: string): string => {
    const bytes = hexToBytes(value);
    bytes[bytes.length - 1] ^= 1;
    return bytesToHex(bytes);
};

describe('authenticated mailbox', () => {
    it('streams with backpressure, authenticates before plaintext release, and handles an identical duplicate idempotently', async () => {
        const sourceKeys = keyPair(0x21);
        const recipientKeys = keyPair(0x51);
        const sourceProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(sourceKeys),
            entropy: deterministicEntropy(40),
        });
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
            entropy: deterministicEntropy(80),
        });
        const plaintext = new Uint8Array(
            foundationProfile.streamChunkByteLength + 37,
        );
        for (let byteIndex = 0; byteIndex < plaintext.length; byteIndex += 1) {
            plaintext[byteIndex] = (byteIndex * 29 + 7) & 0xff;
        }
        const ciphertextChunks: Uint8Array[] = [];
        const outbound = makeOutboundCache();
        const streamBoundary = makeStreamBoundary();
        const sealObservation = { authenticationFinished: false };
        const carrier = await sealAuthenticatedMailbox({
            associatedData,
            emitCiphertextChunk: ({ bytes, chunkIndex }) => {
                expect(chunkIndex).toBe(ciphertextChunks.length);
                ciphertextChunks.push(new Uint8Array(bytes).slice());
                return Promise.resolve();
            },
            gcmRuntime: makeGcmRuntime(sealObservation),
            kernel,
            outboundCache: outbound.cache,
            plaintextByteLength: plaintext.byteLength,
            pullPlaintextChunk: sourceFromBytes(plaintext),
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningCapability: sourceProvider.signingCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            streamBoundary,
        });
        expect(ciphertextChunks).toHaveLength(2);

        const openObservation = { authenticationFinished: false };
        const staging = makeStagingBoundary();
        const inboundSlotAuthority = makeInboundSlotAuthority();
        const openedChunks: Uint8Array[] = [];
        let activeSinkCount = 0;
        let maximumActiveSinkCount = 0;
        const opened = await openAuthenticatedMailbox({
            carrier,
            consumePlaintextChunk: async ({ bytes, chunkIndex }) => {
                expect(openObservation.authenticationFinished).toBe(true);
                expect(chunkIndex).toBe(openedChunks.length);
                activeSinkCount += 1;
                maximumActiveSinkCount = Math.max(
                    maximumActiveSinkCount,
                    activeSinkCount,
                );
                await Promise.resolve();
                openedChunks.push(new Uint8Array(bytes).slice());
                activeSinkCount -= 1;
            },
            expectedAssociatedData: {
                ...associatedData,
                plaintextByteLength: String(plaintext.byteLength),
            },
            gcmRuntime: makeGcmRuntime(openObservation),
            inboundSlotAuthority,
            kernel,
            pullCiphertextChunk: sourceFromChunks(ciphertextChunks),
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: staging.boundary,
            streamBoundary,
        });
        expect(opened).toEqual({
            isValid: true,
            value: {
                disposition: 'accepted',
                envelopeHash: carrier.envelopeHash,
                plaintextByteLength: plaintext.byteLength,
            },
        });
        expect(maximumActiveSinkCount).toBe(1);
        expect(staging.observation.disposeCount).toBe(1);
        expect(
            bytesEqual(
                new Uint8Array(
                    openedChunks.reduce(
                        (sum, chunk) => sum + chunk.byteLength,
                        0,
                    ),
                ).map((_value, byteIndex) =>
                    byteIndex < openedChunks[0].byteLength
                        ? openedChunks[0][byteIndex]
                        : openedChunks[1][
                              byteIndex - openedChunks[0].byteLength
                          ],
                ),
                plaintext,
            ),
        ).toBe(true);

        let duplicateFetchCount = 0;
        let duplicatePlaintextCount = 0;
        const duplicate = await openAuthenticatedMailbox({
            carrier,
            consumePlaintextChunk: () => {
                duplicatePlaintextCount += 1;
                return Promise.resolve();
            },
            expectedAssociatedData: {
                ...associatedData,
                plaintextByteLength: String(plaintext.byteLength),
            },
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            inboundSlotAuthority,
            kernel,
            pullCiphertextChunk: () => {
                duplicateFetchCount += 1;
                return Promise.reject(
                    new Error('Duplicate must not fetch ciphertext.'),
                );
            },
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: makeStagingBoundary().boundary,
            streamBoundary,
        });
        expect(duplicate).toEqual({
            isValid: true,
            value: {
                disposition: 'byteIdenticalRetransmission',
                envelopeHash: carrier.envelopeHash,
                plaintextByteLength: plaintext.byteLength,
            },
        });
        expect(duplicateFetchCount).toBe(0);
        expect(duplicatePlaintextCount).toBe(0);

        const conflictingPlaintext = plaintext.slice();
        conflictingPlaintext[0] ^= 1;
        const conflictingCiphertext: Uint8Array[] = [];
        await expect(
            sealAuthenticatedMailbox({
                associatedData,
                emitCiphertextChunk: ({ bytes }) => {
                    conflictingCiphertext.push(new Uint8Array(bytes).slice());
                    return Promise.resolve();
                },
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                kernel,
                outboundCache: makeOutboundCache().cache,
                plaintextByteLength: conflictingPlaintext.byteLength,
                pullPlaintextChunk: sourceFromBytes(conflictingPlaintext),
                recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
                sourceSigningCapability: sourceProvider.signingCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                streamBoundary,
            }),
        ).rejects.toMatchObject({ refusalReason: 'equivocation' });
        expect(conflictingCiphertext).toHaveLength(0);

        const decodedCarrier = kernel.decodeSignedMailboxEnvelope({
            canonicalBytesHex: bytesToHex(carrier.canonicalEnvelopeBytes),
        });
        const conflictingCarrier = resignEnvelope(
            {
                ...decodedCarrier.value,
                gcmTagHex: flipLastHexByte(decodedCarrier.value.gcmTagHex),
            },
            sourceKeys.signing.secretKey,
        );
        let conflictingFetchCount = 0;
        const conflictingOpen = await openAuthenticatedMailbox({
            carrier: conflictingCarrier,
            consumePlaintextChunk: () =>
                Promise.reject(
                    new Error('Equivocation must not release plaintext.'),
                ),
            expectedAssociatedData: {
                ...associatedData,
                plaintextByteLength: String(conflictingPlaintext.byteLength),
            },
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            inboundSlotAuthority,
            kernel,
            pullCiphertextChunk: () => {
                conflictingFetchCount += 1;
                return Promise.reject(
                    new Error('Equivocation must not fetch ciphertext.'),
                );
            },
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: makeStagingBoundary().boundary,
            streamBoundary,
        });
        expect(conflictingOpen).toEqual({
            isValid: false,
            refusalReason: 'equivocation',
        });
        expect(conflictingFetchCount).toBe(0);

        sourceProvider.close();
        recipientProvider.close();
        plaintext.fill(0);
        conflictingPlaintext.fill(0);
        for (const chunk of [...ciphertextChunks, ...openedChunks]) {
            chunk.fill(0);
        }
    });

    it('refuses wrong bindings and hostile cryptographic bytes before releasing plaintext', async () => {
        const sourceKeys = keyPair(0x31);
        const recipientKeys = keyPair(0x61);
        const wrongRecipientKeys = keyPair(0x71);
        const sourceProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(sourceKeys),
            entropy: deterministicEntropy(100),
        });
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
            entropy: deterministicEntropy(120),
        });
        const wrongRecipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(wrongRecipientKeys),
            entropy: deterministicEntropy(140),
        });
        const plaintext = textEncoder.encode(
            canonicalJson({ objectType: 'PrivateVssShareEnvelope', value: 3 }),
        );
        const ciphertext: Uint8Array[] = [];
        const carrier = await sealAuthenticatedMailbox({
            associatedData,
            emitCiphertextChunk: ({ bytes }) => {
                ciphertext.push(new Uint8Array(bytes).slice());
                return Promise.resolve();
            },
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            kernel,
            outboundCache: makeOutboundCache().cache,
            plaintextByteLength: plaintext.byteLength,
            pullPlaintextChunk: sourceFromBytes(plaintext),
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningCapability: sourceProvider.signingCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            streamBoundary: makeStreamBoundary(),
        });
        const baseExpectation: MailboxAssociatedDataExpectation = {
            ...associatedData,
            plaintextByteLength: String(plaintext.byteLength),
        };
        const open = (
            candidateCarrier: AuthenticatedMailboxCarrier,
            candidateCiphertext: readonly Uint8Array[],
            expectation = baseExpectation,
            mailboxCapability = recipientProvider.mailboxCapability,
            verificationKey = sourceKeys.signing.publicKey,
            stagingBoundary = makeStagingBoundary().boundary,
        ) => {
            let plaintextReleaseCount = 0;
            return openAuthenticatedMailbox({
                carrier: candidateCarrier,
                consumePlaintextChunk: () => {
                    plaintextReleaseCount += 1;
                    return Promise.resolve();
                },
                expectedAssociatedData: expectation,
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                inboundSlotAuthority: makeInboundSlotAuthority(),
                kernel,
                pullCiphertextChunk: sourceFromChunks(candidateCiphertext),
                recipientMailboxCapability: mailboxCapability,
                sourceVerificationKey: verificationKey,
                stagingBoundary,
                streamBoundary: makeStreamBoundary(),
            }).then((result) => ({ plaintextReleaseCount, result }));
        };

        const wrongExpectations = [
            { ...baseExpectation, sourceParticipantId: '90'.repeat(64) },
            { ...baseExpectation, recipientParticipantId: '91'.repeat(64) },
            { ...baseExpectation, producerSequence: '8' },
            { ...baseExpectation, suiteId: '92'.repeat(64) },
            {
                ...baseExpectation,
                ceremonyContextHash: '93'.repeat(64),
            },
            {
                ...baseExpectation,
                actionContextHash: '94'.repeat(64),
            },
            { ...baseExpectation, rosterHash: '95'.repeat(64) },
            {
                ...baseExpectation,
                statementHash: '96'.repeat(64),
            },
            {
                ...baseExpectation,
                orderedMaterialRoots: ['97'.repeat(64)],
            },
            { ...baseExpectation, plaintextByteLength: '999' },
        ];
        recipientProvider.revokeMailboxCapability();
        for (const expectation of wrongExpectations) {
            const refusal = await open(
                carrier,
                ciphertext,
                expectation,
                recipientProvider.mailboxCapability,
            );
            expect(refusal.result).toEqual({
                isValid: false,
                refusalReason: 'wrongContext',
            });
            expect(refusal.plaintextReleaseCount).toBe(0);
        }
        const authenticatedRecipientProvider =
            openBrowserLocalExternalKeyProvider({
                ...createBrowserLocalKeyOperations(recipientKeys),
                entropy: deterministicEntropy(150),
            });

        const wrongSource = await open(
            carrier,
            ciphertext,
            baseExpectation,
            wrongRecipientProvider.mailboxCapability,
            wrongRecipientKeys.signing.publicKey,
        );
        expect(wrongSource.result).toEqual({
            isValid: false,
            refusalReason: 'invalidSignature',
        });

        const tamperedCiphertext = ciphertext.map((chunk) => chunk.slice());
        tamperedCiphertext[0][0] ^= 1;
        const ciphertextRefusal = await open(
            carrier,
            tamperedCiphertext,
            baseExpectation,
            authenticatedRecipientProvider.mailboxCapability,
        );
        expect(ciphertextRefusal.result).toEqual({
            isValid: false,
            refusalReason: 'wrongHashOrRoot',
        });
        expect(ciphertextRefusal.plaintextReleaseCount).toBe(0);

        const envelope = kernel.decodeSignedMailboxEnvelope({
            canonicalBytesHex: bytesToHex(carrier.canonicalEnvelopeBytes),
        }).value;
        const badSignatureCarrier = {
            ...carrier,
            canonicalEnvelopeBytes: hexToBytes(
                kernel.encodeSignedMailboxEnvelope({
                    ...envelope,
                    sourceSignatureHex: flipLastHexByte(
                        envelope.sourceSignatureHex,
                    ),
                }).canonicalBytesHex,
            ),
        };
        const signatureRefusal = await open(
            badSignatureCarrier,
            ciphertext,
            baseExpectation,
            authenticatedRecipientProvider.mailboxCapability,
        );
        expect(signatureRefusal.result).toEqual({
            isValid: false,
            refusalReason: 'invalidSignature',
        });

        const tamperedTagCarrier = resignEnvelope(
            {
                ...envelope,
                gcmTagHex: flipLastHexByte(envelope.gcmTagHex),
            },
            sourceKeys.signing.secretKey,
        );
        const tagRefusal = await open(
            tamperedTagCarrier,
            ciphertext,
            baseExpectation,
            authenticatedRecipientProvider.mailboxCapability,
        );
        expect(tagRefusal.result).toEqual({
            isValid: false,
            refusalReason: 'invalidArithmeticRelation',
        });
        expect(tagRefusal.plaintextReleaseCount).toBe(0);

        const stagedMutation = await open(
            carrier,
            ciphertext,
            baseExpectation,
            authenticatedRecipientProvider.mailboxCapability,
            sourceKeys.signing.publicKey,
            makeStagingBoundary({ mutateFirstRead: true }).boundary,
        );
        expect(stagedMutation.result).toEqual({
            isValid: false,
            refusalReason: 'wrongHashOrRoot',
        });
        expect(stagedMutation.plaintextReleaseCount).toBe(0);

        const wrongLengthEnvelope = {
            ...envelope,
            ciphertextDescriptor: {
                ...envelope.ciphertextDescriptor,
                totalByteLength: String(plaintext.byteLength + 1),
            },
        };
        const wrongLength = await open(
            resignEnvelope(wrongLengthEnvelope, sourceKeys.signing.secretKey),
            ciphertext,
            baseExpectation,
            authenticatedRecipientProvider.mailboxCapability,
        );
        expect(wrongLength.result).toEqual({
            isValid: false,
            refusalReason: 'wrongTypeOrLength',
        });

        const wrongKey = await open(
            carrier,
            ciphertext,
            baseExpectation,
            wrongRecipientProvider.mailboxCapability,
        );
        expect(wrongKey.result).toEqual({
            isValid: false,
            refusalReason: 'invalidArithmeticRelation',
        });
        expect(wrongKey.plaintextReleaseCount).toBe(0);

        sourceProvider.close();
        authenticatedRecipientProvider.close();
        wrongRecipientProvider.close();
        plaintext.fill(0);
    });

    it('cleans up cancellation, authentication failures, and combined cleanup failures deterministically', async () => {
        const sourceKeys = keyPair(0x41);
        const recipientKeys = keyPair(0x71);
        const sourceProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(sourceKeys),
            entropy: deterministicEntropy(160),
        });
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
            entropy: deterministicEntropy(180),
        });
        const plaintext = textEncoder.encode('cleanup-path-mailbox-payload');
        const ciphertext: Uint8Array[] = [];
        const carrier = await sealAuthenticatedMailbox({
            associatedData,
            emitCiphertextChunk: ({ bytes }) => {
                ciphertext.push(new Uint8Array(bytes).slice());
                return Promise.resolve();
            },
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            kernel,
            outboundCache: makeOutboundCache().cache,
            plaintextByteLength: plaintext.byteLength,
            pullPlaintextChunk: sourceFromBytes(plaintext),
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningCapability: sourceProvider.signingCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            streamBoundary: makeStreamBoundary(),
        });
        const expectedAssociatedData = {
            ...associatedData,
            plaintextByteLength: String(plaintext.byteLength),
        };
        const abortController = new AbortController();
        abortController.abort();
        await expect(
            openAuthenticatedMailbox({
                abortSignal: abortController.signal,
                carrier,
                consumePlaintextChunk: () => Promise.resolve(),
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                inboundSlotAuthority: makeInboundSlotAuthority(),
                kernel,
                pullCiphertextChunk: sourceFromChunks(ciphertext),
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: makeStagingBoundary().boundary,
                streamBoundary: makeStreamBoundary(),
            }),
        ).rejects.toThrow('cancelled');

        const envelope = kernel.decodeSignedMailboxEnvelope({
            canonicalBytesHex: bytesToHex(carrier.canonicalEnvelopeBytes),
        }).value;
        const badTagCarrier = resignEnvelope(
            {
                ...envelope,
                gcmTagHex: flipLastHexByte(envelope.gcmTagHex),
            },
            sourceKeys.signing.secretKey,
        );
        const failedStaging = makeStagingBoundary({ failDispose: true });
        await expect(
            openAuthenticatedMailbox({
                carrier: badTagCarrier,
                consumePlaintextChunk: () => Promise.resolve(),
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                inboundSlotAuthority: makeInboundSlotAuthority(),
                kernel,
                pullCiphertextChunk: sourceFromChunks(ciphertext),
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: failedStaging.boundary,
                streamBoundary: makeStreamBoundary(),
            }),
        ).rejects.toBeInstanceOf(AuthenticatedMailboxCleanupError);
        expect(failedStaging.observation.disposeCount).toBe(1);

        sourceProvider.close();
        recipientProvider.close();
        plaintext.fill(0);
    });
});
