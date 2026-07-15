import { hkdf } from "@noble/hashes/hkdf.js";
import { sha384 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
    foundationProfile,
    type ProtocolHash,
    type SetupMailboxSlot,
} from "@sealed-lattice/types";
import { describe, expect, it } from "vitest";

import {
    AuthenticatedMailboxCleanupError,
    openAuthenticatedMailbox,
    sealAuthenticatedMailbox,
    type AuthenticatedMailboxCarrier,
    type AuthenticatedMailboxGcmRuntime,
    type AuthenticatedMailboxInboundSlotAuthority,
    type AuthenticatedMailboxKernel,
    type AuthenticatedMailboxOutboundCache,
    type AuthenticatedMailboxPlaintextSinkBoundary,
    type AuthenticatedMailboxProducerSlot,
    type AuthenticatedMailboxStagingBoundary,
    type AuthenticatedMailboxStreamBoundary,
    type MailboxAssociatedData,
    type MailboxKeyScheduleInput,
    type SignedMailboxEnvelope,
    type UnsignedMailboxEnvelope,
} from "#packages/crypto/src/authenticated-mailbox";
import {
    canonicalJson,
    hash512Hex,
    openBrowserLocalExternalKeyProvider,
} from "#packages/crypto/src/index";
import { createBrowserLocalKeyOperations } from "#packages/crypto/tests/support/browser-local-key-operations";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const mailboxSignatureContext = textEncoder.encode(
    "sealed-lattice/mailbox-signature/v1",
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
    value: MailboxKeyScheduleInput,
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
});

const kernel: AuthenticatedMailboxKernel = {
    encodeMailboxKeyScheduleInput: (input) => {
        const keySchedule = keyScheduleValue(input.value);
        return {
            canonicalBytesHex: canonicalBytesHex(keySchedule),
            hkdfExtractSaltHex: objectHash("test/mailbox-hkdf-salt", {
                kemCiphertextHex: input.kemCiphertextHex,
                keySchedule,
            }).slice(0, 96),
        };
    },
    encodeMailboxAssociatedData: (value) => ({
        canonicalBytesHex: canonicalBytesHex(value),
    }),
    encodeSignedMailboxEnvelope: (value) => ({
        canonicalBytesHex: canonicalBytesHex(value),
        envelopeHash: objectHash(
            "test/mailbox-envelope",
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
                "test/mailbox-envelope",
                unsignedEnvelope(value),
            ),
        };
    },
    deriveMailboxEnvelopeHash: (value) =>
        objectHash("test/mailbox-envelope", value),
    deriveSetupMailboxSlotHash: (value) =>
        objectHash("test/setup-mailbox-slot", value),
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
    | "active"
    | "authenticating"
    | "cancelled"
    | "completed"
    | "decrypting"
    | "failed";

const makeStreamBoundary = (): AuthenticatedMailboxStreamBoundary => ({
    openWriter: ({ totalByteLength }) => {
        const chunkCount = Math.ceil(
            totalByteLength / foundationProfile.streamChunkByteLength,
        );
        const chunkDigests: ProtocolHash[] = [];
        const chunks: Uint8Array[] = [];
        let state: TestLeaseState = "active";
        return {
            absorbChunk: (chunkIndex, bytes) => {
                if (state !== "active" || chunkIndex !== chunkDigests.length) {
                    state = "failed";
                    throw Object.assign(new Error("invalid stream order"), {
                        refusalReason: "wrongTypeOrLength" as const,
                    });
                }
                chunkDigests.push(
                    hash512Hex("test/mailbox-stream-chunk", [
                        new Uint8Array(bytes),
                    ]),
                );
                chunks.push(new Uint8Array(bytes).slice());
            },
            cancel: () => {
                if (state === "active") {
                    state = "cancelled";
                }
            },
            chunkCount,
            finish: () => {
                if (state !== "active" || chunkDigests.length !== chunkCount) {
                    state = "failed";
                    throw Object.assign(new Error("incomplete stream"), {
                        refusalReason: "wrongTypeOrLength" as const,
                    });
                }
                state = "completed";
                return {
                    totalByteLength: String(totalByteLength),
                    orderedChunkDigests: chunkDigests,
                    fullObjectDigest: hash512Hex(
                        "test/mailbox-stream-object",
                        chunks,
                    ),
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
        const observedChunks: Uint8Array[] = [];
        let state: TestLeaseState = "active";
        return {
            absorbChunk: (chunkIndex, bytes) => {
                if (
                    state !== "active" ||
                    chunkIndex !== observedChunkDigests.length
                ) {
                    state = "failed";
                    throw Object.assign(new Error("invalid stream order"), {
                        refusalReason: "wrongTypeOrLength" as const,
                    });
                }
                const observedDigest = hash512Hex("test/mailbox-stream-chunk", [
                    new Uint8Array(bytes),
                ]);
                if (
                    observedDigest !==
                    descriptor.orderedChunkDigests[chunkIndex]
                ) {
                    state = "failed";
                    throw Object.assign(new Error("stream digest mismatch"), {
                        refusalReason: "wrongHashOrRoot" as const,
                    });
                }
                observedChunkDigests.push(observedDigest);
                observedChunks.push(new Uint8Array(bytes).slice());
            },
            cancel: () => {
                if (state === "active") {
                    state = "cancelled";
                }
            },
            chunkCount,
            finish: () => {
                if (
                    state !== "active" ||
                    observedChunkDigests.length !== chunkCount ||
                    observedChunkDigests.some(
                        (digest, chunkIndex) =>
                            digest !==
                            descriptor.orderedChunkDigests[chunkIndex],
                    ) ||
                    hash512Hex("test/mailbox-stream-object", observedChunks) !==
                        descriptor.fullObjectDigest
                ) {
                    state = "failed";
                    throw Object.assign(new Error("stream digest mismatch"), {
                        refusalReason: "wrongHashOrRoot" as const,
                    });
                }
                state = "completed";
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
            let state: TestLeaseState = "active";
            return {
                cancel: () => {
                    if (state === "active") {
                        state = "cancelled";
                    }
                    key.fill(0);
                    nonce.fill(0);
                    hash.destroy();
                },
                encryptChunk: (buffer) => {
                    if (state !== "active") {
                        throw new Error("encryptor is inactive");
                    }
                    const bytes = new Uint8Array(buffer);
                    applyKeystream(bytes, key, nonce, processedByteLength);
                    processedByteLength += bytes.byteLength;
                    hash.update(bytes);
                },
                finish: () => {
                    if (
                        state !== "active" ||
                        processedByteLength !== input.totalByteLength
                    ) {
                        state = "failed";
                        throw Object.assign(new Error("wrong GCM length"), {
                            refusalReason: "wrongTypeOrLength" as const,
                        });
                    }
                    state = "completed";
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
            let state: TestLeaseState = "authenticating";
            return {
                authenticateChunk: (buffer) => {
                    if (state !== "authenticating") {
                        throw new Error("verifier is not authenticating");
                    }
                    const bytes = new Uint8Array(buffer);
                    authenticatedByteLength += bytes.byteLength;
                    hash.update(bytes);
                },
                cancel: () => {
                    if (state !== "completed" && state !== "failed") {
                        state = "cancelled";
                    }
                    key.fill(0);
                    nonce.fill(0);
                    hash.destroy();
                },
                decryptChunk: (buffer) => {
                    if (state !== "decrypting") {
                        throw new Error("verifier is not decrypting");
                    }
                    const bytes = new Uint8Array(buffer);
                    applyKeystream(bytes, key, nonce, decryptedByteLength);
                    decryptedByteLength += bytes.byteLength;
                },
                finishAuthentication: (tag) => {
                    if (
                        state !== "authenticating" ||
                        authenticatedByteLength !== input.totalByteLength
                    ) {
                        state = "failed";
                        throw Object.assign(new Error("wrong GCM length"), {
                            refusalReason: "wrongTypeOrLength" as const,
                        });
                    }
                    const expectedTag = hash.digest().slice(0, 16);
                    if (!bytesEqual(tag, expectedTag)) {
                        state = "failed";
                        throw Object.assign(new Error("invalid GCM tag"), {
                            refusalReason: "invalidArithmeticRelation" as const,
                        });
                    }
                    observation.authenticationFinished = true;
                    state = "decrypting";
                },
                finishDecryption: () => {
                    if (
                        state !== "decrypting" ||
                        decryptedByteLength !== input.totalByteLength
                    ) {
                        state = "failed";
                        throw new Error("incomplete GCM decryption");
                    }
                    state = "completed";
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
                    disposition: cached === undefined ? "fresh" : "cached",
                    cachedCarrier: () => {
                        if (cached === undefined) {
                            return Promise.reject(
                                new Error("No cached carrier is available."),
                            );
                        }
                        return Promise.resolve({
                            canonicalEnvelopeBytes:
                                cached.carrier.canonicalEnvelopeBytes.slice(),
                        });
                    },
                    stageChunk: ({ bytes, chunkIndex }) => {
                        if (
                            cached !== undefined ||
                            cancelled ||
                            chunkIndex !== stagedChunks.length
                        ) {
                            return Promise.reject(
                                new Error("Invalid cache staging state."),
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
                                new Error("Invalid cache commit state."),
                            );
                        }
                        records.set(key, {
                            carrier: {
                                canonicalEnvelopeBytes:
                                    carrier.canonicalEnvelopeBytes.slice(),
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

const makeInboundSlotAuthority = (failureInjection?: {
    readonly failCommitBeforePublicationOnce?: boolean;
    readonly failCommitAfterPublicationOnce?: boolean;
}): AuthenticatedMailboxInboundSlotAuthority => {
    const accepted = new Map<string, Uint8Array>();
    const reserved = new Map<string, Uint8Array>();
    let failCommitBeforePublication =
        failureInjection?.failCommitBeforePublicationOnce === true;
    let failCommitAfterPublication =
        failureInjection?.failCommitAfterPublicationOnce === true;
    return {
        reserve: (input) => {
            const key = slotKey(input.producerSlot);
            const existing = accepted.get(key);
            if (existing !== undefined) {
                if (!bytesEqual(existing, input.canonicalEnvelopeBytes)) {
                    return Promise.resolve({
                        isValid: false,
                        refusalReason: "equivocation",
                    });
                }
                return Promise.resolve({
                    isValid: true,
                    value: {
                        disposition: "byteIdenticalRetransmission",
                        cancel: () => Promise.resolve(),
                        commit: () => Promise.resolve(),
                    },
                });
            }
            const active = reserved.get(key);
            if (active !== undefined) {
                return Promise.resolve({
                    isValid: false,
                    refusalReason: bytesEqual(
                        active,
                        input.canonicalEnvelopeBytes,
                    )
                        ? "consumedState"
                        : "equivocation",
                });
            }
            reserved.set(key, input.canonicalEnvelopeBytes.slice());
            let terminal = false;
            return Promise.resolve({
                isValid: true,
                value: {
                    disposition: "fresh",
                    cancel: () => {
                        if (!terminal) {
                            terminal = true;
                            reserved.get(key)?.fill(0);
                            reserved.delete(key);
                        }
                        return Promise.resolve();
                    },
                    commit: () => {
                        if (terminal) {
                            return Promise.reject(
                                new Error("Inbound slot lease is terminal."),
                            );
                        }
                        if (failCommitBeforePublication) {
                            failCommitBeforePublication = false;
                            terminal = true;
                            reserved.get(key)?.fill(0);
                            reserved.delete(key);
                            return Promise.reject(
                                new Error(
                                    "Injected inbound commit failure before publication.",
                                ),
                            );
                        }
                        terminal = true;
                        reserved.get(key)?.fill(0);
                        reserved.delete(key);
                        accepted.set(key, input.canonicalEnvelopeBytes.slice());
                        if (failCommitAfterPublication) {
                            failCommitAfterPublication = false;
                            return Promise.reject(
                                new Error(
                                    "Injected inbound commit response loss.",
                                ),
                            );
                        }
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
                                new Error("Invalid staging state."),
                            );
                        }
                        chunks.push(new Uint8Array(bytes).slice());
                        return Promise.resolve();
                    },
                    seal: () => {
                        if (disposed || chunks.length !== chunkCount) {
                            return Promise.reject(
                                new Error("Incomplete staging lease."),
                            );
                        }
                        sealed = true;
                        return Promise.resolve();
                    },
                    pullChunk: ({ chunkIndex, expectedByteLength }) => {
                        if (disposed || !sealed) {
                            return Promise.reject(
                                new Error("Staging lease is unreadable."),
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
                                      "Injected staging cleanup failure.",
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

type TestPlaintextDeliveryRecord = {
    readonly declaration: string;
    readonly chunks: Uint8Array[];
    state: "committed" | "prepared";
};

const makePlaintextSinkBoundary = (input?: {
    readonly failCommitAfterPublicationOnce?: boolean;
    readonly failCommitBeforePublicationOnce?: boolean;
    readonly failStageAtChunkIndex?: number;
    readonly observeStage?: (input: {
        readonly bytes: ArrayBuffer;
        readonly chunkIndex: number;
    }) => Promise<void> | void;
}): {
    readonly boundary: AuthenticatedMailboxPlaintextSinkBoundary;
    readonly observation: {
        cancelCount: number;
        commitAttemptCount: number;
        publicationCount: number;
        publishedChunks: Uint8Array[];
        stageCount: number;
    };
} => {
    const records = new Map<ProtocolHash, TestPlaintextDeliveryRecord>();
    const activeEnvelopes = new Set<ProtocolHash>();
    const observation = {
        cancelCount: 0,
        commitAttemptCount: 0,
        publicationCount: 0,
        publishedChunks: [] as Uint8Array[],
        stageCount: 0,
    };
    let failCommitAfterPublication =
        input?.failCommitAfterPublicationOnce === true;
    let failCommitBeforePublication =
        input?.failCommitBeforePublicationOnce === true;
    let failStageAtChunkIndex = input?.failStageAtChunkIndex;

    return {
        boundary: {
            reserve: (reservation) => {
                const declaration = canonicalJson(reservation);
                let record = records.get(reservation.envelopeHash);
                if (
                    record !== undefined &&
                    record.declaration !== declaration
                ) {
                    return Promise.reject(
                        new Error(
                            "A plaintext delivery envelope has conflicting declarations.",
                        ),
                    );
                }
                if (activeEnvelopes.has(reservation.envelopeHash)) {
                    return Promise.reject(
                        new Error(
                            "A plaintext delivery envelope already has an active publisher.",
                        ),
                    );
                }
                if (record?.state === "committed") {
                    return Promise.resolve({
                        disposition: "committed" as const,
                        cancel: () => Promise.resolve(),
                        commit: () => Promise.resolve(),
                        release: () => Promise.resolve(),
                        seal: () =>
                            Promise.reject(
                                new Error(
                                    "A committed plaintext delivery cannot be sealed again.",
                                ),
                            ),
                        stageChunk: () =>
                            Promise.reject(
                                new Error(
                                    "A committed plaintext delivery cannot stage chunks.",
                                ),
                            ),
                    });
                }

                activeEnvelopes.add(reservation.envelopeHash);
                const stagedChunks = record?.chunks ?? [];
                let leaseState: "fresh" | "prepared" =
                    record === undefined ? "fresh" : "prepared";
                let reservationActive = true;
                const releaseReservation = (): void => {
                    if (reservationActive) {
                        reservationActive = false;
                        activeEnvelopes.delete(reservation.envelopeHash);
                    }
                };

                return Promise.resolve({
                    disposition: leaseState,
                    cancel: () => {
                        if (leaseState !== "fresh") {
                            return Promise.reject(
                                new Error(
                                    "A prepared plaintext delivery must remain recoverable.",
                                ),
                            );
                        }
                        observation.cancelCount += 1;
                        for (const chunk of stagedChunks) {
                            chunk.fill(0);
                        }
                        releaseReservation();
                        return Promise.resolve();
                    },
                    commit: () => {
                        if (leaseState !== "prepared") {
                            return Promise.reject(
                                new Error(
                                    "Only a prepared plaintext delivery can commit.",
                                ),
                            );
                        }
                        observation.commitAttemptCount += 1;
                        if (failCommitBeforePublication) {
                            failCommitBeforePublication = false;
                            releaseReservation();
                            return Promise.reject(
                                new Error(
                                    "Injected plaintext publication failure.",
                                ),
                            );
                        }
                        record!.state = "committed";
                        observation.publicationCount += 1;
                        observation.publishedChunks = stagedChunks.map(
                            (chunk) => chunk.slice(),
                        );
                        releaseReservation();
                        if (failCommitAfterPublication) {
                            failCommitAfterPublication = false;
                            return Promise.reject(
                                new Error(
                                    "Injected plaintext publication response loss.",
                                ),
                            );
                        }
                        return Promise.resolve();
                    },
                    release: () => {
                        releaseReservation();
                        return Promise.resolve();
                    },
                    seal: () => {
                        if (
                            leaseState !== "fresh" ||
                            stagedChunks.length !==
                                Math.ceil(
                                    reservation.plaintextByteLength /
                                        foundationProfile.streamChunkByteLength,
                                )
                        ) {
                            return Promise.reject(
                                new Error(
                                    "The plaintext delivery is not complete.",
                                ),
                            );
                        }
                        leaseState = "prepared";
                        record = {
                            chunks: stagedChunks,
                            declaration,
                            state: "prepared",
                        };
                        records.set(reservation.envelopeHash, record);
                        return Promise.resolve();
                    },
                    stageChunk: async ({ bytes, chunkIndex }) => {
                        if (
                            leaseState !== "fresh" ||
                            chunkIndex !== stagedChunks.length
                        ) {
                            return Promise.reject(
                                new Error(
                                    "Plaintext delivery chunks must be staged once in order.",
                                ),
                            );
                        }
                        observation.stageCount += 1;
                        if (failStageAtChunkIndex === chunkIndex) {
                            failStageAtChunkIndex = undefined;
                            throw new Error(
                                "Injected plaintext staging failure.",
                            );
                        }
                        await input?.observeStage?.({ bytes, chunkIndex });
                        stagedChunks.push(new Uint8Array(bytes).slice());
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

const keyPair = (seedValue: number) => ({
    signing: ml_dsa65.keygen(
        new Uint8Array(ml_dsa65.lengths.seed!).fill(seedValue),
    ),
    mailbox: ml_kem768.keygen(
        new Uint8Array(ml_kem768.lengths.seed!).fill(seedValue + 1),
    ),
});

const associatedData = Object.freeze({
    suiteId: "11".repeat(64),
    ceremonyContextHash: "22".repeat(64),
    actionContextHash: "33".repeat(64),
    rosterHash: "44".repeat(64),
    sourceParticipantId: "55".repeat(64),
    recipientParticipantId: "66".repeat(64),
    producerSequence: "7",
    payloadType: 2 as const,
    statementHash: "77".repeat(64),
    orderedMaterialRoots: ["88".repeat(64)],
});

const createAuthenticatedMailboxFixture = (input: {
    readonly plaintext: Uint8Array;
    readonly recipientEncapsulationKey: Uint8Array;
    readonly sourceSigningSecretKey: Uint8Array;
}): Readonly<{
    readonly carrier: AuthenticatedMailboxCarrier;
    readonly ciphertextChunks: readonly Uint8Array[];
}> => {
    const setupMailboxSlotHash = hexToBytes(
        kernel.deriveSetupMailboxSlotHash(associatedData),
    );
    const encapsulationCoins = setupMailboxSlotHash.subarray(32).slice();
    const envelopeAttemptIdentifierHex = bytesToHex(
        setupMailboxSlotHash.subarray(0, 32),
    );
    const encapsulation = ml_kem768.encapsulate(
        input.recipientEncapsulationKey,
        encapsulationCoins,
    );
    const kemCiphertextHex = bytesToHex(encapsulation.cipherText);
    const keySchedule: MailboxKeyScheduleInput = {
        ...associatedData,
        envelopeAttemptIdentifierHex,
    };
    const mailboxAssociatedData: MailboxAssociatedData = keySchedule;
    const encodedKeySchedule = kernel.encodeMailboxKeyScheduleInput({
        kemCiphertextHex,
        value: keySchedule,
    });
    const encodedAssociatedData = kernel.encodeMailboxAssociatedData(
        mailboxAssociatedData,
    );
    const keyAndNonce = hkdf(
        sha384,
        encapsulation.sharedSecret,
        hexToBytes(encodedKeySchedule.hkdfExtractSaltHex),
        hexToBytes(encodedKeySchedule.canonicalBytesHex),
        44,
    );
    const gcmRuntime = makeGcmRuntime({ authenticationFinished: false });
    const encryptor = gcmRuntime.openEncryptor({
        associatedData: hexToBytes(encodedAssociatedData.canonicalBytesHex),
        key: keyAndNonce.subarray(0, 32),
        nonce: keyAndNonce.subarray(32),
        totalByteLength: input.plaintext.byteLength,
    });
    const streamWriter = makeStreamBoundary().openWriter({
        totalByteLength: input.plaintext.byteLength,
    });
    const ciphertextChunks: Uint8Array[] = [];
    for (
        let chunkIndex = 0;
        chunkIndex < streamWriter.chunkCount;
        chunkIndex += 1
    ) {
        const chunkStart = chunkIndex * foundationProfile.streamChunkByteLength;
        const ciphertextChunk = input.plaintext.slice(
            chunkStart,
            Math.min(
                chunkStart + foundationProfile.streamChunkByteLength,
                input.plaintext.byteLength,
            ),
        );
        encryptor.encryptChunk(ciphertextChunk.buffer);
        streamWriter.absorbChunk(chunkIndex, ciphertextChunk.buffer);
        ciphertextChunks.push(ciphertextChunk);
    }
    const gcmTag = encryptor.finish();
    const unsigned: UnsignedMailboxEnvelope = {
        associatedData: mailboxAssociatedData,
        kemCiphertextHex,
        ciphertextDescriptor: streamWriter.finish(),
        gcmTagHex: bytesToHex(gcmTag),
    };
    const envelopeHash = kernel.deriveMailboxEnvelopeHash(unsigned);
    const signature = ml_dsa65.sign(
        hexToBytes(envelopeHash),
        input.sourceSigningSecretKey,
        {
            context: mailboxSignatureContext,
            extraEntropy: false,
        },
    );
    const encodedEnvelope = kernel.encodeSignedMailboxEnvelope({
        ...unsigned,
        sourceSignatureHex: bytesToHex(signature),
    });

    setupMailboxSlotHash.fill(0);
    encapsulationCoins.fill(0);
    encapsulation.cipherText.fill(0);
    encapsulation.sharedSecret.fill(0);
    keyAndNonce.fill(0);
    gcmTag.fill(0);
    signature.fill(0);

    return {
        carrier: {
            canonicalEnvelopeBytes: hexToBytes(
                encodedEnvelope.canonicalBytesHex,
            ),
        },
        ciphertextChunks,
    };
};

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
    };
};

const deriveEnvelopeHashFromCarrier = (
    carrier: AuthenticatedMailboxCarrier,
): ProtocolHash =>
    kernel.decodeSignedMailboxEnvelope({
        canonicalBytesHex: bytesToHex(carrier.canonicalEnvelopeBytes),
    }).envelopeHash;

const flipLastHexByte = (value: string): string => {
    const bytes = hexToBytes(value);
    bytes[bytes.length - 1] ^= 1;
    return bytesToHex(bytes);
};

describe("authenticated mailbox", () => {
    it("streams with backpressure, authenticates before plaintext release, and handles an identical duplicate idempotently", async () => {
        const sourceKeys = keyPair(0x21);
        const recipientKeys = keyPair(0x51);
        const resetSafeObservation = {
            encapsulationConsumptionCount: 0,
            signatureConsumptionCount: 0,
        };
        const sourceProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations({
                ...sourceKeys,
                resetSafeSetupMailboxRandomnessObservation:
                    resetSafeObservation,
            }),
        });
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
        });
        const plaintext = new Uint8Array(
            foundationProfile.streamChunkByteLength + 37,
        );
        for (let byteIndex = 0; byteIndex < plaintext.length; byteIndex += 1) {
            plaintext[byteIndex] = (byteIndex * 29 + 7) & 0xff;
        }
        const streamBoundary = makeStreamBoundary();
        const plaintextChunks = [
            plaintext.slice(0, foundationProfile.streamChunkByteLength),
            plaintext.slice(foundationProfile.streamChunkByteLength),
        ];
        const outbound = makeOutboundCache();
        const ciphertextChunks: Uint8Array[] = [];
        const carrier = await sealAuthenticatedMailbox({
            associatedData,
            emitCiphertextChunk: ({ bytes, chunkIndex }) => {
                expect(chunkIndex).toBe(ciphertextChunks.length);
                ciphertextChunks.push(new Uint8Array(bytes).slice());
                return Promise.resolve();
            },
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            kernel,
            outboundCache: outbound.cache,
            plaintextByteLength: plaintext.byteLength,
            pullPlaintextChunk: sourceFromChunks(plaintextChunks),
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningCapability: sourceProvider.signingCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            streamBoundary,
        });
        expect(ciphertextChunks).toHaveLength(2);
        expect(resetSafeObservation).toEqual({
            encapsulationConsumptionCount: 1,
            signatureConsumptionCount: 1,
        });

        const openObservation = { authenticationFinished: false };
        const staging = makeStagingBoundary();
        const inboundSlotAuthority = makeInboundSlotAuthority();
        let activeSinkCount = 0;
        let maximumActiveSinkCount = 0;
        let observedSinkChunkCount = 0;
        const plaintextSink = makePlaintextSinkBoundary({
            observeStage: async ({ chunkIndex }) => {
                expect(openObservation.authenticationFinished).toBe(true);
                expect(chunkIndex).toBe(observedSinkChunkCount);
                activeSinkCount += 1;
                maximumActiveSinkCount = Math.max(
                    maximumActiveSinkCount,
                    activeSinkCount,
                );
                await Promise.resolve();
                observedSinkChunkCount += 1;
                activeSinkCount -= 1;
            },
        });
        const opened = await openAuthenticatedMailbox({
            carrier,
            expectedAssociatedData: associatedData,
            gcmRuntime: makeGcmRuntime(openObservation),
            inboundSlotAuthority,
            kernel,
            plaintextSinkBoundary: plaintextSink.boundary,
            pullCiphertextChunk: sourceFromChunks(ciphertextChunks),
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: staging.boundary,
            streamBoundary,
        });
        expect(opened).toEqual({
            isValid: true,
            value: {
                disposition: "accepted",
                envelopeHash: deriveEnvelopeHashFromCarrier(carrier),
                plaintextByteLength: plaintext.byteLength,
            },
        });
        expect(maximumActiveSinkCount).toBe(1);
        expect(staging.observation.disposeCount).toBe(1);
        const openedChunks = plaintextSink.observation.publishedChunks;
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
        const duplicate = await openAuthenticatedMailbox({
            carrier,
            expectedAssociatedData: associatedData,
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            inboundSlotAuthority,
            kernel,
            plaintextSinkBoundary: plaintextSink.boundary,
            pullCiphertextChunk: () => {
                duplicateFetchCount += 1;
                return Promise.reject(
                    new Error("Duplicate must not fetch ciphertext."),
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
                disposition: "byteIdenticalRetransmission",
                envelopeHash: deriveEnvelopeHashFromCarrier(carrier),
                plaintextByteLength: plaintext.byteLength,
            },
        });
        expect(duplicateFetchCount).toBe(0);
        expect(plaintextSink.observation.publicationCount).toBe(1);

        const replayedCiphertext: Uint8Array[] = [];
        let plaintextPullCount = 0;
        const replayedCarrier = await sealAuthenticatedMailbox({
            associatedData,
            emitCiphertextChunk: ({ bytes }) => {
                replayedCiphertext.push(new Uint8Array(bytes).slice());
                return Promise.resolve();
            },
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            kernel,
            outboundCache: outbound.cache,
            plaintextByteLength: plaintext.byteLength,
            pullPlaintextChunk: () => {
                plaintextPullCount += 1;
                return Promise.reject(
                    new Error("Cached sealing must not reread plaintext."),
                );
            },
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningCapability: sourceProvider.signingCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            streamBoundary,
        });
        expect(replayedCarrier).toEqual(carrier);
        expect(replayedCiphertext).toEqual(ciphertextChunks);
        expect(plaintextPullCount).toBe(0);
        expect(resetSafeObservation).toEqual({
            encapsulationConsumptionCount: 1,
            signatureConsumptionCount: 1,
        });

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
            expectedAssociatedData: associatedData,
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            inboundSlotAuthority,
            kernel,
            plaintextSinkBoundary: plaintextSink.boundary,
            pullCiphertextChunk: () => {
                conflictingFetchCount += 1;
                return Promise.reject(
                    new Error("Equivocation must not fetch ciphertext."),
                );
            },
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: makeStagingBoundary().boundary,
            streamBoundary,
        });
        expect(conflictingOpen).toEqual({
            isValid: false,
            refusalReason: "equivocation",
        });
        expect(conflictingFetchCount).toBe(0);
        expect(plaintextSink.observation.publicationCount).toBe(1);

        sourceProvider.close();
        recipientProvider.close();
        plaintext.fill(0);
        for (const chunk of [...ciphertextChunks, ...openedChunks]) {
            chunk.fill(0);
        }
    });

    it("cancels unpublished plaintext staging and permits an exact retry after a sink failure", async () => {
        const sourceKeys = keyPair(0x22);
        const recipientKeys = keyPair(0x52);
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
        });
        const plaintext = textEncoder.encode(
            "authenticated mailbox sink failure recovery",
        );
        const { carrier, ciphertextChunks } = createAuthenticatedMailboxFixture(
            {
                plaintext,
                recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
                sourceSigningSecretKey: sourceKeys.signing.secretKey,
            },
        );
        const expectedAssociatedData = associatedData;
        const inboundSlotAuthority = makeInboundSlotAuthority();
        const plaintextSink = makePlaintextSinkBoundary({
            failStageAtChunkIndex: 0,
        });
        const open = () =>
            openAuthenticatedMailbox({
                carrier,
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({
                    authenticationFinished: false,
                }),
                inboundSlotAuthority,
                kernel,
                plaintextSinkBoundary: plaintextSink.boundary,
                pullCiphertextChunk: sourceFromChunks(ciphertextChunks),
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: makeStagingBoundary().boundary,
                streamBoundary: makeStreamBoundary(),
            });

        await expect(open()).rejects.toThrow(
            "Injected plaintext staging failure.",
        );
        expect(plaintextSink.observation.cancelCount).toBe(1);
        expect(plaintextSink.observation.publicationCount).toBe(0);

        await expect(open()).resolves.toMatchObject({
            isValid: true,
            value: { disposition: "accepted" },
        });
        expect(plaintextSink.observation.publicationCount).toBe(1);
        expect(plaintextSink.observation.publishedChunks).toEqual([plaintext]);

        recipientProvider.close();
        plaintext.fill(0);
        for (const chunk of ciphertextChunks) {
            chunk.fill(0);
        }
    });

    it.each([
        {
            expectedRetryDisposition: "accepted" as const,
            inboundFailure: "before publication" as const,
        },
        {
            expectedRetryDisposition: "byteIdenticalRetransmission" as const,
            inboundFailure: "after publication" as const,
        },
    ])(
        "finishes a prepared delivery after inbound commit fails $inboundFailure without decrypting twice",
        async ({ expectedRetryDisposition, inboundFailure }) => {
            const sourceKeys = keyPair(
                inboundFailure === "before publication" ? 0x23 : 0x27,
            );
            const recipientKeys = keyPair(
                inboundFailure === "before publication" ? 0x53 : 0x57,
            );
            const recipientProvider = openBrowserLocalExternalKeyProvider({
                ...createBrowserLocalKeyOperations(recipientKeys),
            });
            const plaintext = textEncoder.encode(
                `authenticated mailbox inbound ${inboundFailure}`,
            );
            const { carrier, ciphertextChunks } =
                createAuthenticatedMailboxFixture({
                    plaintext,
                    recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
                    sourceSigningSecretKey: sourceKeys.signing.secretKey,
                });
            const expectedAssociatedData = associatedData;
            const inboundSlotAuthority = makeInboundSlotAuthority({
                ...(inboundFailure === "before publication"
                    ? { failCommitBeforePublicationOnce: true }
                    : { failCommitAfterPublicationOnce: true }),
            });
            const plaintextSink = makePlaintextSinkBoundary();
            const firstOpen = openAuthenticatedMailbox({
                carrier,
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({
                    authenticationFinished: false,
                }),
                inboundSlotAuthority,
                kernel,
                plaintextSinkBoundary: plaintextSink.boundary,
                pullCiphertextChunk: sourceFromChunks(ciphertextChunks),
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: makeStagingBoundary().boundary,
                streamBoundary: makeStreamBoundary(),
            });

            await expect(firstOpen).rejects.toThrow(/Injected inbound commit/u);
            expect(plaintextSink.observation.publicationCount).toBe(0);

            let retryCiphertextPullCount = 0;
            const retry = await openAuthenticatedMailbox({
                carrier,
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({
                    authenticationFinished: false,
                }),
                inboundSlotAuthority,
                kernel,
                plaintextSinkBoundary: plaintextSink.boundary,
                pullCiphertextChunk: () => {
                    retryCiphertextPullCount += 1;
                    return Promise.reject(
                        new Error("Prepared delivery must not decrypt again."),
                    );
                },
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: makeStagingBoundary().boundary,
                streamBoundary: makeStreamBoundary(),
            });
            expect(retry).toMatchObject({
                isValid: true,
                value: { disposition: expectedRetryDisposition },
            });
            expect(retryCiphertextPullCount).toBe(0);
            expect(plaintextSink.observation.publicationCount).toBe(1);
            expect(plaintextSink.observation.publishedChunks).toEqual([
                plaintext,
            ]);

            recipientProvider.close();
            plaintext.fill(0);
            for (const chunk of ciphertextChunks) {
                chunk.fill(0);
            }
        },
    );

    it.each([
        {
            expectedCommitAttemptCount: 2,
            sinkFailure: "before publication" as const,
        },
        {
            expectedCommitAttemptCount: 1,
            sinkFailure: "after publication" as const,
        },
    ])(
        "publishes exactly once when sink commit fails $sinkFailure and the exact carrier is retried",
        async ({ expectedCommitAttemptCount, sinkFailure }) => {
            const sourceKeys = keyPair(
                sinkFailure === "before publication" ? 0x24 : 0x25,
            );
            const recipientKeys = keyPair(
                sinkFailure === "before publication" ? 0x54 : 0x55,
            );
            const recipientProvider = openBrowserLocalExternalKeyProvider({
                ...createBrowserLocalKeyOperations(recipientKeys),
            });
            const plaintext = textEncoder.encode(
                `authenticated mailbox sink ${sinkFailure}`,
            );
            const { carrier, ciphertextChunks } =
                createAuthenticatedMailboxFixture({
                    plaintext,
                    recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
                    sourceSigningSecretKey: sourceKeys.signing.secretKey,
                });
            const expectedAssociatedData = associatedData;
            const inboundSlotAuthority = makeInboundSlotAuthority();
            const plaintextSink = makePlaintextSinkBoundary({
                ...(sinkFailure === "before publication"
                    ? { failCommitBeforePublicationOnce: true }
                    : { failCommitAfterPublicationOnce: true }),
            });
            await expect(
                openAuthenticatedMailbox({
                    carrier,
                    expectedAssociatedData,
                    gcmRuntime: makeGcmRuntime({
                        authenticationFinished: false,
                    }),
                    inboundSlotAuthority,
                    kernel,
                    plaintextSinkBoundary: plaintextSink.boundary,
                    pullCiphertextChunk: sourceFromChunks(ciphertextChunks),
                    recipientMailboxCapability:
                        recipientProvider.mailboxCapability,
                    sourceVerificationKey: sourceKeys.signing.publicKey,
                    stagingBoundary: makeStagingBoundary().boundary,
                    streamBoundary: makeStreamBoundary(),
                }),
            ).rejects.toThrow(/plaintext publication/u);

            let retryCiphertextPullCount = 0;
            await expect(
                openAuthenticatedMailbox({
                    carrier,
                    expectedAssociatedData,
                    gcmRuntime: makeGcmRuntime({
                        authenticationFinished: false,
                    }),
                    inboundSlotAuthority,
                    kernel,
                    plaintextSinkBoundary: plaintextSink.boundary,
                    pullCiphertextChunk: () => {
                        retryCiphertextPullCount += 1;
                        return Promise.reject(
                            new Error(
                                "A retained delivery must not decrypt again.",
                            ),
                        );
                    },
                    recipientMailboxCapability:
                        recipientProvider.mailboxCapability,
                    sourceVerificationKey: sourceKeys.signing.publicKey,
                    stagingBoundary: makeStagingBoundary().boundary,
                    streamBoundary: makeStreamBoundary(),
                }),
            ).resolves.toMatchObject({
                isValid: true,
                value: { disposition: "byteIdenticalRetransmission" },
            });
            expect(retryCiphertextPullCount).toBe(0);
            expect(plaintextSink.observation.commitAttemptCount).toBe(
                expectedCommitAttemptCount,
            );
            expect(plaintextSink.observation.publicationCount).toBe(1);
            expect(plaintextSink.observation.publishedChunks).toEqual([
                plaintext,
            ]);

            recipientProvider.close();
            plaintext.fill(0);
            for (const chunk of ciphertextChunks) {
                chunk.fill(0);
            }
        },
    );

    it("allows only one concurrent publisher for the same authenticated envelope", async () => {
        const sourceKeys = keyPair(0x26);
        const recipientKeys = keyPair(0x56);
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
        });
        const plaintext = textEncoder.encode(
            "authenticated mailbox concurrent delivery",
        );
        const { carrier, ciphertextChunks } = createAuthenticatedMailboxFixture(
            {
                plaintext,
                recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
                sourceSigningSecretKey: sourceKeys.signing.secretKey,
            },
        );
        const expectedAssociatedData = associatedData;
        const inboundSlotAuthority = makeInboundSlotAuthority();
        let allowFirstPublisher: (() => void) | undefined;
        let reportFirstPublisherReady: (() => void) | undefined;
        const firstPublisherReady = new Promise<void>((resolve) => {
            reportFirstPublisherReady = resolve;
        });
        const firstPublisherMayContinue = new Promise<void>((resolve) => {
            allowFirstPublisher = resolve;
        });
        const plaintextSink = makePlaintextSinkBoundary({
            observeStage: async () => {
                reportFirstPublisherReady?.();
                await firstPublisherMayContinue;
            },
        });
        const firstOpen = openAuthenticatedMailbox({
            carrier,
            expectedAssociatedData,
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            inboundSlotAuthority,
            kernel,
            plaintextSinkBoundary: plaintextSink.boundary,
            pullCiphertextChunk: sourceFromChunks(ciphertextChunks),
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: makeStagingBoundary().boundary,
            streamBoundary: makeStreamBoundary(),
        });
        await firstPublisherReady;

        let competingCiphertextPullCount = 0;
        const competingOpen = await openAuthenticatedMailbox({
            carrier,
            expectedAssociatedData,
            gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
            inboundSlotAuthority,
            kernel,
            plaintextSinkBoundary: plaintextSink.boundary,
            pullCiphertextChunk: () => {
                competingCiphertextPullCount += 1;
                return Promise.reject(
                    new Error("A competing publisher must not read bytes."),
                );
            },
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceVerificationKey: sourceKeys.signing.publicKey,
            stagingBoundary: makeStagingBoundary().boundary,
            streamBoundary: makeStreamBoundary(),
        });
        expect(competingOpen).toEqual({
            isValid: false,
            refusalReason: "consumedState",
        });
        expect(competingCiphertextPullCount).toBe(0);

        allowFirstPublisher?.();
        await expect(firstOpen).resolves.toMatchObject({
            isValid: true,
            value: { disposition: "accepted" },
        });
        expect(plaintextSink.observation.publicationCount).toBe(1);

        recipientProvider.close();
        plaintext.fill(0);
        for (const chunk of ciphertextChunks) {
            chunk.fill(0);
        }
    });

    it("refuses wrong bindings and hostile cryptographic bytes before releasing plaintext", async () => {
        const sourceKeys = keyPair(0x31);
        const recipientKeys = keyPair(0x61);
        const wrongRecipientKeys = keyPair(0x71);
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
        });
        const wrongRecipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(wrongRecipientKeys),
        });
        const plaintext = textEncoder.encode(
            canonicalJson({ objectType: "PrivateVssShareEnvelope", value: 3 }),
        );
        const fixture = createAuthenticatedMailboxFixture({
            plaintext,
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningSecretKey: sourceKeys.signing.secretKey,
        });
        const { carrier, ciphertextChunks: ciphertext } = fixture;
        const baseExpectation: SetupMailboxSlot = {
            ...associatedData,
        };
        const open = (
            candidateCarrier: AuthenticatedMailboxCarrier,
            candidateCiphertext: readonly Uint8Array[],
            expectation = baseExpectation,
            mailboxCapability = recipientProvider.mailboxCapability,
            verificationKey = sourceKeys.signing.publicKey,
            stagingBoundary = makeStagingBoundary().boundary,
        ) => {
            const plaintextSink = makePlaintextSinkBoundary();
            return openAuthenticatedMailbox({
                carrier: candidateCarrier,
                expectedAssociatedData: expectation,
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                inboundSlotAuthority: makeInboundSlotAuthority(),
                kernel,
                plaintextSinkBoundary: plaintextSink.boundary,
                pullCiphertextChunk: sourceFromChunks(candidateCiphertext),
                recipientMailboxCapability: mailboxCapability,
                sourceVerificationKey: verificationKey,
                stagingBoundary,
                streamBoundary: makeStreamBoundary(),
            }).then((result) => ({
                plaintextReleaseCount:
                    plaintextSink.observation.publicationCount,
                result,
            }));
        };

        const wrongExpectations = [
            { ...baseExpectation, sourceParticipantId: "90".repeat(64) },
            { ...baseExpectation, recipientParticipantId: "91".repeat(64) },
            { ...baseExpectation, producerSequence: "8" },
            { ...baseExpectation, suiteId: "92".repeat(64) },
            {
                ...baseExpectation,
                ceremonyContextHash: "93".repeat(64),
            },
            {
                ...baseExpectation,
                actionContextHash: "94".repeat(64),
            },
            { ...baseExpectation, rosterHash: "95".repeat(64) },
            {
                ...baseExpectation,
                statementHash: "96".repeat(64),
            },
            {
                ...baseExpectation,
                orderedMaterialRoots: ["97".repeat(64)],
            },
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
                refusalReason: "wrongContext",
            });
            expect(refusal.plaintextReleaseCount).toBe(0);
        }
        const authenticatedRecipientProvider =
            openBrowserLocalExternalKeyProvider({
                ...createBrowserLocalKeyOperations(recipientKeys),
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
            refusalReason: "invalidSignature",
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
            refusalReason: "wrongHashOrRoot",
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
            refusalReason: "invalidSignature",
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
            refusalReason: "invalidArithmeticRelation",
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
            refusalReason: "wrongHashOrRoot",
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
            refusalReason: "wrongTypeOrLength",
        });

        const wrongKey = await open(
            carrier,
            ciphertext,
            baseExpectation,
            wrongRecipientProvider.mailboxCapability,
        );
        expect(wrongKey.result).toEqual({
            isValid: false,
            refusalReason: "invalidArithmeticRelation",
        });
        expect(wrongKey.plaintextReleaseCount).toBe(0);

        authenticatedRecipientProvider.close();
        wrongRecipientProvider.close();
        plaintext.fill(0);
    });

    it("cleans up cancellation, authentication failures, and combined cleanup failures deterministically", async () => {
        const sourceKeys = keyPair(0x41);
        const recipientKeys = keyPair(0x71);
        const recipientProvider = openBrowserLocalExternalKeyProvider({
            ...createBrowserLocalKeyOperations(recipientKeys),
        });
        const plaintext = textEncoder.encode("cleanup-path-mailbox-payload");
        const fixture = createAuthenticatedMailboxFixture({
            plaintext,
            recipientEncapsulationKey: recipientKeys.mailbox.publicKey,
            sourceSigningSecretKey: sourceKeys.signing.secretKey,
        });
        const { carrier, ciphertextChunks: ciphertext } = fixture;
        const expectedAssociatedData = associatedData;
        const abortController = new AbortController();
        abortController.abort();
        await expect(
            openAuthenticatedMailbox({
                abortSignal: abortController.signal,
                carrier,
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                inboundSlotAuthority: makeInboundSlotAuthority(),
                kernel,
                plaintextSinkBoundary: makePlaintextSinkBoundary().boundary,
                pullCiphertextChunk: sourceFromChunks(ciphertext),
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: makeStagingBoundary().boundary,
                streamBoundary: makeStreamBoundary(),
            }),
        ).rejects.toThrow("cancelled");

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
                expectedAssociatedData,
                gcmRuntime: makeGcmRuntime({ authenticationFinished: false }),
                inboundSlotAuthority: makeInboundSlotAuthority(),
                kernel,
                plaintextSinkBoundary: makePlaintextSinkBoundary().boundary,
                pullCiphertextChunk: sourceFromChunks(ciphertext),
                recipientMailboxCapability: recipientProvider.mailboxCapability,
                sourceVerificationKey: sourceKeys.signing.publicKey,
                stagingBoundary: failedStaging.boundary,
                streamBoundary: makeStreamBoundary(),
            }),
        ).rejects.toBeInstanceOf(AuthenticatedMailboxCleanupError);
        expect(failedStaging.observation.disposeCount).toBe(1);

        recipientProvider.close();
        plaintext.fill(0);
    });
});
