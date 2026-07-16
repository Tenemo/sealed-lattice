import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
    foundationProfile,
    type ProtocolHash,
    type SetupMailboxSlot,
} from '@sealed-lattice/types';

import { createBrowserLocalKeyOperations } from '#packages/crypto/tests/support/browser-local-key-operations';
import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    openMailboxGcmRuntime,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    createCanonicalTestRosterBytes,
    fixedBytesItem,
    foundationHash512,
    variableBytesItem,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import {
    openAuthenticatedMailbox,
    openAuthenticatedMailboxFrozenRoster,
    openBrowserLocalExternalKeyProvider,
    sealAuthenticatedMailbox,
    type AuthenticatedMailboxCarrier,
    type AuthenticatedMailboxInboundSlotAuthority,
    type AuthenticatedMailboxOutboundCache,
    type AuthenticatedMailboxPlaintextSinkBoundary,
    type AuthenticatedMailboxStagingBoundary,
    type AuthenticatedMailboxStreamBoundary,
} from '@sealed-lattice/crypto';

type StartMessage = Readonly<{
    command: 'run';
    requestIdentifier: number;
}>;

type WorkerScope = Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

type MutableObservation = {
    inboundReservationCount: number;
    plaintextReservationCount: number;
    stagingOpenCount: number;
};

const workerScope = globalThis as unknown as WorkerScope;

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isStartMessage = (value: unknown): value is StartMessage =>
    isPlainRecord(value) &&
    value.command === 'run' &&
    Number.isSafeInteger(value.requestIdentifier);

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

const copyBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer;

const participantIdentity = (signingVerificationKey: Uint8Array): string => {
    const signingVerificationKeyItem = fixedBytesItem(signingVerificationKey);
    let identity: Uint8Array | undefined;
    try {
        identity = foundationHash512(
            'sealed-lattice/foundation/participant-id/v1',
            signingVerificationKeyItem,
        );
        return bytesToHex(identity);
    } finally {
        identity?.fill(0);
        signingVerificationKeyItem.fill(0);
    }
};

const rosterHash = (canonicalRosterBytes: Uint8Array): ProtocolHash => {
    const canonicalRosterItem = variableBytesItem(canonicalRosterBytes);
    let digest: Uint8Array | undefined;
    try {
        digest = foundationHash512(
            'sealed-lattice/foundation/roster/v1',
            canonicalRosterItem,
        );
        return bytesToHex(digest);
    } finally {
        digest?.fill(0);
        canonicalRosterItem.fill(0);
    }
};

const createStreamBoundary = (
    kernel: TranscriptCoreKernel,
): AuthenticatedMailboxStreamBoundary => {
    const runtime = openCanonicalStreamWorkerRuntime({ kernel });
    return Object.freeze({
        openWriter: ({ totalByteLength }) => {
            const lease = runtime.openWriter({
                streamDomain: canonicalStreamDomains.privateMailboxCiphertext,
                totalByteLength,
            });
            return Object.freeze({
                absorbChunk: (chunkIndex: number, bytes: ArrayBuffer) =>
                    lease.absorbChunk(chunkIndex, bytes),
                cancel: () => lease.cancel(),
                chunkCount: lease.chunkCount,
                finish: () => {
                    const descriptorBytes = lease.finish();
                    try {
                        return kernel.decodeStreamDescriptor({
                            canonicalBytesHex: bytesToHex(descriptorBytes),
                        }).value;
                    } finally {
                        descriptorBytes.fill(0);
                    }
                },
                state: () => lease.state(),
                totalByteLength: lease.totalByteLength,
            });
        },
        openVerifier: ({ descriptor }) => {
            const encodedDescriptor = kernel.encodeStreamDescriptor(descriptor);
            const descriptorBytes = hexToBytes(
                encodedDescriptor.canonicalBytesHex,
            );
            let lease: ReturnType<typeof runtime.openVerifier>;
            try {
                lease = runtime.openVerifier({
                    descriptorBytes,
                    streamDomain:
                        canonicalStreamDomains.privateMailboxCiphertext,
                });
            } finally {
                descriptorBytes.fill(0);
            }
            return Object.freeze({
                absorbChunk: (chunkIndex: number, bytes: ArrayBuffer) =>
                    lease.absorbChunk(chunkIndex, bytes),
                cancel: () => lease.cancel(),
                chunkCount: lease.chunkCount,
                finish: () => lease.finish(),
                state: () => lease.state(),
                totalByteLength: lease.totalByteLength,
            });
        },
    });
};

const createOutboundCache = (): AuthenticatedMailboxOutboundCache =>
    Object.freeze({
        reserve: () => {
            const stagedChunks: Uint8Array[] = [];
            let committedCarrier: AuthenticatedMailboxCarrier | undefined;
            return Promise.resolve(
                Object.freeze({
                    disposition: 'fresh' as const,
                    cachedCarrier: () =>
                        Promise.reject(
                            new Error('A fresh outbound lease has no carrier.'),
                        ),
                    stageChunk: (input: {
                        readonly bytes: ArrayBuffer;
                        readonly chunkIndex: number;
                    }) => {
                        if (input.chunkIndex !== stagedChunks.length) {
                            return Promise.reject(
                                new Error(
                                    'The outbound mailbox chunk order is invalid.',
                                ),
                            );
                        }
                        stagedChunks.push(new Uint8Array(input.bytes).slice());
                        return Promise.resolve();
                    },
                    commit: (carrier: AuthenticatedMailboxCarrier) => {
                        committedCarrier = Object.freeze({
                            canonicalEnvelopeBytes:
                                carrier.canonicalEnvelopeBytes.slice(),
                        });
                        return Promise.resolve();
                    },
                    pullChunk: (input: {
                        readonly chunkIndex: number;
                        readonly expectedByteLength: number;
                    }) => {
                        if (committedCarrier === undefined) {
                            return Promise.reject(
                                new Error(
                                    'The outbound mailbox carrier is not committed.',
                                ),
                            );
                        }
                        if (input.expectedByteLength === 0) {
                            for (const chunk of stagedChunks) {
                                chunk.fill(0);
                            }
                            committedCarrier.canonicalEnvelopeBytes.fill(0);
                            committedCarrier = undefined;
                            return Promise.resolve(undefined);
                        }
                        const chunk = stagedChunks[input.chunkIndex];
                        if (
                            chunk === undefined ||
                            chunk.byteLength !== input.expectedByteLength
                        ) {
                            return Promise.reject(
                                new Error(
                                    'The outbound mailbox chunk length is invalid.',
                                ),
                            );
                        }
                        return Promise.resolve(copyBuffer(chunk));
                    },
                    cancel: () => {
                        for (const chunk of stagedChunks) {
                            chunk.fill(0);
                        }
                        committedCarrier?.canonicalEnvelopeBytes.fill(0);
                        return Promise.resolve();
                    },
                }),
            );
        },
    });

const createInboundSlotAuthority = (
    observation: MutableObservation,
): AuthenticatedMailboxInboundSlotAuthority =>
    Object.freeze({
        reserve: () => {
            observation.inboundReservationCount += 1;
            let active = true;
            return Promise.resolve({
                isValid: true as const,
                value: Object.freeze({
                    disposition: 'fresh' as const,
                    cancel: () => {
                        active = false;
                        return Promise.resolve();
                    },
                    commit: () => {
                        if (!active) {
                            return Promise.reject(
                                new Error(
                                    'The inbound mailbox lease is inactive.',
                                ),
                            );
                        }
                        active = false;
                        return Promise.resolve();
                    },
                }),
            });
        },
    });

const createStagingBoundary = (
    observation: MutableObservation,
): AuthenticatedMailboxStagingBoundary =>
    Object.freeze({
        open: () => {
            observation.stagingOpenCount += 1;
            const stagedChunks: Uint8Array[] = [];
            let sealed = false;
            return Promise.resolve(
                Object.freeze({
                    stageChunk: (input: {
                        readonly bytes: ArrayBuffer;
                        readonly chunkIndex: number;
                    }) => {
                        if (
                            sealed ||
                            input.chunkIndex !== stagedChunks.length
                        ) {
                            return Promise.reject(
                                new Error(
                                    'The staged mailbox chunk order is invalid.',
                                ),
                            );
                        }
                        stagedChunks.push(new Uint8Array(input.bytes).slice());
                        return Promise.resolve();
                    },
                    seal: () => {
                        sealed = true;
                        return Promise.resolve();
                    },
                    pullChunk: (input: {
                        readonly chunkIndex: number;
                        readonly expectedByteLength: number;
                    }) => {
                        if (!sealed) {
                            return Promise.reject(
                                new Error(
                                    'The staged mailbox chunks are not sealed.',
                                ),
                            );
                        }
                        if (input.expectedByteLength === 0) {
                            return Promise.resolve(undefined);
                        }
                        const chunk = stagedChunks[input.chunkIndex];
                        if (
                            chunk === undefined ||
                            chunk.byteLength !== input.expectedByteLength
                        ) {
                            return Promise.reject(
                                new Error(
                                    'The staged mailbox chunk length is invalid.',
                                ),
                            );
                        }
                        return Promise.resolve(copyBuffer(chunk));
                    },
                    dispose: () => {
                        for (const chunk of stagedChunks) {
                            chunk.fill(0);
                        }
                        return Promise.resolve();
                    },
                }),
            );
        },
    });

const createPlaintextSinkBoundary = (
    observation: MutableObservation,
    publishedChunks: Uint8Array[],
): AuthenticatedMailboxPlaintextSinkBoundary =>
    Object.freeze({
        reserve: () => {
            observation.plaintextReservationCount += 1;
            const stagedChunks: Uint8Array[] = [];
            let sealed = false;
            return Promise.resolve(
                Object.freeze({
                    disposition: 'fresh' as const,
                    cancel: () => {
                        for (const chunk of stagedChunks) {
                            chunk.fill(0);
                        }
                        return Promise.resolve();
                    },
                    commit: () => {
                        if (!sealed) {
                            return Promise.reject(
                                new Error(
                                    'The plaintext mailbox delivery is not sealed.',
                                ),
                            );
                        }
                        publishedChunks.push(
                            ...stagedChunks.map((chunk) => chunk.slice()),
                        );
                        for (const chunk of stagedChunks) {
                            chunk.fill(0);
                        }
                        return Promise.resolve();
                    },
                    release: () => Promise.resolve(),
                    seal: () => {
                        sealed = true;
                        return Promise.resolve();
                    },
                    stageChunk: (input: {
                        readonly bytes: ArrayBuffer;
                        readonly chunkIndex: number;
                    }) => {
                        if (
                            sealed ||
                            input.chunkIndex !== stagedChunks.length
                        ) {
                            return Promise.reject(
                                new Error(
                                    'The plaintext mailbox chunk order is invalid.',
                                ),
                            );
                        }
                        stagedChunks.push(new Uint8Array(input.bytes).slice());
                        return Promise.resolve();
                    },
                }),
            );
        },
    });

const pullFromChunks =
    (chunks: readonly Uint8Array[]) =>
    (input: {
        readonly chunkIndex: number;
        readonly expectedByteLength: number;
    }): Promise<ArrayBuffer | undefined> => {
        if (input.expectedByteLength === 0) {
            return Promise.resolve(undefined);
        }
        const chunk = chunks[input.chunkIndex];
        if (
            chunk === undefined ||
            chunk.byteLength !== input.expectedByteLength
        ) {
            return Promise.reject(
                new Error('The mailbox source chunk length is invalid.'),
            );
        }
        return Promise.resolve(copyBuffer(chunk));
    };

const concatenate = (chunks: readonly Uint8Array[]): Uint8Array => {
    const byteLength = chunks.reduce(
        (totalByteLength, chunk) => totalByteLength + chunk.byteLength,
        0,
    );
    const bytes = new Uint8Array(byteLength);
    let byteOffset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, byteOffset);
        byteOffset += chunk.byteLength;
    }
    return bytes;
};

const run = async (message: StartMessage): Promise<void> => {
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
        foundationProfile.participantCount,
    );
    const canonicalRosterBytes = createCanonicalTestRosterBytes(
        signingKeyPairs.map(({ publicKey }, rosterPosition) => ({
            mailboxEncapsulationKey: mailboxKeyPairs[rosterPosition].publicKey,
            signingVerificationKey: publicKey,
        })),
    );
    const canonicalRosterHash = rosterHash(canonicalRosterBytes);
    const sourceParticipantId = participantIdentity(
        signingKeyPairs[0].publicKey,
    );
    const recipientParticipantId = participantIdentity(
        signingKeyPairs[1].publicKey,
    );
    const sourceVerificationKey = signingKeyPairs[0].publicKey.slice();
    const recipientEncapsulationKey = mailboxKeyPairs[1].publicKey.slice();
    const sourceRoster =
        openAuthenticatedMailboxFrozenRoster(canonicalRosterBytes);
    const associatedData: SetupMailboxSlot = Object.freeze({
        suiteId: '11'.repeat(64),
        ceremonyContextHash: '22'.repeat(64),
        actionContextHash: '33'.repeat(64),
        rosterHash: canonicalRosterHash,
        sourceParticipantId,
        recipientParticipantId,
        producerSequence: '7',
        payloadType: 2,
        statementHash: '44'.repeat(64),
        orderedMaterialRoots: Object.freeze(['55'.repeat(64), '66'.repeat(64)]),
    });
    const sourceProvider = openBrowserLocalExternalKeyProvider(
        createBrowserLocalKeyOperations({
            mailbox: mailboxKeyPairs[0],
            signing: signingKeyPairs[0],
            resetSafeSetupMailboxScope: {
                suiteId: associatedData.suiteId,
                ceremonyContextHash: associatedData.ceremonyContextHash,
                actionContextHash: associatedData.actionContextHash,
                rosterHash: associatedData.rosterHash,
                sourceParticipantId: associatedData.sourceParticipantId,
            },
        }),
    );
    const recipientProvider = openBrowserLocalExternalKeyProvider(
        createBrowserLocalKeyOperations({
            mailbox: mailboxKeyPairs[1],
            signing: signingKeyPairs[1],
        }),
    );
    canonicalRosterBytes.fill(0);
    for (const keyPair of signingKeyPairs) {
        keyPair.publicKey.fill(0);
        keyPair.secretKey.fill(0);
    }
    for (const keyPair of mailboxKeyPairs) {
        keyPair.publicKey.fill(0);
        keyPair.secretKey.fill(0);
    }

    const plaintext = Uint8Array.from(
        { length: 4_097 },
        (_unused, byteIndex) => (byteIndex * 131 + 17) & 0xff,
    );
    const plaintextChunks = [plaintext.slice()];
    const ciphertextChunks: Uint8Array[] = [];
    const publishedChunks: Uint8Array[] = [];
    const observation: MutableObservation = {
        inboundReservationCount: 0,
        plaintextReservationCount: 0,
        stagingOpenCount: 0,
    };
    let carrier: AuthenticatedMailboxCarrier | undefined;
    let malformedCarrierBytes: Uint8Array | undefined;
    let openedPlaintext: Uint8Array | undefined;
    try {
        const kernel = await loadFreshTranscriptCoreKernel();
        const streamBoundary = createStreamBoundary(kernel);
        const gcmRuntime = openMailboxGcmRuntime({ kernel });
        carrier = await sealAuthenticatedMailbox({
            associatedData,
            emitCiphertextChunk: ({ bytes }) => {
                ciphertextChunks.push(new Uint8Array(bytes).slice());
                return Promise.resolve();
            },
            gcmRuntime,
            kernel,
            outboundCache: createOutboundCache(),
            plaintextByteLength: plaintext.byteLength,
            pullPlaintextChunk: pullFromChunks(plaintextChunks),
            recipientEncapsulationKey,
            sourceSigningCapability: sourceProvider.signingCapability,
            sourceVerificationKey,
            streamBoundary,
        });
        const successfulOpen = await openAuthenticatedMailbox({
            carrier,
            expectedAssociatedData: associatedData,
            gcmRuntime,
            inboundSlotAuthority: createInboundSlotAuthority(observation),
            kernel,
            plaintextSinkBoundary: createPlaintextSinkBoundary(
                observation,
                publishedChunks,
            ),
            pullCiphertextChunk: pullFromChunks(ciphertextChunks),
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceRoster,
            stagingBoundary: createStagingBoundary(observation),
            streamBoundary,
        });
        openedPlaintext = concatenate(publishedChunks);

        let malformedCiphertextPullCount = 0;
        const malformedObservation: MutableObservation = {
            inboundReservationCount: 0,
            plaintextReservationCount: 0,
            stagingOpenCount: 0,
        };
        malformedCarrierBytes = carrier.canonicalEnvelopeBytes.slice(0, -1);
        const malformedOpen = await openAuthenticatedMailbox({
            carrier: {
                canonicalEnvelopeBytes: malformedCarrierBytes,
            },
            expectedAssociatedData: associatedData,
            gcmRuntime,
            inboundSlotAuthority:
                createInboundSlotAuthority(malformedObservation),
            kernel,
            plaintextSinkBoundary: createPlaintextSinkBoundary(
                malformedObservation,
                [],
            ),
            pullCiphertextChunk: () => {
                malformedCiphertextPullCount += 1;
                return Promise.reject(
                    new Error('Malformed carriers must not fetch ciphertext.'),
                );
            },
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceRoster,
            stagingBoundary: createStagingBoundary(malformedObservation),
            streamBoundary,
        });

        let wrongContextCiphertextPullCount = 0;
        const wrongContextObservation: MutableObservation = {
            inboundReservationCount: 0,
            plaintextReservationCount: 0,
            stagingOpenCount: 0,
        };
        const wrongContextOpen = await openAuthenticatedMailbox({
            carrier,
            expectedAssociatedData: Object.freeze({
                ...associatedData,
                statementHash: '77'.repeat(64),
            }),
            gcmRuntime,
            inboundSlotAuthority: createInboundSlotAuthority(
                wrongContextObservation,
            ),
            kernel,
            plaintextSinkBoundary: createPlaintextSinkBoundary(
                wrongContextObservation,
                [],
            ),
            pullCiphertextChunk: () => {
                wrongContextCiphertextPullCount += 1;
                return Promise.reject(
                    new Error(
                        'Wrong-context carriers must not fetch ciphertext.',
                    ),
                );
            },
            recipientMailboxCapability: recipientProvider.mailboxCapability,
            sourceRoster,
            stagingBoundary: createStagingBoundary(wrongContextObservation),
            streamBoundary,
        });

        workerScope.postMessage({
            carrierByteLength: carrier.canonicalEnvelopeBytes.byteLength,
            ciphertextChunkCount: ciphertextChunks.length,
            malformedCiphertextPullCount,
            malformedDownstreamCount:
                malformedObservation.inboundReservationCount +
                malformedObservation.plaintextReservationCount +
                malformedObservation.stagingOpenCount,
            malformedRefusalReason: malformedOpen.isValid
                ? undefined
                : malformedOpen.refusalReason,
            messageKind: 'completed',
            plaintextMatches: bytesEqual(openedPlaintext, plaintext),
            requestIdentifier: message.requestIdentifier,
            roundTripDisposition: successfulOpen.isValid
                ? successfulOpen.value.disposition
                : undefined,
            roundTripRefusalReason: successfulOpen.isValid
                ? undefined
                : successfulOpen.refusalReason,
            successfulDownstreamCount:
                observation.inboundReservationCount +
                observation.plaintextReservationCount +
                observation.stagingOpenCount,
            wrongContextCiphertextPullCount,
            wrongContextDownstreamCount:
                wrongContextObservation.inboundReservationCount +
                wrongContextObservation.plaintextReservationCount +
                wrongContextObservation.stagingOpenCount,
            wrongContextRefusalReason: wrongContextOpen.isValid
                ? undefined
                : wrongContextOpen.refusalReason,
        });
    } finally {
        sourceProvider.close();
        recipientProvider.close();
        plaintext.fill(0);
        sourceVerificationKey.fill(0);
        recipientEncapsulationKey.fill(0);
        carrier?.canonicalEnvelopeBytes.fill(0);
        malformedCarrierBytes?.fill(0);
        openedPlaintext?.fill(0);
        for (const chunk of [
            ...plaintextChunks,
            ...ciphertextChunks,
            ...publishedChunks,
        ]) {
            chunk.fill(0);
        }
    }
};

workerScope.addEventListener('message', (event) => {
    const message = event.data;
    if (!isStartMessage(message)) {
        return;
    }
    void run(message).catch((error: unknown) => {
        workerScope.postMessage({
            failureMessage:
                error instanceof Error ? error.message : 'Unknown failure.',
            failureName: error instanceof Error ? error.name : 'UnknownError',
            messageKind: 'failed',
            requestIdentifier: message.requestIdentifier,
        });
    });
});
