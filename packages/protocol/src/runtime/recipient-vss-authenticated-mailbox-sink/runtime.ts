import type {
    AuthenticatedMailboxPlaintextCapability,
    AuthenticatedMailboxPlaintextSinkBoundary,
    AuthenticatedMailboxPlaintextSinkLease,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';
import { resolveAggregateThresholdShareAuthenticatedRecipientConsumer } from '@sealed-lattice/wasm';

import {
    AuthenticatedMailboxStorageError,
    asStorageError,
    cleanupError,
    closeTransactionAfterFailure,
    expectedChunkByteLength,
    requireArrayBuffer,
    requireProtocolHash,
    streamChunkCount,
    validateLimits,
    validateProducerSlotAuthority,
} from '../authenticated-mailbox-storage/records.js';
import {
    copyRuntimeRecordProtectionAuthorityContext,
    readRuntimeRecord,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
} from '../authenticated-runtime-record.js';

import {
    copyExpectedSetupMailboxSlot,
    decodeRecipientVssPlaintextJournal,
    decodeRecipientVssPlaintextManifest,
    encodeRecipientVssPlaintextJournal,
    encodeRecipientVssPlaintextManifest,
    producerSlotFromSetupMailboxSlot,
    recipientVssPlaintextChunkKey,
    recipientVssPlaintextChunkOperationDomain,
    recipientVssPlaintextJournalKey,
    recipientVssPlaintextJournalOperationDomain,
    recipientVssPlaintextManifestKey,
    recipientVssPlaintextManifestOperationDomain,
    recipientVssPlaintextRecordMatches,
    recipientVssPlaintextRecordVersion,
    requireMatchingReservedProducerSlot,
    type OpenedStoredRecipientVssRecord,
    type RecipientVssAuthenticatedMailboxPlaintextSink,
    type RecipientVssAuthenticatedMailboxPlaintextSinkConfiguration,
    type RecipientVssAuthenticatedMailboxPlaintextSinkInternalConfiguration,
    type StoredRecipientVssPlaintextJournal,
    type StoredRecipientVssPlaintextManifest,
} from './records.js';

export { AuthenticatedMailboxStorageError } from '../authenticated-mailbox-storage/records.js';
export type {
    RecipientVssAuthenticatedMailboxPlaintextSink,
    RecipientVssAuthenticatedMailboxPlaintextSinkConfiguration,
} from './records.js';

const concatenateChunks = (
    chunks: readonly Uint8Array[],
    totalByteLength: number,
): Uint8Array => {
    const plaintext = new Uint8Array(totalByteLength);
    let byteOffset = 0;
    for (const chunk of chunks) {
        plaintext.set(chunk, byteOffset);
        byteOffset += chunk.byteLength;
    }
    if (byteOffset !== totalByteLength) {
        plaintext.fill(0);
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored recipient VSS plaintext chunks have the wrong total byte length.',
        );
    }
    return plaintext;
};

export const createRecipientVssAuthenticatedMailboxPlaintextSinkWithConsumer = (
    configuration: RecipientVssAuthenticatedMailboxPlaintextSinkInternalConfiguration,
): RecipientVssAuthenticatedMailboxPlaintextSink => {
    const limits = validateLimits(configuration.limits);
    const expectedSetupMailboxSlot = copyExpectedSetupMailboxSlot(
        configuration.expectedSetupMailboxSlot,
    );
    const expectedSetupMailboxSlotHash = requireProtocolHash(
        configuration.expectedSetupMailboxSlotHash,
        'expectedSetupMailboxSlotHash',
    );
    const expectedProducerSlot = producerSlotFromSetupMailboxSlot(
        expectedSetupMailboxSlot,
    );
    const authorityContext = copyRuntimeRecordProtectionAuthorityContext(
        configuration.protection,
    );
    try {
        validateProducerSlotAuthority({
            authorityContext,
            direction: 'inbound',
            producerSlot: expectedProducerSlot,
        });
    } finally {
        authorityContext.actionContextHash.fill(0);
        authorityContext.ceremonyContextHash.fill(0);
        authorityContext.ownerParticipantIdentity.fill(0);
        authorityContext.runtimeBuildManifestHash.fill(0);
        authorityContext.suiteIdentifier.fill(0);
    }

    const activeEnvelopeHashes = new Set<ProtocolHash>();
    const consumedEnvelopeHashes = new Set<ProtocolHash>();
    const issuedIdentifiers = new Set<string>();
    let consumerRetired = false;

    const readDecodedRecord = async <RecordValue>(input: {
        decode(plaintext: Uint8Array): RecordValue;
        logicalRecordKey: string;
        operationDomain: string;
    }): Promise<OpenedStoredRecipientVssRecord<RecordValue> | undefined> => {
        const opened = await readRuntimeRecord({
            logicalRecordKey: input.logicalRecordKey,
            operationDomain: input.operationDomain,
            protection: configuration.protection,
            store: configuration.store,
        });
        if (opened === undefined) {
            return undefined;
        }
        try {
            let record: RecordValue;
            try {
                record = input.decode(opened.plaintext);
            } catch (error) {
                throw new AuthenticatedMailboxStorageError(
                    'AuthenticationFailed',
                    'A root-protected recipient VSS plaintext record has invalid contents.',
                    error,
                );
            }
            return Object.freeze({
                record,
                sealedBytes: opened.sealedBytes.slice(),
            });
        } finally {
            opened.plaintext.fill(0);
            opened.sealedBytes.fill(0);
        }
    };

    const readManifest = (
        envelopeHash: ProtocolHash,
    ): Promise<
        | OpenedStoredRecipientVssRecord<StoredRecipientVssPlaintextManifest>
        | undefined
    > =>
        readDecodedRecord({
            decode: decodeRecipientVssPlaintextManifest,
            logicalRecordKey: recipientVssPlaintextManifestKey(envelopeHash),
            operationDomain: recipientVssPlaintextManifestOperationDomain,
        });

    const readJournal = (
        envelopeHash: ProtocolHash,
    ): Promise<
        | OpenedStoredRecipientVssRecord<StoredRecipientVssPlaintextJournal>
        | undefined
    > =>
        readDecodedRecord({
            decode: decodeRecipientVssPlaintextJournal,
            logicalRecordKey: recipientVssPlaintextJournalKey(envelopeHash),
            operationDomain: recipientVssPlaintextJournalOperationDomain,
        });

    const writeRecord = async (input: {
        expectedCurrentSealedBytes?: Uint8Array | null;
        logicalRecordKey: string;
        operationDomain: string;
        plaintext: Uint8Array;
    }): Promise<Uint8Array> => {
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            const sealedBytes = await stageRuntimeRecordWrite({
                ...(input.expectedCurrentSealedBytes === undefined
                    ? {}
                    : {
                          expectedCurrentSealedBytes:
                              input.expectedCurrentSealedBytes,
                      }),
                logicalRecordKey: input.logicalRecordKey,
                operationDomain: input.operationDomain,
                plaintext: input.plaintext,
                protection: configuration.protection,
                transaction,
            });
            await transaction.commit();
            return sealedBytes;
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        }
    };

    const deleteRecord = async (logicalRecordKey: string): Promise<void> => {
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await transaction.stageDeletion(logicalRecordKey);
            await transaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        }
    };

    const cleanupJournal = async (
        journal: StoredRecipientVssPlaintextJournal,
    ): Promise<void> => {
        const chunkCount = streamChunkCount(
            journal.plaintextByteLength,
            limits,
        );
        const failures: unknown[] = [];
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            try {
                await deleteRecord(
                    recipientVssPlaintextChunkKey({
                        chunkIndex,
                        envelopeHash: journal.envelopeHash,
                        publicationIdentifier: journal.publicationIdentifier,
                    }),
                );
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length === 0) {
            try {
                await deleteRecord(
                    recipientVssPlaintextJournalKey(journal.envelopeHash),
                );
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length !== 0) {
            throw cleanupError(
                'Recipient VSS plaintext cleanup did not remove every transaction-owned record.',
                failures,
            );
        }
    };

    const requireMatchingRecord = (input: {
        envelopeHash: ProtocolHash;
        plaintextByteLength: number;
        record: StoredRecipientVssPlaintextJournal;
    }): void => {
        if (
            !recipientVssPlaintextRecordMatches({
                envelopeHash: input.envelopeHash,
                expectedProducerSlot,
                expectedSetupMailboxSlotHash,
                plaintextByteLength: input.plaintextByteLength,
                record: input.record,
            })
        ) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'Stored recipient VSS plaintext belongs to another authenticated mailbox delivery.',
            );
        }
    };

    const retireConsumer = async (
        operationFailure: unknown,
    ): Promise<never> => {
        let cleanupFailure: unknown;
        if (!consumerRetired) {
            consumerRetired = true;
            try {
                await configuration.consumer.retireAfterUncertainConsumption(
                    operationFailure,
                );
            } catch (error) {
                cleanupFailure = error;
            }
        }
        if (cleanupFailure !== undefined) {
            throw cleanupError(
                'Recipient VSS plaintext consumption failed and its worker-owned authority could not retire.',
                [operationFailure, cleanupFailure],
            );
        }
        throw asStorageError(operationFailure);
    };

    const consumeManifest = async (
        manifest: StoredRecipientVssPlaintextManifest,
        authenticatedPlaintextCapability: AuthenticatedMailboxPlaintextCapability,
        canonicalSignedEnvelopeBytes: Uint8Array,
    ): Promise<void> => {
        if (consumerRetired) {
            throw new AuthenticatedMailboxStorageError(
                'InvalidState',
                'The recipient VSS plaintext consumer is retired.',
            );
        }
        const chunkCount = streamChunkCount(
            manifest.plaintextByteLength,
            limits,
        );
        const chunks: Uint8Array[] = [];
        let canonicalPlaintextBytes: Uint8Array | undefined;
        let capabilityTransferred = false;
        try {
            for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
                const opened = await readRuntimeRecord({
                    logicalRecordKey: recipientVssPlaintextChunkKey({
                        chunkIndex,
                        envelopeHash: manifest.envelopeHash,
                        publicationIdentifier: manifest.publicationIdentifier,
                    }),
                    operationDomain: recipientVssPlaintextChunkOperationDomain,
                    protection: configuration.protection,
                    store: configuration.store,
                });
                if (opened === undefined) {
                    throw new AuthenticatedMailboxStorageError(
                        'AuthenticationFailed',
                        'A retained recipient VSS plaintext chunk is missing.',
                    );
                }
                try {
                    const expectedByteLength = expectedChunkByteLength(
                        manifest.plaintextByteLength,
                        chunkCount,
                        chunkIndex,
                    );
                    if (opened.plaintext.byteLength !== expectedByteLength) {
                        throw new AuthenticatedMailboxStorageError(
                            'AuthenticationFailed',
                            'A retained recipient VSS plaintext chunk has the wrong length.',
                        );
                    }
                    chunks.push(opened.plaintext.slice());
                } finally {
                    opened.plaintext.fill(0);
                    opened.sealedBytes.fill(0);
                }
            }
            canonicalPlaintextBytes = concatenateChunks(
                chunks,
                manifest.plaintextByteLength,
            );
            capabilityTransferred = true;
            await configuration.consumer.consumeAuthenticatedPlaintext({
                authenticatedPlaintextCapability,
                canonicalSignedEnvelopeBytes,
                canonicalPlaintextBytes,
            });
            consumedEnvelopeHashes.add(manifest.envelopeHash);
        } catch (error) {
            if (!capabilityTransferred) {
                try {
                    authenticatedPlaintextCapability.release();
                } catch (releaseError) {
                    return retireConsumer(
                        cleanupError(
                            'Recipient VSS plaintext consumption failed before its authenticated capability could be retired.',
                            [error, releaseError],
                        ),
                    );
                }
            }
            return retireConsumer(error);
        } finally {
            canonicalPlaintextBytes?.fill(0);
            for (const chunk of chunks) {
                chunk.fill(0);
            }
        }
    };

    const replaceManifest = async (
        current: OpenedStoredRecipientVssRecord<StoredRecipientVssPlaintextManifest>,
        disposition: StoredRecipientVssPlaintextManifest['disposition'],
    ): Promise<
        OpenedStoredRecipientVssRecord<StoredRecipientVssPlaintextManifest>
    > => {
        const replacement: StoredRecipientVssPlaintextManifest = Object.freeze({
            ...current.record,
            disposition,
        });
        const plaintext = encodeRecipientVssPlaintextManifest(replacement);
        try {
            const sealedBytes = await writeRecord({
                expectedCurrentSealedBytes: current.sealedBytes,
                logicalRecordKey: recipientVssPlaintextManifestKey(
                    current.record.envelopeHash,
                ),
                operationDomain: recipientVssPlaintextManifestOperationDomain,
                plaintext,
            });
            return Object.freeze({ record: replacement, sealedBytes });
        } finally {
            plaintext.fill(0);
        }
    };

    const makeLease = (input: {
        authenticationRequirement: AuthenticatedMailboxPlaintextSinkLease['authenticationRequirement'];
        canonicalSignedEnvelopeBytes: Uint8Array;
        disposition: AuthenticatedMailboxPlaintextSinkLease['disposition'];
        envelopeHash: ProtocolHash;
        manifest?: OpenedStoredRecipientVssRecord<StoredRecipientVssPlaintextManifest>;
        plaintextByteLength: number;
        publicationIdentifier: string;
    }): AuthenticatedMailboxPlaintextSinkLease => {
        const chunkCount = streamChunkCount(input.plaintextByteLength, limits);
        const canonicalSignedEnvelopeBytes =
            input.canonicalSignedEnvelopeBytes.slice();
        let currentManifest = input.manifest;
        let authenticatedPlaintextCapability:
            | AuthenticatedMailboxPlaintextCapability
            | undefined;
        let stagedChunkCount = 0;
        let state: 'active' | 'busy' | 'closed' | 'failed' = 'active';

        const releaseActiveEnvelope = (): void => {
            activeEnvelopeHashes.delete(input.envelopeHash);
        };
        const assertActive = (): void => {
            if (state !== 'active') {
                throw new AuthenticatedMailboxStorageError(
                    'InvalidState',
                    'The recipient VSS plaintext lease is not active.',
                );
            }
        };
        const finish = (): void => {
            state = 'closed';
            canonicalSignedEnvelopeBytes.fill(0);
            currentManifest?.sealedBytes.fill(0);
            currentManifest = undefined;
            releaseActiveEnvelope();
        };
        const fail = (): void => {
            state = 'failed';
            canonicalSignedEnvelopeBytes.fill(0);
            currentManifest?.sealedBytes.fill(0);
            currentManifest = undefined;
            releaseActiveEnvelope();
        };

        return Object.freeze({
            authenticationRequirement: input.authenticationRequirement,
            disposition: input.disposition,
            cancel: async () => {
                if (state === 'closed') {
                    return;
                }
                if (state === 'failed') {
                    if (input.disposition !== 'fresh') {
                        state = 'closed';
                        return;
                    }
                    state = 'busy';
                    try {
                        await cleanupJournal(
                            Object.freeze({
                                envelopeHash: input.envelopeHash,
                                plaintextByteLength: input.plaintextByteLength,
                                producerSlot: expectedProducerSlot,
                                publicationIdentifier:
                                    input.publicationIdentifier,
                                recordVersion:
                                    recipientVssPlaintextRecordVersion,
                                setupMailboxSlotHash:
                                    expectedSetupMailboxSlotHash,
                            }),
                        );
                        await deleteRecord(
                            recipientVssPlaintextManifestKey(
                                input.envelopeHash,
                            ),
                        );
                        finish();
                    } catch (error) {
                        fail();
                        throw asStorageError(error);
                    }
                    return;
                }
                assertActive();
                if (input.disposition !== 'fresh') {
                    const capability = authenticatedPlaintextCapability;
                    authenticatedPlaintextCapability = undefined;
                    try {
                        capability?.release();
                    } finally {
                        finish();
                    }
                    return;
                }
                state = 'busy';
                try {
                    authenticatedPlaintextCapability?.release();
                    authenticatedPlaintextCapability = undefined;
                    const cleanupRecord =
                        currentManifest?.record ??
                        Object.freeze({
                            envelopeHash: input.envelopeHash,
                            plaintextByteLength: input.plaintextByteLength,
                            producerSlot: expectedProducerSlot,
                            publicationIdentifier: input.publicationIdentifier,
                            recordVersion: recipientVssPlaintextRecordVersion,
                            setupMailboxSlotHash: expectedSetupMailboxSlotHash,
                        });
                    await cleanupJournal(cleanupRecord);
                    if (currentManifest !== undefined) {
                        await deleteRecord(
                            recipientVssPlaintextManifestKey(
                                input.envelopeHash,
                            ),
                        );
                    }
                    finish();
                } catch (error) {
                    fail();
                    throw asStorageError(error);
                }
            },
            commit: async () => {
                if (state === 'closed') {
                    return;
                }
                assertActive();
                if (input.authenticationRequirement === 'none') {
                    finish();
                    return;
                }
                if (
                    currentManifest === undefined ||
                    authenticatedPlaintextCapability === undefined
                ) {
                    throw new AuthenticatedMailboxStorageError(
                        'InvalidState',
                        'Recipient VSS plaintext cannot commit before its authenticated manifest is prepared.',
                    );
                }
                state = 'busy';
                try {
                    const capability = authenticatedPlaintextCapability;
                    authenticatedPlaintextCapability = undefined;
                    await consumeManifest(
                        currentManifest.record,
                        capability,
                        canonicalSignedEnvelopeBytes,
                    );
                    if (currentManifest.record.disposition === 'prepared') {
                        try {
                            const committedManifest = await replaceManifest(
                                currentManifest,
                                'committed',
                            );
                            currentManifest.sealedBytes.fill(0);
                            currentManifest = committedManifest;
                        } catch (error) {
                            await retireConsumer(error);
                        }
                    }
                    finish();
                } catch (error) {
                    fail();
                    throw asStorageError(error);
                }
            },
            release: () => {
                if (state === 'closed' || state === 'failed') {
                    return Promise.resolve();
                }
                assertActive();
                const capability = authenticatedPlaintextCapability;
                authenticatedPlaintextCapability = undefined;
                try {
                    capability?.release();
                } finally {
                    finish();
                }
                return Promise.resolve();
            },
            seal: async (capability) => {
                assertActive();
                if (
                    input.authenticationRequirement !== 'authenticate' ||
                    authenticatedPlaintextCapability !== undefined
                ) {
                    throw new AuthenticatedMailboxStorageError(
                        'InvalidState',
                        'Recipient VSS plaintext cannot accept another authentication capability.',
                    );
                }
                if (stagedChunkCount !== chunkCount) {
                    throw new AuthenticatedMailboxStorageError(
                        'InvalidState',
                        'Recipient VSS plaintext cannot seal before every exact chunk is staged.',
                    );
                }
                if (input.disposition !== 'fresh') {
                    authenticatedPlaintextCapability = capability;
                    return;
                }
                state = 'busy';
                const manifest: StoredRecipientVssPlaintextManifest =
                    Object.freeze({
                        disposition: 'prepared',
                        envelopeHash: input.envelopeHash,
                        plaintextByteLength: input.plaintextByteLength,
                        producerSlot: expectedProducerSlot,
                        publicationIdentifier: input.publicationIdentifier,
                        recordVersion: recipientVssPlaintextRecordVersion,
                        setupMailboxSlotHash: expectedSetupMailboxSlotHash,
                    });
                const plaintext = encodeRecipientVssPlaintextManifest(manifest);
                const transaction = await configuration.store.beginTransaction({
                    lifetimeMilliseconds:
                        limits.transactionLifetimeMilliseconds,
                });
                try {
                    const sealedBytes = await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey: recipientVssPlaintextManifestKey(
                            input.envelopeHash,
                        ),
                        operationDomain:
                            recipientVssPlaintextManifestOperationDomain,
                        plaintext,
                        protection: configuration.protection,
                        transaction,
                    });
                    await transaction.stageDeletion(
                        recipientVssPlaintextJournalKey(input.envelopeHash),
                    );
                    await transaction.commit();
                    currentManifest = Object.freeze({
                        record: manifest,
                        sealedBytes,
                    });
                    authenticatedPlaintextCapability = capability;
                    state = 'active';
                } catch (error) {
                    fail();
                    throw await closeTransactionAfterFailure(
                        transaction,
                        error,
                    );
                } finally {
                    plaintext.fill(0);
                }
            },
            stageChunk: async ({ bytes, chunkIndex }) => {
                assertActive();
                if (
                    chunkIndex !== stagedChunkCount ||
                    chunkIndex >= chunkCount
                ) {
                    throw new AuthenticatedMailboxStorageError(
                        'InvalidInput',
                        'Recipient VSS plaintext chunks must be staged once in exact order.',
                    );
                }
                const expectedByteLength = expectedChunkByteLength(
                    input.plaintextByteLength,
                    chunkCount,
                    chunkIndex,
                );
                const plaintext = requireArrayBuffer(
                    bytes,
                    expectedByteLength,
                    'Recipient VSS plaintext chunk',
                );
                if (input.disposition !== 'fresh') {
                    plaintext.fill(0);
                    stagedChunkCount += 1;
                    return;
                }
                state = 'busy';
                try {
                    const sealedBytes = await writeRecord({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey: recipientVssPlaintextChunkKey({
                            chunkIndex,
                            envelopeHash: input.envelopeHash,
                            publicationIdentifier: input.publicationIdentifier,
                        }),
                        operationDomain:
                            recipientVssPlaintextChunkOperationDomain,
                        plaintext,
                    });
                    sealedBytes.fill(0);
                    stagedChunkCount += 1;
                    state = 'active';
                } catch (error) {
                    fail();
                    throw asStorageError(error);
                } finally {
                    plaintext.fill(0);
                }
            },
        });
    };

    return Object.freeze({
        plaintextSinkBoundary: Object.freeze({
            reserve: async (
                reservation: Parameters<
                    AuthenticatedMailboxPlaintextSinkBoundary['reserve']
                >[0],
            ) => {
                const {
                    canonicalEnvelopeBytes,
                    envelopeHash: untrustedEnvelopeHash,
                    plaintextByteLength,
                    producerSlot,
                } = reservation;
                if (consumerRetired) {
                    throw new AuthenticatedMailboxStorageError(
                        'InvalidState',
                        'The recipient VSS plaintext consumer is retired.',
                    );
                }
                const envelopeHash = requireProtocolHash(
                    untrustedEnvelopeHash,
                    'envelopeHash',
                );
                if (
                    !(canonicalEnvelopeBytes instanceof Uint8Array) ||
                    canonicalEnvelopeBytes.byteLength === 0
                ) {
                    throw new AuthenticatedMailboxStorageError(
                        'InvalidInput',
                        'The recipient VSS signed mailbox envelope bytes are malformed.',
                    );
                }
                streamChunkCount(plaintextByteLength, limits);
                requireMatchingReservedProducerSlot(
                    producerSlot,
                    expectedProducerSlot,
                );
                if (activeEnvelopeHashes.has(envelopeHash)) {
                    throw new AuthenticatedMailboxStorageError(
                        'Conflict',
                        'The recipient VSS plaintext envelope already has an active delivery lease.',
                    );
                }
                activeEnvelopeHashes.add(envelopeHash);
                try {
                    const manifest = await readManifest(envelopeHash);
                    if (manifest !== undefined) {
                        requireMatchingRecord({
                            envelopeHash,
                            plaintextByteLength,
                            record: manifest.record,
                        });
                        return makeLease({
                            authenticationRequirement:
                                consumedEnvelopeHashes.has(envelopeHash)
                                    ? 'none'
                                    : 'authenticate',
                            canonicalSignedEnvelopeBytes:
                                canonicalEnvelopeBytes,
                            disposition: manifest.record.disposition,
                            envelopeHash,
                            manifest,
                            plaintextByteLength,
                            publicationIdentifier:
                                manifest.record.publicationIdentifier,
                        });
                    }

                    const staleJournal = await readJournal(envelopeHash);
                    if (staleJournal !== undefined) {
                        try {
                            requireMatchingRecord({
                                envelopeHash,
                                plaintextByteLength,
                                record: staleJournal.record,
                            });
                            await cleanupJournal(staleJournal.record);
                        } finally {
                            staleJournal.sealedBytes.fill(0);
                        }
                    }

                    const publicationIdentifierBytes = sampleRuntimeIdentifier(
                        configuration.protection,
                        issuedIdentifiers,
                        'recipient VSS plaintext publication identifier',
                    );
                    const publicationIdentifier = Array.from(
                        publicationIdentifierBytes,
                        (byte) => byte.toString(16).padStart(2, '0'),
                    ).join('');
                    publicationIdentifierBytes.fill(0);
                    const journal: StoredRecipientVssPlaintextJournal =
                        Object.freeze({
                            envelopeHash,
                            plaintextByteLength,
                            producerSlot: expectedProducerSlot,
                            publicationIdentifier,
                            recordVersion: recipientVssPlaintextRecordVersion,
                            setupMailboxSlotHash: expectedSetupMailboxSlotHash,
                        });
                    const plaintext =
                        encodeRecipientVssPlaintextJournal(journal);
                    try {
                        const sealedBytes = await writeRecord({
                            expectedCurrentSealedBytes: null,
                            logicalRecordKey:
                                recipientVssPlaintextJournalKey(envelopeHash),
                            operationDomain:
                                recipientVssPlaintextJournalOperationDomain,
                            plaintext,
                        });
                        sealedBytes.fill(0);
                    } finally {
                        plaintext.fill(0);
                    }
                    return makeLease({
                        authenticationRequirement: 'authenticate',
                        canonicalSignedEnvelopeBytes: canonicalEnvelopeBytes,
                        disposition: 'fresh',
                        envelopeHash,
                        plaintextByteLength,
                        publicationIdentifier,
                    });
                } catch (error) {
                    activeEnvelopeHashes.delete(envelopeHash);
                    throw asStorageError(error);
                }
            },
        }),
    });
};

export const createRecipientVssAuthenticatedMailboxPlaintextSink = (
    configuration: RecipientVssAuthenticatedMailboxPlaintextSinkConfiguration,
): RecipientVssAuthenticatedMailboxPlaintextSink => {
    const { authority, ...storageConfiguration } = configuration;
    return createRecipientVssAuthenticatedMailboxPlaintextSinkWithConsumer({
        ...storageConfiguration,
        consumer:
            resolveAggregateThresholdShareAuthenticatedRecipientConsumer(
                authority,
            ),
    });
};
