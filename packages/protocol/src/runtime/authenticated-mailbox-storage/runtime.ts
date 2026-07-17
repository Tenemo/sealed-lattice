import type {
    AuthenticatedMailboxCarrier,
    AuthenticatedMailboxInboundSlotAuthority,
    AuthenticatedMailboxOutboundCache,
    AuthenticatedMailboxStagingBoundary,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    bytesEqual,
    bytesToHex,
    copyRuntimeRecordProtectionAuthorityContext,
    createRuntimeRecordProtection,
    readRuntimeRecord,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
} from '../authenticated-runtime-record.js';
import type { UntrustedStorageTransaction } from '../untrusted-storage-transaction-store.js';

import {
    AuthenticatedMailboxStorageError,
    asStorageError,
    carriersEqual,
    carrierFromManifest,
    cleanupError,
    closeTransactionAfterFailure,
    copyCarrier,
    decodeInboundSlot,
    decodeOutboundManifest,
    decodeStagingManifest,
    decodeStreamJournal,
    deriveChunkDigest,
    encodeInboundSlot,
    encodeOutboundManifest,
    encodeStagingManifest,
    encodeStreamJournal,
    expectedChunkByteLength,
    hexToBytes,
    inboundSlotKey,
    inboundSlotOperationDomain,
    normalizeProducerSlot,
    outboundChunkKey,
    outboundChunkOperationDomain,
    outboundJournalKey,
    outboundJournalOperationDomain,
    outboundManifestKey,
    outboundManifestOperationDomain,
    producerSlotFingerprint,
    producerSlotsEqual,
    recordVersion,
    requireArrayBuffer,
    requireProtocolHash,
    stagingChunkKey,
    stagingChunkOperationDomain,
    stagingJournalKey,
    stagingJournalOperationDomain,
    stagingManifestKey,
    stagingManifestOperationDomain,
    streamChunkCount,
    throwIfAborted,
    validateLimits,
    validateProducerSlotAuthority,
    type BrowserLocalAuthenticatedMailboxStorage,
    type BrowserLocalAuthenticatedMailboxStorageConfiguration,
    type OpenedStoredRecord,
    type StoredChunkDescriptor,
    type StoredInboundSlot,
    type StoredOutboundManifest,
    type StoredStagingManifest,
    type StoredStreamJournal,
} from './records.js';

export { AuthenticatedMailboxStorageError } from './records.js';
export type {
    AuthenticatedMailboxStorageErrorCode,
    AuthenticatedMailboxStorageLimits,
    BrowserLocalAuthenticatedMailboxStorage,
    BrowserLocalAuthenticatedMailboxStorageConfiguration,
} from './records.js';

export const createBrowserLocalAuthenticatedMailboxStorage = (
    configuration: BrowserLocalAuthenticatedMailboxStorageConfiguration,
): BrowserLocalAuthenticatedMailboxStorage => {
    const limits = validateLimits(configuration.limits);
    const protection = createRuntimeRecordProtection({
        authorityContext: configuration.authorityContext,
        ...(configuration.cryptoProvider === undefined
            ? {}
            : { cryptoProvider: configuration.cryptoProvider }),
        encryptionKey: configuration.encryptionKey,
        maximumRecordSealingCount: limits.maximumRecordSealingCount,
    });
    const authorityContext =
        copyRuntimeRecordProtectionAuthorityContext(protection);
    const issuedIdentifiers = new Set<string>();
    const activeOutboundSlots = new Map<string, number>();
    const activeInboundSlots = new Map<string, AuthenticatedMailboxCarrier>();
    const activeStagingEnvelopes = new Set<ProtocolHash>();

    const writeRecord = async (input: {
        expectedCurrentSealedBytes?: Uint8Array | null;
        logicalRecordKey: string;
        operationDomain: string;
        plaintext: Uint8Array;
    }): Promise<void> => {
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                ...(input.expectedCurrentSealedBytes === undefined
                    ? {}
                    : {
                          expectedCurrentSealedBytes:
                              input.expectedCurrentSealedBytes,
                      }),
                logicalRecordKey: input.logicalRecordKey,
                operationDomain: input.operationDomain,
                plaintext: input.plaintext,
                protection,
                transaction,
            });
            await transaction.commit();
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

    const readDecodedRecord = async <RecordValue>(input: {
        decode: (plaintext: Uint8Array) => RecordValue;
        logicalRecordKey: string;
        operationDomain: string;
    }): Promise<OpenedStoredRecord<RecordValue> | undefined> => {
        const opened = await readRuntimeRecord({
            logicalRecordKey: input.logicalRecordKey,
            operationDomain: input.operationDomain,
            protection,
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
                const mapped = asStorageError(error);
                if (mapped.code === 'AuthenticationFailed') {
                    throw mapped;
                }
                throw new AuthenticatedMailboxStorageError(
                    'AuthenticationFailed',
                    'An authenticated mailbox storage record has invalid contents.',
                    mapped,
                );
            }
            return {
                record,
                sealedBytes: opened.sealedBytes,
            };
        } finally {
            opened.plaintext.fill(0);
        }
    };

    const readOutboundManifest = async (
        slotFingerprint: string,
    ): Promise<OpenedStoredRecord<StoredOutboundManifest> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) => decodeOutboundManifest(plaintext, limits),
            logicalRecordKey: outboundManifestKey(slotFingerprint),
            operationDomain: outboundManifestOperationDomain,
        });

    const readOutboundJournal = async (
        slotFingerprint: string,
    ): Promise<OpenedStoredRecord<StoredStreamJournal> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) =>
                decodeStreamJournal(plaintext, 'outbound', limits),
            logicalRecordKey: outboundJournalKey(slotFingerprint),
            operationDomain: outboundJournalOperationDomain,
        });

    const readStagingManifest = async (
        envelopeHash: ProtocolHash,
    ): Promise<OpenedStoredRecord<StoredStagingManifest> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) => decodeStagingManifest(plaintext, limits),
            logicalRecordKey: stagingManifestKey(envelopeHash),
            operationDomain: stagingManifestOperationDomain,
        });

    const readStagingJournal = async (
        envelopeHash: ProtocolHash,
    ): Promise<OpenedStoredRecord<StoredStreamJournal> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) =>
                decodeStreamJournal(plaintext, 'staging', limits),
            logicalRecordKey: stagingJournalKey(envelopeHash),
            operationDomain: stagingJournalOperationDomain,
        });

    const cleanupStreamChunks = async (input: {
        chunkKey: (chunkIndex: number) => string;
        chunkCount: number;
        journalKey: string;
    }): Promise<void> => {
        const failures: unknown[] = [];
        for (
            let chunkIndex = 0;
            chunkIndex < input.chunkCount;
            chunkIndex += 1
        ) {
            try {
                await deleteRecord(input.chunkKey(chunkIndex));
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length === 0) {
            try {
                await deleteRecord(input.journalKey);
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length > 0) {
            throw cleanupError(
                'Authenticated mailbox stream cleanup did not remove every lease-owned record.',
                failures,
            );
        }
    };

    const cleanupOutboundJournal = async (
        slotFingerprint: string,
        journal: StoredStreamJournal,
    ): Promise<void> => {
        if (journal.producerSlot === undefined) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'Outbound mailbox journal omitted its producer slot.',
            );
        }
        await cleanupStreamChunks({
            chunkCount: streamChunkCount(journal.totalByteLength, limits),
            chunkKey: (chunkIndex) =>
                outboundChunkKey({
                    chunkIndex,
                    publicationIdentifier: journal.publicationIdentifier,
                    slotFingerprint,
                }),
            journalKey: outboundJournalKey(slotFingerprint),
        });
    };

    const readChunk = async (input: {
        descriptor: StoredChunkDescriptor;
        expectedByteLength: number;
        logicalRecordKey: string;
        operationDomain: string;
    }): Promise<ArrayBuffer> => {
        const opened = await readRuntimeRecord({
            logicalRecordKey: input.logicalRecordKey,
            operationDomain: input.operationDomain,
            protection,
            store: configuration.store,
        });
        if (opened === undefined) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'An authenticated mailbox chunk is missing.',
            );
        }
        try {
            if (
                opened.plaintext.byteLength !== input.expectedByteLength ||
                deriveChunkDigest(opened.plaintext) !== input.descriptor.digest
            ) {
                throw new AuthenticatedMailboxStorageError(
                    'AuthenticationFailed',
                    'An authenticated mailbox chunk does not match its published descriptor.',
                );
            }
            const result = new Uint8Array(
                new ArrayBuffer(opened.plaintext.byteLength),
            );
            result.set(opened.plaintext);

            return result.buffer;
        } finally {
            opened.plaintext.fill(0);
        }
    };

    const outboundCache: AuthenticatedMailboxOutboundCache = Object.freeze({
        reserve: async ({
            plaintextByteLength,
            producerSlot: untrustedProducerSlot,
        }) => {
            try {
                const chunkCount = streamChunkCount(
                    plaintextByteLength,
                    limits,
                );
                const producerSlot = normalizeProducerSlot(
                    untrustedProducerSlot,
                );
                validateProducerSlotAuthority({
                    authorityContext,
                    direction: 'outbound',
                    producerSlot,
                });
                const slotFingerprint = producerSlotFingerprint(producerSlot);
                const activeReservation =
                    activeOutboundSlots.get(slotFingerprint);
                if (activeReservation !== undefined) {
                    const declarationsMatch =
                        activeReservation === plaintextByteLength;
                    throw new AuthenticatedMailboxStorageError(
                        declarationsMatch ? 'Conflict' : 'Equivocation',
                        declarationsMatch
                            ? 'The outbound mailbox producer slot already has an active reservation.'
                            : 'The outbound mailbox producer slot was reused with conflicting stream declarations.',
                    );
                }

                const existingManifest =
                    await readOutboundManifest(slotFingerprint);
                const existingJournal =
                    await readOutboundJournal(slotFingerprint);
                if (existingManifest !== undefined) {
                    if (
                        !producerSlotsEqual(
                            existingManifest.record.producerSlot,
                            producerSlot,
                        )
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'AuthenticationFailed',
                            'Outbound mailbox slot fingerprint resolves to a different authenticated producer slot.',
                        );
                    }
                    if (
                        existingManifest.record.plaintextByteLength !==
                            plaintextByteLength ||
                        existingManifest.record.chunkDescriptors.length !==
                            chunkCount
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'Equivocation',
                            'The outbound mailbox producer slot already contains conflicting stream declarations.',
                        );
                    }
                    if (existingJournal !== undefined) {
                        if (
                            existingJournal.record.publicationIdentifier ===
                            existingManifest.record.publicationIdentifier
                        ) {
                            await deleteRecord(
                                outboundJournalKey(slotFingerprint),
                            );
                        } else {
                            await cleanupOutboundJournal(
                                slotFingerprint,
                                existingJournal.record,
                            );
                        }
                    }
                    const manifest = existingManifest.record;
                    const carrier = carrierFromManifest(manifest);

                    return Object.freeze({
                        disposition: 'cached' as const,
                        cachedCarrier: () =>
                            Promise.resolve(
                                Object.freeze({
                                    canonicalEnvelopeBytes:
                                        carrier.canonicalEnvelopeBytes.slice(),
                                }),
                            ),
                        stageChunk: () =>
                            Promise.reject(
                                new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'A cached outbound mailbox lease cannot stage chunks.',
                                ),
                            ),
                        commit: () =>
                            Promise.reject(
                                new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'A cached outbound mailbox lease is already committed.',
                                ),
                            ),
                        pullChunk: async ({
                            abortSignal,
                            chunkIndex,
                            expectedByteLength,
                        }) => {
                            throwIfAborted(abortSignal);
                            if (
                                chunkIndex === manifest.chunkDescriptors.length
                            ) {
                                if (expectedByteLength !== 0) {
                                    throw new AuthenticatedMailboxStorageError(
                                        'InvalidInput',
                                        'Trailing mailbox chunk probe must request zero bytes.',
                                    );
                                }
                                return undefined;
                            }
                            const descriptor =
                                manifest.chunkDescriptors[chunkIndex];
                            const descriptorByteLength =
                                expectedChunkByteLength(
                                    manifest.plaintextByteLength,
                                    manifest.chunkDescriptors.length,
                                    chunkIndex,
                                );
                            if (
                                descriptor === undefined ||
                                !Number.isSafeInteger(chunkIndex) ||
                                chunkIndex < 0 ||
                                expectedByteLength !== descriptorByteLength
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidInput',
                                    'Outbound mailbox chunk pull does not match the published descriptor.',
                                );
                            }

                            return readChunk({
                                descriptor,
                                expectedByteLength: descriptorByteLength,
                                logicalRecordKey: outboundChunkKey({
                                    chunkIndex,
                                    publicationIdentifier:
                                        manifest.publicationIdentifier,
                                    slotFingerprint,
                                }),
                                operationDomain: outboundChunkOperationDomain,
                            });
                        },
                        cancel: () => Promise.resolve(),
                    });
                }
                if (existingJournal !== undefined) {
                    if (
                        existingJournal.record.producerSlot === undefined ||
                        !producerSlotsEqual(
                            existingJournal.record.producerSlot,
                            producerSlot,
                        )
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'AuthenticationFailed',
                            'Outbound mailbox journal belongs to a different producer slot.',
                        );
                    }
                    await cleanupOutboundJournal(
                        slotFingerprint,
                        existingJournal.record,
                    );
                }

                const publicationIdentifier = bytesToHex(
                    sampleRuntimeIdentifier(
                        protection,
                        issuedIdentifiers,
                        'outbound mailbox publication identifier',
                    ),
                );
                const journal: StoredStreamJournal = Object.freeze({
                    producerSlot,
                    publicationIdentifier,
                    recordVersion,
                    totalByteLength: plaintextByteLength,
                });
                const journalPlaintext = encodeStreamJournal(journal);
                try {
                    await writeRecord({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey: outboundJournalKey(slotFingerprint),
                        operationDomain: outboundJournalOperationDomain,
                        plaintext: journalPlaintext,
                    });
                } finally {
                    journalPlaintext.fill(0);
                }
                activeOutboundSlots.set(slotFingerprint, plaintextByteLength);

                const chunkDescriptors: StoredChunkDescriptor[] = [];
                let state:
                    | 'active'
                    | 'cancelled'
                    | 'committing'
                    | 'committed'
                    | 'failed' = 'active';
                let published = false;
                let committedManifest: StoredOutboundManifest | undefined;

                const releaseReservation = (): void => {
                    activeOutboundSlots.delete(slotFingerprint);
                };

                const pullPublishedChunk = async (input: {
                    abortSignal?: AbortSignal;
                    chunkIndex: number;
                    expectedByteLength: number;
                }): Promise<ArrayBuffer | undefined> => {
                    throwIfAborted(input.abortSignal);
                    if (
                        state !== 'committed' ||
                        committedManifest === undefined
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'InvalidState',
                            'Outbound mailbox chunks are unreadable before manifest publication.',
                        );
                    }
                    if (
                        input.chunkIndex ===
                        committedManifest.chunkDescriptors.length
                    ) {
                        if (input.expectedByteLength !== 0) {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidInput',
                                'Trailing mailbox chunk probe must request zero bytes.',
                            );
                        }
                        return undefined;
                    }
                    const descriptor =
                        committedManifest.chunkDescriptors[input.chunkIndex];
                    const descriptorByteLength = expectedChunkByteLength(
                        committedManifest.plaintextByteLength,
                        committedManifest.chunkDescriptors.length,
                        input.chunkIndex,
                    );
                    if (
                        descriptor === undefined ||
                        !Number.isSafeInteger(input.chunkIndex) ||
                        input.chunkIndex < 0 ||
                        input.expectedByteLength !== descriptorByteLength
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'InvalidInput',
                            'Outbound mailbox chunk pull does not match the published descriptor.',
                        );
                    }

                    return readChunk({
                        descriptor,
                        expectedByteLength: descriptorByteLength,
                        logicalRecordKey: outboundChunkKey({
                            chunkIndex: input.chunkIndex,
                            publicationIdentifier,
                            slotFingerprint,
                        }),
                        operationDomain: outboundChunkOperationDomain,
                    });
                };

                return Object.freeze({
                    disposition: 'fresh' as const,
                    cachedCarrier: () => {
                        if (
                            state !== 'committed' ||
                            committedManifest === undefined
                        ) {
                            return Promise.reject(
                                new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Fresh outbound mailbox carrier is unavailable before commit.',
                                ),
                            );
                        }

                        return Promise.resolve(
                            carrierFromManifest(committedManifest),
                        );
                    },
                    stageChunk: async ({ bytes, chunkIndex }) => {
                        if (state !== 'active') {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease is not accepting chunks.',
                            );
                        }
                        if (
                            !Number.isSafeInteger(chunkIndex) ||
                            chunkIndex !== chunkDescriptors.length ||
                            chunkIndex >= chunkCount
                        ) {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidInput',
                                'Outbound mailbox chunks must be staged once in exact order.',
                            );
                        }
                        const expectedByteLength = expectedChunkByteLength(
                            plaintextByteLength,
                            chunkCount,
                            chunkIndex,
                        );
                        const chunk = requireArrayBuffer(
                            bytes,
                            expectedByteLength,
                            'outbound mailbox chunk',
                        );
                        const descriptor = Object.freeze({
                            digest: deriveChunkDigest(chunk),
                        });
                        try {
                            await writeRecord({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey: outboundChunkKey({
                                    chunkIndex,
                                    publicationIdentifier,
                                    slotFingerprint,
                                }),
                                operationDomain: outboundChunkOperationDomain,
                                plaintext: chunk,
                            });
                            chunkDescriptors.push(descriptor);
                        } catch (error) {
                            state = 'failed';
                            throw asStorageError(error);
                        } finally {
                            chunk.fill(0);
                        }
                    },
                    commit: async (untrustedCarrier) => {
                        if (state !== 'active') {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease cannot commit from its current state.',
                            );
                        }
                        if (chunkDescriptors.length !== chunkCount) {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease cannot commit before every exact chunk is staged.',
                            );
                        }
                        const carrier = copyCarrier(untrustedCarrier, limits);
                        state = 'committing';
                        const manifest: StoredOutboundManifest = Object.freeze({
                            canonicalEnvelopeHex: bytesToHex(
                                carrier.canonicalEnvelopeBytes,
                            ),
                            chunkDescriptors: Object.freeze([
                                ...chunkDescriptors,
                            ]),
                            plaintextByteLength,
                            producerSlot,
                            publicationIdentifier,
                            recordVersion,
                        });
                        const manifestPlaintext =
                            encodeOutboundManifest(manifest);
                        let transaction:
                            | UntrustedStorageTransaction
                            | undefined;
                        let operationFailure: unknown;
                        try {
                            transaction =
                                await configuration.store.beginTransaction({
                                    lifetimeMilliseconds:
                                        limits.transactionLifetimeMilliseconds,
                                });
                            const currentJournal =
                                await readOutboundJournal(slotFingerprint);
                            if (
                                currentJournal === undefined ||
                                currentJournal.record.publicationIdentifier !==
                                    publicationIdentifier
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'Conflict',
                                    'Outbound mailbox journal changed before manifest publication.',
                                );
                            }
                            await stageRuntimeRecordWrite({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey:
                                    outboundManifestKey(slotFingerprint),
                                operationDomain:
                                    outboundManifestOperationDomain,
                                plaintext: manifestPlaintext,
                                protection,
                                transaction,
                            });
                            await transaction.stageDeletion(
                                outboundJournalKey(slotFingerprint),
                                currentJournal.sealedBytes,
                            );
                            await transaction.commit();
                            published = true;
                        } catch (error) {
                            operationFailure =
                                transaction === undefined
                                    ? asStorageError(error)
                                    : await closeTransactionAfterFailure(
                                          transaction,
                                          error,
                                      );
                            try {
                                const observedManifest =
                                    await readOutboundManifest(slotFingerprint);
                                if (
                                    observedManifest !== undefined &&
                                    bytesEqual(
                                        encodeOutboundManifest(
                                            observedManifest.record,
                                        ),
                                        encodeOutboundManifest(manifest),
                                    )
                                ) {
                                    published = true;
                                }
                            } catch (observationFailure) {
                                state = 'failed';
                                throw cleanupError(
                                    'Outbound mailbox publication failed and its committed state could not be confirmed.',
                                    [operationFailure, observationFailure],
                                );
                            }
                        } finally {
                            manifestPlaintext.fill(0);
                            carrier.canonicalEnvelopeBytes.fill(0);
                        }
                        try {
                            if (published) {
                                const reread =
                                    await readOutboundManifest(slotFingerprint);
                                if (
                                    reread === undefined ||
                                    !producerSlotsEqual(
                                        reread.record.producerSlot,
                                        producerSlot,
                                    ) ||
                                    reread.record.publicationIdentifier !==
                                        publicationIdentifier
                                ) {
                                    state = 'failed';
                                    releaseReservation();
                                    throw new AuthenticatedMailboxStorageError(
                                        'AuthenticationFailed',
                                        'Published outbound mailbox manifest failed its authenticated reread.',
                                    );
                                }
                                committedManifest = reread.record;
                                state = 'committed';
                                releaseReservation();
                            } else {
                                state = 'failed';
                            }
                            if (operationFailure !== undefined) {
                                throw asStorageError(operationFailure);
                            }
                        } catch (error) {
                            if (state === 'committing') {
                                state = 'failed';
                            }
                            throw asStorageError(error);
                        }
                    },
                    pullChunk: pullPublishedChunk,
                    cancel: async () => {
                        if (state === 'cancelled' || state === 'committed') {
                            return;
                        }
                        if (state === 'committing') {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease cannot cancel during manifest publication.',
                            );
                        }
                        if (published) {
                            state = 'committed';
                            releaseReservation();
                            return;
                        }
                        try {
                            await cleanupOutboundJournal(
                                slotFingerprint,
                                journal,
                            );
                            state = 'cancelled';
                            releaseReservation();
                        } catch (error) {
                            state = 'failed';
                            releaseReservation();
                            throw asStorageError(error);
                        }
                    },
                });
            } catch (error) {
                throw asStorageError(error);
            }
        },
    });

    const inboundSlotAuthority: AuthenticatedMailboxInboundSlotAuthority =
        Object.freeze({
            reserve: async ({
                canonicalEnvelopeBytes: untrustedCanonicalEnvelopeBytes,
                producerSlot: untrustedProducerSlot,
            }) => {
                try {
                    const producerSlot = normalizeProducerSlot(
                        untrustedProducerSlot,
                    );
                    validateProducerSlotAuthority({
                        authorityContext,
                        direction: 'inbound',
                        producerSlot,
                    });
                    const carrier = copyCarrier(
                        {
                            canonicalEnvelopeBytes:
                                untrustedCanonicalEnvelopeBytes,
                        },
                        limits,
                    );
                    const slotFingerprint =
                        producerSlotFingerprint(producerSlot);
                    const activeReservation =
                        activeInboundSlots.get(slotFingerprint);
                    if (activeReservation !== undefined) {
                        const identical = carriersEqual(
                            activeReservation,
                            carrier,
                        );
                        carrier.canonicalEnvelopeBytes.fill(0);

                        return identical
                            ? {
                                  isValid: false as const,
                                  refusalReason: 'consumedState' as const,
                              }
                            : {
                                  isValid: false as const,
                                  refusalReason: 'equivocation' as const,
                              };
                    }
                    const logicalRecordKey = inboundSlotKey(slotFingerprint);
                    const opened = await readDecodedRecord({
                        decode: (plaintext) =>
                            decodeInboundSlot(plaintext, limits),
                        logicalRecordKey,
                        operationDomain: inboundSlotOperationDomain,
                    });
                    if (opened !== undefined) {
                        if (
                            !producerSlotsEqual(
                                opened.record.producerSlot,
                                producerSlot,
                            )
                        ) {
                            carrier.canonicalEnvelopeBytes.fill(0);
                            throw new AuthenticatedMailboxStorageError(
                                'AuthenticationFailed',
                                'Inbound mailbox slot fingerprint resolves to a different authenticated producer slot.',
                            );
                        }
                        const storedCarrier = Object.freeze({
                            canonicalEnvelopeBytes: hexToBytes(
                                opened.record.canonicalEnvelopeHex,
                            ),
                        });
                        const identical = carriersEqual(storedCarrier, carrier);
                        storedCarrier.canonicalEnvelopeBytes.fill(0);
                        carrier.canonicalEnvelopeBytes.fill(0);
                        if (!identical) {
                            return {
                                isValid: false,
                                refusalReason: 'equivocation',
                            };
                        }

                        return {
                            isValid: true,
                            value: Object.freeze({
                                disposition:
                                    'byteIdenticalRetransmission' as const,
                                cancel: () => Promise.resolve(),
                                commit: () => Promise.resolve(),
                            }),
                        };
                    }

                    activeInboundSlots.set(
                        slotFingerprint,
                        Object.freeze({
                            canonicalEnvelopeBytes:
                                carrier.canonicalEnvelopeBytes.slice(),
                        }),
                    );
                    let state:
                        | 'active'
                        | 'cancelled'
                        | 'committed'
                        | 'committing'
                        | 'failed' = 'active';
                    const releaseReservation = (): void => {
                        const active = activeInboundSlots.get(slotFingerprint);
                        active?.canonicalEnvelopeBytes.fill(0);
                        activeInboundSlots.delete(slotFingerprint);
                    };

                    return {
                        isValid: true,
                        value: Object.freeze({
                            disposition: 'fresh' as const,
                            cancel: () => {
                                if (state === 'committing') {
                                    return Promise.reject(
                                        new AuthenticatedMailboxStorageError(
                                            'InvalidState',
                                            'Inbound mailbox slot cannot cancel during commit.',
                                        ),
                                    );
                                }
                                if (state === 'active') {
                                    state = 'cancelled';
                                    releaseReservation();
                                }
                                carrier.canonicalEnvelopeBytes.fill(0);
                                return Promise.resolve();
                            },
                            commit: async () => {
                                if (state !== 'active') {
                                    throw new AuthenticatedMailboxStorageError(
                                        'InvalidState',
                                        'Inbound mailbox slot cannot commit from its current state.',
                                    );
                                }
                                state = 'committing';
                                const storedSlot: StoredInboundSlot =
                                    Object.freeze({
                                        canonicalEnvelopeHex: bytesToHex(
                                            carrier.canonicalEnvelopeBytes,
                                        ),
                                        producerSlot,
                                        recordVersion,
                                    });
                                const plaintext = encodeInboundSlot(storedSlot);
                                let operationFailure: unknown;
                                try {
                                    try {
                                        await writeRecord({
                                            expectedCurrentSealedBytes: null,
                                            logicalRecordKey,
                                            operationDomain:
                                                inboundSlotOperationDomain,
                                            plaintext,
                                        });
                                    } catch (error) {
                                        operationFailure = error;
                                        const observed =
                                            await readDecodedRecord({
                                                decode: (bytes) =>
                                                    decodeInboundSlot(
                                                        bytes,
                                                        limits,
                                                    ),
                                                logicalRecordKey,
                                                operationDomain:
                                                    inboundSlotOperationDomain,
                                            });
                                        state =
                                            observed !== undefined &&
                                            observed.record
                                                .canonicalEnvelopeHex ===
                                                storedSlot.canonicalEnvelopeHex &&
                                            producerSlotsEqual(
                                                observed.record.producerSlot,
                                                producerSlot,
                                            )
                                                ? 'committed'
                                                : 'failed';
                                    }
                                    if (operationFailure === undefined) {
                                        const reread = await readDecodedRecord({
                                            decode: (bytes) =>
                                                decodeInboundSlot(
                                                    bytes,
                                                    limits,
                                                ),
                                            logicalRecordKey,
                                            operationDomain:
                                                inboundSlotOperationDomain,
                                        });
                                        if (
                                            reread === undefined ||
                                            reread.record
                                                .canonicalEnvelopeHex !==
                                                storedSlot.canonicalEnvelopeHex
                                        ) {
                                            state = 'failed';
                                            throw new AuthenticatedMailboxStorageError(
                                                'AuthenticationFailed',
                                                'Committed inbound mailbox slot failed its authenticated reread.',
                                            );
                                        }
                                        state = 'committed';
                                    }
                                    if (operationFailure !== undefined) {
                                        throw asStorageError(operationFailure);
                                    }
                                } catch (error) {
                                    if (state === 'committing') {
                                        state = 'failed';
                                    }
                                    throw asStorageError(error);
                                } finally {
                                    plaintext.fill(0);
                                    carrier.canonicalEnvelopeBytes.fill(0);
                                    releaseReservation();
                                }
                            },
                        }),
                    };
                } catch (error) {
                    throw asStorageError(error);
                }
            },
        });

    const convertStagingManifestToJournal = async (input: {
        envelopeHash: ProtocolHash;
        manifest: OpenedStoredRecord<StoredStagingManifest>;
    }): Promise<StoredStreamJournal> => {
        const journal: StoredStreamJournal = Object.freeze({
            envelopeHash: input.envelopeHash,
            publicationIdentifier: input.manifest.record.publicationIdentifier,
            recordVersion,
            totalByteLength: input.manifest.record.totalByteLength,
        });
        const journalPlaintext = encodeStreamJournal(journal);
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: null,
                logicalRecordKey: stagingJournalKey(input.envelopeHash),
                operationDomain: stagingJournalOperationDomain,
                plaintext: journalPlaintext,
                protection,
                transaction,
            });
            await transaction.stageDeletion(
                stagingManifestKey(input.envelopeHash),
                input.manifest.sealedBytes,
            );
            await transaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        } finally {
            journalPlaintext.fill(0);
        }

        return journal;
    };

    const cleanupStagingJournal = async (
        envelopeHash: ProtocolHash,
        journal: StoredStreamJournal,
    ): Promise<void> => {
        if (journal.envelopeHash !== envelopeHash) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'Mailbox staging journal belongs to a different envelope.',
            );
        }
        await cleanupStreamChunks({
            chunkCount: streamChunkCount(journal.totalByteLength, limits),
            chunkKey: (chunkIndex) =>
                stagingChunkKey({
                    chunkIndex,
                    envelopeHash,
                    publicationIdentifier: journal.publicationIdentifier,
                }),
            journalKey: stagingJournalKey(envelopeHash),
        });
    };

    const stagingBoundary: AuthenticatedMailboxStagingBoundary = Object.freeze({
        open: ({ envelopeHash: untrustedEnvelopeHash, totalByteLength }) => {
            try {
                const envelopeHash = requireProtocolHash(
                    untrustedEnvelopeHash,
                    'envelopeHash',
                );
                const chunkCount = streamChunkCount(totalByteLength, limits);
                if (activeStagingEnvelopes.has(envelopeHash)) {
                    throw new AuthenticatedMailboxStorageError(
                        'Conflict',
                        'The mailbox envelope already has an active staging lease.',
                    );
                }
                const publicationIdentifier = bytesToHex(
                    sampleRuntimeIdentifier(
                        protection,
                        issuedIdentifiers,
                        'mailbox staging publication identifier',
                    ),
                );
                activeStagingEnvelopes.add(envelopeHash);
                const journal: StoredStreamJournal = Object.freeze({
                    envelopeHash,
                    publicationIdentifier,
                    recordVersion,
                    totalByteLength,
                });
                const chunkDescriptors: StoredChunkDescriptor[] = [];
                let state:
                    | 'active'
                    | 'busy'
                    | 'disposed'
                    | 'failed'
                    | 'sealed' = 'active';
                let prepared = false;
                let preparePromise: Promise<void> | undefined;

                const releaseLease = (): void => {
                    activeStagingEnvelopes.delete(envelopeHash);
                };

                const prepare = (): Promise<void> => {
                    preparePromise ??= (async () => {
                        const staleManifest =
                            await readStagingManifest(envelopeHash);
                        const staleJournal =
                            await readStagingJournal(envelopeHash);
                        if (staleManifest !== undefined) {
                            if (
                                staleManifest.record.envelopeHash !==
                                envelopeHash
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'AuthenticationFailed',
                                    'Stored mailbox staging manifest belongs to another envelope.',
                                );
                            }
                            if (staleJournal !== undefined) {
                                await cleanupStagingJournal(
                                    envelopeHash,
                                    staleJournal.record,
                                );
                            }
                            const cleanupJournal =
                                await convertStagingManifestToJournal({
                                    envelopeHash,
                                    manifest: staleManifest,
                                });
                            await cleanupStagingJournal(
                                envelopeHash,
                                cleanupJournal,
                            );
                        } else if (staleJournal !== undefined) {
                            await cleanupStagingJournal(
                                envelopeHash,
                                staleJournal.record,
                            );
                        }
                        const journalPlaintext = encodeStreamJournal(journal);
                        try {
                            await writeRecord({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey:
                                    stagingJournalKey(envelopeHash),
                                operationDomain: stagingJournalOperationDomain,
                                plaintext: journalPlaintext,
                            });
                            prepared = true;
                        } finally {
                            journalPlaintext.fill(0);
                        }
                    })();

                    return preparePromise;
                };

                const disposePreparedRecords = async (): Promise<void> => {
                    const manifest = await readStagingManifest(envelopeHash);
                    let cleanupJournal = await readStagingJournal(envelopeHash);
                    if (manifest !== undefined) {
                        if (cleanupJournal !== undefined) {
                            await cleanupStagingJournal(
                                envelopeHash,
                                cleanupJournal.record,
                            );
                        }
                        const converted = await convertStagingManifestToJournal(
                            {
                                envelopeHash,
                                manifest,
                            },
                        );
                        cleanupJournal = {
                            record: converted,
                            sealedBytes: new Uint8Array(),
                        };
                    }
                    if (cleanupJournal !== undefined) {
                        await cleanupStagingJournal(
                            envelopeHash,
                            cleanupJournal.record,
                        );
                    }
                };

                return Promise.resolve(
                    Object.freeze({
                        stageChunk: async ({ bytes, chunkIndex }) => {
                            if (state !== 'active') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease is not accepting chunks.',
                                );
                            }
                            if (
                                !Number.isSafeInteger(chunkIndex) ||
                                chunkIndex !== chunkDescriptors.length ||
                                chunkIndex >= chunkCount
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidInput',
                                    'Mailbox staging chunks must be written once in exact order.',
                                );
                            }
                            const expectedByteLength = expectedChunkByteLength(
                                totalByteLength,
                                chunkCount,
                                chunkIndex,
                            );
                            const chunk = requireArrayBuffer(
                                bytes,
                                expectedByteLength,
                                'mailbox staging chunk',
                            );
                            state = 'busy';
                            try {
                                await prepare();
                                const descriptor = Object.freeze({
                                    digest: deriveChunkDigest(chunk),
                                });
                                await writeRecord({
                                    expectedCurrentSealedBytes: null,
                                    logicalRecordKey: stagingChunkKey({
                                        chunkIndex,
                                        envelopeHash,
                                        publicationIdentifier,
                                    }),
                                    operationDomain:
                                        stagingChunkOperationDomain,
                                    plaintext: chunk,
                                });
                                chunkDescriptors.push(descriptor);
                                state = 'active';
                            } catch (error) {
                                state = 'failed';
                                throw asStorageError(error);
                            } finally {
                                chunk.fill(0);
                            }
                        },
                        seal: async () => {
                            if (state !== 'active') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease cannot seal from its current state.',
                                );
                            }
                            if (chunkDescriptors.length !== chunkCount) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease cannot seal before every exact chunk is stored.',
                                );
                            }
                            state = 'busy';
                            let manifestPlaintext: Uint8Array | undefined;
                            let transaction:
                                | UntrustedStorageTransaction
                                | undefined;
                            try {
                                await prepare();
                                const manifest: StoredStagingManifest =
                                    Object.freeze({
                                        chunkDescriptors: Object.freeze([
                                            ...chunkDescriptors,
                                        ]),
                                        envelopeHash,
                                        publicationIdentifier,
                                        recordVersion,
                                        totalByteLength,
                                    });
                                manifestPlaintext =
                                    encodeStagingManifest(manifest);
                                transaction =
                                    await configuration.store.beginTransaction({
                                        lifetimeMilliseconds:
                                            limits.transactionLifetimeMilliseconds,
                                    });
                                const currentJournal =
                                    await readStagingJournal(envelopeHash);
                                if (
                                    currentJournal === undefined ||
                                    currentJournal.record
                                        .publicationIdentifier !==
                                        publicationIdentifier
                                ) {
                                    throw new AuthenticatedMailboxStorageError(
                                        'Conflict',
                                        'Mailbox staging journal changed before manifest publication.',
                                    );
                                }
                                await stageRuntimeRecordWrite({
                                    expectedCurrentSealedBytes: null,
                                    logicalRecordKey:
                                        stagingManifestKey(envelopeHash),
                                    operationDomain:
                                        stagingManifestOperationDomain,
                                    plaintext: manifestPlaintext,
                                    protection,
                                    transaction,
                                });
                                await transaction.stageDeletion(
                                    stagingJournalKey(envelopeHash),
                                    currentJournal.sealedBytes,
                                );
                                await transaction.commit();
                                state = 'sealed';
                            } catch (error) {
                                const mapped =
                                    transaction === undefined
                                        ? asStorageError(error)
                                        : await closeTransactionAfterFailure(
                                              transaction,
                                              error,
                                          );
                                try {
                                    const observed =
                                        await readStagingManifest(envelopeHash);
                                    state =
                                        observed?.record
                                            .publicationIdentifier ===
                                        publicationIdentifier
                                            ? 'sealed'
                                            : 'failed';
                                } catch (observationFailure) {
                                    state = 'failed';
                                    throw cleanupError(
                                        'Mailbox staging publication failed and its committed state could not be confirmed.',
                                        [mapped, observationFailure],
                                    );
                                }
                                throw mapped;
                            } finally {
                                manifestPlaintext?.fill(0);
                            }
                            const reread =
                                await readStagingManifest(envelopeHash);
                            if (
                                reread === undefined ||
                                reread.record.publicationIdentifier !==
                                    publicationIdentifier ||
                                reread.record.chunkDescriptors.length !==
                                    chunkCount
                            ) {
                                state = 'failed';
                                throw new AuthenticatedMailboxStorageError(
                                    'AuthenticationFailed',
                                    'Published mailbox staging manifest failed its authenticated reread.',
                                );
                            }
                        },
                        pullChunk: async ({
                            abortSignal,
                            chunkIndex,
                            expectedByteLength,
                        }) => {
                            throwIfAborted(abortSignal);
                            if (state !== 'sealed') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging chunks are unreadable before the manifest commits.',
                                );
                            }
                            if (chunkIndex === chunkCount) {
                                if (expectedByteLength !== 0) {
                                    throw new AuthenticatedMailboxStorageError(
                                        'InvalidInput',
                                        'Trailing mailbox staging probe must request zero bytes.',
                                    );
                                }
                                return undefined;
                            }
                            const descriptor = chunkDescriptors[chunkIndex];
                            const descriptorByteLength =
                                expectedChunkByteLength(
                                    totalByteLength,
                                    chunkCount,
                                    chunkIndex,
                                );
                            if (
                                descriptor === undefined ||
                                !Number.isSafeInteger(chunkIndex) ||
                                chunkIndex < 0 ||
                                expectedByteLength !== descriptorByteLength
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidInput',
                                    'Mailbox staging pull does not match its published descriptor.',
                                );
                            }
                            const manifest =
                                await readStagingManifest(envelopeHash);
                            if (
                                manifest === undefined ||
                                manifest.record.publicationIdentifier !==
                                    publicationIdentifier ||
                                manifest.record.chunkDescriptors[chunkIndex]
                                    ?.digest !== descriptor.digest
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'AuthenticationFailed',
                                    'Mailbox staging manifest changed before chunk reread.',
                                );
                            }

                            return readChunk({
                                descriptor,
                                expectedByteLength: descriptorByteLength,
                                logicalRecordKey: stagingChunkKey({
                                    chunkIndex,
                                    envelopeHash,
                                    publicationIdentifier,
                                }),
                                operationDomain: stagingChunkOperationDomain,
                            });
                        },
                        dispose: async () => {
                            if (state === 'disposed') {
                                return;
                            }
                            if (state === 'busy') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease cannot dispose during another operation.',
                                );
                            }
                            try {
                                if (
                                    prepared ||
                                    state === 'sealed' ||
                                    state === 'failed'
                                ) {
                                    await disposePreparedRecords();
                                }
                                state = 'disposed';
                                releaseLease();
                            } catch (error) {
                                state = 'failed';
                                releaseLease();
                                throw asStorageError(error);
                            }
                        },
                    }),
                );
            } catch (error) {
                return Promise.reject(asStorageError(error));
            }
        },
    });

    return Object.freeze({
        inboundSlotAuthority,
        outboundCache,
        stagingBoundary,
    });
};
