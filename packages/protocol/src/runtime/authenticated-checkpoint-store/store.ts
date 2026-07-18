import { foundationProfile } from '@sealed-lattice/types';

import {
    AuthenticatedRuntimeRecordError,
    type AuthenticatedRuntimeRecordErrorCode,
    bytesEqual,
    bytesToHex,
    copyBoundedBytes,
    copyExactBytes,
    copyRuntimeRecordProtectionAuthorityContext,
    copyRuntimeStorageAuthorityContext,
    createRuntimeRecordProtection,
    readRuntimeRecord,
    releaseRuntimeRecordProtection,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
    type RuntimeStorageAuthorityContext,
} from '../authenticated-runtime-record.js';
import {
    ExclusiveResourceLifecycle,
    type ExclusiveResourceOwnerToken,
} from '../exclusive-resource-lifecycle.js';
import type { UntrustedStorageTransactionStore } from '../untrusted-storage-transaction-store.js';

import {
    identifierByteLength,
    checkpointRecordVersion,
    checkpointManifestOperationDomain,
    checkpointJournalOperationDomain,
    checkpointChunkOperationDomain,
    checkpointOperationIdentityBrand,
    copyAndValidateBoundary,
    encodeCheckpointManifest,
    parseStreamDescriptor,
    deriveChunkDigest,
    createFullObjectDigestHasher,
    authenticateFullObjectDigest,
    expectedChunkByteLength,
    manifestRecordKey,
    journalRecordKey,
    chunkRecordKey,
    encodeCanonicalJson,
    decodeStoredManifest,
    encodeStoredManifest,
    decodeStoredJournal,
    closeTransactionAfterFailure,
    deleteAuthenticatedRecord,
    deleteJournalOwnedChunkRecord,
    asAsyncIterable,
    runCheckpointLineageExclusive,
    validateAuthenticatedCheckpointStoreLimits,
    type CheckpointBoundaryPolicy,
    type CheckpointOperationIdentity,
    type CheckpointBoundary,
    type ExpectedCheckpointBoundary,
    type AuthenticatedCheckpointStoreLimits,
    type AuthenticatedCheckpointStore,
    type TransferableAuthenticatedCheckpointStore,
    type StoredCheckpointJournal,
    type CheckpointOperationIdentityRecord,
} from './records.js';

export { describeAuthenticatedCheckpointStateStream } from './records.js';
export type {
    AuthenticatedCheckpointStore,
    AuthenticatedCheckpointStoreLimits,
    CheckpointBoundary,
    CheckpointBoundaryPolicy,
    CheckpointOperationIdentity,
    ExpectedCheckpointBoundary,
    ResumedCheckpoint,
    TransferableAuthenticatedCheckpointStore,
} from './records.js';

export const openAuthenticatedCheckpointStoreWithProtection = (input: {
    boundaryPolicy: CheckpointBoundaryPolicy;
    limits: AuthenticatedCheckpointStoreLimits;
    protection: RuntimeRecordProtection;
    store: UntrustedStorageTransactionStore;
}): TransferableAuthenticatedCheckpointStore => {
    const limits = validateAuthenticatedCheckpointStoreLimits(input.limits);
    const protection = input.protection;
    const authorityContext =
        copyRuntimeRecordProtectionAuthorityContext(protection);
    const identifierReferenceCounts = new Map<string, number>();
    const recentlyReleasedLineageIdentifierKeys: string[] = [];
    let pendingOperationIdentityCount = 0;
    let operationIdentities = new WeakMap<
        CheckpointOperationIdentity,
        CheckpointOperationIdentityRecord
    >();
    let releasedOperationIdentities =
        new WeakSet<CheckpointOperationIdentity>();
    const issuedOperationIdentityRecords =
        new Set<CheckpointOperationIdentityRecord>();

    const retainIdentifierKey = (identifierKey: string): void => {
        identifierReferenceCounts.set(
            identifierKey,
            (identifierReferenceCounts.get(identifierKey) ?? 0) + 1,
        );
    };

    const releaseIdentifierKey = (identifierKey: string): void => {
        const referenceCount = identifierReferenceCounts.get(identifierKey);
        if (referenceCount === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Checkpoint identifier ownership accounting is inconsistent.',
            );
        }
        if (referenceCount === 1) {
            identifierReferenceCounts.delete(identifierKey);
            return;
        }
        identifierReferenceCounts.set(identifierKey, referenceCount - 1);
    };

    const rememberReleasedLineageIdentifierKey = (
        identifierKey: string,
    ): void => {
        const existingIndex =
            recentlyReleasedLineageIdentifierKeys.indexOf(identifierKey);
        if (existingIndex !== -1) {
            recentlyReleasedLineageIdentifierKeys.splice(existingIndex, 1);
        }
        recentlyReleasedLineageIdentifierKeys.push(identifierKey);
        while (
            recentlyReleasedLineageIdentifierKeys.length >
            limits.maximumActiveOperationIdentityCount
        ) {
            recentlyReleasedLineageIdentifierKeys.shift();
        }
    };

    const unavailableIdentifierKeys = (): Set<string> =>
        new Set([
            ...identifierReferenceCounts.keys(),
            ...recentlyReleasedLineageIdentifierKeys,
        ]);

    const reserveOperationIdentitySlot = (): (() => void) => {
        if (
            issuedOperationIdentityRecords.size +
                pendingOperationIdentityCount >=
            limits.maximumActiveOperationIdentityCount
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                'Active checkpoint operation identities exceed the configured profile.',
            );
        }
        pendingOperationIdentityCount += 1;
        let released = false;
        return () => {
            if (released) {
                return;
            }
            released = true;
            pendingOperationIdentityCount -= 1;
        };
    };

    const destroyBoundary = (
        boundary: CheckpointBoundary | undefined,
    ): void => {
        if (boundary === undefined) {
            return;
        }
        for (const sourceDigest of boundary.orderedSourceDigests) {
            sourceDigest.fill(0);
        }
        boundary.stateStreamDescriptorBytes.fill(0);
        boundary.privateRandomCursorManifestBytes.fill(0);
        boundary.privateRandomnessStreamAttemptIdentifier?.fill(0);
    };

    const destroyOperationIdentityRecord = (
        identity: CheckpointOperationIdentity,
        identityRecord: CheckpointOperationIdentityRecord,
    ): void => {
        const lineageIdentifierKey = bytesToHex(
            identityRecord.checkpointLineageIdentifier,
        );
        const ownedIdentifierKeyCounts = new Map<string, number>();
        for (const identifierKey of [
            lineageIdentifierKey,
            identityRecord.currentPublicationIdentifierKey,
            identityRecord.pendingPublicationIdentifierKey,
        ]) {
            if (identifierKey !== undefined) {
                ownedIdentifierKeyCounts.set(
                    identifierKey,
                    (ownedIdentifierKeyCounts.get(identifierKey) ?? 0) + 1,
                );
            }
        }
        for (const [
            identifierKey,
            ownedReferenceCount,
        ] of ownedIdentifierKeyCounts) {
            if (
                (identifierReferenceCounts.get(identifierKey) ?? 0) <
                ownedReferenceCount
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Checkpoint identity ownership accounting is inconsistent.',
                );
            }
        }
        releaseIdentifierKey(lineageIdentifierKey);
        if (identityRecord.currentPublicationIdentifierKey !== undefined) {
            releaseIdentifierKey(
                identityRecord.currentPublicationIdentifierKey,
            );
            identityRecord.currentPublicationIdentifierKey = undefined;
        }
        if (identityRecord.pendingPublicationIdentifierKey !== undefined) {
            releaseIdentifierKey(
                identityRecord.pendingPublicationIdentifierKey,
            );
            identityRecord.pendingPublicationIdentifierKey = undefined;
        }
        operationIdentities.delete(identity);
        releasedOperationIdentities.add(identity);
        issuedOperationIdentityRecords.delete(identityRecord);
        rememberReleasedLineageIdentifierKey(lineageIdentifierKey);
        identityRecord.checkpointLineageIdentifier.fill(0);
        identityRecord.lastCanonicalManifestBytes?.fill(0);
        identityRecord.lastCanonicalManifestBytes = undefined;
        destroyBoundary(identityRecord.lastPublishedBoundary);
        identityRecord.lastPublishedBoundary = undefined;
        identityRecord.operationKind = undefined;
        identityRecord.orderedSourceDigestHex = undefined;
        identityRecord.stateStreamDomain = undefined;
        identityRecord.privateRandomnessStreamAttemptIdentifier?.fill(0);
        identityRecord.privateRandomnessStreamAttemptIdentifier = undefined;
    };

    const synchronizePublicationIdentifier = (
        identityRecord: CheckpointOperationIdentityRecord,
        observedPublicationIdentifierKey: string | undefined,
    ): void => {
        const pendingIdentifierKey =
            identityRecord.pendingPublicationIdentifierKey;
        const currentIdentifierKey =
            identityRecord.currentPublicationIdentifierKey;
        if (
            pendingIdentifierKey !== undefined &&
            pendingIdentifierKey === observedPublicationIdentifierKey
        ) {
            if (
                currentIdentifierKey !== undefined &&
                currentIdentifierKey !== pendingIdentifierKey
            ) {
                releaseIdentifierKey(currentIdentifierKey);
            }
            identityRecord.currentPublicationIdentifierKey =
                pendingIdentifierKey;
            identityRecord.pendingPublicationIdentifierKey = undefined;
            return;
        }
        if (pendingIdentifierKey !== undefined) {
            releaseIdentifierKey(pendingIdentifierKey);
            identityRecord.pendingPublicationIdentifierKey = undefined;
        }
        if (currentIdentifierKey === observedPublicationIdentifierKey) {
            return;
        }
        if (observedPublicationIdentifierKey !== undefined) {
            retainIdentifierKey(observedPublicationIdentifierKey);
        }
        if (currentIdentifierKey !== undefined) {
            releaseIdentifierKey(currentIdentifierKey);
        }
        identityRecord.currentPublicationIdentifierKey =
            observedPublicationIdentifierKey;
    };

    const createOperationIdentity = (
        checkpointLineageIdentifier: Uint8Array,
        privateRandomnessStreamAttemptIdentifier: Uint8Array | undefined,
        lineageIdentifierAlreadyRetained: boolean,
        resumedPublication?: Readonly<{
            boundary: CheckpointBoundary;
            canonicalManifestBytes: Uint8Array;
            publicationIdentifierKey: string;
        }>,
    ): CheckpointOperationIdentity => {
        const lineageIdentifier = checkpointLineageIdentifier.slice();
        const attemptIdentifier =
            privateRandomnessStreamAttemptIdentifier?.slice();
        const identity = Object.freeze({
            [checkpointOperationIdentityBrand]: true as const,
            get checkpointLineageIdentifier(): Uint8Array {
                return lineageIdentifier.slice();
            },
            get privateRandomnessStreamAttemptIdentifier():
                | Uint8Array
                | undefined {
                return attemptIdentifier?.slice();
            },
        });
        const identityRecord: CheckpointOperationIdentityRecord = {
            checkpointLineageIdentifier: lineageIdentifier,
            ...(resumedPublication === undefined
                ? {}
                : {
                      lastCanonicalManifestBytes:
                          resumedPublication.canonicalManifestBytes.slice(),
                      currentPublicationIdentifierKey:
                          resumedPublication.publicationIdentifierKey,
                      lastPublishedBoundary: copyAndValidateBoundary(
                          resumedPublication.boundary,
                          limits,
                      ),
                      operationKind: resumedPublication.boundary.operationKind,
                      orderedSourceDigestHex:
                          resumedPublication.boundary.orderedSourceDigests.map(
                              bytesToHex,
                          ),
                      stateStreamDomain:
                          resumedPublication.boundary.stateStreamDomain,
                  }),
            ...(attemptIdentifier === undefined
                ? {}
                : {
                      privateRandomnessStreamAttemptIdentifier:
                          attemptIdentifier,
                  }),
        };
        const lineageIdentifierKey = bytesToHex(lineageIdentifier);
        if (!lineageIdentifierAlreadyRetained) {
            retainIdentifierKey(lineageIdentifierKey);
        }
        if (resumedPublication !== undefined) {
            retainIdentifierKey(resumedPublication.publicationIdentifierKey);
        }
        operationIdentities.set(identity, identityRecord);
        issuedOperationIdentityRecords.add(identityRecord);
        return identity;
    };

    const runBoundaryPolicy = async (
        operation: 'publish' | 'resume',
        checkpointLineageIdentifier: Uint8Array,
        boundary: CheckpointBoundary | ExpectedCheckpointBoundary,
        previousBoundary?: CheckpointBoundary,
    ): Promise<void> => {
        try {
            if (operation === 'publish') {
                await input.boundaryPolicy.validatePublication({
                    boundary: copyAndValidateBoundary(
                        boundary as CheckpointBoundary,
                        limits,
                    ),
                    checkpointLineageIdentifier:
                        checkpointLineageIdentifier.slice(),
                    ...(previousBoundary === undefined
                        ? {}
                        : {
                              previousBoundary: copyAndValidateBoundary(
                                  previousBoundary,
                                  limits,
                              ),
                          }),
                });
                return;
            }
            await input.boundaryPolicy.validateResume({
                checkpointLineageIdentifier:
                    checkpointLineageIdentifier.slice(),
                expectedBoundary: copyAndValidateBoundary(boundary, limits),
            });
        } catch (error) {
            if (error instanceof AuthenticatedRuntimeRecordError) {
                throw error;
            }
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'The operation owner refused the checkpoint boundary.',
                error,
            );
        }
    };

    const requireMonotonicPublicationBoundary = (
        identityRecord: CheckpointOperationIdentityRecord,
        boundary: CheckpointBoundary,
        canonicalManifestBytes: Uint8Array,
    ): void => {
        const sourceDigestHex = boundary.orderedSourceDigests.map(bytesToHex);
        if (identityRecord.operationKind === undefined) {
            identityRecord.operationKind = boundary.operationKind;
            identityRecord.orderedSourceDigestHex = sourceDigestHex;
            identityRecord.stateStreamDomain = boundary.stateStreamDomain;
            identityRecord.privateRandomnessStreamAttemptIdentifier =
                boundary.privateRandomnessStreamAttemptIdentifier?.slice();
        } else if (
            identityRecord.operationKind !== boundary.operationKind ||
            identityRecord.stateStreamDomain !== boundary.stateStreamDomain ||
            (identityRecord.privateRandomnessStreamAttemptIdentifier ===
                undefined) !==
                (boundary.privateRandomnessStreamAttemptIdentifier ===
                    undefined) ||
            (identityRecord.privateRandomnessStreamAttemptIdentifier !==
                undefined &&
                boundary.privateRandomnessStreamAttemptIdentifier !==
                    undefined &&
                !bytesEqual(
                    identityRecord.privateRandomnessStreamAttemptIdentifier,
                    boundary.privateRandomnessStreamAttemptIdentifier,
                )) ||
            identityRecord.orderedSourceDigestHex?.length !==
                sourceDigestHex.length ||
            identityRecord.orderedSourceDigestHex.some(
                (digest, digestIndex) =>
                    digest !== sourceDigestHex[digestIndex],
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Checkpoint replacement cannot change its operation or verified source identity.',
            );
        }
        const previousBoundary = identityRecord.lastPublishedBoundary;
        if (previousBoundary === undefined) {
            return;
        }
        if (
            boundary.safeBoundaryOrdinal < previousBoundary.safeBoundaryOrdinal
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Checkpoint replacement cannot rewind its safe boundary.',
            );
        }
        if (
            boundary.safeBoundaryOrdinal ===
            previousBoundary.safeBoundaryOrdinal
        ) {
            if (
                identityRecord.lastCanonicalManifestBytes === undefined ||
                !bytesEqual(
                    canonicalManifestBytes,
                    identityRecord.lastCanonicalManifestBytes,
                )
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'A checkpoint safe boundary can only be republished byte-identically.',
                );
            }
            return;
        }
        // The canonical private-randomness manifest is opaque to JavaScript.
        // Rust creates it from the exact coordinate plan and authenticates it
        // again during deterministic-prefix replay. The store binds its exact
        // bytes at every boundary and never expands it into an ordinal map.
    };

    const readManifest = async (lineageIdentifier: Uint8Array) => {
        const logicalRecordKey = manifestRecordKey(lineageIdentifier);
        const opened = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: checkpointManifestOperationDomain,
            protection,
            store: input.store,
        });
        if (opened === undefined) {
            return undefined;
        }
        try {
            return {
                opened,
                record: decodeStoredManifest(
                    opened.plaintext,
                    limits,
                    lineageIdentifier,
                ),
            };
        } catch (error) {
            opened.plaintext.fill(0);
            throw error;
        }
    };

    const readJournal = async (lineageIdentifier: Uint8Array) => {
        const logicalRecordKey = journalRecordKey(lineageIdentifier);
        const opened = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: checkpointJournalOperationDomain,
            protection,
            store: input.store,
        });
        if (opened === undefined) {
            return undefined;
        }
        try {
            return {
                opened,
                record: decodeStoredJournal(
                    opened.plaintext,
                    limits,
                    lineageIdentifier,
                ),
            };
        } catch (error) {
            opened.plaintext.fill(0);
            throw error;
        }
    };

    const repairInterruptedPublicationUnlocked = async (
        lineageIdentifier: Uint8Array,
    ): Promise<void> => {
        const journal = await readJournal(lineageIdentifier);
        if (journal === undefined) {
            return;
        }
        const manifest = await readManifest(lineageIdentifier);
        const publicationIsActive =
            manifest?.record.publicationIdentifier ===
            journal.record.publicationIdentifier;
        const chunkKeysToDelete = publicationIsActive
            ? journal.record.obsoleteChunkRecordKeys
            : journal.record.newChunkRecordKeys;
        journal.opened.plaintext.fill(0);
        manifest?.opened.plaintext.fill(0);
        for (const logicalRecordKey of chunkKeysToDelete) {
            await deleteJournalOwnedChunkRecord({
                logicalRecordKey,
                store: input.store,
                transactionLifetimeMilliseconds:
                    limits.transactionLifetimeMilliseconds,
            });
        }
        await deleteAuthenticatedRecord({
            logicalRecordKey: journalRecordKey(lineageIdentifier),
            operationDomain: checkpointJournalOperationDomain,
            protection,
            store: input.store,
            transactionLifetimeMilliseconds:
                limits.transactionLifetimeMilliseconds,
        });
    };

    const repair: AuthenticatedCheckpointStore['repair'] = async (
        checkpointLineageIdentifier,
    ) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => repairInterruptedPublicationUnlocked(lineageIdentifier),
        );
    };

    const beginOperation: AuthenticatedCheckpointStore['beginOperation'] =
        async (untrustedPrivateRandomnessStreamAttemptIdentifier) => {
            let privateRandomnessStreamAttemptIdentifier:
                | Uint8Array
                | undefined;
            let releaseOperationIdentitySlot: (() => void) | undefined;
            let checkpointLineageIdentifier: Uint8Array | undefined;
            let sampledLineageIdentifierKey: string | undefined;
            let sampledLineageIdentifierTransferred = false;
            try {
                privateRandomnessStreamAttemptIdentifier =
                    untrustedPrivateRandomnessStreamAttemptIdentifier ===
                    undefined
                        ? undefined
                        : copyExactBytes(
                              untrustedPrivateRandomnessStreamAttemptIdentifier,
                              identifierByteLength,
                              'privateRandomnessStreamAttemptIdentifier',
                          );
                releaseOperationIdentitySlot = reserveOperationIdentitySlot();
                checkpointLineageIdentifier = sampleRuntimeIdentifier(
                    protection,
                    unavailableIdentifierKeys(),
                    'checkpoint lineage identifier',
                );
                const retainedLineageIdentifier = checkpointLineageIdentifier;
                sampledLineageIdentifierKey = bytesToHex(
                    retainedLineageIdentifier,
                );
                retainIdentifierKey(sampledLineageIdentifierKey);
                await runCheckpointLineageExclusive(
                    input.store,
                    retainedLineageIdentifier,
                    async () => {
                        const collidingManifest = await readManifest(
                            retainedLineageIdentifier,
                        );
                        const collidingJournal = await readJournal(
                            retainedLineageIdentifier,
                        );
                        collidingManifest?.opened.plaintext.fill(0);
                        collidingJournal?.opened.plaintext.fill(0);
                        if (
                            collidingManifest !== undefined ||
                            collidingJournal !== undefined
                        ) {
                            throw new AuthenticatedRuntimeRecordError(
                                'EntropyFailure',
                                'Checkpoint lineage identifier collides with retained storage.',
                            );
                        }
                    },
                );
                const identity = createOperationIdentity(
                    retainedLineageIdentifier,
                    privateRandomnessStreamAttemptIdentifier,
                    true,
                );
                sampledLineageIdentifierTransferred = true;
                return identity;
            } finally {
                releaseOperationIdentitySlot?.();
                privateRandomnessStreamAttemptIdentifier?.fill(0);
                checkpointLineageIdentifier?.fill(0);
                if (
                    sampledLineageIdentifierKey !== undefined &&
                    !sampledLineageIdentifierTransferred
                ) {
                    releaseIdentifierKey(sampledLineageIdentifierKey);
                    rememberReleasedLineageIdentifierKey(
                        sampledLineageIdentifierKey,
                    );
                }
            }
        };

    const publishUnlocked: AuthenticatedCheckpointStore['publish'] = async ({
        boundary: untrustedBoundary,
        identity,
        stateChunks,
    }) => {
        const boundary = copyAndValidateBoundary(untrustedBoundary, limits);
        const issuedIdentity = operationIdentities.get(identity);
        if (issuedIdentity === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint publication requires an operation identity issued by this authenticated store.',
            );
        }
        const lineageIdentifier =
            issuedIdentity.checkpointLineageIdentifier.slice();
        if (
            (issuedIdentity.privateRandomnessStreamAttemptIdentifier ===
                undefined) !==
                (boundary.privateRandomnessStreamAttemptIdentifier ===
                    undefined) ||
            (issuedIdentity.privateRandomnessStreamAttemptIdentifier !==
                undefined &&
                boundary.privateRandomnessStreamAttemptIdentifier !==
                    undefined &&
                !bytesEqual(
                    issuedIdentity.privateRandomnessStreamAttemptIdentifier,
                    boundary.privateRandomnessStreamAttemptIdentifier,
                ))
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint private-randomness attempt was not issued for this operation.',
            );
        }
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        const descriptor = parseStreamDescriptor(
            boundary.stateStreamDescriptorBytes,
            limits,
        );
        const previousManifest = await readManifest(lineageIdentifier);
        synchronizePublicationIdentifier(
            issuedIdentity,
            previousManifest?.record.publicationIdentifier,
        );
        previousManifest?.opened.plaintext.fill(0);
        const previousCanonicalManifestBytes =
            previousManifest === undefined
                ? undefined
                : previousManifest.record.canonicalManifestBytes.slice();
        if (
            (issuedIdentity.lastCanonicalManifestBytes === undefined) !==
                (previousCanonicalManifestBytes === undefined) ||
            (issuedIdentity.lastCanonicalManifestBytes !== undefined &&
                previousCanonicalManifestBytes !== undefined &&
                !bytesEqual(
                    issuedIdentity.lastCanonicalManifestBytes,
                    previousCanonicalManifestBytes,
                ))
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Checkpoint operation identity is stale for the current lineage manifest.',
            );
        }
        const canonicalManifestBytes = encodeCheckpointManifest({
            authorityContext,
            boundary,
            checkpointLineageIdentifier: lineageIdentifier,
            stateStreamDescriptorBytes: boundary.stateStreamDescriptorBytes,
        });
        if (
            canonicalManifestBytes.byteLength > limits.maximumManifestByteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                'Canonical checkpoint manifest exceeds the configured profile.',
            );
        }
        await runBoundaryPolicy(
            'publish',
            lineageIdentifier,
            boundary,
            issuedIdentity.lastPublishedBoundary,
        );
        requireMonotonicPublicationBoundary(
            issuedIdentity,
            boundary,
            canonicalManifestBytes,
        );
        const publicationIdentifier = sampleRuntimeIdentifier(
            protection,
            unavailableIdentifierKeys(),
            'checkpoint publication identifier',
        );
        const publicationIdentifierKey = bytesToHex(publicationIdentifier);
        retainIdentifierKey(publicationIdentifierKey);
        issuedIdentity.pendingPublicationIdentifierKey =
            publicationIdentifierKey;
        const newChunkRecordKeys = descriptor.orderedChunkDigests.map(
            (chunkDigest, chunkIndex) =>
                chunkRecordKey({
                    checkpointLineageIdentifier: lineageIdentifier,
                    chunkDigest,
                    chunkIndex,
                    publicationIdentifier,
                }),
        );
        const journalRecord: StoredCheckpointJournal = {
            checkpointLineageIdentifier: bytesToHex(lineageIdentifier),
            newChunkRecordKeys,
            obsoleteChunkRecordKeys:
                previousManifest?.record.chunkRecordKeys ?? [],
            publicationIdentifier: bytesToHex(publicationIdentifier),
            recordVersion: checkpointRecordVersion,
        };
        const journalPlaintext = encodeCanonicalJson(journalRecord);
        const journalTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: null,
                logicalRecordKey: journalRecordKey(lineageIdentifier),
                operationDomain: checkpointJournalOperationDomain,
                plaintext: journalPlaintext,
                protection,
                transaction: journalTransaction,
            });
            await journalTransaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(journalTransaction, error);
        } finally {
            journalPlaintext.fill(0);
        }

        const fullObjectDigestHasher = createFullObjectDigestHasher({
            stateStreamDomain: boundary.stateStreamDomain,
            totalByteLength: descriptor.totalByteLength,
        });
        let observedChunkCount = 0;
        try {
            for await (const untrustedChunk of asAsyncIterable(stateChunks)) {
                if (
                    observedChunkCount >= descriptor.orderedChunkDigests.length
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'InvalidInput',
                        'Checkpoint state contains a trailing chunk.',
                    );
                }
                const chunkBytes = copyBoundedBytes(
                    untrustedChunk,
                    foundationProfile.streamChunkByteLength,
                    `stateChunks[${observedChunkCount}]`,
                );
                const expectedByteLength = expectedChunkByteLength(
                    descriptor,
                    observedChunkCount,
                );
                const observedDigest = deriveChunkDigest({
                    chunkBytes,
                    chunkIndex: observedChunkCount,
                    stateStreamDomain: boundary.stateStreamDomain,
                });
                if (
                    chunkBytes.byteLength !== expectedByteLength ||
                    !bytesEqual(
                        observedDigest,
                        descriptor.orderedChunkDigests[observedChunkCount],
                    )
                ) {
                    chunkBytes.fill(0);
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Checkpoint state chunk does not match its canonical descriptor.',
                    );
                }
                fullObjectDigestHasher.update(chunkBytes);
                const chunkTransaction = await input.store.beginTransaction({
                    lifetimeMilliseconds:
                        limits.transactionLifetimeMilliseconds,
                });
                try {
                    await stageRuntimeRecordWrite({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey:
                            newChunkRecordKeys[observedChunkCount],
                        operationDomain: checkpointChunkOperationDomain,
                        plaintext: chunkBytes,
                        protection,
                        transaction: chunkTransaction,
                    });
                    await chunkTransaction.commit();
                } catch (error) {
                    throw await closeTransactionAfterFailure(
                        chunkTransaction,
                        error,
                    );
                } finally {
                    chunkBytes.fill(0);
                }
                observedChunkCount += 1;
            }
            if (observedChunkCount !== descriptor.orderedChunkDigests.length) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Checkpoint state is incomplete.',
                );
            }
            authenticateFullObjectDigest(
                fullObjectDigestHasher,
                descriptor.fullObjectDigest,
            );
        } finally {
            fullObjectDigestHasher.destroy();
        }

        const storedPublicationIdentifier = bytesToHex(publicationIdentifier);
        const manifestPlaintext = encodeStoredManifest({
            canonicalManifestBytes,
            publicationIdentifier,
        });
        const manifestTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes:
                    previousManifest?.opened.sealedBytes ?? null,
                logicalRecordKey: manifestRecordKey(lineageIdentifier),
                operationDomain: checkpointManifestOperationDomain,
                plaintext: manifestPlaintext,
                protection,
                transaction: manifestTransaction,
            });
            await manifestTransaction.commit();
            issuedIdentity.lastCanonicalManifestBytes =
                canonicalManifestBytes.slice();
            issuedIdentity.lastPublishedBoundary = copyAndValidateBoundary(
                boundary,
                limits,
            );
        } catch (error) {
            const mappedFailure = await closeTransactionAfterFailure(
                manifestTransaction,
                error,
            );
            const observedManifest = await readManifest(lineageIdentifier);
            if (
                observedManifest?.record.publicationIdentifier ===
                    storedPublicationIdentifier &&
                bytesEqual(
                    observedManifest.record.canonicalManifestBytes,
                    canonicalManifestBytes,
                )
            ) {
                issuedIdentity.lastCanonicalManifestBytes =
                    canonicalManifestBytes.slice();
                issuedIdentity.lastPublishedBoundary = copyAndValidateBoundary(
                    boundary,
                    limits,
                );
            }
            observedManifest?.opened.plaintext.fill(0);
            throw mappedFailure;
        } finally {
            manifestPlaintext.fill(0);
        }
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        synchronizePublicationIdentifier(
            issuedIdentity,
            storedPublicationIdentifier,
        );
        return canonicalManifestBytes.slice();
    };

    const publish: AuthenticatedCheckpointStore['publish'] = async (
        publication,
    ) => {
        const identity = publication.identity;
        const issuedIdentity = operationIdentities.get(identity);
        if (issuedIdentity === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint publication requires an operation identity issued by this authenticated store.',
            );
        }
        const lineageIdentifier =
            issuedIdentity.checkpointLineageIdentifier.slice();
        const normalizedPublication = Object.freeze({
            boundary: copyAndValidateBoundary(publication.boundary, limits),
            identity,
            stateChunks: publication.stateChunks,
        });
        return runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => publishUnlocked(normalizedPublication),
        );
    };

    const resumeUnlocked: AuthenticatedCheckpointStore['resume'] = async ({
        checkpointLineageIdentifier,
        expectedBoundary: untrustedExpectedBoundary,
    }) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        const expectedBoundary = copyAndValidateBoundary(
            untrustedExpectedBoundary,
            limits,
        );
        await runBoundaryPolicy('resume', lineageIdentifier, expectedBoundary);
        const manifest = await readManifest(lineageIdentifier);
        if (manifest === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'MissingRecord',
                'No authenticated checkpoint exists for this lineage.',
            );
        }
        const descriptorBytes =
            manifest.record.stateStreamDescriptorBytes.slice();
        const descriptor = parseStreamDescriptor(descriptorBytes, limits);
        const expectedCanonicalManifest = encodeCheckpointManifest({
            authorityContext,
            boundary: expectedBoundary,
            checkpointLineageIdentifier: lineageIdentifier,
            stateStreamDescriptorBytes: descriptorBytes,
        });
        const storedCanonicalManifest =
            manifest.record.canonicalManifestBytes.slice();
        manifest.opened.plaintext.fill(0);
        if (!bytesEqual(storedCanonicalManifest, expectedCanonicalManifest)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Checkpoint manifest does not match the exact resume boundary.',
            );
        }
        const manifestSealedBytes = manifest.opened.sealedBytes.slice();
        const chunkRecordKeys = [...manifest.record.chunkRecordKeys];
        return Object.freeze({
            canonicalManifestBytes: storedCanonicalManifest.slice(),
            operationIdentity: createOperationIdentity(
                lineageIdentifier,
                expectedBoundary.privateRandomnessStreamAttemptIdentifier,
                false,
                {
                    boundary: {
                        ...expectedBoundary,
                        stateStreamDescriptorBytes: descriptorBytes,
                    },
                    canonicalManifestBytes: storedCanonicalManifest,
                    publicationIdentifierKey:
                        manifest.record.publicationIdentifier,
                },
            ),
            stateStreamDescriptorBytes: descriptorBytes.slice(),
            restoreState: async (consumeChunk) =>
                runCheckpointLineageExclusive(
                    input.store,
                    lineageIdentifier,
                    async () => {
                        const currentManifest =
                            await readManifest(lineageIdentifier);
                        if (currentManifest === undefined) {
                            throw new AuthenticatedRuntimeRecordError(
                                'MissingRecord',
                                'The checkpoint was evicted before state restoration.',
                            );
                        }
                        const manifestIsCurrent = bytesEqual(
                            currentManifest.opened.sealedBytes,
                            manifestSealedBytes,
                        );
                        currentManifest.opened.plaintext.fill(0);
                        if (!manifestIsCurrent) {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'The checkpoint changed before state restoration.',
                            );
                        }
                        const fullObjectDigestHasher =
                            createFullObjectDigestHasher({
                                stateStreamDomain:
                                    expectedBoundary.stateStreamDomain,
                                totalByteLength: descriptor.totalByteLength,
                            });
                        try {
                            for (
                                let chunkIndex = 0;
                                chunkIndex < chunkRecordKeys.length;
                                chunkIndex += 1
                            ) {
                                const openedChunk = await readRuntimeRecord({
                                    logicalRecordKey:
                                        chunkRecordKeys[chunkIndex],
                                    operationDomain:
                                        checkpointChunkOperationDomain,
                                    protection,
                                    store: input.store,
                                });
                                if (openedChunk === undefined) {
                                    throw new AuthenticatedRuntimeRecordError(
                                        'MissingRecord',
                                        'An authenticated checkpoint state chunk is missing.',
                                    );
                                }
                                const chunkBytes = openedChunk.plaintext;
                                const observedDigest = deriveChunkDigest({
                                    chunkBytes,
                                    chunkIndex,
                                    stateStreamDomain:
                                        expectedBoundary.stateStreamDomain,
                                });
                                if (
                                    chunkBytes.byteLength !==
                                        expectedChunkByteLength(
                                            descriptor,
                                            chunkIndex,
                                        ) ||
                                    !bytesEqual(
                                        observedDigest,
                                        descriptor.orderedChunkDigests[
                                            chunkIndex
                                        ],
                                    )
                                ) {
                                    chunkBytes.fill(0);
                                    throw new AuthenticatedRuntimeRecordError(
                                        'AuthenticationFailed',
                                        'Checkpoint state chunk failed descriptor authentication.',
                                    );
                                }
                                fullObjectDigestHasher.update(chunkBytes);
                                try {
                                    await consumeChunk(
                                        chunkIndex,
                                        chunkBytes.slice(),
                                    );
                                } finally {
                                    chunkBytes.fill(0);
                                }
                            }
                            authenticateFullObjectDigest(
                                fullObjectDigestHasher,
                                descriptor.fullObjectDigest,
                            );
                        } finally {
                            fullObjectDigestHasher.destroy();
                        }
                    },
                ),
        });
    };

    const resume: AuthenticatedCheckpointStore['resume'] = async (
        resumeInput,
    ) => {
        const lineageIdentifier = copyExactBytes(
            resumeInput.checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        const normalizedResumeInput = Object.freeze({
            checkpointLineageIdentifier: lineageIdentifier,
            expectedBoundary: copyAndValidateBoundary(
                resumeInput.expectedBoundary,
                limits,
            ),
        });
        const releaseOperationIdentitySlot = reserveOperationIdentitySlot();
        try {
            return await runCheckpointLineageExclusive(
                input.store,
                lineageIdentifier,
                () => resumeUnlocked(normalizedResumeInput),
            );
        } finally {
            releaseOperationIdentitySlot();
            lineageIdentifier.fill(0);
        }
    };

    const releaseOperationIdentity: AuthenticatedCheckpointStore['releaseOperationIdentity'] =
        async (identity) => {
            if (releasedOperationIdentities.has(identity)) {
                return;
            }
            const identityRecord = operationIdentities.get(identity);
            if (identityRecord === undefined) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Checkpoint identity release requires an operation identity issued by this authenticated store.',
                );
            }
            const lineageIdentifier =
                identityRecord.checkpointLineageIdentifier.slice();
            try {
                await runCheckpointLineageExclusive(
                    input.store,
                    lineageIdentifier,
                    () => {
                        const currentIdentityRecord =
                            operationIdentities.get(identity);
                        if (currentIdentityRecord === undefined) {
                            if (releasedOperationIdentities.has(identity)) {
                                return Promise.resolve();
                            }
                            throw new AuthenticatedRuntimeRecordError(
                                'InvalidInput',
                                'Checkpoint identity release requires a current operation identity.',
                            );
                        }
                        destroyOperationIdentityRecord(
                            identity,
                            currentIdentityRecord,
                        );
                        return Promise.resolve();
                    },
                );
            } finally {
                lineageIdentifier.fill(0);
            }
        };

    const evictUnlocked: AuthenticatedCheckpointStore['evict'] = async (
        checkpointLineageIdentifier,
    ) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
        const manifest = await readManifest(lineageIdentifier);
        if (manifest === undefined) {
            return;
        }
        manifest.opened.plaintext.fill(0);
        const journalRecord: StoredCheckpointJournal = {
            checkpointLineageIdentifier: bytesToHex(lineageIdentifier),
            newChunkRecordKeys: manifest.record.chunkRecordKeys,
            obsoleteChunkRecordKeys: [],
            publicationIdentifier: manifest.record.publicationIdentifier,
            recordVersion: checkpointRecordVersion,
        };
        const journalPlaintext = encodeCanonicalJson(journalRecord);
        const journalTransaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: null,
                logicalRecordKey: journalRecordKey(lineageIdentifier),
                operationDomain: checkpointJournalOperationDomain,
                plaintext: journalPlaintext,
                protection,
                transaction: journalTransaction,
            });
            await journalTransaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(journalTransaction, error);
        } finally {
            journalPlaintext.fill(0);
        }
        await deleteAuthenticatedRecord({
            logicalRecordKey: manifestRecordKey(lineageIdentifier),
            operationDomain: checkpointManifestOperationDomain,
            protection,
            store: input.store,
            transactionLifetimeMilliseconds:
                limits.transactionLifetimeMilliseconds,
        });
        await repairInterruptedPublicationUnlocked(lineageIdentifier);
    };

    const evict: AuthenticatedCheckpointStore['evict'] = async (
        checkpointLineageIdentifier,
    ) => {
        const lineageIdentifier = copyExactBytes(
            checkpointLineageIdentifier,
            identifierByteLength,
            'checkpointLineageIdentifier',
        );
        await runCheckpointLineageExclusive(
            input.store,
            lineageIdentifier,
            () => evictUnlocked(lineageIdentifier),
        );
    };

    const lifecycle = new ExclusiveResourceLifecycle({
        cleanup: async () => {
            await releaseRuntimeRecordProtection(protection);
            operationIdentities = new WeakMap();
            releasedOperationIdentities = new WeakSet();
            for (const identityRecord of issuedOperationIdentityRecords) {
                identityRecord.checkpointLineageIdentifier.fill(0);
                identityRecord.lastCanonicalManifestBytes?.fill(0);
                destroyBoundary(identityRecord.lastPublishedBoundary);
                identityRecord.privateRandomnessStreamAttemptIdentifier?.fill(
                    0,
                );
            }
            issuedOperationIdentityRecords.clear();
            identifierReferenceCounts.clear();
            recentlyReleasedLineageIdentifierKeys.length = 0;
            pendingOperationIdentityCount = 0;
            authorityContext.actionContextHash.fill(0);
            authorityContext.ceremonyContextHash.fill(0);
            authorityContext.ownerParticipantIdentity.fill(0);
            authorityContext.runtimeBuildManifestHash.fill(0);
            authorityContext.suiteIdentifier.fill(0);
        },
        createInvalidStateError: (message) =>
            new AuthenticatedRuntimeRecordError('InvalidState', message),
    });
    const initialOwner = lifecycle.initialOwner();
    const createOwnedStore = (
        owner: ExclusiveResourceOwnerToken,
    ): AuthenticatedCheckpointStore =>
        Object.freeze({
            beginOperation: (privateRandomnessStreamAttemptIdentifier) =>
                lifecycle.run(owner, () =>
                    beginOperation(privateRandomnessStreamAttemptIdentifier),
                ),
            close: () => lifecycle.close(owner),
            copyAuthorityContext: () => {
                lifecycle.assertOpen(owner);
                return copyRuntimeStorageAuthorityContext(authorityContext);
            },
            copyStorageInstanceIdentity: () => {
                lifecycle.assertOpen(owner);
                return input.store.copyStorageInstanceIdentity();
            },
            evict: (checkpointLineageIdentifier) =>
                lifecycle.run(owner, () => evict(checkpointLineageIdentifier)),
            publish: (publication) =>
                lifecycle.run(owner, () => publish(publication)),
            releaseOperationIdentity: (identity) =>
                lifecycle.run(owner, () => releaseOperationIdentity(identity)),
            repair: (checkpointLineageIdentifier) =>
                lifecycle.run(owner, () => repair(checkpointLineageIdentifier)),
            resume: (resumeInput) =>
                lifecycle.run(owner, () => resume(resumeInput)),
        });
    const initialStore = createOwnedStore(initialOwner);
    return Object.freeze({
        ...initialStore,
        claimExclusiveOwner: () =>
            createOwnedStore(lifecycle.claim(initialOwner)),
    });
};

/** Local-key constructor retained only for focused storage tests. */
export const openAuthenticatedCheckpointStore = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    boundaryPolicy: CheckpointBoundaryPolicy;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    limits: AuthenticatedCheckpointStoreLimits;
    store: UntrustedStorageTransactionStore;
}): TransferableAuthenticatedCheckpointStore => {
    const limits = validateAuthenticatedCheckpointStoreLimits(input.limits);
    return openAuthenticatedCheckpointStoreWithProtection({
        boundaryPolicy: input.boundaryPolicy,
        limits,
        protection: createRuntimeRecordProtection({
            authorityContext: input.authorityContext,
            cryptoProvider: input.cryptoProvider,
            encryptionKey: input.encryptionKey,
            maximumRecordSealingCount: limits.maximumRecordSealingCount,
        }),
        store: input.store,
    });
};

export { AuthenticatedRuntimeRecordError as AuthenticatedCheckpointStoreError };
export type { AuthenticatedRuntimeRecordErrorCode as AuthenticatedCheckpointStoreErrorCode };
