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
import type { UntrustedStorageExclusiveCapacityReservationInput } from '../untrusted-storage-transaction-store/records.js';
import type {
    UntrustedStorageExclusiveCapacityReservation,
    UntrustedStorageTransactionStore,
} from '../untrusted-storage-transaction-store.js';

import {
    identifierByteLength,
    checkpointRecordVersion,
    checkpointManifestOperationDomain,
    checkpointJournalOperationDomain,
    checkpointChunkOperationDomain,
    checkpointOperationIdentityBrand,
    checkpointLineageReservationBrand,
    authenticatedCheckpointPhysicalAccountingScopeBrand,
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
    type CheckpointLineageReservation,
    type CheckpointBoundary,
    type ExpectedCheckpointBoundary,
    type AuthenticatedCheckpointStoreLimits,
    type AuthenticatedCheckpointStore,
    type AuthenticatedCheckpointPhysicalAccountingScope,
    type AuthenticatedCheckpointPhysicalAccountingSnapshot,
    type TransferableAuthenticatedCheckpointStore,
    type StoredCheckpointJournal,
    type CheckpointOperationIdentityRecord,
    type CheckpointLineageReservationRecord,
} from './records.js';

export { describeAuthenticatedCheckpointStateStream } from './records.js';
export type {
    AuthenticatedCheckpointStore,
    AuthenticatedCheckpointStoreLimits,
    AuthenticatedCheckpointPhysicalAccountingScope,
    CheckpointBoundary,
    CheckpointBoundaryPolicy,
    CheckpointLineageReservation,
    CheckpointOperationIdentity,
    ExpectedCheckpointBoundary,
    ResumedCheckpoint,
    TransferableAuthenticatedCheckpointStore,
} from './records.js';

const runtimeRecordEnvelopeOverheadByteLength = 34n;
const checkpointStorageIndexValueByteLength = 256n;
const authenticatedRepairRecordFixedByteLength = 68n;
const checkpointStorageObjectKeyByteLength = 256n;
const checkpointStorageProfileTextEncoder = new TextEncoder();

const checkedCheckpointStorageNumber = (
    value: bigint,
    label: string,
): number => {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} exceeds the exact JavaScript integer range.`,
        );
    }
    return Number(value);
};

const checkpointPhysicalAccountingCapacity = (
    limits: AuthenticatedCheckpointStoreLimits,
): Omit<
    UntrustedStorageExclusiveCapacityReservationInput,
    'initialLogicalRecordKeyPrefixes'
> => {
    const maximumChunkCount = BigInt(
        Math.ceil(
            limits.maximumCheckpointStateByteLength /
                foundationProfile.streamChunkByteLength,
        ),
    );
    const maximumChunkRecordKeyByteLength = BigInt(
        checkpointStorageProfileTextEncoder.encode(
            `checkpoint/chunk/${'0'.repeat(64)}/${'0'.repeat(64)}/${'0'.repeat(8)}-${'0'.repeat(128)}`,
        ).byteLength,
    );
    const maximumManifestRecordKeyByteLength = BigInt(
        checkpointStorageProfileTextEncoder.encode(
            `checkpoint/manifest/${'0'.repeat(64)}`,
        ).byteLength,
    );
    const maximumJournalRecordKeyByteLength = BigInt(
        checkpointStorageProfileTextEncoder.encode(
            `checkpoint/journal/${'0'.repeat(64)}`,
        ).byteLength,
    );
    const maximumLogicalRecordKeyByteLength = [
        maximumChunkRecordKeyByteLength,
        maximumManifestRecordKeyByteLength,
        maximumJournalRecordKeyByteLength,
    ].reduce((maximum, value) => (maximum > value ? maximum : value));
    const simultaneousLogicalRecordCount = maximumChunkCount * 2n + 2n;
    const checkpointChunkStoredValueByteLength =
        BigInt(limits.maximumCheckpointStateByteLength) * 2n +
        maximumChunkCount * runtimeRecordEnvelopeOverheadByteLength * 2n;
    const manifestPlaintextByteLength =
        BigInt(limits.maximumManifestByteLength) + 38n;
    const manifestStoredValueByteLength =
        (manifestPlaintextByteLength +
            runtimeRecordEnvelopeOverheadByteLength) *
        2n;
    const journalPlaintextByteLength =
        1_024n +
        maximumChunkCount * 2n * (maximumChunkRecordKeyByteLength + 4n);
    const journalStoredValueByteLength =
        (journalPlaintextByteLength + runtimeRecordEnvelopeOverheadByteLength) *
        2n;
    const indexStoredValueByteLength =
        simultaneousLogicalRecordCount * checkpointStorageIndexValueByteLength;
    const authenticatedRepairHeadPlaintextByteLength =
        simultaneousLogicalRecordCount *
        (authenticatedRepairRecordFixedByteLength +
            maximumLogicalRecordKeyByteLength +
            checkpointStorageObjectKeyByteLength);
    return Object.freeze({
        maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength:
            checkedCheckpointStorageNumber(
                authenticatedRepairHeadPlaintextByteLength,
                'Checkpoint repair-head capacity',
            ),
        maximumAdditionalOwnedRecordCount: checkedCheckpointStorageNumber(
            simultaneousLogicalRecordCount * 2n + 2n,
            'Checkpoint owned-record capacity',
        ),
        maximumAdditionalStoredValueByteLength: checkedCheckpointStorageNumber(
            checkpointChunkStoredValueByteLength +
                manifestStoredValueByteLength +
                journalStoredValueByteLength +
                indexStoredValueByteLength,
            'Checkpoint stored-value capacity',
        ),
        maximumDeletionBatchRecordCount: 1,
    });
};

type CheckpointPhysicalAccountingScopeRecord = {
    readonly checkpointLineageIdentifier: Uint8Array;
    openCallCount: number;
    openCiphertextByteLength: number;
    openPlaintextByteLength: number;
    readonly reservation: UntrustedStorageExclusiveCapacityReservation;
    released: boolean;
    sealCallCount: number;
    sealCiphertextByteLength: number;
    sealPlaintextByteLength: number;
};

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
    let checkpointLineageReservations = new WeakMap<
        CheckpointLineageReservation,
        CheckpointLineageReservationRecord
    >();
    let releasedOperationIdentities =
        new WeakSet<CheckpointOperationIdentity>();
    let releasedCheckpointLineageReservations =
        new WeakSet<CheckpointLineageReservation>();
    const issuedOperationIdentityRecords =
        new Set<CheckpointOperationIdentityRecord>();
    const issuedCheckpointLineageReservationRecords =
        new Set<CheckpointLineageReservationRecord>();
    let physicalAccountingScopes = new WeakMap<
        AuthenticatedCheckpointPhysicalAccountingScope,
        CheckpointPhysicalAccountingScopeRecord
    >();
    let activePhysicalAccountingScopeRecord:
        | CheckpointPhysicalAccountingScopeRecord
        | undefined;
    const issuedPhysicalAccountingScopeRecords =
        new Set<CheckpointPhysicalAccountingScopeRecord>();

    const checkedAccountingAdd = (
        currentValue: number,
        increment: number,
        label: string,
    ): number => {
        const value = currentValue + increment;
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                `${label} exceeds the exact JavaScript integer range.`,
            );
        }
        return value;
    };

    const requirePhysicalAccountingLineage = (
        checkpointLineageIdentifier: Uint8Array,
    ): void => {
        if (
            activePhysicalAccountingScopeRecord !== undefined &&
            !bytesEqual(
                activePhysicalAccountingScopeRecord.checkpointLineageIdentifier,
                checkpointLineageIdentifier,
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint physical accounting is reserved for a different lineage.',
            );
        }
    };

    const observeOpenedRecord = (opened: {
        plaintext: Uint8Array;
        sealedBytes: Uint8Array;
    }): void => {
        const accounting = activePhysicalAccountingScopeRecord;
        if (accounting === undefined) {
            return;
        }
        accounting.openCallCount = checkedAccountingAdd(
            accounting.openCallCount,
            1,
            'Checkpoint open call accounting',
        );
        accounting.openCiphertextByteLength = checkedAccountingAdd(
            accounting.openCiphertextByteLength,
            opened.sealedBytes.byteLength,
            'Checkpoint open ciphertext accounting',
        );
        accounting.openPlaintextByteLength = checkedAccountingAdd(
            accounting.openPlaintextByteLength,
            opened.plaintext.byteLength,
            'Checkpoint open plaintext accounting',
        );
    };

    const readCheckpointRuntimeRecord = async (
        readInput: Parameters<typeof readRuntimeRecord>[0],
        checkpointLineageIdentifier: Uint8Array,
    ) => {
        requirePhysicalAccountingLineage(checkpointLineageIdentifier);
        const opened = await readRuntimeRecord(readInput);
        if (opened !== undefined) {
            observeOpenedRecord(opened);
        }
        return opened;
    };

    const stageCheckpointRuntimeRecordWrite = async (
        writeInput: Parameters<typeof stageRuntimeRecordWrite>[0],
        checkpointLineageIdentifier: Uint8Array,
    ): Promise<void> => {
        requirePhysicalAccountingLineage(checkpointLineageIdentifier);
        const sealedBytes = await stageRuntimeRecordWrite(writeInput);
        const accounting = activePhysicalAccountingScopeRecord;
        try {
            if (accounting === undefined) {
                return;
            }
            accounting.sealCallCount = checkedAccountingAdd(
                accounting.sealCallCount,
                1,
                'Checkpoint seal call accounting',
            );
            accounting.sealCiphertextByteLength = checkedAccountingAdd(
                accounting.sealCiphertextByteLength,
                sealedBytes.byteLength,
                'Checkpoint seal ciphertext accounting',
            );
            accounting.sealPlaintextByteLength = checkedAccountingAdd(
                accounting.sealPlaintextByteLength,
                writeInput.plaintext.byteLength,
                'Checkpoint seal plaintext accounting',
            );
        } finally {
            sealedBytes.fill(0);
        }
    };

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
                issuedCheckpointLineageReservationRecords.size +
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

    const consumeCheckpointLineageReservationRecord = (
        reservation: CheckpointLineageReservation,
        reservationRecord: CheckpointLineageReservationRecord,
    ): void => {
        checkpointLineageReservations.delete(reservation);
        releasedCheckpointLineageReservations.add(reservation);
        issuedCheckpointLineageReservationRecords.delete(reservationRecord);
        reservationRecord.checkpointLineageIdentifier.fill(0);
    };

    const destroyCheckpointLineageReservationRecord = (
        reservation: CheckpointLineageReservation,
        reservationRecord: CheckpointLineageReservationRecord,
    ): void => {
        const lineageIdentifierKey = bytesToHex(
            reservationRecord.checkpointLineageIdentifier,
        );
        releaseIdentifierKey(lineageIdentifierKey);
        rememberReleasedLineageIdentifierKey(lineageIdentifierKey);
        consumeCheckpointLineageReservationRecord(
            reservation,
            reservationRecord,
        );
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

    const createCheckpointLineageReservation = (
        checkpointLineageIdentifier: Uint8Array,
    ): CheckpointLineageReservation => {
        const lineageIdentifier = checkpointLineageIdentifier.slice();
        const reservation = Object.freeze({
            [checkpointLineageReservationBrand]: true as const,
            get checkpointLineageIdentifier(): Uint8Array {
                return lineageIdentifier.slice();
            },
        });
        const reservationRecord = {
            checkpointLineageIdentifier: lineageIdentifier,
        };
        checkpointLineageReservations.set(reservation, reservationRecord);
        issuedCheckpointLineageReservationRecords.add(reservationRecord);
        return reservation;
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
        const opened = await readCheckpointRuntimeRecord(
            {
                logicalRecordKey,
                operationDomain: checkpointManifestOperationDomain,
                protection,
                store: input.store,
            },
            lineageIdentifier,
        );
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
        const opened = await readCheckpointRuntimeRecord(
            {
                logicalRecordKey,
                operationDomain: checkpointJournalOperationDomain,
                protection,
                store: input.store,
            },
            lineageIdentifier,
        );
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
            observeOpenedRecord,
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

    const sampleFreshCheckpointLineage = async (): Promise<
        Readonly<{
            checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
            lineageIdentifierKey: string;
        }>
    > => {
        const checkpointLineageIdentifier = Uint8Array.from(
            sampleRuntimeIdentifier(
                protection,
                unavailableIdentifierKeys(),
                'checkpoint lineage identifier',
            ),
        );
        const lineageIdentifierKey = bytesToHex(checkpointLineageIdentifier);
        retainIdentifierKey(lineageIdentifierKey);
        try {
            await runCheckpointLineageExclusive(
                input.store,
                checkpointLineageIdentifier,
                async () => {
                    const collidingManifest = await readManifest(
                        checkpointLineageIdentifier,
                    );
                    const collidingJournal = await readJournal(
                        checkpointLineageIdentifier,
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
            return Object.freeze({
                checkpointLineageIdentifier,
                lineageIdentifierKey,
            });
        } catch (error) {
            releaseIdentifierKey(lineageIdentifierKey);
            rememberReleasedLineageIdentifierKey(lineageIdentifierKey);
            checkpointLineageIdentifier.fill(0);
            throw error;
        }
    };

    const beginOperation: AuthenticatedCheckpointStore['beginOperation'] =
        async (untrustedPrivateRandomnessStreamAttemptIdentifier) => {
            let privateRandomnessStreamAttemptIdentifier:
                | Uint8Array
                | undefined;
            let releaseOperationIdentitySlot: (() => void) | undefined;
            let sampledLineage:
                | Awaited<ReturnType<typeof sampleFreshCheckpointLineage>>
                | undefined;
            let sampledLineageTransferred = false;
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
                sampledLineage = await sampleFreshCheckpointLineage();
                const identity = createOperationIdentity(
                    sampledLineage.checkpointLineageIdentifier,
                    privateRandomnessStreamAttemptIdentifier,
                    true,
                );
                sampledLineageTransferred = true;
                return identity;
            } finally {
                releaseOperationIdentitySlot?.();
                privateRandomnessStreamAttemptIdentifier?.fill(0);
                sampledLineage?.checkpointLineageIdentifier.fill(0);
                if (
                    sampledLineage !== undefined &&
                    !sampledLineageTransferred
                ) {
                    releaseIdentifierKey(sampledLineage.lineageIdentifierKey);
                    rememberReleasedLineageIdentifierKey(
                        sampledLineage.lineageIdentifierKey,
                    );
                }
            }
        };

    const reserveCheckpointLineage: AuthenticatedCheckpointStore['reserveCheckpointLineage'] =
        async () => {
            const releaseOperationIdentitySlot = reserveOperationIdentitySlot();
            let sampledLineage:
                | Awaited<ReturnType<typeof sampleFreshCheckpointLineage>>
                | undefined;
            let sampledLineageTransferred = false;
            try {
                sampledLineage = await sampleFreshCheckpointLineage();
                const reservation = createCheckpointLineageReservation(
                    sampledLineage.checkpointLineageIdentifier,
                );
                sampledLineageTransferred = true;
                return reservation;
            } finally {
                releaseOperationIdentitySlot();
                sampledLineage?.checkpointLineageIdentifier.fill(0);
                if (
                    sampledLineage !== undefined &&
                    !sampledLineageTransferred
                ) {
                    releaseIdentifierKey(sampledLineage.lineageIdentifierKey);
                    rememberReleasedLineageIdentifierKey(
                        sampledLineage.lineageIdentifierKey,
                    );
                }
            }
        };

    const bindCheckpointLineageToProofAttempt: AuthenticatedCheckpointStore['bindCheckpointLineageToProofAttempt'] =
        async (reservation, untrustedProofAttemptLineageIdentifier) => {
            const proofAttemptLineageIdentifier = copyExactBytes(
                untrustedProofAttemptLineageIdentifier,
                identifierByteLength,
                'proofAttemptLineageIdentifier',
            );
            const reservationRecord =
                checkpointLineageReservations.get(reservation);
            if (reservationRecord === undefined) {
                proofAttemptLineageIdentifier.fill(0);
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Checkpoint-lineage binding requires an active reservation issued by this authenticated store.',
                );
            }
            const checkpointLineageIdentifier =
                reservationRecord.checkpointLineageIdentifier.slice();
            try {
                return await runCheckpointLineageExclusive(
                    input.store,
                    checkpointLineageIdentifier,
                    () => {
                        const currentReservationRecord =
                            checkpointLineageReservations.get(reservation);
                        if (currentReservationRecord !== reservationRecord) {
                            throw new AuthenticatedRuntimeRecordError(
                                'InvalidInput',
                                'Checkpoint-lineage reservation was already consumed or released.',
                            );
                        }
                        const identity = createOperationIdentity(
                            currentReservationRecord.checkpointLineageIdentifier,
                            proofAttemptLineageIdentifier,
                            true,
                        );
                        consumeCheckpointLineageReservationRecord(
                            reservation,
                            currentReservationRecord,
                        );
                        return Promise.resolve(identity);
                    },
                );
            } finally {
                checkpointLineageIdentifier.fill(0);
                proofAttemptLineageIdentifier.fill(0);
            }
        };

    const releaseCheckpointLineageReservation: AuthenticatedCheckpointStore['releaseCheckpointLineageReservation'] =
        async (reservation) => {
            if (releasedCheckpointLineageReservations.has(reservation)) {
                return;
            }
            const reservationRecord =
                checkpointLineageReservations.get(reservation);
            if (reservationRecord === undefined) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Checkpoint-lineage release requires a reservation issued by this authenticated store.',
                );
            }
            const checkpointLineageIdentifier =
                reservationRecord.checkpointLineageIdentifier.slice();
            try {
                await runCheckpointLineageExclusive(
                    input.store,
                    checkpointLineageIdentifier,
                    () => {
                        const currentReservationRecord =
                            checkpointLineageReservations.get(reservation);
                        if (currentReservationRecord === undefined) {
                            if (
                                releasedCheckpointLineageReservations.has(
                                    reservation,
                                )
                            ) {
                                return Promise.resolve();
                            }
                            throw new AuthenticatedRuntimeRecordError(
                                'InvalidInput',
                                'Checkpoint-lineage release requires a current reservation.',
                            );
                        }
                        destroyCheckpointLineageReservationRecord(
                            reservation,
                            currentReservationRecord,
                        );
                        return Promise.resolve();
                    },
                );
            } finally {
                checkpointLineageIdentifier.fill(0);
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
            await stageCheckpointRuntimeRecordWrite(
                {
                    expectedCurrentSealedBytes: null,
                    logicalRecordKey: journalRecordKey(lineageIdentifier),
                    operationDomain: checkpointJournalOperationDomain,
                    plaintext: journalPlaintext,
                    protection,
                    transaction: journalTransaction,
                },
                lineageIdentifier,
            );
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
                    await stageCheckpointRuntimeRecordWrite(
                        {
                            expectedCurrentSealedBytes: null,
                            logicalRecordKey:
                                newChunkRecordKeys[observedChunkCount],
                            operationDomain: checkpointChunkOperationDomain,
                            plaintext: chunkBytes,
                            protection,
                            transaction: chunkTransaction,
                        },
                        lineageIdentifier,
                    );
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
            await stageCheckpointRuntimeRecordWrite(
                {
                    expectedCurrentSealedBytes:
                        previousManifest?.opened.sealedBytes ?? null,
                    logicalRecordKey: manifestRecordKey(lineageIdentifier),
                    operationDomain: checkpointManifestOperationDomain,
                    plaintext: manifestPlaintext,
                    protection,
                    transaction: manifestTransaction,
                },
                lineageIdentifier,
            );
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
                                const openedChunk =
                                    await readCheckpointRuntimeRecord(
                                        {
                                            logicalRecordKey:
                                                chunkRecordKeys[chunkIndex],
                                            operationDomain:
                                                checkpointChunkOperationDomain,
                                            protection,
                                            store: input.store,
                                        },
                                        lineageIdentifier,
                                    );
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
            await stageCheckpointRuntimeRecordWrite(
                {
                    expectedCurrentSealedBytes: null,
                    logicalRecordKey: journalRecordKey(lineageIdentifier),
                    operationDomain: checkpointJournalOperationDomain,
                    plaintext: journalPlaintext,
                    protection,
                    transaction: journalTransaction,
                },
                lineageIdentifier,
            );
            await journalTransaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(journalTransaction, error);
        } finally {
            journalPlaintext.fill(0);
        }
        await deleteAuthenticatedRecord({
            logicalRecordKey: manifestRecordKey(lineageIdentifier),
            observeOpenedRecord,
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

    const requirePhysicalAccountingScopeRecord = (
        scope: AuthenticatedCheckpointPhysicalAccountingScope,
    ): CheckpointPhysicalAccountingScopeRecord => {
        const record = physicalAccountingScopes.get(scope);
        if (record === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Checkpoint physical accounting requires a scope issued by this store.',
            );
        }
        return record;
    };

    const openPhysicalAccountingScope: AuthenticatedCheckpointStore['openPhysicalAccountingScope'] =
        async (checkpointLineageIdentifier) => {
            if (activePhysicalAccountingScopeRecord !== undefined) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'Checkpoint physical accounting already owns this store.',
                );
            }
            const lineageIdentifier = copyExactBytes(
                checkpointLineageIdentifier,
                identifierByteLength,
                'checkpointLineageIdentifier',
            );
            const lineageHex = bytesToHex(lineageIdentifier);
            const capacity = checkpointPhysicalAccountingCapacity(limits);
            let reservation:
                | UntrustedStorageExclusiveCapacityReservation
                | undefined;
            try {
                reservation = await input.store.reserveExclusiveCapacity({
                    ...capacity,
                    initialLogicalRecordKeyPrefixes: [
                        `checkpoint/manifest/${lineageHex}`,
                        `checkpoint/journal/${lineageHex}`,
                        `checkpoint/chunk/${lineageHex}/`,
                    ],
                });
                const scope = Object.freeze({
                    [authenticatedCheckpointPhysicalAccountingScopeBrand]:
                        true as const,
                });
                const record: CheckpointPhysicalAccountingScopeRecord = {
                    checkpointLineageIdentifier: lineageIdentifier,
                    openCallCount: 0,
                    openCiphertextByteLength: 0,
                    openPlaintextByteLength: 0,
                    reservation,
                    released: false,
                    sealCallCount: 0,
                    sealCiphertextByteLength: 0,
                    sealPlaintextByteLength: 0,
                };
                physicalAccountingScopes.set(scope, record);
                issuedPhysicalAccountingScopeRecords.add(record);
                activePhysicalAccountingScopeRecord = record;
                return scope;
            } catch (error) {
                if (reservation !== undefined) {
                    await reservation.release();
                }
                lineageIdentifier.fill(0);
                throw error;
            }
        };

    const copyPhysicalAccounting: AuthenticatedCheckpointStore['copyPhysicalAccounting'] =
        (scope): AuthenticatedCheckpointPhysicalAccountingSnapshot => {
            const record = requirePhysicalAccountingScopeRecord(scope);
            return Object.freeze({
                ...record.reservation.copyPhysicalStorageAccounting(),
                openCallCount: record.openCallCount,
                openCiphertextByteLength: record.openCiphertextByteLength,
                openPlaintextByteLength: record.openPlaintextByteLength,
                sealCallCount: record.sealCallCount,
                sealCiphertextByteLength: record.sealCiphertextByteLength,
                sealPlaintextByteLength: record.sealPlaintextByteLength,
            });
        };

    const releasePhysicalAccountingScope: AuthenticatedCheckpointStore['releasePhysicalAccountingScope'] =
        async (scope) => {
            const record = requirePhysicalAccountingScopeRecord(scope);
            if (record.released) {
                return;
            }
            if (activePhysicalAccountingScopeRecord !== record) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Checkpoint physical accounting scope is not the active store owner.',
                );
            }
            await record.reservation.release();
            record.released = true;
            activePhysicalAccountingScopeRecord = undefined;
        };

    const lifecycle = new ExclusiveResourceLifecycle({
        cleanup: async () => {
            if (
                activePhysicalAccountingScopeRecord !== undefined &&
                !activePhysicalAccountingScopeRecord.released
            ) {
                await activePhysicalAccountingScopeRecord.reservation.release();
                activePhysicalAccountingScopeRecord.released = true;
                activePhysicalAccountingScopeRecord = undefined;
            }
            await releaseRuntimeRecordProtection(protection);
            operationIdentities = new WeakMap();
            releasedOperationIdentities = new WeakSet();
            checkpointLineageReservations = new WeakMap();
            releasedCheckpointLineageReservations = new WeakSet();
            physicalAccountingScopes = new WeakMap();
            for (const identityRecord of issuedOperationIdentityRecords) {
                identityRecord.checkpointLineageIdentifier.fill(0);
                identityRecord.lastCanonicalManifestBytes?.fill(0);
                destroyBoundary(identityRecord.lastPublishedBoundary);
                identityRecord.privateRandomnessStreamAttemptIdentifier?.fill(
                    0,
                );
            }
            issuedOperationIdentityRecords.clear();
            for (const reservationRecord of issuedCheckpointLineageReservationRecords) {
                reservationRecord.checkpointLineageIdentifier.fill(0);
            }
            issuedCheckpointLineageReservationRecords.clear();
            for (const accountingRecord of issuedPhysicalAccountingScopeRecords) {
                accountingRecord.checkpointLineageIdentifier.fill(0);
            }
            issuedPhysicalAccountingScopeRecords.clear();
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
            bindCheckpointLineageToProofAttempt: (
                reservation,
                proofAttemptLineageIdentifier,
            ) =>
                lifecycle.run(owner, () =>
                    bindCheckpointLineageToProofAttempt(
                        reservation,
                        proofAttemptLineageIdentifier,
                    ),
                ),
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
            copyPhysicalAccounting: (scope) => {
                lifecycle.assertOpen(owner);
                return copyPhysicalAccounting(scope);
            },
            evict: (checkpointLineageIdentifier) =>
                lifecycle.run(owner, () => evict(checkpointLineageIdentifier)),
            openPhysicalAccountingScope: (checkpointLineageIdentifier) =>
                lifecycle.run(owner, () =>
                    openPhysicalAccountingScope(checkpointLineageIdentifier),
                ),
            publish: (publication) =>
                lifecycle.run(owner, () => publish(publication)),
            releaseOperationIdentity: (identity) =>
                lifecycle.run(owner, () => releaseOperationIdentity(identity)),
            releasePhysicalAccountingScope: (scope) =>
                lifecycle.run(owner, () =>
                    releasePhysicalAccountingScope(scope),
                ),
            releaseCheckpointLineageReservation: (reservation) =>
                lifecycle.run(owner, () =>
                    releaseCheckpointLineageReservation(reservation),
                ),
            repair: (checkpointLineageIdentifier) =>
                lifecycle.run(owner, () => repair(checkpointLineageIdentifier)),
            reserveCheckpointLineage: () =>
                lifecycle.run(owner, reserveCheckpointLineage),
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
