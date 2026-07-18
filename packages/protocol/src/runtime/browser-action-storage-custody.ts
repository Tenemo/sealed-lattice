import type {
    BrowserActionProofAttemptBinding,
    BrowserActionRandomnessRecordContext,
    BrowserActionRandomnessReservationVerificationInput,
    BrowserActionStateReservationVerificationInput,
    BrowserActionStateVerifierSessionInput,
    BrowserActionStorageRootBinding,
    BrowserOpenedActionRandomnessSession,
    BrowserSealedActionRandomnessSession,
    BrowserTargetReleaseAttemptInput,
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    BrowserFoundationInitializationPreparationInput,
    UntrustedExpectedStorageRootCommitment,
    VerificationResult,
} from '@sealed-lattice/types';

import type {
    CheckpointBoundary,
    ExpectedCheckpointBoundary,
} from './authenticated-checkpoint-store.js';

export { BrowserActionStorageCustodyError } from '@sealed-lattice/types';
export type {
    BrowserActionStorageCustodyErrorCode,
    BrowserActionStorageRootBinding,
    BrowserActionProofAttemptBinding,
    BrowserActionRandomnessRecordContext,
    BrowserActionRandomnessReservationVerificationInput,
    BrowserActionStateReservationVerificationInput,
    BrowserActionStateVerifierSessionInput,
    BrowserOpenedActionRandomnessSession,
    BrowserSealedActionRandomnessSession,
    BrowserTargetReleaseAttemptInput,
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    BrowserFoundationInitializationPreparationInput,
    UntrustedExpectedStorageRootCommitment,
    VerificationResult,
} from '@sealed-lattice/types';

declare const preparedBrowserFoundationInitializationBrand: unique symbol;
declare const committedBrowserFoundationInitializationBatchBrand: unique symbol;
declare const browserFoundationCheckpointHandleBrand: unique symbol;

export type PreparedBrowserFoundationInitialization = Readonly<{
    readonly [preparedBrowserFoundationInitializationBrand]: true;
}>;

export type CommittedBrowserFoundationInitializationBatch = Readonly<{
    readonly [committedBrowserFoundationInitializationBatchBrand]: true;
}>;

/**
 * Authenticated local-head metadata for optimistic concurrency inside the
 * currently retained storage instance. It is rollbackable with that storage
 * and is not a recency certificate, quorum decision, or release authority.
 */
export type BrowserFoundationFreshnessCoordinate = Readonly<{
    authenticatedHeadDigest: Uint8Array;
    freshnessSequence: bigint;
    storageInstanceIdentity: Uint8Array;
}>;

export type BrowserFoundationCheckpointHandle = Readonly<{
    readonly [browserFoundationCheckpointHandleBrand]: true;
}>;

export type BrowserFoundationCheckpointDescription = Readonly<{
    canonicalManifestBytes?: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    stateStreamDescriptorBytes?: Uint8Array;
}>;

export type BrowserFreshFoundationInitializationCommit = Readonly<{
    committedBatch: CommittedBrowserFoundationInitializationBatch;
    freshnessCoordinate: BrowserFoundationFreshnessCoordinate;
}>;

/**
 * Optimistic-concurrency metadata for one local wrapping pair. This snapshot
 * is not rollback protection, quorum authority, or one-shot authorization.
 */
export type BrowserDeviceWrappingSnapshot = Readonly<{
    mutationIdentifier: Uint8Array;
    storageRootCommitment: Uint8Array;
}>;

/**
 * Structured-clone-safe custody commands exposed by the owned worker. The
 * main thread receives mutation metadata and the local-record plaintext or
 * envelope bytes it explicitly requests. Device keys, wrapped root envelopes,
 * plaintext roots, and root handles never occur in this contract.
 */
export type BrowserActionStorageCustody = Readonly<{
    copyBinding(): BrowserActionStorageRootBinding;
    /**
     * Persists a fresh wrapping pair but leaves root access inactive. The
     * snapshot's public commitment is the proposal to sign and publish.
     */
    initialize(): Promise<BrowserDeviceWrappingSnapshot>;
    currentSnapshot(): Promise<BrowserDeviceWrappingSnapshot | undefined>;
    openIntoOwnedWorker(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<void>;
    deriveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array>;
    sealLocalRecord(input: BrowserLocalRecordSealInput): Promise<Uint8Array>;
    openLocalRecord(input: BrowserLocalRecordOpenInput): Promise<Uint8Array>;
    hashLocalRecordEnvelope(envelope: Uint8Array): Promise<Uint8Array>;
    openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>>;
    verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>>;
    verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>>;
    releaseActionStateObject(identifier: string): Promise<void>;
    closeActionStateVerifierSession(identifier: string): Promise<void>;
    createAndSealActionRandomness(
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserSealedActionRandomnessSession>;
    openSealedActionRandomness(
        input: BrowserActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession>;
    closeActionRandomness(identifier: string): Promise<void>;
    deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding>;
    delete(expectedSnapshot: BrowserDeviceWrappingSnapshot): Promise<void>;
    /** Permanently replaces this action's local wrapping state with a tombstone. */
    retire(): Promise<void>;
    close(): Promise<void>;
}>;

export type BrowserFoundationStorageAuthority = BrowserActionStorageCustody &
    Readonly<{
        authenticateFoundationHead(): Promise<BrowserFoundationFreshnessCoordinate>;
        beginCheckpoint(
            privateRandomnessStreamAttemptIdentifier?: Uint8Array,
        ): Promise<BrowserFoundationCheckpointHandle>;
        copyCheckpointDescription(
            checkpoint: BrowserFoundationCheckpointHandle,
        ): Promise<BrowserFoundationCheckpointDescription>;
        commitFreshFoundationInitialization(
            input: BrowserFoundationInitializationPreparationInput,
        ): Promise<BrowserFreshFoundationInitializationCommit>;
        evictCheckpoint(
            checkpoint: BrowserFoundationCheckpointHandle,
        ): Promise<void>;
        publishCheckpoint(
            checkpoint: BrowserFoundationCheckpointHandle,
            input: {
                boundary: CheckpointBoundary;
                stateChunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>;
            },
        ): Promise<Uint8Array>;
        restoreCheckpointState(
            checkpoint: BrowserFoundationCheckpointHandle,
            consumeChunk: (
                chunkIndex: number,
                chunkBytes: Uint8Array,
            ) => Promise<void> | void,
        ): Promise<void>;
        resumeCheckpoint(input: {
            checkpointLineageIdentifier: Uint8Array;
            expectedBoundary: ExpectedCheckpointBoundary;
        }): Promise<BrowserFoundationCheckpointHandle>;
    }>;

export type TransferableBrowserFoundationStorageAuthority =
    BrowserFoundationStorageAuthority &
        Readonly<{
            claimExclusiveOwner(): BrowserFoundationStorageAuthority;
        }>;
