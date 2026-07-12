export type BrowserActionStorageCustodyErrorCode =
    | 'Closed'
    | 'CommitmentMismatch'
    | 'CommitmentRequired'
    | 'Conflict'
    | 'InvalidCanonicalMaterial'
    | 'InvalidInput'
    | 'InvalidState'
    | 'OwnedWorkerFailure'
    | 'RecoveryAlreadyExported'
    | 'RecoveryConfirmationFailed'
    | 'StorageFailure'
    | 'Unavailable';

export class BrowserActionStorageCustodyError extends Error {
    public readonly code: BrowserActionStorageCustodyErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: BrowserActionStorageCustodyErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'BrowserActionStorageCustodyError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

/**
 * Optimistic-concurrency metadata for one local wrapping pair. This snapshot
 * is not rollback protection, quorum authority, or one-shot authorization.
 */
export type BrowserDeviceWrappingSnapshot = Readonly<{
    mutationIdentifier: Uint8Array;
    recoveryValueExported: boolean;
    storageRootCommitment: Uint8Array;
}>;

/** Complete public binding used by the Rust local-storage root commitment. */
export type BrowserActionStorageRootBinding = Readonly<{
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    participantId: Uint8Array;
    suiteId: Uint8Array;
}>;

/**
 * Public commitment obtained from a signature- and context-verified
 * storage-root commitment object. Constructing this value is the caller's
 * explicit handoff from protocol verification into local custody.
 */
export type ExternallyVerifiedStorageRootCommitment = Readonly<{
    storageRootCommitment: Uint8Array;
}>;

export type BrowserRecoveryExportChallenge = Readonly<{
    preparationIdentifier: string;
    recoveryChecksum: Uint8Array;
}>;

export type BrowserRecoveryExportConfirmation = Readonly<{
    canonicalRecoveryText: string;
    snapshot: BrowserDeviceWrappingSnapshot;
}>;

/**
 * Structured-clone-safe custody commands exposed by the owned worker. The
 * main thread receives only mutation metadata and an explicitly confirmed
 * recovery value. Device keys, wrapped envelopes, plaintext roots, and root
 * handles never occur in this contract.
 */
export type BrowserActionStorageCustody = Readonly<{
    /**
     * Persists a fresh wrapping pair but leaves root access inactive. The
     * snapshot's public commitment is the proposal to sign and publish.
     */
    initialize(): Promise<BrowserDeviceWrappingSnapshot>;
    currentSnapshot(): Promise<BrowserDeviceWrappingSnapshot | undefined>;
    openIntoOwnedWorker(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
    }): Promise<void>;
    beginRecoveryExport(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
    }): Promise<BrowserRecoveryExportChallenge>;
    confirmRecoveryExport(input: {
        preparationIdentifier: string;
        confirmedChecksum: Uint8Array;
    }): Promise<BrowserRecoveryExportConfirmation>;
    cancelRecoveryExport(preparationIdentifier: string): Promise<void>;
    recover(input: {
        caseInsensitiveRecoveryText: string;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
        expectedSnapshot?: BrowserDeviceWrappingSnapshot;
    }): Promise<BrowserDeviceWrappingSnapshot>;
    delete(expectedSnapshot: BrowserDeviceWrappingSnapshot): Promise<void>;
    close(): Promise<void>;
}>;
