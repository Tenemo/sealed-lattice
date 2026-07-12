import type { ExternallyVerifiedStorageRootCommitment } from '@sealed-lattice/types';

export { BrowserActionStorageCustodyError } from '@sealed-lattice/types';
export type {
    BrowserActionStorageCustodyErrorCode,
    BrowserActionStorageRootBinding,
    ExternallyVerifiedStorageRootCommitment,
} from '@sealed-lattice/types';

/**
 * Optimistic-concurrency metadata for one local wrapping pair. This snapshot
 * is not rollback protection, quorum authority, or one-shot authorization.
 */
export type BrowserDeviceWrappingSnapshot = Readonly<{
    mutationIdentifier: Uint8Array;
    recoveryValueExported: boolean;
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
