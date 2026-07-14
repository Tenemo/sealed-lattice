import type {
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    UntrustedExpectedStorageRootCommitment,
} from '@sealed-lattice/types';

export { BrowserActionStorageCustodyError } from '@sealed-lattice/types';
export type {
    BrowserActionStorageCustodyErrorCode,
    BrowserActionStorageRootBinding,
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    UntrustedExpectedStorageRootCommitment,
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
 * main thread receives mutation metadata, explicitly confirmed recovery
 * material, and the local-record plaintext or envelope bytes it explicitly
 * requests. Device keys, wrapped root envelopes, plaintext roots, and root
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
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<void>;
    beginRecoveryExport(input: {
        expectedSnapshot: BrowserDeviceWrappingSnapshot;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<BrowserRecoveryExportChallenge>;
    confirmRecoveryExport(input: {
        preparationIdentifier: string;
        confirmedChecksum: Uint8Array;
    }): Promise<BrowserRecoveryExportConfirmation>;
    cancelRecoveryExport(preparationIdentifier: string): Promise<void>;
    recover(input: {
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        expectedSnapshot?: BrowserDeviceWrappingSnapshot;
    }): Promise<BrowserDeviceWrappingSnapshot>;
    deriveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array>;
    sealLocalRecord(input: BrowserLocalRecordSealInput): Promise<Uint8Array>;
    openLocalRecord(input: BrowserLocalRecordOpenInput): Promise<Uint8Array>;
    hashLocalRecordEnvelope(envelope: Uint8Array): Promise<Uint8Array>;
    delete(expectedSnapshot: BrowserDeviceWrappingSnapshot): Promise<void>;
    close(): Promise<void>;
}>;
