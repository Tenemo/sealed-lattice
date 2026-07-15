import type {
    BrowserActionProofAttemptBinding,
    BrowserActionRandomnessRecordContext,
    BrowserActionRandomnessReservationVerificationInput,
    BrowserActionStateReservationVerificationInput,
    BrowserActionStateVerifierSessionInput,
    BrowserOpenedActionRandomnessSession,
    BrowserPersistentProofAttemptInput,
    BrowserSealedActionRandomnessSession,
    BrowserTargetReleaseAttemptInput,
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    UntrustedExpectedStorageRootCommitment,
    VerificationResult,
} from '@sealed-lattice/types';

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
    BrowserPersistentProofAttemptInput,
    BrowserSealedActionRandomnessSession,
    BrowserTargetReleaseAttemptInput,
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    UntrustedExpectedStorageRootCommitment,
    VerificationResult,
} from '@sealed-lattice/types';

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
    derivePersistentProofAttempt(
        input: BrowserPersistentProofAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding>;
    deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding>;
    delete(expectedSnapshot: BrowserDeviceWrappingSnapshot): Promise<void>;
    close(): Promise<void>;
}>;
