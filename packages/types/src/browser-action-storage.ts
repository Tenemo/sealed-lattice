export const browserActionStorageCustodyErrorCodes = Object.freeze([
    'Closed',
    'CommitmentMismatch',
    'CommitmentRequired',
    'Conflict',
    'InvalidCanonicalMaterial',
    'InvalidInput',
    'InvalidState',
    'OwnedWorkerFailure',
    'RecoveryAlreadyExported',
    'RecoveryConfirmationFailed',
    'StorageFailure',
    'Unavailable',
] as const);

export type BrowserActionStorageCustodyErrorCode =
    (typeof browserActionStorageCustodyErrorCodes)[number];

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

/** Complete public binding used by the Rust local-storage root commitment. */
export type BrowserActionStorageRootBinding = Readonly<{
    actionContextHash: Uint8Array;
    ceremonyContextHash: Uint8Array;
    participantId: Uint8Array;
    suiteId: Uint8Array;
}>;

/** A storage-root commitment supplied after external signature and context verification. */
export type ExternallyVerifiedStorageRootCommitment = Readonly<{
    storageRootCommitment: Uint8Array;
}>;

export type WorkerPreparedDeviceWrappingState = Readonly<{
    deviceKey: CryptoKey;
    storageRootCommitment: Uint8Array;
    wrappedStorageRoot: Uint8Array;
}>;

export type WorkerPreparedRecoveryState = WorkerPreparedDeviceWrappingState &
    Readonly<{
        canonicalRecoveryText: string;
    }>;

export type LocalStorageRecoveryExportMaterial = Readonly<{
    canonicalRecoveryText: string;
    recoveryChecksum: Uint8Array;
}>;

/** Cryptographic storage-root kernel retained by the dedicated worker. */
export type BrowserActionStorageWorkerKernel = Readonly<{
    createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState>;
    stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void>;
    stageRecoveryValueImportAndDeviceWrapping(input: {
        binding: BrowserActionStorageRootBinding;
        caseInsensitiveRecoveryText: string;
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
    }): Promise<WorkerPreparedRecoveryState>;
    commitStagedActionStorageRoot(input: {
        mutationIdentifier: Uint8Array;
    }): Promise<void>;
    discardStagedActionStorageRoot(): Promise<void>;
    destroyActiveActionStorageRoot(): Promise<void>;
    prepareRecoveryExport(input: {
        activeMutationIdentifier: Uint8Array;
    }): Promise<LocalStorageRecoveryExportMaterial>;
    confirmRecoveryChecksum(input: {
        canonicalRecoveryText: string;
        confirmedChecksum: Uint8Array;
    }): Promise<void>;
}>;
