export const browserActionStorageCustodyErrorCodes = Object.freeze([
    'Closed',
    'CommitmentMismatch',
    'CommitmentRequired',
    'Conflict',
    'InvalidCanonicalMaterial',
    'InvalidInput',
    'InvalidState',
    'OwnedWorkerFailure',
    'RecordAuthenticationFailed',
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

/** An untrusted expected commitment authenticated and recomputed by the owned worker. */
export type UntrustedExpectedStorageRootCommitment = Readonly<{
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

export type BrowserLocalRecordIdentifierInput =
    | Readonly<{ recordType: 'actionRandomness' }>
    | Readonly<{ recordType: 'publicCoinPrivateMaterial' }>
    | Readonly<{
          materialContextHash: Uint8Array;
          recordType: 'sourceVssMaterial';
      }>
    | Readonly<{
          recipientInputRoot: Uint8Array;
          recordType: 'aggregateThresholdShare';
      }>
    | Readonly<{
          applicationSlotHash: Uint8Array;
          recordType: 'proofAttempt';
      }>
    | Readonly<{
          ballotEncryptionAttemptIdentifier: Uint8Array;
          canonicalBallotStatementBytes: Uint8Array;
          recordType: 'ballotAttempt';
      }>
    | Readonly<{
          capabilityKind: number;
          exactOutputHash: Uint8Array;
          outputChunkIndex: bigint;
          recordType: 'exactOutputChunk';
      }>
    | Readonly<{
          recordType: 'subjectState';
          stateKey: Uint8Array;
      }>
    | Readonly<{
          recordType: 'witnessState';
          stateKey: Uint8Array;
      }>
    | Readonly<{
          checkpointLineageIdentifier: Uint8Array;
          operationKind: number;
          orderedSourceDigests: readonly Uint8Array[];
          recordType: 'checkpointManifest';
          runtimeBuildManifestHash: Uint8Array;
          safeBoundaryOrdinal: number;
      }>
    | Readonly<{
          checkpointIdentifier: Uint8Array;
          chunkDigest: Uint8Array;
          chunkIndex: number;
          recordType: 'checkpointChunk';
      }>;

export type BrowserLocalRecordExpectedContext = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    creationRecoveryEpoch: bigint;
    identifierInput: BrowserLocalRecordIdentifierInput;
    predecessorRecordHash?: Uint8Array;
    recordVersion: bigint;
}>;

export type BrowserLocalRecordSealInput = BrowserLocalRecordExpectedContext &
    Readonly<{
        plaintext: Uint8Array;
    }>;

export type BrowserLocalRecordOpenInput = BrowserLocalRecordExpectedContext &
    Readonly<{
        envelope: Uint8Array;
    }>;

/** Cryptographic storage-root kernel retained by the dedicated worker. */
export type BrowserActionStorageWorkerKernel = Readonly<{
    createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState>;
    stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void>;
    stageRecoveryValueImportAndDeviceWrapping(input: {
        binding: BrowserActionStorageRootBinding;
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
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
    deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array>;
    sealActiveLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array>;
    openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array>;
    hashActiveLocalRecordEnvelope(envelope: Uint8Array): Promise<Uint8Array>;
}>;
