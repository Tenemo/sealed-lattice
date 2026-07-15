import type {
    StateCapabilityKind,
    VerificationResult,
} from './foundation-contract.js';

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

export type BrowserActionStateVerifierSessionInput = Readonly<{
    canonicalRosterBytes: Uint8Array;
    maximumRecoveryTransitionsPerStateKey: number;
}>;

export type BrowserActionStateReservationVerificationInput = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    capabilityKind: StateCapabilityKind;
    expectedAuthorizationHash: Uint8Array;
    stateVerifierSessionIdentifier: string;
    subjectParticipantIdentity: Uint8Array;
    verifiedPredecessorRecoveryIdentifier?: string;
}>;

export type BrowserActionRandomnessReservationVerificationInput = Readonly<{
    actionRandomnessSessionIdentifier: string;
    canonicalReservationIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    stateVerifierSessionIdentifier: string;
    verifiedPredecessorRecoveryIdentifier?: string;
}>;

export type BrowserActionStateRecoveryVerificationInput = Readonly<{
    canonicalRecoveryTransitionCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    capabilityKind: StateCapabilityKind;
    stateVerifierSessionIdentifier: string;
    subjectParticipantIdentity: Uint8Array;
    verifiedPredecessorRecoveryIdentifier?: string;
}>;

export type BrowserActionRandomnessRecordContext = Readonly<{
    creationRecoveryEpoch: bigint;
    predecessorRecordHash?: Uint8Array;
    recordVersion: bigint;
}>;

export type BrowserSealedActionRandomnessSession = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    actionRandomnessSessionIdentifier: string;
    canonicalEnvelope: Uint8Array;
}>;

export type BrowserOpenedActionRandomnessSession = Omit<
    BrowserSealedActionRandomnessSession,
    'canonicalEnvelope'
>;

export type BrowserActionProofAttemptBinding = Readonly<{
    applicationSlotHash: Uint8Array;
    attemptIdentifier: Uint8Array;
}>;

export type BrowserPersistentProofAttemptInput = Readonly<{
    actionRandomnessSessionIdentifier: string;
    applicationStatementHash: Uint8Array;
    rosterPosition: number;
    schedulePosition?: number;
    stateReservationIdentifier: string;
    statementSchemaIdentifier: number;
}>;

export type BrowserTargetReleaseAttemptInput = Readonly<{
    actionRandomnessSessionIdentifier: string;
    rosterPosition: number;
    stateReservationIdentifier: string;
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

export type BrowserLocalRecordOpenableIdentifierInput = Exclude<
    BrowserLocalRecordIdentifierInput,
    Readonly<{ recordType: 'actionRandomness' }>
>;

export type BrowserLocalRecordExpectedContext = Readonly<{
    actionRandomnessCommitment: Uint8Array;
    creationRecoveryEpoch: bigint;
    identifierInput: BrowserLocalRecordOpenableIdentifierInput;
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
    openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>>;
    verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>>;
    verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>>;
    verifyActionStateRecovery(
        input: BrowserActionStateRecoveryVerificationInput,
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
}>;
