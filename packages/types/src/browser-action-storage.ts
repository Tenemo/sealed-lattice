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

export type BrowserAuthenticatedRepairProtectionInput = Readonly<{
    namespace: string;
    runtimeBuildManifestHash: Uint8Array;
}>;

export type WorkerOpenedBrowserAuthenticatedRepairProtection = Readonly<{
    repairIdentity: Uint8Array;
    repairProtectionSessionIdentifier: string;
}>;

export type BrowserFoundationWitnessProvisioningBinding = Readonly<{
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}>;

export type BrowserFoundationInitializationWitnessInput =
    BrowserFoundationWitnessProvisioningBinding;

export type BrowserFoundationInitializationPreparationInput = Readonly<{
    actionRandomnessRecordContext: BrowserActionRandomnessRecordContext;
    orderedWitnessBindings: readonly BrowserFoundationInitializationWitnessInput[];
    runtimeBuildManifestHash: Uint8Array;
}>;

/** Worker-only validated preparation input. */
export type WorkerBrowserFoundationInitializationPreparationInput = Readonly<{
    actionRandomnessRecordContext: BrowserActionRandomnessRecordContext;
    orderedWitnessBindings: readonly BrowserFoundationWitnessProvisioningBinding[];
    runtimeBuildManifestHash: Uint8Array;
}>;

/** Structured-clone-safe result retained only inside the custody channel. */
export type WorkerPreparedBrowserFoundationInitialization = Readonly<{
    actionRandomness: BrowserSealedActionRandomnessSession &
        Readonly<{
            envelopeHash: Uint8Array;
            localRecordIdentifier: Uint8Array;
        }>;
    witnessStateRecords: readonly Readonly<{
        authorizedEmptyPlaintext: Uint8Array;
        canonicalEnvelope: Uint8Array;
        envelopeHash: Uint8Array;
        localRecordIdentifier: Uint8Array;
        roleIndex: number;
        stateKey: Uint8Array;
    }>[];
}>;

/** Worker-only deterministic bindings used to authenticate a retained batch. */
export type WorkerDerivedBrowserFoundationInitializationRecords = Readonly<{
    actionRandomnessLocalRecordIdentifier: Uint8Array;
    witnessStateRecords: readonly Readonly<{
        authorizedEmptyPlaintext: Uint8Array;
        localRecordIdentifier: Uint8Array;
        roleIndex: number;
        stateKey: Uint8Array;
    }>[];
}>;

export type BrowserActionStateVerifierSessionInput = Readonly<{
    canonicalRosterBytes: Uint8Array;
}>;

export type BrowserActionStateReservationVerificationInput = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    capabilityKind: StateCapabilityKind;
    expectedAuthorizationHash: Uint8Array;
    stateVerifierSessionIdentifier: string;
    subjectParticipantIdentity: Uint8Array;
}>;

export type BrowserActionRandomnessReservationVerificationInput = Readonly<{
    actionRandomnessSessionIdentifier: string;
    canonicalReservationIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    stateVerifierSessionIdentifier: string;
}>;

export type BrowserStateObjectSignatureOperation = Readonly<{
    signStateObjectMessage(signatureMessageHash: Uint8Array): Uint8Array;
}>;

export type BrowserProducedActionRandomnessReservationIntent = Readonly<{
    canonicalReservationIntentCarrier: Uint8Array;
    stateIntentIdentifier: string;
}>;

export type BrowserProducedActionRandomnessReservation = Readonly<{
    canonicalStateCertificate: Uint8Array;
    stateReservationIdentifier: string;
}>;

export type BrowserActionRandomnessReservationIntentProductionInput = Readonly<{
    actionRandomnessSessionIdentifier: string;
    signatureOperation: BrowserStateObjectSignatureOperation;
    stateVerifierSessionIdentifier: string;
}>;

export type BrowserActionRandomnessReservationIntentWitnessVerificationInput =
    Readonly<{
        canonicalReservationIntentCarrier: Uint8Array;
        stateVerifierSessionIdentifier: string;
        subjectParticipantIdentity: Uint8Array;
    }>;

export type BrowserActionRandomnessReservationWitnessVoteProductionInput =
    Readonly<{
        signatureOperation: BrowserStateObjectSignatureOperation;
        stateIntentIdentifier: string;
        witnessParticipantIdentity: Uint8Array;
    }>;

export type BrowserActionRandomnessReservationCertificationInput = Readonly<{
    stateIntentIdentifier: string;
    untrustedVoteCarriers: readonly Uint8Array[];
}>;

export type BrowserActionRandomnessRecordContext = Readonly<{
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
      }>
    | Readonly<{
          commonProofEnvironmentIdentifier: Uint8Array;
          commonProofRuntimeBindingHash: Uint8Array;
          externalMemoryByteOffset: bigint;
          externalMemoryChunkOrdinal: number;
          externalMemoryObjectOrdinal: number;
          externalMemoryRecordKind:
              | 'object-header'
              | 'data-chunk'
              | 'seal-marker';
          proofAttemptLineageIdentifier: Uint8Array;
          recordType: 'commonProofExternalMemory';
      }>;

export type BrowserLocalRecordOpenableIdentifierInput = Exclude<
    BrowserLocalRecordIdentifierInput,
    Readonly<{ recordType: 'actionRandomness' }>
>;

export type BrowserLocalRecordExpectedContext = Readonly<{
    actionRandomnessCommitment: Uint8Array;
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
    commitStagedActionStorageRoot(): Promise<void>;
    discardStagedActionStorageRoot(): Promise<void>;
    destroyActiveActionStorageRoot(): Promise<void>;
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
    openActiveAuthenticatedRepairProtection(
        input: BrowserAuthenticatedRepairProtectionInput,
    ): Promise<WorkerOpenedBrowserAuthenticatedRepairProtection>;
    sealAuthenticatedRepairHead(input: {
        plaintext: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array>;
    openAuthenticatedRepairHead(input: {
        canonicalEnvelope: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array>;
    deriveAuthenticatedRepairHeadDigest(input: {
        sealedHeadBytes: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array>;
    closeAuthenticatedRepairProtection(identifier: string): Promise<void>;
    prepareBrowserFoundationInitialization(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerPreparedBrowserFoundationInitialization>;
    deriveBrowserFoundationInitializationRecords(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerDerivedBrowserFoundationInitializationRecords>;
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
}>;
