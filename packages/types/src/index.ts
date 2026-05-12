export type BaseClaimProfile =
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult';

export type MheSecurityStage = 'PassiveMHEPrototype' | 'ActiveMalicious';

/**
 * Alias retained for backward compatibility with consumers that read
 * the transcript-core fixture shape. Prefer {@link MheSecurityStage}.
 */
export type TranscriptCoreMheSecurityStage = MheSecurityStage;

export type TranscriptCoreStatusLabel = 'TranscriptCoreVerified';

export type TranscriptCoreVerificationLabel =
    | 'TranscriptCoreVerified'
    | 'TranscriptCoreRejected';

export const canonicalErrorCodeValues = [
    'DuplicateField',
    'FieldOrder',
    'FixtureMismatch',
    'InvalidChunkSize',
    'InvalidEnum',
    'InvalidFixture',
    'InvalidHex',
    'InvalidUtf8',
    'MalformedLength',
    'MalformedMagic',
    'MalformedVarUint',
    'MissingField',
    'NonCanonicalVarUint',
    'ProfileComponentMismatch',
    'TrailingBytes',
    'UnknownBaseClaimProfile',
    'UnknownField',
    'UnknownMheSecurityStage',
    'UnknownProofProfile',
    'UnsupportedCanonicalEnvelopeVersion',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
] as const;

export type CanonicalErrorCode = (typeof canonicalErrorCodeValues)[number];

export type CanonicalError = {
    readonly code: CanonicalErrorCode;
    readonly message: string;
};

export type GoldenTranscriptCoreFixture = {
    readonly kind: 'golden-transcript-core';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly baseClaimProfile: BaseClaimProfile;
    readonly mheSecurityStage: MheSecurityStage;
    readonly baseClaimProfileId: string;
    readonly mheSecurityProfileId: string;
    readonly heSetupProofProfileId: string;
    readonly evaluationProofProfileId: string;
    readonly decryptionProofProfileId: string;
    readonly expectedObjectHash512: string;
    readonly expectedChunkRoot: string;
    readonly chunkSize: number;
    readonly expectedStatusLabels: readonly TranscriptCoreStatusLabel[];
};

export type MalformedObjectFixture = {
    readonly kind: 'malformed-object';
    readonly fixtureVersion: 1;
    readonly caseName: string;
    readonly canonicalBytesHex: string;
    readonly expectedErrorCode: CanonicalErrorCode;
};

export type TranscriptCoreFixture =
    | GoldenTranscriptCoreFixture
    | MalformedObjectFixture;

export type TranscriptCoreReplayFixture = {
    readonly schemaVersion: 1;
    readonly caseName: string;
    readonly fixture: GoldenTranscriptCoreFixture;
    readonly expectedStatusLabels: readonly TranscriptCoreStatusLabel[];
};

export type TranscriptCoreAnalysis = {
    readonly canonicalBytesHex: string;
    readonly objectType: 'TranscriptCore';
    readonly objectVersion: 1;
    readonly baseClaimProfile: BaseClaimProfile;
    readonly mheSecurityStage: MheSecurityStage;
    readonly baseClaimProfileId: string;
    readonly mheSecurityProfileId: string;
    readonly heSetupProofProfileId: string;
    readonly evaluationProofProfileId: string;
    readonly decryptionProofProfileId: string;
    readonly objectHash512: string;
    readonly chunkRoot: string;
    readonly chunkSize: number;
    readonly statusLabels: readonly TranscriptCoreStatusLabel[];
    readonly title: string;
    readonly sequence: number;
    readonly payloadHex: string;
    readonly tags: readonly string[];
    readonly checkpoints: readonly number[];
};

export type GoldenTranscriptCoreFixtureVerification = {
    readonly verified: true;
    readonly caseName: string;
    readonly objectHash512: string;
    readonly chunkRoot: string;
    readonly statusLabels: readonly TranscriptCoreStatusLabel[];
};

export type MalformedObjectFixtureVerification = {
    readonly verified: true;
    readonly caseName: string;
    readonly expectedErrorCode: CanonicalErrorCode;
};

export type TranscriptCoreFixtureVerification =
    | GoldenTranscriptCoreFixtureVerification
    | MalformedObjectFixtureVerification;

export type TranscriptCoreVerificationResult = {
    readonly caseName: string;
    readonly label: TranscriptCoreVerificationLabel;
    readonly statusLabels: readonly TranscriptCoreStatusLabel[];
    readonly objectHash512?: string;
    readonly chunkRoot?: string;
    readonly rejection?: {
        readonly code: CanonicalErrorCode;
    };
};

export type ResultClaimLabel =
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult';

export type EvaluationProofMode =
    | 'NoOptionalEvaluationProof'
    | 'OptionalEvaluationProofPresent'
    | 'OptionalEvaluationProofVerified';

export type HeBackendCorruptionModel =
    | {
          readonly kind: 'StrictLessThanOneThird';
      }
    | {
          readonly kind: 'CertifiedCustom';
          readonly backendCorruptionBound: number;
          readonly certificateDigest: string;
      };

export type ThresholdProfileInput = {
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly unsafeMicroRosterAcknowledged?: boolean;
};

export type RosterProfileKind =
    | 'UnsafeMicroRoster'
    | 'MandatoryN20'
    | 'CertificateGatedRange';

export type ThresholdWarning =
    | 'UnsafeMicroRoster'
    | 'CertificateGatedProfile'
    | 'BackendCertificateRequired'
    | 'BackendCorruptionBoundTooHigh';

export type ThresholdProfile = {
    readonly rosterSize: number;
    readonly rosterProfileKind: RosterProfileKind;
    readonly claimBearing: boolean;
    readonly structuralCorruptionBound: number;
    readonly backendCorruptionBound: number;
    readonly privacyCorruptionBound: number;
    readonly decryptionCorruptionBound: number;
    readonly activeFaultBound: number;
    readonly replayBadCorruptionBound: number;
    readonly pvssThreshold: number;
    readonly decryptionThreshold: number;
    readonly releaseQuorum: number;
    readonly aggregateContributionQuorum: number;
    readonly decryptionShareQuorum: number;
    readonly evaluationReplayQuorum: number;
    readonly maximumRaceShares: number;
    readonly setupCompletionQuorum: number;
    readonly backendCorruptionModel: HeBackendCorruptionModel;
    readonly warnings: readonly ThresholdWarning[];
};

export type ScoreDomain = {
    readonly min: 1;
    readonly max: 10;
    readonly skippedOptionScore: 1;
};

export type DuplicateBallotPolicy = 'LastValidBeforeVotingClosedCounts';

export type TiePolicy = 'HigherScoreThenLowerOptionIndex';

export type PollSpecInput = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly scoreDomain?: ScoreDomain;
    readonly duplicateBallotPolicy?: DuplicateBallotPolicy;
    readonly tiePolicy?: TiePolicy;
};

export type PollSpec = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly scoreDomain: ScoreDomain;
    readonly duplicateBallotPolicy: DuplicateBallotPolicy;
    readonly tiePolicy: TiePolicy;
};

export type PollSpecValidationErrorCode =
    | 'EmptyPollId'
    | 'EmptyQuestion'
    | 'InvalidOptionCount'
    | 'EmptyOptionLabel'
    | 'DuplicateOptionLabel'
    | 'InvalidTopOptionCount'
    | 'UnsupportedScoreDomain'
    | 'UnsupportedDuplicateBallotPolicy'
    | 'UnsupportedTiePolicy';

export type PollSpecValidationError = {
    readonly code: PollSpecValidationErrorCode;
    readonly field: string;
    readonly message: string;
};

export type PollSpecValidation =
    | {
          readonly ok: true;
          readonly normalized: PollSpec;
      }
    | {
          readonly ok: false;
          readonly errors: readonly PollSpecValidationError[];
      };

export type LifecycleState =
    | 'DraftPoll'
    | 'RegistrationOpen'
    | 'TrusteeSetupOpen'
    | 'RegistrationClosed'
    | 'RosterFrozen'
    | 'VotingOpen'
    | 'VotingClosed'
    | 'AwaitingAggregateContributors'
    | 'AggregateInputsReady'
    | 'AwaitingMobileEvaluation'
    | 'TopKEvaluated'
    | 'EvaluationReplayOpen'
    | 'EvaluationReplayAttested'
    | 'OptionalEvaluationProofVerified'
    | 'EvaluationRejected'
    | 'TargetAccepted'
    | 'AwaitingFirstDecryptionShares'
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult'
    | 'Unresolved'
    | 'ForkedElection';

export type PrimaryStatusLabel =
    | 'RosterAudited'
    | 'BallotIncluded'
    | 'BridgeProofPending'
    | 'BridgeProofLocallyVerified'
    | 'AggregateInputsReady'
    | 'AggregateInputsBridgeVerified'
    | 'TopKEvaluated'
    | 'EvaluationLocallyReplayed'
    | 'EvaluationReplayAttested'
    | 'OptionalEvaluationProofVerified'
    | 'TargetAccepted'
    | 'FirstThresholdSharesReached'
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult'
    | 'Unresolved';

export type FailureStatusLabel =
    | 'BoardForkSuspected'
    | 'BoardEvidencePublished'
    | 'ForkedElection'
    | 'SetupIncomplete'
    | 'TurnoutBelowReleaseFloor'
    | 'AggregateThresholdNotReached'
    | 'EvaluationReplayThresholdNotReached'
    | 'MobileEvaluationPending'
    | 'BridgeProofRejected'
    | 'OptionalEvaluationProofRejected'
    | 'EvaluationRejected'
    | 'TargetRejected'
    | 'CPADProfileRejected'
    | 'AnyTDecryptionProfileRejected'
    | 'BrakerskiBackendProfileRejected'
    | 'EvaluationKeySizeProfileRejected'
    | 'MobileReplayProfileRejected'
    | 'BridgeMobileCertRejected'
    | 'UnsupportedLowResourceDevice';

export type ModeStatusLabel =
    | 'UnsafeMicroRoster'
    | 'PassiveMHEPrototype'
    | 'MobileFlagshipProfile'
    | 'ForegroundProofGenerationRequired'
    | 'ForegroundProofVerificationRequired'
    | 'ProofCheckpointRestored'
    | 'ProofCheckpointRejected'
    | 'LongRunningCryptographicCheck';

export type LifecycleTransition = {
    readonly from: LifecycleState;
    readonly to: LifecycleState;
};

export type LifecycleLabelInput = {
    readonly lifecycleState: LifecycleState;
    readonly thresholdProfile: ThresholdProfile;
    readonly mheSecurityStage?: MheSecurityStage;
    readonly evaluationProofMode?: EvaluationProofMode;
    readonly rosterAudited?: boolean;
    readonly ownBallotIncluded?: boolean;
    readonly evaluationLocallyReplayed?: boolean;
    readonly bridgeProofPending?: boolean;
    readonly bridgeProofLocallyVerified?: boolean;
    readonly aggregateInputsBridgeVerified?: boolean;
    readonly bridgeProofRejected?: boolean;
    readonly brakerskiBackendProfileRejected?: boolean;
    readonly bridgeMobileCertRejected?: boolean;
    readonly unsupportedLowResourceDevice?: boolean;
    readonly mobileFlagshipProfile?: boolean;
    readonly foregroundProofGenerationRequired?: boolean;
    readonly foregroundProofVerificationRequired?: boolean;
    readonly proofCheckpointRestored?: boolean;
    readonly proofCheckpointRejected?: boolean;
    readonly longRunningCryptographicCheck?: boolean;
    readonly bridgeMobileCertificatePresent?: boolean;
    readonly bridgeProverCertificatePresent?: boolean;
    readonly brakerskiMobileProofCertificatePresent?: boolean;
    readonly mobileClaimGatePassed?: boolean;
};

export type LifecycleLabels = {
    readonly primary: readonly PrimaryStatusLabel[];
    readonly failures: readonly FailureStatusLabel[];
    readonly modes: readonly ModeStatusLabel[];
    readonly resultClaimLabel?: ResultClaimLabel;
    readonly evaluationProofMode: EvaluationProofMode;
};

export type ProtocolAction =
    | 'CreatePoll'
    | 'OpenRegistration'
    | 'CreateRegistrationEntry'
    | 'CreateTrusteeSetupEntry'
    | 'CloseRegistration'
    | 'FreezeRoster'
    | 'OpenVoting'
    | 'SubmitVote'
    | 'CloseVoting'
    | 'DeriveAggregateContribution'
    | 'ReplayEvaluation'
    | 'AttestReplay'
    | 'AcceptTarget'
    | 'CreateTargetBoundDecryptionShare'
    | 'VerifyDecryptionShare'
    | 'RecombineAcceptedTarget'
    | 'DecodeVerifiedTopK'
    | 'CreateRecoveryEpochUpdate'
    | 'VerifyEncryptedEnvelope';

export type RecoveryState =
    | 'NotRequired'
    | 'Ready'
    | 'Ambiguous'
    | 'StaleEpoch'
    | 'ClonedDeviceSuspected'
    | 'MissingRecoveryMaterial';

export type CapabilityContext = {
    readonly lifecycleState: LifecycleState;
    readonly thresholdProfile: ThresholdProfile;
    readonly pollSpecValid: boolean;
    readonly setupCompleteCount?: number;
    readonly turnoutCount?: number;
    readonly replayAttestationCount?: number;
    readonly decryptionShareCount?: number;
    readonly targetFinalityAccepted?: boolean;
    readonly targetAccepted?: boolean;
    readonly optionalEvaluationProofVerified?: boolean;
    readonly localReplaySucceeded?: boolean;
    readonly browserSupported?: boolean;
    readonly mobileProfileSupported?: boolean;
    readonly storageQuotaSufficient?: boolean;
    readonly bridgeMobileCertificatePresent?: boolean;
    readonly bridgeProverCertificatePresent?: boolean;
    readonly brakerskiMobileProofCertificatePresent?: boolean;
    readonly recoveryState?: RecoveryState;
};

export type RefusalReason =
    | 'OperationUnavailable'
    | 'InvalidLifecycleState'
    | 'PollSpecInvalid'
    | 'ProfileNotClaimBearing'
    | 'SetupIncomplete'
    | 'TurnoutBelowReleaseFloor'
    | 'AggregateThresholdNotReached'
    | 'EvaluationReplayThresholdNotReached'
    | 'LocalReplayNotVerified'
    | 'TargetFinalityCheckpointMissing'
    | 'TargetNotAccepted'
    | 'FirstThresholdSharesNotReached'
    | 'UnsupportedBrowserContext'
    | 'UnsupportedMobileProfile'
    | 'InsufficientStorageQuota'
    | 'MissingBridgeMobileCertificate'
    | 'MissingBridgeProverCertificate'
    | 'MissingBrakerskiMobileProofCertificate'
    | 'AmbiguousRecoveryState'
    | 'StaleRecoveryEpoch'
    | 'ClonedDeviceState'
    | 'ForbiddenOperation';

export type CapabilityDecision =
    | {
          readonly allowed: true;
          readonly action: ProtocolAction;
      }
    | {
          readonly allowed: false;
          readonly action: ProtocolAction;
          readonly reason: RefusalReason;
      };

export type ProtocolDigest = string;

export type ProtocolObjectType =
    | 'ActionContext'
    | 'BoardHead'
    | 'CastReceipt'
    | 'CloseRecord'
    | 'ElectionManifest'
    | 'EvaluationReplayAttestation'
    | 'FirstComeOrder'
    | 'RecoveryEpochUpdate'
    | 'ReceiverKeyRegistration'
    | 'RegistrationEntry'
    | 'Roster'
    | 'TargetAcceptedRecord'
    | 'TargetFinalityRecord'
    | 'TopKDecryptionShare'
    | 'TopKEvaluationRecord'
    | 'TrusteeSetupEntry'
    | 'WitnessCheckpoint';

export type SignedObjectType =
    | 'BoardHead'
    | 'CastReceipt'
    | 'CloseRecord'
    | 'ElectionManifest'
    | 'EvaluationReplayAttestation'
    | 'RecoveryEpochUpdate'
    | 'ReceiverKeyRegistration'
    | 'RegistrationEntry'
    | 'TargetAcceptedRecord'
    | 'TargetFinalityRecord'
    | 'TopKDecryptionShare'
    | 'TrusteeSetupEntry'
    | 'WitnessCheckpoint';

export type SignerRole =
    | 'Board'
    | 'Organizer'
    | 'Participant'
    | 'RecoveryRoot'
    | 'Trustee'
    | 'Voter'
    | 'Witness';

export type MlDsaSignatureMode = 'PureMLDSA' | 'HashMLDSA' | 'ExternalMuMLDSA';

export type MlDsaSignatureProfile = {
    readonly algorithm: 'ML-DSA-65';
    readonly mode: MlDsaSignatureMode;
    readonly providerName: string;
    readonly providerVersion: string;
    readonly providerBuildHash: ProtocolDigest;
    readonly fips204Version: string;
    readonly errataStatus: string;
    readonly contextString: string;
    readonly contextStringByteLength: number;
};

export type CanonicalSignedRootObject = {
    readonly objectType: SignedObjectType;
    readonly objectVersion: number;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolDigest | null;
    readonly boardHeadHash: ProtocolDigest | null;
    readonly objectRoot: ProtocolDigest | null;
    readonly chunkMerkleRoot: ProtocolDigest | null;
    readonly byteLength: number;
    readonly signerRole: SignerRole;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextDigest: ProtocolDigest;
};

export type ProtocolSignatureEnvelope = {
    readonly profile: MlDsaSignatureProfile;
    readonly publicKeyDigest: ProtocolDigest;
    readonly publicKeyBytesHex: string;
    readonly signedRoot: CanonicalSignedRootObject;
    readonly signatureBytesHex: string;
    readonly signatureDigest: ProtocolDigest;
};

export type ProtocolVerificationStatusLabel =
    | PrimaryStatusLabel
    | FailureStatusLabel
    | ModeStatusLabel;

export type ProtocolRefusalCode =
    | 'BoardConsistencyFailure'
    | 'BoardForkDetected'
    | 'CastReceiptInvalid'
    | 'CloseRecordInvalid'
    | 'ConflictingFirstComeCandidate'
    | 'ConflictingManifest'
    | 'DecryptionShareInvalid'
    | 'DuplicateReceiverKeyRegistration'
    | 'DuplicateFirstComeCandidate'
    | 'DuplicateRegistration'
    | 'DuplicateTrusteeSetupEntry'
    | 'DuplicateWitness'
    | 'FirstComeContextMismatch'
    | 'FirstComePolicyMismatch'
    | 'InclusionProofInvalid'
    | 'InvalidMlDsaContext'
    | 'InvalidSignature'
    | 'InvalidSignedRoot'
    | 'LateRegistration'
    | 'ManifestDigestMismatch'
    | 'MissingReceiverKeyRegistration'
    | 'MissingTrusteeSetupEntry'
    | 'RecoveryUpdateConflict'
    | 'RecoveryUpdateInvalid'
    | 'RecoveryUpdateStale'
    | 'ReplayAttestationInvalid'
    | 'RosterDigestMismatch'
    | 'TargetAcceptedRecordInvalid'
    | 'TargetFinalityPolicyMismatch'
    | 'TargetPhaseAuthorizationFailure'
    | 'TopKEvaluationRecordNotIncluded'
    | 'StaleRecoveryEpoch'
    | 'UnknownBoardHead'
    | 'UnknownRecoveryEpoch'
    | 'UnknownWitness'
    | 'WitnessPolicyMismatch'
    | 'WitnessQuorumNotReached'
    | 'WrongCeremony'
    | 'WrongObjectType'
    | 'WrongPublicKey'
    | 'WrongSignerRole';

export type RefusalRecord = {
    readonly code: ProtocolRefusalCode;
    readonly message: string;
    readonly objectDigest?: ProtocolDigest;
    readonly objectType?: ProtocolObjectType | SignedObjectType;
};

export type ConflictingHeadEvidence = {
    readonly evidenceDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly leftBoardHeadDigest: ProtocolDigest;
    readonly rightBoardHeadDigest: ProtocolDigest;
    readonly targetPhase?: string;
    readonly equivocatingWitnessIdentities?: readonly string[];
};

export type StructuredProtocolVerificationResult = {
    readonly ok: boolean;
    readonly statusLabels: readonly ProtocolVerificationStatusLabel[];
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly RefusalRecord[];
    readonly forkEvidence?: ConflictingHeadEvidence;
    readonly unresolvedReason?: string;
};

export type SignatureVerificationResult = StructuredProtocolVerificationResult;

export type SignedBoardHead = {
    readonly objectType: 'BoardHead';
    readonly objectVersion: 1;
    readonly headDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly boardSeq: number;
    readonly boardRoot: ProtocolDigest;
    readonly previousHeadDigest: ProtocolDigest | null;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

export type InclusionProof = {
    readonly boardHeadDigest: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly includedObjectType: ProtocolObjectType;
    readonly includedObjectDigest: ProtocolDigest;
    readonly boardEntryDigest: ProtocolDigest;
    readonly boardRoot: ProtocolDigest;
    readonly boardEntryDigests: readonly ProtocolDigest[];
    readonly inclusionProofDigest: ProtocolDigest;
};

export type AppendOnlyConsistencyProof = {
    readonly proofType: 'SignedHeadChain';
    readonly fromBoardHeadDigest: ProtocolDigest | null;
    readonly toBoardHeadDigest: ProtocolDigest;
    readonly signedBoardHeads: readonly SignedBoardHead[];
};

export type BoardConsistencyInput = {
    readonly ceremonyId: string;
    readonly boardPolicyDigest: ProtocolDigest;
    readonly signedBoardHeads: readonly SignedBoardHead[];
    readonly expectedBoardPublicKeyDigest: ProtocolDigest;
    readonly inclusionProofs?: readonly InclusionProof[];
    readonly consistencyProofs?: readonly AppendOnlyConsistencyProof[];
    readonly conflictingHeadEvidence?: readonly ConflictingHeadEvidence[];
};

export type BoardConsistencyVerification =
    StructuredProtocolVerificationResult & {
        readonly verifiedHeadDigests: readonly ProtocolDigest[];
    };

export type CastReceipt = {
    readonly objectType: 'CastReceipt';
    readonly objectVersion: 1;
    readonly castReceiptDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly voterIdentity: string;
    readonly ballotPackageDigest: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly contextDigest: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

export type CloseRecordKind = 'RegistrationClosed' | 'VotingClosed';

export type CloseRecord = {
    readonly objectType: 'CloseRecord';
    readonly objectVersion: 1;
    readonly closeRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly closeKind: CloseRecordKind;
    readonly closedBoardHeadDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest | null;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly organizerIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

export type CastReceiptVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly receipt: CastReceipt;
    readonly receiptInclusionProof: InclusionProof;
    readonly expectedElectionManifestDigest: ProtocolDigest;
    readonly expectedVoterPublicKeyDigest: ProtocolDigest;
};

export type CastReceiptVerification = StructuredProtocolVerificationResult & {
    readonly castReceiptDigest?: ProtocolDigest;
};

export type CloseRecordVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly closeRecord: CloseRecord;
    readonly closeRecordInclusionProof: InclusionProof;
    readonly expectedElectionManifestDigest: ProtocolDigest;
    readonly expectedOrganizerIdentity: string;
    readonly expectedOrganizerPublicKeyDigest: ProtocolDigest;
};

export type CloseRecordVerification = StructuredProtocolVerificationResult & {
    readonly closeRecordDigest?: ProtocolDigest;
    readonly postVotingClosedContextDigest?: ProtocolDigest;
};

export type WitnessPolicy = {
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly witnessIdentities: readonly string[];
    readonly witnessQuorum: number;
    readonly totalWitnesses: number;
};

export type TargetFinalityPolicy = {
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly targetPhase: string;
    readonly witnessQuorum: number;
    readonly totalWitnesses: number;
};

export type WitnessCheckpoint = {
    readonly objectType: 'WitnessCheckpoint';
    readonly objectVersion: 1;
    readonly checkpointDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly targetPhase: string;
    readonly finalizedBoardHeadDigest: ProtocolDigest;
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly witnessIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TargetFinalityRecord = {
    readonly objectType: 'TargetFinalityRecord';
    readonly objectVersion: 1;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly targetPhase: string;
    readonly finalizedBoardHeadDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly inclusionProof: InclusionProof;
    readonly witnessCheckpoints: readonly WitnessCheckpoint[];
};

export type TargetFinalityVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly record: TargetFinalityRecord;
    readonly targetFinalityPolicy: TargetFinalityPolicy;
    readonly witnessPolicy: WitnessPolicy;
    readonly witnessPublicKeyDigests: Readonly<Record<string, ProtocolDigest>>;
    readonly conflictingRecords?: readonly TargetFinalityRecord[];
};

export type TargetFinalityVerification =
    StructuredProtocolVerificationResult & {
        readonly targetFinalityRecordDigest?: ProtocolDigest;
        readonly finalizedBoardHeadDigest?: ProtocolDigest;
        readonly validWitnessIdentities: readonly string[];
        readonly equivocatingWitnessIdentities: readonly string[];
    };

export type AcceptedTargetFinalityCheckpoint = {
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly finalizedBoardHeadDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly targetPhase: string;
    readonly witnessPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
};

export type EvaluationReplayAttestation = {
    readonly objectType: 'EvaluationReplayAttestation';
    readonly objectVersion: 1;
    readonly evaluationReplayAttestationDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly signerIdentity: string;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly finalizedBoardHeadDigest: ProtocolDigest;
    readonly replayContextDigest: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TargetAcceptedRecord = {
    readonly objectType: 'TargetAcceptedRecord';
    readonly objectVersion: 1;
    readonly targetAcceptedRecordDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly targetPhase: string;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly replayAttestationDigests: readonly ProtocolDigest[];
    readonly optionalEvaluationProofRoot: ProtocolDigest | null;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly organizerIdentity: string;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TopKDecryptionShareShell = {
    readonly objectType: 'TopKDecryptionShare';
    readonly objectVersion: 1;
    readonly topKDecryptionShareDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly trusteeIdentity: string;
    readonly targetAcceptedRecordDigest: ProtocolDigest;
    readonly targetFinalityRecordDigest: ProtocolDigest;
    readonly topKEvaluationRecordDigest: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly shareRoot: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

export type EvaluationReplayAttestationVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly attestation: EvaluationReplayAttestation;
    readonly attestationInclusionProof: InclusionProof;
    readonly targetFinalityRecord: TargetFinalityRecord;
    readonly targetFinalityVerification: TargetFinalityVerification;
    readonly expectedSignerPublicKeyDigest: ProtocolDigest;
};

export type EvaluationReplayAttestationVerification =
    StructuredProtocolVerificationResult & {
        readonly evaluationReplayAttestationDigest?: ProtocolDigest;
        readonly targetFinalityRecordDigest?: ProtocolDigest;
    };

export type TargetAcceptedRecordVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly targetAcceptedRecord: TargetAcceptedRecord;
    readonly targetAcceptedRecordInclusionProof: InclusionProof;
    readonly targetFinalityRecord: TargetFinalityRecord;
    readonly targetFinalityVerification: TargetFinalityVerification;
    readonly acceptedReplayAttestationDigests: readonly ProtocolDigest[];
    readonly expectedOrganizerPublicKeyDigest: ProtocolDigest;
};

export type TargetAcceptedRecordVerification =
    StructuredProtocolVerificationResult & {
        readonly targetAcceptedRecordDigest?: ProtocolDigest;
        readonly targetFinalityRecordDigest?: ProtocolDigest;
    };

export type TopKDecryptionShareShellVerificationInput = {
    readonly boardEvidence: BoardConsistencyInput;
    readonly decryptionShare: TopKDecryptionShareShell;
    readonly decryptionShareInclusionProof: InclusionProof;
    readonly targetAcceptedRecord: TargetAcceptedRecord;
    readonly targetAcceptedRecordVerification: TargetAcceptedRecordVerification;
    readonly expectedTrusteePublicKeyDigest: ProtocolDigest;
};

export type TopKDecryptionShareShellVerification =
    StructuredProtocolVerificationResult & {
        readonly topKDecryptionShareDigest?: ProtocolDigest;
        readonly targetAcceptedRecordDigest?: ProtocolDigest;
        readonly targetFinalityRecordDigest?: ProtocolDigest;
    };

export type RegistrationEntry = {
    readonly objectType: 'RegistrationEntry';
    readonly objectVersion: 1;
    readonly registrationEntryDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly signingPublicKeyDigest: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

export type ReceiverKeyRegistration = {
    readonly objectType: 'ReceiverKeyRegistration';
    readonly objectVersion: 1;
    readonly receiverKeyRegistrationDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly participantIdentity: string;
    readonly receiverKeyRoot: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

export type TrusteeSetupEntry = {
    readonly objectType: 'TrusteeSetupEntry';
    readonly objectVersion: 1;
    readonly trusteeSetupEntryDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly trusteeIdentity: string;
    readonly trusteeSetupRoot: ProtocolDigest;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signature: ProtocolSignatureEnvelope;
};

export type ManifestPolicyDigests = {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly duplicateBallotPolicyDigest: ProtocolDigest;
    readonly firstComePolicyDigest: ProtocolDigest;
    readonly recoveryPolicyDigest: ProtocolDigest;
    readonly targetFinalityPolicyDigest: ProtocolDigest;
    readonly witnessPolicyDigest: ProtocolDigest;
};

export type ManifestOpaqueBindings = {
    readonly bridgeProofProfileId: string;
    readonly proofPrimeParamId: string;
    readonly proofPrimePublicKeyRoot: ProtocolDigest;
    readonly proofPrimeToQDataKeyConsistencyDigest: ProtocolDigest;
    readonly proofPrimeToQDataKeyConsistencyEvidence: ProtocolDigest;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly bfvBatchEncoderDigest: ProtocolDigest;
    readonly bridgeLayoutDigest: ProtocolDigest;
    readonly brakerskiBackendProfileId: string;
    readonly brakerskiShareVerificationKeyRoot: ProtocolDigest;
    readonly mobileProfileId: string;
    readonly bridgeMobileCertificatePolicyDigest: ProtocolDigest;
};

export type ElectionManifest = {
    readonly objectType: 'ElectionManifest';
    readonly objectVersion: 1;
    readonly electionManifestDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly pollSpecDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly manifestPolicyDigests: ManifestPolicyDigests;
    readonly manifestOpaqueBindings: ManifestOpaqueBindings;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly signature: ProtocolSignatureEnvelope;
};

export type ConflictingManifestEvidence = {
    readonly manifest: ElectionManifest;
    readonly manifestInclusionProof: InclusionProof;
};

export type RosterManifestTranscriptInput = {
    readonly ceremonyId: string;
    readonly boardEvidence: BoardConsistencyInput;
    readonly registrationEntries: readonly RegistrationEntry[];
    readonly registrationInclusionProofs: readonly InclusionProof[];
    readonly receiverKeyRegistrations: readonly ReceiverKeyRegistration[];
    readonly receiverKeyRegistrationInclusionProofs: readonly InclusionProof[];
    readonly trusteeSetupEntries: readonly TrusteeSetupEntry[];
    readonly trusteeSetupInclusionProofs: readonly InclusionProof[];
    readonly electionManifest: ElectionManifest;
    readonly organizerPublicKeyDigest: ProtocolDigest;
    readonly organizerIdentity: string;
    readonly rosterFreezeBoardSeq: number;
    readonly manifestInclusionProof: InclusionProof;
    readonly suppliedElectionManifests?: readonly ElectionManifest[];
    readonly conflictingManifestEvidence?: readonly ConflictingManifestEvidence[];
};

export type RosterManifestTranscriptVerification =
    StructuredProtocolVerificationResult & {
        readonly electionManifestDigest?: ProtocolDigest;
        readonly rosterDigest?: ProtocolDigest;
        readonly participantIdentities: readonly string[];
    };

export type ActionContext = {
    readonly actionContextDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly electionManifestDigest: ProtocolDigest;
    readonly signerIdentity: string;
    readonly boardHeadDigest: ProtocolDigest;
    readonly boardSeq: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly actionSequence: number;
    readonly recoveryPolicyDigest: ProtocolDigest;
    readonly acceptedRecoveryEpochUpdateDigest: ProtocolDigest | null;
    readonly contextDigest: ProtocolDigest;
};

export type RecoveryEpochMapEntry = {
    readonly signerIdentity: string;
    readonly currentRecoveryEpoch: number;
    readonly currentDeviceEpoch: number;
    readonly oldActionCutoffBoardSeq?: number;
};

export type ValidatedFirstComeCandidate = {
    readonly objectDigest: ProtocolDigest;
    readonly objectType: ProtocolObjectType;
    readonly boardSeq: number;
    readonly boardPosition: number;
    readonly signerIdentity: string;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly actionSequence: number;
    readonly contextDigest: ProtocolDigest;
    readonly isByteIdenticalRetransmission: boolean;
};

export type FirstComeOrderingInput = {
    readonly candidates: readonly ValidatedFirstComeCandidate[];
    readonly requiredContextDigest: ProtocolDigest;
    readonly selectionPolicyDigest: ProtocolDigest;
    readonly expectedSelectionPolicyDigest: ProtocolDigest;
    readonly currentRecoveryEpochMap: Readonly<
        Record<string, RecoveryEpochMapEntry>
    >;
    readonly maxPerIdentity?: number;
};

export type FirstComeOrderingVerification =
    StructuredProtocolVerificationResult & {
        readonly firstComeOrderDigest?: ProtocolDigest;
        readonly orderedCandidates: readonly ValidatedFirstComeCandidate[];
    };

export type RecoveryEpochUpdate = {
    readonly objectType: 'RecoveryEpochUpdate';
    readonly objectVersion: 1;
    readonly recoveryEpochUpdateDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly signerIdentity: string;
    readonly recoveryRootPublicKeyDigest: ProtocolDigest;
    readonly recoveryPolicyDigest: ProtocolDigest;
    readonly previousRecoveryEpoch: number;
    readonly newRecoveryEpoch: number;
    readonly previousDeviceEpoch: number;
    readonly newDeviceEpoch: number;
    readonly oldActionCutoffBoardSeq: number;
    readonly boardHeadDigest: ProtocolDigest;
    readonly newSigningPublicKeyDigest: ProtocolDigest;
    readonly restoredFrozenReceiverStateCommitment: ProtocolDigest;
    readonly newTrusteeSetupCommitment: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

export type RecoveryEpochVerificationInput = {
    readonly update: RecoveryEpochUpdate;
    readonly currentEntry: RecoveryEpochMapEntry;
    readonly expectedRecoveryRootPublicKeyDigest: ProtocolDigest;
    readonly expectedRecoveryPolicyDigest: ProtocolDigest;
    readonly boardEvidence: BoardConsistencyInput;
    readonly updateInclusionProof: InclusionProof;
    readonly conflictingUpdates?: readonly RecoveryEpochUpdate[];
};

export type RecoveryEpochVerification = StructuredProtocolVerificationResult & {
    readonly updatedEntry?: RecoveryEpochMapEntry;
};

export type ActionCurrentForRecoveryEpochInput = {
    readonly actionContext: ActionContext;
    readonly recoveryEpochState: RecoveryEpochMapEntry;
};

export type ActionCurrentForRecoveryEpochResult =
    StructuredProtocolVerificationResult;
