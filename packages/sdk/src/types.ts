export type BaseClaimProfile =
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult';

export type TranscriptCoreMheSecurityStage =
    | 'PassiveMHEPrototype'
    | 'ActiveMalicious';

export type TranscriptCoreStatusLabel = 'TranscriptCoreVerified';

export type TranscriptCoreVerificationLabel =
    | 'TranscriptCoreVerified'
    | 'TranscriptCoreRejected';

export type CanonicalErrorCode =
    | 'DuplicateField'
    | 'FieldOrder'
    | 'FixtureMismatch'
    | 'InvalidChunkSize'
    | 'InvalidEnum'
    | 'InvalidFixture'
    | 'InvalidHex'
    | 'InvalidUtf8'
    | 'MalformedLength'
    | 'MalformedMagic'
    | 'MalformedVarUint'
    | 'MissingField'
    | 'NonCanonicalVarUint'
    | 'ProfileComponentMismatch'
    | 'TrailingBytes'
    | 'UnknownBaseClaimProfile'
    | 'UnknownField'
    | 'UnknownMheSecurityStage'
    | 'UnknownProofProfile'
    | 'UnsupportedCanonicalEnvelopeVersion'
    | 'UnsupportedObjectType'
    | 'UnsupportedObjectVersion';

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
    readonly mheSecurityStage: TranscriptCoreMheSecurityStage;
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

export type TranscriptCoreFixtureVerification =
    | {
          readonly verified: true;
          readonly caseName: string;
          readonly objectHash512: string;
          readonly chunkRoot: string;
          readonly statusLabels: readonly TranscriptCoreStatusLabel[];
      }
    | {
          readonly verified: true;
          readonly caseName: string;
          readonly expectedErrorCode: CanonicalErrorCode;
      };

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

export type MheSecurityStage = 'PassiveMHEPrototype' | 'ActiveMalicious';

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
          readonly cHeBackend: number;
          readonly certificateDigest: string;
      };

export type ThresholdProfileInput = {
    readonly n: number;
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
    readonly n: number;
    readonly rosterProfileKind: RosterProfileKind;
    readonly claimBearing: boolean;
    readonly cStruct: number;
    readonly cHeBackend: number;
    readonly cPriv: number;
    readonly cDec: number;
    readonly fAct: number;
    readonly tPvss: number;
    readonly tDec: number;
    readonly qRelease: number;
    readonly qAgg: number;
    readonly qDec: number;
    readonly qEval: number;
    readonly raceShareMax: number;
    readonly qSetupComplete: number;
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
    readonly ceremonyId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly kTop: number;
    readonly scoreDomain?: ScoreDomain;
    readonly duplicateBallotPolicy?: DuplicateBallotPolicy;
    readonly tiePolicy?: TiePolicy;
};

export type PollSpec = {
    readonly ceremonyId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly kTop: number;
    readonly scoreDomain: ScoreDomain;
    readonly duplicateBallotPolicy: DuplicateBallotPolicy;
    readonly tiePolicy: TiePolicy;
};

export type PollSpecValidationErrorCode =
    | 'EmptyCeremonyId'
    | 'EmptyQuestion'
    | 'InvalidOptionCount'
    | 'EmptyOptionLabel'
    | 'DuplicateOptionLabel'
    | 'InvalidKTop'
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
    | 'AggregateInputsReady'
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
    | 'OptionalEvaluationProofRejected'
    | 'EvaluationRejected'
    | 'TargetRejected'
    | 'CPADProfileRejected'
    | 'AnyTDecryptionProfileRejected'
    | 'EvaluationKeySizeProfileRejected'
    | 'MobileReplayProfileRejected';

export type ModeStatusLabel = 'UnsafeMicroRoster' | 'PassiveMHEPrototype';

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
    readonly aggregateContributionCount?: number;
    readonly replayAttestationCount?: number;
    readonly decryptionShareCount?: number;
    readonly targetFinalityAccepted?: boolean;
    readonly targetAccepted?: boolean;
    readonly optionalEvaluationProofVerified?: boolean;
    readonly localReplaySucceeded?: boolean;
    readonly browserSupported?: boolean;
    readonly recoveryState?: RecoveryState;
};

export type RefusalReason =
    | 'NotImplementedUntilLaterMilestone'
    | 'InvalidLifecycleState'
    | 'PollSpecInvalid'
    | 'UnsafeMicroRosterNotClaimBearing'
    | 'SetupIncomplete'
    | 'TurnoutBelowReleaseFloor'
    | 'AggregateThresholdNotReached'
    | 'EvaluationReplayThresholdNotReached'
    | 'LocalReplayNotVerified'
    | 'TargetFinalityCheckpointMissing'
    | 'TargetNotAccepted'
    | 'FirstThresholdSharesNotReached'
    | 'UnsupportedBrowserContext'
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
