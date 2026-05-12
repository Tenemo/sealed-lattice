import type { MheSecurityStage } from './transcript-core.js';

/** Result claim labels used after decryption and verification complete. */
export type ResultClaimLabel =
    | 'ResultComputedAuditable'
    | 'FullyVerifiedResult';

/** Evaluation proof state represented in lifecycle labels. */
export type EvaluationProofMode =
    | 'NoOptionalEvaluationProof'
    | 'OptionalEvaluationProofPresent'
    | 'OptionalEvaluationProofVerified';

/** Backend corruption model used when deriving threshold profiles. */
export type HeBackendCorruptionModel =
    | {
          readonly kind: 'StrictLessThanOneThird';
      }
    | {
          readonly kind: 'CertifiedCustom';
          readonly backendCorruptionBound: number;
          readonly certificateDigest: string;
      };

/** Input used to derive a threshold profile from roster and backend assumptions. */
export type ThresholdProfileInput = {
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly unsafeMicroRosterAcknowledged?: boolean;
};

/** Roster profile classification for the derived threshold parameters. */
export type RosterProfileKind =
    | 'UnsafeMicroRoster'
    | 'MandatoryN20'
    | 'CertificateGatedRange';

/** Warning label emitted when threshold parameters require caveats. */
export type ThresholdWarning =
    | 'UnsafeMicroRoster'
    | 'CertificateGatedProfile'
    | 'BackendCertificateRequired'
    | 'BackendCorruptionBoundTooHigh';

/** Derived threshold, quorum, and corruption-bound parameters for one roster. */
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

/** Supported score domain for additive score ballots. */
export type ScoreDomain = {
    readonly min: 1;
    readonly max: 10;
    readonly skippedOptionScore: 1;
};

/** Duplicate ballot policy currently supported by the public facade. */
export type DuplicateBallotPolicy = 'LastValidBeforeVotingClosedCounts';

/** Tie-breaking policy currently supported by the public facade. */
export type TiePolicy = 'HigherScoreThenLowerOptionIndex';

/** Untrusted poll specification input accepted by validation helpers. */
export type PollSpecInput = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly scoreDomain?: ScoreDomain;
    readonly duplicateBallotPolicy?: DuplicateBallotPolicy;
    readonly tiePolicy?: TiePolicy;
};

/** Normalized poll specification after validation defaults have been applied. */
export type PollSpec = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly scoreDomain: ScoreDomain;
    readonly duplicateBallotPolicy: DuplicateBallotPolicy;
    readonly tiePolicy: TiePolicy;
};

/** Stable poll specification validation error code. */
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

/** Structured poll specification validation error. */
export type PollSpecValidationError = {
    readonly code: PollSpecValidationErrorCode;
    readonly field: string;
    readonly message: string;
};

/** Poll specification validation result with normalized output or errors. */
export type PollSpecValidation =
    | {
          readonly ok: true;
          readonly normalized: PollSpec;
      }
    | {
          readonly ok: false;
          readonly errors: readonly PollSpecValidationError[];
      };

/** Protocol lifecycle state label used by capability and status helpers. */
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

/** Primary non-failure status label shown for lifecycle progress. */
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

/** Failure status label shown when transcript or profile checks cannot proceed. */
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

/** Mode or caveat status label attached to lifecycle outputs. */
export type ModeStatusLabel =
    | 'UnsafeMicroRoster'
    | 'PassiveMHEPrototype'
    | 'MobileFlagshipProfile'
    | 'ForegroundProofGenerationRequired'
    | 'ForegroundProofVerificationRequired'
    | 'ProofCheckpointRestored'
    | 'ProofCheckpointRejected'
    | 'LongRunningCryptographicCheck';

/** Allowed lifecycle transition edge. */
export type LifecycleTransition = {
    readonly from: LifecycleState;
    readonly to: LifecycleState;
};

/** Input used to derive lifecycle, failure, and mode labels. */
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

/** Derived lifecycle labels for device-facing status presentation. */
export type LifecycleLabels = {
    readonly primary: readonly PrimaryStatusLabel[];
    readonly failures: readonly FailureStatusLabel[];
    readonly modes: readonly ModeStatusLabel[];
    readonly resultClaimLabel?: ResultClaimLabel;
    readonly evaluationProofMode: EvaluationProofMode;
};

/** Public protocol action checked by capability helpers. */
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

/** Recovery state used to gate actions after device or key recovery events. */
export type RecoveryState =
    | 'NotRequired'
    | 'Ready'
    | 'Ambiguous'
    | 'StaleEpoch'
    | 'ClonedDeviceSuspected'
    | 'MissingRecoveryMaterial';

/** Context used to decide whether a protocol action is currently allowed. */
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

/** Stable reason returned when a protocol action is refused. */
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

/** Capability decision for a requested protocol action. */
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
