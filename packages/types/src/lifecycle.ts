import type { ProtocolDigest } from './protocol-digest.js';
import type { MheSecurityClosure } from './transcript-core.js';

/** Result claim labels used after decryption and verification complete. */
export type ResultClaimLabel = 'fullyVerified';

/** Evaluation proof state represented in lifecycle labels. */
export type EvaluationProofMode =
    | 'evaluationProofPending'
    | 'evaluationProofVerified'
    | 'rejectedEvaluationProof'
    | 'rejectedEvaluationProofProfile';

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

/** How target-bound share selection filters invalid decryption shares. */
export type DecryptionShareFilteringMode =
    | 'ProofVerifiedSharesOnly'
    | 'RobustDecodeAfterInvalidShareFiltering';

/** Canonical rule used to select target-bound decryption shares. */
export type DecryptionShareSelectionRule =
    'FirstValidSharesInCanonicalBoardOrder';

/** Certified target-bound decryption share-selection profile. */
export type TargetBoundShareSelectionProfile = {
    readonly profileId: string;
    readonly certificateDigest: string;
    readonly cpadProfileId: string;
    readonly targetBasisDigest: ProtocolDigest;
    readonly decryptionShareQuorum: number;
    readonly minimumSharesForInterpolation: number;
    readonly minimumArrivalsForRobustDecode: number;
    readonly invalidShareFilteringMode: DecryptionShareFilteringMode;
    readonly selectedShareRule: DecryptionShareSelectionRule;
};

/** Input used to derive a threshold profile from roster and backend assumptions. */
export type ThresholdProfileInput = {
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly targetBoundShareSelectionProfile?: TargetBoundShareSelectionProfile;
    readonly dynamicRosterProfileCertificateDigest?: ProtocolDigest;
    readonly casualMicroRosterAcknowledged?: boolean;
    readonly unsafeSmallRosterAcknowledged?: boolean;
    readonly unsafeMicroRosterAcknowledged?: boolean;
};

/** Roster profile classification for the derived threshold parameters. */
export type RosterProfileKind =
    | 'CasualMicroRoster'
    | 'MandatoryBenchmarkRoster'
    | 'SupportedDynamicRosterRange'
    | 'UncertifiedDynamicRoster';

/** Claim boundary carried by a derived threshold profile. */
export type ThresholdProfileClaimBoundary =
    | 'CasualMicroRoster'
    | 'MandatoryBenchmark'
    | 'DynamicRosterCertificate'
    | 'DynamicRosterCertificateMissing';

/** Warning label emitted when threshold parameters require caveats. */
export type ThresholdWarning =
    | 'CasualMicroRoster'
    | 'DynamicRosterProfileCertificateRequired'
    | 'BackendCorruptionBoundTooHigh'
    | 'ShareSelectionProfileRequired';

/** Derived threshold, quorum, and corruption-bound parameters for one roster. */
export type ThresholdProfile = {
    readonly rosterSize: number;
    readonly rosterProfileKind: RosterProfileKind;
    readonly claimBoundary: ThresholdProfileClaimBoundary;
    readonly claimBearing: boolean;
    readonly dynamicRosterProfileCertificateDigest: ProtocolDigest | null;
    readonly structuralCorruptionBound: number;
    readonly backendCorruptionBound: number;
    readonly privacyCorruptionBound: number;
    readonly decryptionCorruptionBound: number;
    readonly activeFaultBound: number;
    readonly pvssThreshold: number;
    readonly decryptionThreshold: number;
    readonly releaseQuorum: number;
    readonly aggregateContributionQuorum: number;
    readonly decryptionShareQuorum: number | null;
    readonly targetBoundShareSelectionProfile: TargetBoundShareSelectionProfile | null;
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

/** Public roster admission model selected at poll creation. */
export type RosterPolicy = 'OpenLinkPublicRoster';

/** Threshold/profile family selected at poll creation. */
export type ThresholdProfileFamily = 'BalancedDefault';

/** Policy for rosters below the dynamic claim-bearing family. */
export type SmallRosterPolicy =
    | 'ForbidMicroRoster'
    | 'WarnMicroRoster'
    | 'AllowMicroRoster';

/** Untrusted poll specification input accepted by validation helpers. */
export type PollSpecInput = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly scoreDomain?: ScoreDomain;
    readonly duplicateBallotPolicy?: DuplicateBallotPolicy;
    readonly tiePolicy?: TiePolicy;
    readonly rosterPolicy?: RosterPolicy;
    readonly minRosterSize?: number;
    readonly maxRosterSize?: number;
    readonly thresholdProfileFamily?: ThresholdProfileFamily;
    readonly smallRosterPolicy?: SmallRosterPolicy;
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
    readonly rosterPolicy: RosterPolicy;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly thresholdProfileFamily: ThresholdProfileFamily;
    readonly smallRosterPolicy: SmallRosterPolicy;
};

/** Concrete threshold/profile output derived after roster freeze. */
export type FrozenRosterProfile = {
    readonly objectType: 'FrozenRosterProfile';
    readonly objectVersion: 1;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly pollSpecDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly rosterSize: number;
    readonly rosterPolicy: RosterPolicy;
    readonly thresholdProfileFamily: ThresholdProfileFamily;
    readonly smallRosterPolicy: SmallRosterPolicy;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly dynamicRosterProfileCertificateDigest: ProtocolDigest | null;
    readonly thresholdProfile: ThresholdProfile;
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
    | 'UnsupportedTiePolicy'
    | 'UnsupportedRosterPolicy'
    | 'InvalidRosterBounds'
    | 'UnsupportedThresholdProfileFamily'
    | 'UnsupportedSmallRosterPolicy';

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
    | 'draft'
    | 'registrationOpen'
    | 'trusteeSetupOpen'
    | 'registrationClosed'
    | 'rosterFrozen'
    | 'votingOpen'
    | 'votingClosed'
    | 'aggregatePending'
    | 'aggregateReady'
    | 'aggregateBridgeVerified'
    | 'evaluationPending'
    | 'topKEvaluated'
    | 'targetFinalityReached'
    | 'evaluationProofPending'
    | 'evaluationProofVerified'
    | 'targetAccepted'
    | 'decryptionPending'
    | 'decryptionSharesReady'
    | 'cpadProfileVerified'
    | 'fullyVerified'
    | 'pending'
    | 'outsideClaim'
    | 'forkDetected';

/** Primary non-failure status label shown for lifecycle progress. */
export type PrimaryStatusLabel =
    | 'pending'
    | 'rosterFrozen'
    | 'ballotSubmitted'
    | 'targetAccepted'
    | 'evaluationProofVerified'
    | 'cpadProfileVerified'
    | 'fullyVerified'
    | 'forkDetected'
    | 'outsideClaim';

/** Failure status label shown when transcript or profile checks cannot proceed. */
export type FailureStatusLabel =
    | 'boardForkSuspected'
    | 'boardEvidencePublished'
    | 'forkDetected'
    | 'witnessEquivocationEvidence'
    | 'missingTargetFinality'
    | 'setupIncomplete'
    | 'turnoutFloorNotReached'
    | 'missingAggregateContributions'
    | 'missingDecryptionShares'
    | 'rejectedBridgeProof'
    | 'rejectedEvaluationProof'
    | 'rejectedEvaluationProofProfile'
    | 'rejectedTarget'
    | 'unsupportedBackendProfile'
    | 'unsupportedBgvProfile'
    | 'unsupportedKllpsCpadProfile'
    | 'rejectedEvaluationKeySizeProfile'
    | 'outsideMeasuredRuntimeProfile'
    | 'rejectedLocalReplayDiagnostic'
    | 'rejectedBridgeBenchmarkReport'
    | 'rejectedBoardFinalityProfile';

/** Mode or caveat status label attached to lifecycle outputs. */
export type ModeStatusLabel =
    | 'casualMicroRoster'
    | 'developmentIntegration'
    | 'evaluationProofClosure'
    | 'kllpsCpadClosure'
    | 'activeMaliciousClosure'
    | 'measuredRuntimeProfile'
    | 'longRunningCryptographicCheck'
    | 'localReplayMatched'
    | 'localReplayUnavailable'
    | 'localReplayFailed';

/** Allowed lifecycle transition edge. */
export type LifecycleTransition = {
    readonly from: LifecycleState;
    readonly to: LifecycleState;
};

/** Input used to derive lifecycle, failure, and mode labels. */
export type LifecycleLabelInput = {
    readonly lifecycleState: LifecycleState;
    readonly thresholdProfile: ThresholdProfile;
    readonly mheSecurityClosure?: MheSecurityClosure;
    readonly securityProfileIds?: readonly string[];
    readonly evaluationProofMode?: EvaluationProofMode;
    readonly localRosterAccepted?: boolean;
    readonly ownBallotSubmitted?: boolean;
    readonly evaluationLocallyReplayed?: boolean;
    readonly localReplayDiagnosticVerified?: boolean;
    readonly localReplayUnavailable?: boolean;
    readonly aggregateInputsBridgeVerified?: boolean;
    readonly witnessEquivocationEvidence?: boolean;
    readonly targetFinalityNotReached?: boolean;
    readonly bridgeProofRejected?: boolean;
    readonly backendProfileRejected?: boolean;
    readonly bgvProfileRejected?: boolean;
    readonly kllpsCpadProfileRejected?: boolean;
    readonly decryptionThresholdNotReached?: boolean;
    readonly bridgeBenchmarkReportRejected?: boolean;
    readonly boardFinalityProfileRejected?: boolean;
    readonly runtimeProfileRejected?: boolean;
    readonly outsideMeasuredRuntimeProfile?: boolean;
    readonly measuredRuntimeProfile?: boolean;
    readonly longRunningCryptographicCheck?: boolean;
    readonly bridgeBenchmarkReportPresent?: boolean;
    readonly bridgeProverCertificatePresent?: boolean;
    readonly evaluationProofCertificatePresent?: boolean;
    readonly oneShotDecryptionProofCertificatePresent?: boolean;
    readonly kllpsCpadCertificatePresent?: boolean;
    readonly thresholdDecryptionCertificatePresent?: boolean;
    readonly evaluationProofClosureApplied?: boolean;
    readonly kllpsCpadClosureApplied?: boolean;
    readonly activeMaliciousClosureApplied?: boolean;
    readonly decodedResultLayoutVerified?: boolean;
    readonly runtimeClaimGatePassed?: boolean;
};

/** Derived lifecycle labels for device-facing status presentation. */
export type LifecycleLabels = {
    readonly primary: readonly PrimaryStatusLabel[];
    readonly failures: readonly FailureStatusLabel[];
    readonly modes: readonly ModeStatusLabel[];
    readonly resultClaimLabels: readonly ResultClaimLabel[];
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
    | 'VerifyBridgeProof'
    | 'VerifyTranscript'
    | 'VerifyEvaluationProof'
    | 'AcceptTarget'
    | 'ReplayEvaluation'
    | 'CreateLocalReplayDiagnostic'
    | 'CreateTargetBoundDecryptionShare'
    | 'VerifyDecryptionShare'
    | 'VerifyOneShotSharePolicy'
    | 'VerifyKllpsTargetDecryptionProfile'
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
    readonly finalRosterDigest?: ProtocolDigest;
    readonly frozenRosterProfileDigest?: ProtocolDigest;
    readonly receiverKeyCoverageComplete?: boolean;
    readonly trusteeSetupComplete?: boolean;
    readonly ballotProofProfileFrozen?: boolean;
    readonly shareLayoutFrozen?: boolean;
    readonly targetOutputLayoutFrozen?: boolean;
    readonly kllpsCpadProfileReferencePresent?: boolean;
    readonly localRosterAccepted?: boolean;
    readonly rosterExternalAcceptanceDigest?: ProtocolDigest;
    readonly actionContextRosterExternalAcceptanceDigest?: ProtocolDigest | null;
    readonly setupCompleteCount?: number;
    readonly turnoutCount?: number;
    readonly decryptionShareCount?: number;
    readonly targetFinalityAccepted?: boolean;
    readonly targetAccepted?: boolean;
    readonly evaluationProofVerified?: boolean;
    readonly cpadProfileVerified?: boolean;
    readonly localReplaySucceeded?: boolean;
    readonly runtimeProfileSupported?: boolean;
    readonly bridgeBenchmarkReportPresent?: boolean;
    readonly bridgeProverCertificatePresent?: boolean;
    readonly evaluationProofCertificatePresent?: boolean;
    readonly oneShotDecryptionProofCertificatePresent?: boolean;
    readonly kllpsCpadCertificatePresent?: boolean;
    readonly thresholdDecryptionCertificatePresent?: boolean;
    readonly evaluationProofClosureApplied?: boolean;
    readonly kllpsCpadClosureApplied?: boolean;
    readonly activeMaliciousClosureApplied?: boolean;
    readonly recoveryState?: RecoveryState;
};

/** Stable reason returned when a protocol action is refused. */
export type RefusalReason =
    | 'OperationUnavailable'
    | 'InvalidLifecycleState'
    | 'PollSpecInvalid'
    | 'ProfileNotClaimBearing'
    | 'LocalRosterNotAccepted'
    | 'RosterExternalAcceptanceDigestMissing'
    | 'RosterExternalAcceptanceDigestMismatch'
    | 'setupIncomplete'
    | 'turnoutFloorNotReached'
    | 'missingAggregateContributions'
    | 'EvaluationProofMissing'
    | 'rejectedEvaluationProof'
    | 'LocalReplayNotVerified'
    | 'TargetFinalityCheckpointMissing'
    | 'TargetNotAccepted'
    | 'FirstThresholdSharesNotReached'
    | 'KllpsCpadProfileNotVerified'
    | 'OutsideMeasuredRuntimeProfile'
    | 'MissingBridgeBenchmarkReport'
    | 'MissingBridgeProverCertificate'
    | 'MissingEvaluationProofCertificate'
    | 'MissingOneShotDecryptionProofCertificate'
    | 'MissingKllpsCpadCertificate'
    | 'MissingThresholdDecryptionCertificate'
    | 'ThresholdDecryptionProfileNotCertified'
    | 'ClaimClosureMissing'
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
