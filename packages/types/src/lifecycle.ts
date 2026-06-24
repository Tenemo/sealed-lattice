import type { ProtocolHash } from './protocol-hash.js';

/** Backend corruption model used when deriving threshold profiles. */
export type HeBackendCorruptionModel =
    | {
          readonly kind: 'StructuralOneThird';
      }
    | {
          readonly kind: 'CertifiedCustom';
          readonly backendCorruptionBound: number;
          readonly certificateHash: string;
      };

/** How target-bound share selection filters invalid decryption shares. */
export type DecryptionShareFilteringMode =
    | 'ProofVerifiedSharesOnly'
    | 'RobustDecodeAfterInvalidShareFiltering';

/** Certified target-bound decryption share-selection profile. */
export type TargetBoundShareSelectionProfile = {
    readonly profileId: string;
    readonly certificateHash: string;
    readonly targetDecryptionProfileId: string;
    readonly targetBasisHash: ProtocolHash;
    readonly decryptionShareQuorum: number;
    readonly minimumSharesForInterpolation: number;
    readonly minimumArrivalsForRobustDecode: number;
    readonly invalidShareFilteringMode: DecryptionShareFilteringMode;
};

/** Input used to derive a threshold profile from roster and backend assumptions. */
export type ThresholdProfileInput = {
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly targetBoundShareSelectionProfile?: TargetBoundShareSelectionProfile;
    readonly dynamicRosterProfileCertificateHash?: ProtocolHash;
    readonly casualMicroRosterAcknowledged?: boolean;
};

/** Roster profile classification for the derived threshold parameters. */
export type RosterProfileKind =
    | 'CasualMicroRoster'
    | 'FirstProfileRoster'
    | 'SupportedDynamicRosterRange'
    | 'UncertifiedDynamicRoster';

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
    readonly dynamicRosterProfileCertificateHash: ProtocolHash | null;
    readonly structuralCorruptionBound: number;
    readonly backendCorruptionBound: number;
    readonly privacyCorruptionBound: number;
    readonly decryptionCorruptionBound: number;
    readonly activeFaultBound: number;
    readonly ballotReleaseFloor: number;
    readonly decryptionThreshold: number;
    readonly releaseQuorum: number;
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

/** Policy for rosters below the dynamic supported-roster family. */
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
    readonly minRosterSize?: number;
    readonly maxRosterSize?: number;
    readonly smallRosterPolicy?: SmallRosterPolicy;
};

/** Normalized poll specification after validation defaults have been applied. */
export type PollSpec = {
    readonly pollId: string;
    readonly question: string;
    readonly options: readonly string[];
    readonly topOptionCount: number;
    readonly scoreDomain: ScoreDomain;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly smallRosterPolicy: SmallRosterPolicy;
};

/** Concrete threshold/profile output derived after roster freeze. */
export type FrozenRosterProfile = {
    readonly objectType: 'FrozenRosterProfile';
    readonly objectVersion: 1;
    readonly thresholdProfileHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
    readonly smallRosterPolicy: SmallRosterPolicy;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly dynamicRosterProfileCertificateHash: ProtocolHash | null;
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
    | 'InvalidRosterBounds'
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
    | 'encryptedBallotsSelected'
    | 'ballotProofsVerified'
    | 'encryptedBallotAggregateComputed'
    | 'evaluatorReplayed'
    | 'targetFinalityReached'
    | 'targetAccepted'
    | 'decryptionPending'
    | 'decryptionSharesReady'
    | 'resultDecoded'
    | 'fullyVerified'
    | 'pending'
    | 'outsideSupportedProfile'
    | 'forkDetected';

/** Allowed lifecycle transition edge. */
export type LifecycleTransition = {
    readonly from: LifecycleState;
    readonly to: LifecycleState;
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
    | 'VerifyEncryptedBallotProofs'
    | 'AggregateEncryptedBallots'
    | 'ReplayEvaluator'
    | 'VerifyTranscript'
    | 'AcceptTarget'
    | 'CreateTargetBoundDecryptionShare'
    | 'VerifyDecryptionShare'
    | 'VerifyTargetDecryptionProfile'
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
    readonly finalRosterHash?: ProtocolHash;
    readonly frozenRosterProfileHash?: ProtocolHash;
    readonly trusteeSetupComplete?: boolean;
    readonly encryptedBallotLayoutFrozen?: boolean;
    readonly ballotValidityProofProfileFrozen?: boolean;
    readonly evaluatorReplayProfileFrozen?: boolean;
    readonly targetOutputLayoutFrozen?: boolean;
    readonly targetDecryptionProfileReferencePresent?: boolean;
    readonly localRosterAccepted?: boolean;
    readonly rosterExternalAcceptanceHash?: ProtocolHash;
    readonly actionContextRosterExternalAcceptanceHash?: ProtocolHash | null;
    readonly setupCompleteCount?: number;
    readonly turnoutCount?: number;
    readonly decryptionShareCount?: number;
    readonly ballotProofsVerified?: boolean;
    readonly encryptedBallotAggregateComputed?: boolean;
    readonly evaluatorReplaySucceeded?: boolean;
    readonly targetFinalityAccepted?: boolean;
    readonly targetAccepted?: boolean;
    readonly targetDecryptionProfileVerified?: boolean;
    readonly runtimeProfileSupported?: boolean;
    readonly directProofTransportPresent?: boolean;
    readonly mobileReplayEvidencePresent?: boolean;
    readonly targetDecryptionCertificatePresent?: boolean;
    readonly targetDecryptionClosureApplied?: boolean;
    readonly activeMaliciousClosureApplied?: boolean;
    readonly recoveryState?: RecoveryState;
};

/** Stable reason returned when a protocol action is refused. */
export type RefusalReason =
    | 'OperationUnavailable'
    | 'InvalidLifecycleState'
    | 'PollSpecInvalid'
    | 'LocalRosterNotAccepted'
    | 'RosterExternalAcceptanceHashMissing'
    | 'RosterExternalAcceptanceHashMismatch'
    | 'setupIncomplete'
    | 'turnoutFloorNotReached'
    | 'BallotProofsMissing'
    | 'EncryptedBallotAggregateMissing'
    | 'EvaluatorReplayMissing'
    | 'TargetFinalityCheckpointMissing'
    | 'TargetNotAccepted'
    | 'FirstThresholdSharesNotReached'
    | 'TargetDecryptionProfileNotCertified'
    | 'OutsideMeasuredRuntimeProfile'
    | 'MissingDirectProofTransport'
    | 'MissingMobileReplayEvidence'
    | 'MissingTargetDecryptionCertificate'
    | 'FrozenStateIncomplete'
    | 'TargetDecryptionClosureMissing'
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
