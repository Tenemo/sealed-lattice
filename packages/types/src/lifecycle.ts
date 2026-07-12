import type { ProtocolHash } from './protocol-hash.js';

/** Backend corruption model used when deriving threshold parameters. */
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

/** Certified target-bound decryption share-selection parameters. */
export type TargetBoundShareSelectionParameters = {
    readonly certificateHash: string;
    readonly targetBasisHash: ProtocolHash;
    readonly decryptionShareQuorum: number;
    readonly minimumSharesForInterpolation: number;
    readonly minimumArrivalsForRobustDecode: number;
    readonly invalidShareFilteringMode: DecryptionShareFilteringMode;
};

/** Input used to derive threshold parameters from roster and backend assumptions. */
export type ThresholdParametersInput = {
    readonly rosterSize: number;
    readonly heBackendCorruptionModel?: HeBackendCorruptionModel;
    readonly targetBoundShareSelectionParameters?: TargetBoundShareSelectionParameters;
    readonly dynamicRosterParametersCertificateHash?: ProtocolHash;
    readonly isCasualMicroRosterAcknowledged?: boolean;
};

/** Roster parameters classification for the derived threshold parameters. */
export type RosterParametersKind =
    | 'CasualMicroRoster'
    | 'FoundationRoster'
    | 'SupportedDynamicRosterRange'
    | 'UncertifiedDynamicRoster';

/** Warning label emitted when threshold parameters require caveats. */
export type ThresholdWarning =
    | 'CasualMicroRoster'
    | 'DynamicRosterParametersCertificateRequired'
    | 'BackendCorruptionBoundTooHigh'
    | 'ShareSelectionParametersRequired';

/**
 * Derived threshold, quorum, and corruption-bound parameters for one roster.
 *
 * This is parameter derivation, not a security certificate. Dynamic roster
 * parameter sets still need their own certificate and runtime evidence before
 * they carry a security or supported-phone claim.
 */
export type ThresholdParameters = {
    readonly rosterSize: number;
    readonly rosterParametersKind: RosterParametersKind;
    readonly dynamicRosterParametersCertificateHash: ProtocolHash | null;
    readonly structuralCorruptionBound: number;
    readonly backendCorruptionBound: number;
    readonly privacyCorruptionBound: number;
    readonly decryptionCorruptionBound: number;
    readonly activeFaultBound: number;
    readonly ballotReleaseFloor: number;
    readonly decryptionThreshold: number;
    readonly releaseQuorum: number;
    readonly decryptionShareQuorum: number | null;
    readonly targetBoundShareSelectionParameters: TargetBoundShareSelectionParameters | null;
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

/** Concrete threshold parameter output derived after roster freeze. */
export type FrozenRosterParameters = {
    readonly objectType: 'FrozenRosterParameters';
    readonly thresholdParametersHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly rosterSize: number;
    readonly smallRosterPolicy: SmallRosterPolicy;
    readonly minRosterSize: number;
    readonly maxRosterSize: number;
    readonly dynamicRosterParametersCertificateHash: ProtocolHash | null;
    readonly thresholdParameters: ThresholdParameters;
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
          readonly isValid: true;
          readonly normalized: PollSpec;
      }
    | {
          readonly isValid: false;
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
    | 'isBallotProofsVerified'
    | 'isEncryptedBallotAggregateComputed'
    | 'evaluatorReplayed'
    | 'targetFinalityReached'
    | 'isTargetAccepted'
    | 'decryptionPending'
    | 'decryptionSharesReady'
    | 'resultDecoded'
    | 'fullyVerified'
    | 'pending'
    | 'outsideSupportedParameters'
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
    | 'AcceptTarget'
    | 'CreateTargetBoundDecryptionShare'
    | 'VerifyDecryptionShare'
    | 'VerifyTargetDecryptionParameters'
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
    readonly thresholdParameters: ThresholdParameters;
    readonly isPollSpecValid: boolean;
    readonly finalRosterHash?: ProtocolHash;
    readonly frozenRosterParametersHash?: ProtocolHash;
    readonly isTrusteeSetupComplete?: boolean;
    readonly isEncryptedBallotLayoutFrozen?: boolean;
    readonly isBallotValidityProofParametersFrozen?: boolean;
    readonly isEvaluatorReplayParametersFrozen?: boolean;
    readonly isTargetOutputLayoutFrozen?: boolean;
    readonly isTargetDecryptionParametersReferencePresent?: boolean;
    readonly isLocalRosterAccepted?: boolean;
    readonly rosterExternalAcceptanceHash?: ProtocolHash;
    readonly actionContextRosterExternalAcceptanceHash?: ProtocolHash | null;
    readonly setupCompleteCount?: number;
    readonly turnoutCount?: number;
    readonly decryptionShareCount?: number;
    readonly isBallotProofsVerified?: boolean;
    readonly isEncryptedBallotAggregateComputed?: boolean;
    readonly isEvaluatorReplaySucceeded?: boolean;
    readonly isTargetFinalityAccepted?: boolean;
    readonly isTargetAccepted?: boolean;
    readonly isTargetDecryptionParametersVerified?: boolean;
    readonly isRuntimeParametersSupported?: boolean;
    readonly isDirectProofTransportPresent?: boolean;
    readonly isMobileReplayEvidencePresent?: boolean;
    readonly isTargetDecryptionCertificatePresent?: boolean;
    readonly recoveryState?: RecoveryState;
};

/** Stable reason returned when a protocol action is refused. */
export type LifecycleRefusalReason =
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
    | 'TargetDecryptionParametersNotCertified'
    | 'OutsideMeasuredRuntimeParameters'
    | 'MissingDirectProofTransport'
    | 'MissingMobileReplayEvidence'
    | 'MissingTargetDecryptionCertificate'
    | 'FrozenStateIncomplete'
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
          readonly reason: LifecycleRefusalReason;
      };
