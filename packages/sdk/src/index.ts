import {
    createCommonRandomnessCommit as createCommonRandomnessCommitInternal,
    createCommonRandomnessReveal as createCommonRandomnessRevealInternal,
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares as exportEncryptedLocalTrusteeSetupStateInternal,
    createEvaluatorKeySchedule as createEvaluatorKeyScheduleInternal,
    createGaloisKeyShareBatches as createGaloisKeyShareBatchesInternal,
    createPublicKeyShareLnpProofSet as createPublicKeyShareLnpProofSetInternal,
    createPublicKeyShareMaterialSet as createPublicKeyShareMaterialSetInternal,
    createPublicEvaluationKeySet as createPublicEvaluationKeySetInternal,
    createPublicKeyShareProofSet as createPublicKeyShareProofSetInternal,
    createPublicKeyShareSet as createPublicKeyShareSetInternal,
    createRelinearizationKeyShareRounds as createRelinearizationKeyShareRoundsInternal,
    createSameSecretProofSet as createSameSecretProofSetInternal,
    createSetupCommonRandomness as createSetupCommonRandomnessInternal,
    createSetupContributionAssembly as createSetupContributionInternal,
    createSetupCertificates as createSetupCertificatesInternal,
    createSetupPackage as createSetupPackageInternal,
    createSetupPhaseParticipantObject as createSetupIntentInternal,
    createSetupPhaseRecord as createSetupPhaseRecordInternal,
    createVssShareAcceptanceRecord as createVssShareAcceptanceInternal,
    createVssShareComplaintRecordFromLocalVerification as createVssComplaintInternal,
    deriveValidatedFirstValidOrder as deriveValidatedFirstValidOrderInternal,
    deriveLifecycleLabels as deriveLifecycleLabelsInternal,
    deriveFrozenRosterProfile as deriveFrozenRosterProfileInternal,
    derivePollSpecHash as derivePollSpecHashInternal,
    deriveThresholdProfile as deriveThresholdProfileInternal,
    deriveThresholdProfileHash as deriveThresholdProfileHashInternal,
    evaluateActionCapability as evaluateActionCapabilityInternal,
    verifyFoundationTranscript as verifyFoundationTranscriptInternal,
    verifyCastReceiptShell as verifyCastReceiptShellInternal,
    verifyCloseRecordShell as verifyCloseRecordShellInternal,
    isValidLifecycleTransition as isValidLifecycleTransitionInternal,
    isActionCurrentForRecoveryEpoch as isActionCurrentForRecoveryEpochInternal,
    validatePollSpec as validatePollSpecInternal,
    verifyBoardConsistency as verifyBoardConsistencyInternal,
    verifyRecoveryEpochUpdate as verifyRecoveryEpochUpdateInternal,
    verifyRosterExternalAcceptance as verifyRosterExternalAcceptanceInternal,
    verifyRosterManifestTranscript as verifyRosterManifestTranscriptInternal,
    verifyTargetFinality as verifyTargetFinalityInternal,
    decryptLocalTrusteeSetupState as restoreEncryptedLocalTrusteeSetupStateInternal,
} from '@sealed-lattice/protocol';
import type {
    EvaluatorKeySchedule as ProtocolEvaluatorKeySchedule,
    EvaluatorKeyScheduleInput as ProtocolEvaluatorKeyScheduleInput,
    GaloisKeyRootReference as ProtocolGaloisKeyRootReference,
    GaloisKeyShareBatch as ProtocolGaloisKeyShareBatch,
    GaloisKeyShareBatchRootReference as ProtocolGaloisKeyShareBatchRootReference,
    GaloisKeyShareProof as ProtocolGaloisKeyShareProof,
    GaloisKeyShareProofMaterial as ProtocolGaloisKeyShareProofMaterial,
    GaloisKeyShareRootReference as ProtocolGaloisKeyShareRootReference,
    LocalTrusteeSetupStateDecryptionInput,
    PublicEvaluationKeySet as ProtocolPublicEvaluationKeySet,
    PublicEvaluationKeySetInput as ProtocolPublicEvaluationKeySetInput,
    PublicKeyShareCoefficientVectorHash as ProtocolPublicKeyShareCoefficientVectorHash,
    PublicKeyShareCoefficientVectorMaterial as ProtocolPublicKeyShareCoefficientVectorMaterial,
    PublicKeyShareContributionInput as ProtocolPublicKeyShareContributionInput,
    PublicKeyShareLnpProofMaterial as ProtocolPublicKeyShareLnpProofMaterial,
    PublicKeyShareLnpProofRecord as ProtocolPublicKeyShareLnpProofRecord,
    PublicKeyShareLnpProofSet as ProtocolPublicKeyShareLnpProofSet,
    PublicKeyShareLnpProofSetInput as ProtocolPublicKeyShareLnpProofSetInput,
    PublicKeyShareMaterialContributionInput as ProtocolPublicKeyShareMaterialContributionInput,
    PublicKeyShareMaterialRecord as ProtocolPublicKeyShareMaterialRecord,
    PublicKeyShareMaterialSet as ProtocolPublicKeyShareMaterialSet,
    PublicKeyShareMaterialSetInput as ProtocolPublicKeyShareMaterialSetInput,
    PublicKeyShareProofRecord as ProtocolPublicKeyShareProofRecord,
    PublicKeyShareProofSet as ProtocolPublicKeyShareProofSet,
    PublicKeyShareProofSetInput as ProtocolPublicKeyShareProofSetInput,
    PublicKeyShareRecord as ProtocolPublicKeyShareRecord,
    PublicKeyShareSet as ProtocolPublicKeyShareSet,
    PublicKeyShareSetInput as ProtocolPublicKeyShareSetInput,
    RelinearizationKeyRootReference as ProtocolRelinearizationKeyRootReference,
    RelinearizationKeyShareProofMaterial as ProtocolRelinearizationKeyShareProofMaterial,
    RelinearizationKeyShareRoundOneRecord as ProtocolRelinearizationKeyShareRoundOneRecord,
    RelinearizationKeyShareRoundTwoRecord as ProtocolRelinearizationKeyShareRoundTwoRecord,
    RelinearizationKeyShareRounds as ProtocolRelinearizationKeyShareRounds,
    RelinearizationKeyShareRoundsInput as ProtocolRelinearizationKeyShareRoundsInput,
    RelinearizationLevelScheduleEntry as ProtocolRelinearizationLevelScheduleEntry,
    RequiredGaloisKeyScheduleEntry as ProtocolRequiredGaloisKeyScheduleEntry,
    RequiredGaloisSet as ProtocolRequiredGaloisSet,
    SameSecretProofMaterial as ProtocolSameSecretProofMaterial,
    SameSecretProofRecord as ProtocolSameSecretProofRecord,
    SameSecretProofReference as ProtocolSameSecretProofReference,
    SameSecretProofSet as ProtocolSameSecretProofSet,
    SameSecretProofSetInput as ProtocolSameSecretProofSetInput,
    BgvHeSecurityCertificate as ProtocolBgvHeSecurityCertificate,
    SetupCertificates as ProtocolSetupCertificates,
    SetupCommitmentSecurityCertificate as ProtocolSetupCommitmentSecurityCertificate,
    SetupTransportCertificate as ProtocolSetupTransportCertificate,
    SetupContributionAssemblyInput,
    SetupPackage as ProtocolSetupPackage,
    SetupPackageInput as ProtocolSetupPackageInput,
    SetupPhaseParticipantObjectInput as ProtocolSetupPhaseParticipantObjectInput,
} from '@sealed-lattice/protocol';
import type {
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    CastReceiptVerification,
    CastReceiptVerificationInput,
    CapabilityContext,
    CapabilityDecision,
    CloseRecordVerification,
    CloseRecordVerificationInput,
    CanonicalSignedRootObject,
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FutureProtocolOperationResult,
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleTransition,
    PollSpecInput,
    PollSpecValidation,
    ProtocolAction,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    ThresholdProfile,
    ThresholdProfileInput,
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
} from '@sealed-lattice/types';

import { loadTranscriptCoreKernel } from './kernel.js';

export type {
    AcceptedTargetFinalityCheckpoint,
    ActionContext,
    ActionCurrentForRecoveryEpochInput,
    ActionCurrentForRecoveryEpochResult,
    TargetBoundShareSelectionProfile,
    AppendOnlyConsistencyProof,
    BaseClaimProfile,
    BoardConsistencyInput,
    BoardConsistencyVerification,
    BoardEntryMerklePathStep,
    CanonicalError,
    CanonicalErrorCode,
    CanonicalSignedRootObject,
    CapabilityContext,
    CapabilityDecision,
    CastReceipt,
    CastReceiptVerification,
    CastReceiptVerificationInput,
    CloseRecord,
    CloseRecordKind,
    CloseRecordVerification,
    CloseRecordVerificationInput,
    ConflictingHeadEvidence,
    ConflictingManifestEvidence,
    DuplicateBallotPolicy,
    ElectionManifest,
    DecryptionShareFilteringMode,
    DecryptionShareSelectionRule,
    FailureStatusLabel,
    FoundationTranscriptComponentResults,
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    FirstValidOrderingInput,
    FirstValidOrderingVerification,
    FrozenRosterProfile,
    FutureProtocolOperationResult,
    GoldenTranscriptCoreFixture,
    GoldenTranscriptCoreFixtureVerification,
    HeBackendCorruptionModel,
    InclusionProof,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleState,
    LifecycleTransition,
    MalformedObjectFixture,
    MalformedObjectFixtureVerification,
    ManifestOpaqueBindings,
    ManifestPolicyHashes,
    MlDsaSignatureMode,
    MlDsaSignatureProfile,
    ModeStatusLabel,
    PollSpec,
    PollSpecInput,
    PollSpecValidation,
    PollSpecValidationError,
    PollSpecValidationErrorCode,
    PrimaryStatusLabel,
    ProtocolAction,
    ProtocolHash,
    ProtocolObjectType,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    ProtocolVerificationStatusLabel,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RecoveryEpochVerification,
    RecoveryEpochVerificationInput,
    RecoveryState,
    RefusalReason,
    RefusalRecord,
    RegistrationEntry,
    ResultClaimLabel,
    RosterExternalAcceptance,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    RosterProfileKind,
    RosterPolicy,
    ScoreDomain,
    SignatureVerificationResult,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    SmallRosterPolicy,
    StructuredProtocolVerificationResult,
    TargetFinalityPolicy,
    TargetFinalityCheckpoint,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TargetFinalityVerificationInput,
    TargetProposal,
    ThresholdProfile,
    ThresholdProfileClaimBoundary,
    ThresholdProfileFamily,
    ThresholdProfileInput,
    ThresholdWarning,
    TiePolicy,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
    TranscriptCoreSecurityClosure,
    TranscriptCoreStatusLabel,
    TranscriptCoreVerificationLabel,
    TranscriptCoreVerificationResult,
    TrusteeSetupEntry,
    ValidatedFirstValidObject,
    WitnessCheckpoint,
    WitnessPolicy,
} from '@sealed-lattice/types';

type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly qShareHash: ProtocolHash;
    readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
    readonly commitmentProfileHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

export type ProtocolRootSigner = (
    signedRoot: CanonicalSignedRootObject,
) => ProtocolSignatureEnvelope | Promise<ProtocolSignatureEnvelope>;

export type SetupIntentInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly privateVssMailboxPublicKeyHash: ProtocolHash;
    readonly privateVssMailboxPublicKeyBytesHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
}>;

export type SetupPhaseParticipantObject = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPhaseParticipantObject';
        readonly objectVersion: 1;
        readonly phaseId: string;
        readonly phaseNumber: number;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly signerRole: 'Trustee';
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly privateVssMailboxPublicKeyHash?: ProtocolHash;
        readonly privateVssMailboxPublicKeyBytesHash?: ProtocolHash;
        readonly phaseObjectRoot: ProtocolHash;
        readonly phaseObjectByteLength: number;
        readonly phaseSignatureContextHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type SetupPhaseRecordInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly phaseId: string;
    readonly phaseNumber: number;
    readonly previousPhaseRoot: ProtocolHash | null;
    readonly participantPhaseObjects: readonly SetupPhaseParticipantObject[];
}>;

export type SetupPhaseRecord = Readonly<
    JsonRecord & {
        readonly phaseId: string;
        readonly phaseNumber: number;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly previousPhaseRoot: ProtocolHash | null;
        readonly participantPhaseObjects: readonly SetupPhaseParticipantObject[];
        readonly phaseRoot: ProtocolHash;
    }
>;

export type CommonRandomnessRevealInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signatureEnvelopeHash: ProtocolHash;
    readonly revealHex: string;
}>;

export type CommonRandomnessReveal = Readonly<
    JsonRecord & {
        readonly objectType: 'CommonRandomnessReveal';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly signerRole: 'Trustee';
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly revealHex: string;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly revealHash: ProtocolHash;
    }
>;

export type CommonRandomnessCommitInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signatureEnvelopeHash: ProtocolHash;
    readonly revealHash: ProtocolHash;
}>;

export type CommonRandomnessCommit = Readonly<
    JsonRecord & {
        readonly objectType: 'CommonRandomnessCommit';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly signerRole: 'Trustee';
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly revealHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly commitHash: ProtocolHash;
    }
>;

export type SetupCommonRandomnessInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly commitRecords: readonly CommonRandomnessCommit[];
    readonly revealRecords: readonly CommonRandomnessReveal[];
}>;

export type SetupCommonRandomness = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupCommonRandomness';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly commitRecords: readonly CommonRandomnessCommit[];
        readonly revealRecords: readonly CommonRandomnessReveal[];
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicDerivations: Readonly<
            JsonRecord & {
                readonly objectType: 'SetupPublicDerivations';
                readonly objectVersion: 1;
                readonly setupProfileId: 'CollectiveBgvSetup-v1';
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly publicDerivationRoot: ProtocolHash;
            }
        >;
        readonly commonRandomnessRoot: ProtocolHash;
    }
>;

export type PrivateVssEnvelopeVerificationReference = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitment';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeCommitmentRoot: ProtocolHash;
        readonly encryptedEnvelopeHash: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
    }
>;

export type VerifyPrivateVssShareInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly privateEnvelope: unknown;
    readonly transportedPrivateVssShareProofMaterial?: unknown;
    readonly expectedPrivateEnvelopeHash?: ProtocolHash;
    readonly expectedLocalVerificationRoot?: ProtocolHash;
}>;

export type PrivateVssShareVerification = Readonly<{
    readonly ok: boolean;
    readonly operation: 'verifyPrivateVssShareEnvelope';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verifierStatus: 'accepted' | 'refused';
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly ringDegree?: number;
    readonly ringDegreeStatus?: 'profile-ring' | 'development-reduced-ring';
    readonly verifiedRnsLimbCount?: number;
    readonly verifiedShamirCoefficientCommitmentCount?: number;
    readonly verifiedPrivateVssShareProofCount?: number;
    readonly limbVerifications: readonly Readonly<{
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly shareValuesHash: ProtocolHash;
        readonly privateVssShareProofHash: ProtocolHash;
        readonly proofStatementRoot: ProtocolHash;
        readonly limbVerificationRoot: ProtocolHash;
    }>[];
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

export type VssShareAcceptanceInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly localVerification: PrivateVssShareVerification;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
}>;

export type VssShareAcceptance = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareAcceptance';
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
        readonly verificationStatus: 'accepted';
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly acceptanceRoot: ProtocolHash;
        readonly acceptanceByteLength: number;
        readonly acceptanceContextHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type VssComplaintInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
    readonly envelopeReference: PrivateVssEnvelopeVerificationReference;
    readonly localVerification: PrivateVssShareVerification;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
}>;

export type VssComplaint = Readonly<
    JsonRecord & {
        readonly objectType: 'VssShareComplaint';
        readonly objectVersion: 1;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly sourceTrusteeCommitmentRoot: ProtocolHash;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly complaintEvidenceRoot: ProtocolHash;
        readonly complaintReasonCode: string;
        readonly complaintStatus: 'valid-complaint-aborts-setup';
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: ProtocolHash;
        readonly complaintRoot: ProtocolHash;
        readonly complaintByteLength: number;
        readonly complaintContextHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
    }
>;

export type LocalTrusteeSetupStateDeletionReceipt = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateDeletionReceipt';
        readonly objectVersion: 1;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly trusteePoint: number;
        readonly deletionBoundary: 'after-private-vss-aggregation';
        readonly deletionReceiptRoot: ProtocolHash;
    }
>;

export type LocalTrusteeSetupStateCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateCommitment';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly trusteePoint: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
        readonly aggregateThresholdShareRoot: ProtocolHash;
        readonly issuedVssAcceptanceRoot: ProtocolHash;
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
        readonly deletionReceiptRoot: ProtocolHash;
        readonly deletionReceipt: LocalTrusteeSetupStateDeletionReceipt;
        readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
        readonly storageProfile: 'encrypted-local-device-state-required';
        readonly localStateRoot: ProtocolHash;
    }
>;

export type LocalTrusteeSetupStateSealedMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateSealedMaterial';
        readonly objectVersion: 1;
        readonly materialClass: 'aggregate-threshold-share-sealed';
        readonly materialRoot: ProtocolHash;
        readonly ciphertextReference: ProtocolHash;
        readonly encryptedMaterial: Readonly<JsonRecord>;
    }
>;

export type LocalTrusteeSetupStateSealedPayload = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateSealedPayload';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly deviceEpoch: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
        readonly sealedAggregateThresholdShare: LocalTrusteeSetupStateSealedMaterial;
        readonly issuedVssAcceptanceRoots: readonly ProtocolHash[];
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
    }
>;

export type EncryptedLocalTrusteeSetupState = Readonly<
    JsonRecord & {
        readonly objectType: 'EncryptedLocalTrusteeSetupState';
        readonly objectVersion: 1;
        readonly storageProfileId: string;
        readonly ciphertextContentType: 'local-trustee-setup-state';
        readonly localStateRoot: ProtocolHash;
        readonly localStateCommitmentHash: ProtocolHash;
        readonly storageAad: Readonly<JsonRecord>;
        readonly storageAadHash: ProtocolHash;
        readonly keyCommitmentHash: ProtocolHash;
        readonly aeadNonceHex: string;
        readonly ciphertextBytesHex: string;
        readonly ciphertextBytesHash: ProtocolHash;
        readonly ciphertextByteLength: number;
        readonly plaintextByteLength: number;
        readonly aeadTagLength: 128;
        readonly encryptedLocalStateHash: ProtocolHash;
    }
>;

export type SetupContributionInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupPhaseParticipantObjects: readonly JsonRecord[];
    readonly commonRandomnessCommitRoot?: ProtocolHash;
    readonly commonRandomnessRevealRoot?: ProtocolHash;
    readonly vssSourceTrusteeRecord?: JsonRecord;
    readonly privateVssEnvelopeReferences?: readonly JsonRecord[];
    readonly vssShareAcceptanceRecords?: readonly JsonRecord[];
    readonly vssShareComplaintRecords?: readonly JsonRecord[];
    readonly localStateCommitment?: LocalTrusteeSetupStateCommitment;
    readonly publicKeyShareRecord?: JsonRecord;
    readonly publicKeyShareProofRecord?: JsonRecord;
}>;

export type SetupContribution = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupContributionAssembly';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly phaseObjectRoots: readonly ProtocolHash[];
        readonly commonRandomnessCommitRoot: ProtocolHash | null;
        readonly commonRandomnessRevealRoot: ProtocolHash | null;
        readonly vssSourceTrusteeCommitmentRoot: ProtocolHash | null;
        readonly issuedVssAcceptanceRoots: readonly ProtocolHash[];
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash | null;
        readonly aggregateThresholdShareRoot: ProtocolHash | null;
        readonly localStateRoot: ProtocolHash | null;
        readonly localStateDeletionReceiptRoot: ProtocolHash | null;
        readonly publicKeyShareRoot: ProtocolHash | null;
        readonly publicKeyShareProofRoot: ProtocolHash | null;
        readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
        readonly setupContributionRoot: ProtocolHash;
    }
>;

export type SetupCertificateTransportInput = Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
}>;

export type SetupCertificatesInput = Readonly<{
    readonly setupProfile: JsonRecord;
    readonly bgvProfile: JsonRecord;
    readonly vssCoefficientCommitmentMaterial: JsonRecord;
    readonly transport: SetupCertificateTransportInput;
}>;

export type SetupCertificates = ProtocolSetupCertificates;
export type SetupCommitmentSecurityCertificate =
    ProtocolSetupCommitmentSecurityCertificate;
export type SetupTransportCertificate = ProtocolSetupTransportCertificate;
export type BgvHeSecurityCertificate = ProtocolBgvHeSecurityCertificate;

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly JsonRecord[];
    readonly commonRandomness: JsonRecord;
    readonly vssCoefficientCommitments: JsonRecord;
    readonly vssCoefficientCommitmentMaterial: JsonRecord;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: JsonRecord;
    readonly vssComplaints?: JsonRecord;
    readonly thresholdShareCommitments?: JsonRecord;
    readonly sameSecretConsistency: JsonRecord;
    readonly sameSecretProofs?: JsonRecord;
    readonly publicKeyShares: JsonRecord;
    readonly publicKeyShareProofs: JsonRecord;
    readonly publicKeyShareMaterial?: JsonRecord;
    readonly publicKeyShareLnpProofs?: JsonRecord;
    readonly collectivePublicKey?: JsonRecord;
    readonly evaluatorKeySchedule: JsonRecord;
    readonly relinearizationKeyShareRounds: JsonRecord;
    readonly galoisKeyShareBatches: readonly JsonRecord[];
    readonly evaluationKeys: JsonRecord;
    readonly setupCertificateInput?: Omit<
        SetupCertificatesInput,
        'vssCoefficientCommitmentMaterial'
    >;
    readonly setupCommitmentSecurityCertificate?: JsonRecord;
    readonly setupTransportCertificate?: JsonRecord;
    readonly heSecurityCertificate?: JsonRecord;
}>;

export type SetupPackage = ProtocolSetupPackage;

export type PublicKeyShareCoefficientVectorHash =
    ProtocolPublicKeyShareCoefficientVectorHash;
export type PublicKeyShareCoefficientVectorMaterial =
    ProtocolPublicKeyShareCoefficientVectorMaterial;
export type PublicKeyShareContributionInput =
    ProtocolPublicKeyShareContributionInput;
export type PublicKeyShareRecord = ProtocolPublicKeyShareRecord;
export type PublicKeyShareSet = ProtocolPublicKeyShareSet;
export type PublicKeyShareSetInput = ProtocolPublicKeyShareSetInput;
export type PublicKeyShareProofRecord = ProtocolPublicKeyShareProofRecord;
export type PublicKeyShareProofSet = ProtocolPublicKeyShareProofSet;
export type PublicKeyShareProofSetInput = ProtocolPublicKeyShareProofSetInput;
export type PublicKeyShareMaterialContributionInput =
    ProtocolPublicKeyShareMaterialContributionInput;
export type PublicKeyShareMaterialRecord = ProtocolPublicKeyShareMaterialRecord;
export type PublicKeyShareMaterialSet = ProtocolPublicKeyShareMaterialSet;
export type PublicKeyShareMaterialSetInput =
    ProtocolPublicKeyShareMaterialSetInput;
export type PublicKeyShareLnpProofMaterial =
    ProtocolPublicKeyShareLnpProofMaterial;
export type PublicKeyShareLnpProofRecord = ProtocolPublicKeyShareLnpProofRecord;
export type PublicKeyShareLnpProofSet = ProtocolPublicKeyShareLnpProofSet;
export type PublicKeyShareLnpProofSetInput =
    ProtocolPublicKeyShareLnpProofSetInput;
export type RelinearizationLevelScheduleEntry =
    ProtocolRelinearizationLevelScheduleEntry;
export type RequiredGaloisKeyScheduleEntry =
    ProtocolRequiredGaloisKeyScheduleEntry;
export type RequiredGaloisSet = ProtocolRequiredGaloisSet;
export type EvaluatorKeySchedule = ProtocolEvaluatorKeySchedule;
export type EvaluatorKeyScheduleInput = ProtocolEvaluatorKeyScheduleInput;
export type SameSecretProofMaterial = ProtocolSameSecretProofMaterial;
export type SameSecretProofRecord = ProtocolSameSecretProofRecord;
export type SameSecretProofReference = ProtocolSameSecretProofReference;
export type SameSecretProofSet = ProtocolSameSecretProofSet;
export type SameSecretProofSetInput = ProtocolSameSecretProofSetInput;
export type RelinearizationKeyShareProofMaterial =
    ProtocolRelinearizationKeyShareProofMaterial;
export type RelinearizationRoundOneContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundOneShareRoot: ProtocolHash;
    readonly proofMaterial: RelinearizationKeyShareProofMaterial;
}>;
export type RelinearizationRoundTwoContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly roundTwoShareRoot: ProtocolHash;
    readonly proofMaterial: RelinearizationKeyShareProofMaterial;
}>;
export type RelinearizationKeyShareRoundOneRecord =
    ProtocolRelinearizationKeyShareRoundOneRecord;
export type RelinearizationKeyShareRoundTwoRecord =
    ProtocolRelinearizationKeyShareRoundTwoRecord;
export type RelinearizationKeyShareRounds =
    ProtocolRelinearizationKeyShareRounds;
type PublicEvaluationKeyProofCommonInput = Readonly<
    Omit<
        ProtocolRelinearizationKeyShareRoundsInput,
        | 'roundOneContributions'
        | 'roundTwoContributions'
        | 'evaluationKeyShareProofGenerator'
    >
>;
export type RelinearizationKeyShareRoundsInput =
    PublicEvaluationKeyProofCommonInput &
        Readonly<{
            readonly roundOneContributions: readonly RelinearizationRoundOneContribution[];
            readonly roundTwoContributions: readonly RelinearizationRoundTwoContribution[];
        }>;
export type GaloisKeyShareRootReference = ProtocolGaloisKeyShareRootReference;
export type GaloisKeyShareProofMaterial = ProtocolGaloisKeyShareProofMaterial;
export type GaloisKeyShareProofContribution =
    ProtocolGaloisKeyShareRootReference &
        Readonly<{
            readonly proofMaterial: GaloisKeyShareProofMaterial;
        }>;
export type GaloisKeyShareBatchContribution = Readonly<{
    readonly trusteeRosterPosition: number;
    readonly galoisKeyShareProofs: readonly GaloisKeyShareProofContribution[];
}>;
export type GaloisKeyShareProof = ProtocolGaloisKeyShareProof;
export type GaloisKeyShareBatch = ProtocolGaloisKeyShareBatch;
export type GaloisKeyShareBatchesInput = PublicEvaluationKeyProofCommonInput &
    Readonly<{
        readonly batchContributions: readonly GaloisKeyShareBatchContribution[];
    }>;
export type RelinearizationKeyRootReference =
    ProtocolRelinearizationKeyRootReference;
export type GaloisKeyShareBatchRootReference =
    ProtocolGaloisKeyShareBatchRootReference;
export type GaloisKeyRootReference = ProtocolGaloisKeyRootReference;
export type PublicEvaluationKeySet = ProtocolPublicEvaluationKeySet;
export type PublicEvaluationKeySetInput = PublicEvaluationKeyProofCommonInput &
    Readonly<
        Pick<
            ProtocolPublicEvaluationKeySetInput,
            | 'relinearizationKeyShareRounds'
            | 'galoisKeyShareBatches'
            | 'publicEvaluationKeyMaterialReference'
        >
    >;

export type ExportEncryptedLocalTrusteeSetupStateInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly deviceEpoch: number;
    readonly thresholdShareCommitments: unknown;
    readonly privateVssEnvelopeCommitments: unknown;
    readonly verifiedPrivateVssShareEnvelopes: readonly unknown[];
    readonly vssShareAcceptances: unknown;
    readonly vssComplaints?: unknown;
    readonly storageKeyBytesHex: string;
    readonly localStateAeadNonceBytesHex?: string;
    readonly sealedAggregateThresholdShareAeadNonceBytesHex?: string;
}>;

export type ExportEncryptedLocalTrusteeSetupStateResult = Readonly<{
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStatePlaintextHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
}>;

export type RestoreLocalTrusteeSetupStateInput = Readonly<{
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly storageKeyBytesHex: string;
    readonly expectedLocalStateRoot?: ProtocolHash;
    readonly expectedSetupEpoch?: string;
    readonly expectedTrusteeIdentity?: string;
    readonly expectedTrusteeRosterPosition?: number;
    readonly expectedDeviceEpoch?: number;
    readonly minimumDeviceEpoch?: number;
    readonly expectedThresholdShareCommitmentRecipientRoot?: ProtocolHash;
    readonly expectedAggregateThresholdShareRoot?: ProtocolHash;
    readonly expectedIssuedVssAcceptanceRoot?: ProtocolHash;
}>;

export type LocalTrusteeSetupStateVerification = Readonly<{
    readonly ok: true;
    readonly operation: 'verifyLocalTrusteeSetupState';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteePoint: number;
    readonly localStateRoot: ProtocolHash;
    readonly deletionReceiptRoot: ProtocolHash;
    readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
    readonly storageProfile: 'encrypted-local-device-state-required';
    readonly deletionBoundary: 'after-private-vss-aggregation';
    readonly statusLabels: readonly string[];
}>;

export type RestoredLocalTrusteeSetupState = Readonly<{
    readonly ok: true;
    readonly operation: 'restoreLocalTrusteeSetupState';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
    readonly localStatePlaintextHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
    readonly localStateVerification: LocalTrusteeSetupStateVerification;
}>;

export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash?: ProtocolHash;
    readonly expectedRosterHash?: ProtocolHash;
    readonly transportedVssCoefficientCommitmentMaterial?: unknown;
    readonly transportedSameSecretProofMaterial?: unknown;
    readonly transportedPublicKeyShareProofMaterial?: unknown;
    readonly transportedEvaluationKeyShareProofMaterial?: unknown;
    readonly transportedEvaluationKeyShareComponentMaterial?: unknown;
    readonly transportedPublicEvaluationKeyMaterial?: unknown;
}>;

export type SetupPackageVerification = Readonly<{
    readonly ok: boolean;
    readonly operation: 'verifyCollectiveBgvSetupPackage';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly verifierStatus:
        | 'accepted'
        | 'pending'
        | 'refused'
        | 'aborted'
        | 'forkDetected'
        | 'outsideProfile';
    readonly currentPhase: string | null;
    readonly phaseOrderHash: ProtocolHash;
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly missingObjects: readonly string[];
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

/** Derives threshold, quorum, and warning parameters for a roster profile. */
export const deriveThresholdProfile = (
    input: ThresholdProfileInput,
): ThresholdProfile => deriveThresholdProfileInternal(input);

/** Derives the concrete roster profile after registration closes and the roster freezes. */
export const deriveFrozenRosterProfile = deriveFrozenRosterProfileInternal;

/** Derives the canonical poll-spec hash including roster policy fields. */
export const derivePollSpecHash = derivePollSpecHashInternal;

/** Derives the canonical threshold-profile hash for a frozen roster profile. */
export const deriveThresholdProfileHash = deriveThresholdProfileHashInternal;

/** Validates and normalizes a poll specification from trusted or untrusted input. */
export function validatePollSpec(input: PollSpecInput): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation;
export function validatePollSpec(input: unknown): PollSpecValidation {
    return validatePollSpecInternal(input);
}

/** Returns whether a lifecycle transition is part of the supported state graph. */
export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => isValidLifecycleTransitionInternal(transition);

/** Derives user-facing lifecycle, failure, and mode labels for one state. */
export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => deriveLifecycleLabelsInternal(input);

/** Evaluates whether a protocol action is allowed in the current context. */
export const evaluateActionCapability = (
    action: ProtocolAction,
    context: CapabilityContext,
): CapabilityDecision => evaluateActionCapabilityInternal(action, context);

// Fail-closed result builder for the reserved future complete-protocol entry points
// below: each returns a structured OperationUnavailable refusal (ok:false) rather than
// throwing, so callers get a typed, non-crashing refusal until the path is implemented.
const unavailableFutureProtocolOperation = (
    operation: string,
): FutureProtocolOperationResult => ({
    ok: false,
    statusLabels: [],
    acceptedHashes: [],
    refusedObjects: [
        {
            code: 'OperationUnavailable',
            message: `${operation} is reserved for later protocol implementation and is not implemented in this package build.`,
        },
    ],
    unresolvedReason: 'OperationUnavailable',
    operation,
});

/** Reserved transcript verifier entry point for the future complete protocol path. */
export const verifyTranscript = (): FutureProtocolOperationResult =>
    unavailableFutureProtocolOperation('verifyTranscript');

/** Verifies the integrated foundation transcript without claiming full election verification. */
export const verifyFoundationTranscript = (
    input: FoundationTranscriptInput,
): FoundationTranscriptVerification =>
    verifyFoundationTranscriptInternal(input);

/** Verifies signed board heads, inclusion proofs, and append-only evidence. */
export const verifyBoardConsistency = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => verifyBoardConsistencyInternal(input);

/** Verifies the signed shell and inclusion evidence for a cast receipt. */
export const verifyCastReceiptShell = (
    input: CastReceiptVerificationInput,
): CastReceiptVerification => verifyCastReceiptShellInternal(input);

/** Verifies the signed shell and inclusion evidence for a close record. */
export const verifyCloseRecordShell = (
    input: CloseRecordVerificationInput,
): CloseRecordVerification => verifyCloseRecordShellInternal(input);

/** Verifies witness checkpoints and board evidence for a target finality record. */
export const verifyTargetFinality = (
    input: TargetFinalityVerificationInput,
): TargetFinalityVerification => verifyTargetFinalityInternal(input);

/** Derives the deterministic first-valid order for validated objects. */
export const deriveValidatedFirstValidOrder = (
    input: FirstValidOrderingInput,
): FirstValidOrderingVerification =>
    deriveValidatedFirstValidOrderInternal(input);

/** Verifies one participant's local acceptance of the frozen public roster. */
export const verifyRosterExternalAcceptance = (
    input: RosterExternalAcceptanceVerificationInput,
): RosterExternalAcceptanceVerification =>
    verifyRosterExternalAcceptanceInternal(input);

/** Verifies roster freeze inputs, manifest evidence, and setup uniqueness. */
export const verifyRosterManifestTranscript = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification =>
    verifyRosterManifestTranscriptInternal(input);

/** Checks whether an action context is current for a signer recovery epoch. */
export const isActionCurrentForRecoveryEpoch = (
    input: ActionCurrentForRecoveryEpochInput,
): ActionCurrentForRecoveryEpochResult =>
    isActionCurrentForRecoveryEpochInternal(input);

/** Verifies a recovery epoch update and returns the accepted epoch entry. */
export const verifyRecoveryEpochUpdate = (
    input: RecoveryEpochVerificationInput,
): RecoveryEpochVerification => verifyRecoveryEpochUpdateInternal(input);

const setupPhaseNumber = (
    phaseOrder: readonly {
        readonly phaseId: string;
        readonly phaseNumber: number;
    }[],
    phaseId: string,
): number => {
    const phase = phaseOrder.find(
        (candidatePhase) => candidatePhase.phaseId === phaseId,
    );
    if (phase === undefined) {
        throw new Error(`Accepted setup phase ${phaseId} is not available.`);
    }

    return phase.phaseNumber;
};

/** Creates the signed setup intent object for one trustee. */
export const createSetupIntent = async (
    input: SetupIntentInput,
): Promise<SetupPhaseParticipantObject> => {
    const kernel = await loadTranscriptCoreKernel();

    return createSetupIntentInternal({
        ...input,
        phaseId: 'setupIntent',
        phaseNumber: setupPhaseNumber(
            kernel.describeCollectiveBgvSetupProfile().phaseOrder,
            'setupIntent',
        ),
    } satisfies ProtocolSetupPhaseParticipantObjectInput) as Promise<SetupPhaseParticipantObject>;
};

/** Creates a deterministic setup phase record from signed participant objects. */
export const createSetupPhaseRecord = (
    input: SetupPhaseRecordInput,
): SetupPhaseRecord =>
    createSetupPhaseRecordInternal(input) as SetupPhaseRecord;

/** Creates a public common-randomness reveal record for one trustee. */
export const createCommonRandomnessReveal = (
    input: CommonRandomnessRevealInput,
): CommonRandomnessReveal => createCommonRandomnessRevealInternal(input);

/** Creates a public common-randomness commit record for one trustee. */
export const createCommonRandomnessCommit = (
    input: CommonRandomnessCommitInput,
): CommonRandomnessCommit => createCommonRandomnessCommitInternal(input);

/** Assembles full-roster common randomness and accepted public derivations. */
export const createSetupCommonRandomness = async (
    input: SetupCommonRandomnessInput,
): Promise<SetupCommonRandomness> => {
    const kernel = await loadTranscriptCoreKernel();
    const profile = kernel.describeCollectiveBgvSetupProfile();

    return createSetupCommonRandomnessInternal({
        ...input,
        participantCount: profile.participantCount,
        derivePublicDerivations: (publicMatrixSeedHash: ProtocolHash) =>
            kernel.deriveCollectiveBgvSetupPublicDerivations({
                publicMatrixSeedHash,
            }),
    });
};

/** Verifies one private VSS share envelope locally without returning raw shares. */
export const verifyPrivateVssShare = async (
    input: VerifyPrivateVssShareInput,
): Promise<PrivateVssShareVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyPrivateVssShareEnvelope(input);
};

const assertAcceptedPrivateVssVerification = (
    localVerification: PrivateVssShareVerification,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): void => {
    if (
        !localVerification.ok ||
        localVerification.verifierStatus !== 'accepted'
    ) {
        throw new Error(
            'localVerification must be accepted before creating a VSS share acceptance.',
        );
    }
    if (
        localVerification.privateEnvelopeHash !==
        envelopeReference.privateEnvelopeHash
    ) {
        throw new Error(
            'localVerification.privateEnvelopeHash must match envelopeReference.privateEnvelopeHash.',
        );
    }
    if (
        localVerification.localVerificationRoot !==
        envelopeReference.localVerificationRoot
    ) {
        throw new Error(
            'localVerification.localVerificationRoot must match envelopeReference.localVerificationRoot.',
        );
    }
};

const assertRefusedPrivateVssVerification = (
    localVerification: PrivateVssShareVerification,
): void => {
    if (
        localVerification.ok ||
        localVerification.verifierStatus !== 'refused'
    ) {
        throw new Error(
            'localVerification must be refused before creating a VSS complaint.',
        );
    }
    if (localVerification.refusedObjects.length === 0) {
        throw new Error(
            'localVerification.refusedObjects must include the local verification failure.',
        );
    }
};

/** Creates a signed VSS share acceptance from a matching accepted local verification. */
export const createVssShareAcceptance = async (
    input: VssShareAcceptanceInput,
): Promise<VssShareAcceptance> => {
    assertAcceptedPrivateVssVerification(
        input.localVerification,
        input.envelopeReference,
    );

    return createVssShareAcceptanceInternal(
        input as unknown as Parameters<
            typeof createVssShareAcceptanceInternal
        >[0],
    );
};

/** Creates a signed VSS complaint from a refused local private VSS verification. */
export const createVssComplaint = async (
    input: VssComplaintInput,
): Promise<VssComplaint> => {
    assertRefusedPrivateVssVerification(input.localVerification);

    return createVssComplaintInternal({
        ...input,
        localVerification: {
            ok: false,
            privateEnvelopeHash: input.localVerification.privateEnvelopeHash,
            localVerificationRoot:
                input.localVerification.localVerificationRoot,
            refusedObjects: input.localVerification.refusedObjects,
        },
    } as unknown as Parameters<typeof createVssComplaintInternal>[0]);
};

/** Creates a roots-only setup contribution record for one trustee. */
export const createSetupContribution = (
    input: SetupContributionInput,
): SetupContribution =>
    createSetupContributionInternal(
        input as unknown as SetupContributionAssemblyInput,
    );

/** Creates root-bound setup certificates from profile and transport evidence. */
export const createSetupCertificates = (
    input: SetupCertificatesInput,
): SetupCertificates => createSetupCertificatesInternal(input);

/** Creates a hash-bound setup package from canonical public setup records. */
export const createSetupPackage = (input: SetupPackageInput): SetupPackage =>
    createSetupPackageInternal(input as unknown as ProtocolSetupPackageInput);

const assertNoEvaluationKeyProofGeneration = (
    contribution: Readonly<Record<string, unknown>>,
    fieldName: string,
): void => {
    if (Object.prototype.hasOwnProperty.call(contribution, 'proofGeneration')) {
        throw new Error(
            `${fieldName}.proofGeneration is not accepted by the public setup facade; supply proofMaterial from a proof generator instead.`,
        );
    }
};

/** Creates root-bound public-key share records from public component hashes. */
export const createPublicKeyShareSet = (
    input: PublicKeyShareSetInput,
): PublicKeyShareSet => createPublicKeyShareSetInternal(input);

/** Creates root-bound public-key share proof statement records. */
export const createPublicKeyShareProofSet = (
    input: PublicKeyShareProofSetInput,
): PublicKeyShareProofSet => createPublicKeyShareProofSetInternal(input);

/** Creates root-bound same-secret proof records from generated proof material. */
export const createSameSecretProofSet = (
    input: SameSecretProofSetInput,
): SameSecretProofSet => createSameSecretProofSetInternal(input);

/** Creates root-bound public-key share material records from public coefficients. */
export const createPublicKeyShareMaterialSet = (
    input: PublicKeyShareMaterialSetInput,
): PublicKeyShareMaterialSet => createPublicKeyShareMaterialSetInternal(input);

/** Creates root-bound public-key LNP proof records from generated proof material. */
export const createPublicKeyShareLnpProofSet = (
    input: PublicKeyShareLnpProofSetInput,
): PublicKeyShareLnpProofSet => createPublicKeyShareLnpProofSetInternal(input);

/** Freezes the evaluator-key schedule used by setup verification. */
export const createEvaluatorKeySchedule = (
    input: EvaluatorKeyScheduleInput,
): EvaluatorKeySchedule => createEvaluatorKeyScheduleInternal(input);

/** Creates root-bound relinearization proof records from generated proof material. */
export const createRelinearizationKeyShareRounds = (
    input: RelinearizationKeyShareRoundsInput,
): RelinearizationKeyShareRounds => {
    input.roundOneContributions.forEach((contribution, contributionIndex) =>
        assertNoEvaluationKeyProofGeneration(
            contribution,
            `roundOneContributions.${String(contributionIndex)}`,
        ),
    );
    input.roundTwoContributions.forEach((contribution, contributionIndex) =>
        assertNoEvaluationKeyProofGeneration(
            contribution,
            `roundTwoContributions.${String(contributionIndex)}`,
        ),
    );

    return createRelinearizationKeyShareRoundsInternal(input);
};

/** Creates root-bound Galois proof batch records from generated proof material. */
export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => {
    input.batchContributions.forEach((batchContribution, batchIndex) =>
        batchContribution.galoisKeyShareProofs.forEach(
            (proofContribution, proofIndex) =>
                assertNoEvaluationKeyProofGeneration(
                    proofContribution,
                    `batchContributions.${String(batchIndex)}.galoisKeyShareProofs.${String(proofIndex)}`,
                ),
        ),
    );

    return createGaloisKeyShareBatchesInternal(input);
};

/** Creates public evaluation-key roots from verified relinearization and Galois records. */
export const createPublicEvaluationKeySet = (
    input: PublicEvaluationKeySetInput,
): PublicEvaluationKeySet => createPublicEvaluationKeySetInternal(input);

/** Encrypts local setup state from verified private VSS shares without returning plaintext. */
export const exportEncryptedLocalTrusteeSetupState = async (
    input: ExportEncryptedLocalTrusteeSetupStateInput,
): Promise<ExportEncryptedLocalTrusteeSetupStateResult> => {
    const result = await exportEncryptedLocalTrusteeSetupStateInternal(input);

    return {
        localStateCommitment: result.localStateCommitment,
        encryptedLocalState: result.encryptedLocalState,
        localStatePlaintextHash: result.localStatePlaintextHash,
        storageAadHash: result.storageAadHash,
    };
};

const assertExpectedString = (
    actual: string,
    expected: string | undefined,
    fieldName: string,
): void => {
    if (expected !== undefined && actual !== expected) {
        throw new Error(`${fieldName} does not match the expected value.`);
    }
};

const assertExpectedNumber = (
    actual: number,
    expected: number | undefined,
    fieldName: string,
): void => {
    if (expected !== undefined && actual !== expected) {
        throw new Error(`${fieldName} does not match the expected value.`);
    }
};

const assertExpectedHash = (
    actual: ProtocolHash,
    expected: ProtocolHash | undefined,
    fieldName: string,
): void => {
    if (expected !== undefined && actual !== expected) {
        throw new Error(`${fieldName} does not match the expected root.`);
    }
};

const assertRestoredLocalStateBindings = (
    input: RestoreLocalTrusteeSetupStateInput,
    localStatePlaintext: LocalTrusteeSetupStateSealedPayload,
): void => {
    const expectedSetupEpoch =
        input.expectedSetupEpoch ?? input.setupContext.setupEpoch;
    assertExpectedString(
        input.localStateCommitment.setupEpoch,
        expectedSetupEpoch,
        'localStateCommitment.setupEpoch',
    );
    assertExpectedString(
        localStatePlaintext.setupEpoch,
        expectedSetupEpoch,
        'localStatePlaintext.setupEpoch',
    );
    assertExpectedString(
        input.localStateCommitment.trusteeIdentity,
        input.expectedTrusteeIdentity,
        'localStateCommitment.trusteeIdentity',
    );
    assertExpectedString(
        localStatePlaintext.trusteeIdentity,
        input.expectedTrusteeIdentity,
        'localStatePlaintext.trusteeIdentity',
    );
    assertExpectedNumber(
        input.localStateCommitment.trusteeRosterPosition,
        input.expectedTrusteeRosterPosition,
        'localStateCommitment.trusteeRosterPosition',
    );
    assertExpectedNumber(
        localStatePlaintext.trusteeRosterPosition,
        input.expectedTrusteeRosterPosition,
        'localStatePlaintext.trusteeRosterPosition',
    );
    assertExpectedNumber(
        localStatePlaintext.deviceEpoch,
        input.expectedDeviceEpoch,
        'localStatePlaintext.deviceEpoch',
    );
    if (
        input.minimumDeviceEpoch !== undefined &&
        localStatePlaintext.deviceEpoch < input.minimumDeviceEpoch
    ) {
        throw new Error(
            'localStatePlaintext.deviceEpoch is older than the minimum accepted device epoch.',
        );
    }
    assertExpectedHash(
        input.localStateCommitment.thresholdShareCommitmentRecipientRoot,
        input.expectedThresholdShareCommitmentRecipientRoot,
        'localStateCommitment.thresholdShareCommitmentRecipientRoot',
    );
    assertExpectedHash(
        localStatePlaintext.thresholdShareCommitmentRecipientRoot,
        input.expectedThresholdShareCommitmentRecipientRoot,
        'localStatePlaintext.thresholdShareCommitmentRecipientRoot',
    );
    assertExpectedHash(
        input.localStateCommitment.aggregateThresholdShareRoot,
        input.expectedAggregateThresholdShareRoot,
        'localStateCommitment.aggregateThresholdShareRoot',
    );
    assertExpectedHash(
        localStatePlaintext.sealedAggregateThresholdShare.materialRoot,
        input.expectedAggregateThresholdShareRoot,
        'localStatePlaintext.sealedAggregateThresholdShare.materialRoot',
    );
    assertExpectedHash(
        input.localStateCommitment.issuedVssAcceptanceRoot,
        input.expectedIssuedVssAcceptanceRoot,
        'localStateCommitment.issuedVssAcceptanceRoot',
    );
    if (localStatePlaintext.issuedVssAcceptanceRoots.length !== 1) {
        throw new Error(
            'localStatePlaintext.issuedVssAcceptanceRoots must contain exactly one issued acceptance root.',
        );
    }
    assertExpectedHash(
        localStatePlaintext.issuedVssAcceptanceRoots[0],
        input.expectedIssuedVssAcceptanceRoot ??
            input.localStateCommitment.issuedVssAcceptanceRoot,
        'localStatePlaintext.issuedVssAcceptanceRoots.0',
    );
    if (
        localStatePlaintext.sealedAggregateThresholdShare.materialRoot !==
        input.localStateCommitment.aggregateThresholdShareRoot
    ) {
        throw new Error(
            'localStatePlaintext.sealedAggregateThresholdShare.materialRoot must match the local state commitment.',
        );
    }
};

/** Restores encrypted local setup state and verifies the roots-only commitment. */
export const restoreLocalTrusteeSetupState = async (
    input: RestoreLocalTrusteeSetupStateInput,
): Promise<RestoredLocalTrusteeSetupState> => {
    const expectedLocalStateRoot =
        input.expectedLocalStateRoot ??
        input.localStateCommitment.localStateRoot;
    if (input.localStateCommitment.localStateRoot !== expectedLocalStateRoot) {
        throw new Error(
            'localStateCommitment.localStateRoot does not match expectedLocalStateRoot.',
        );
    }
    if (input.encryptedLocalState.localStateRoot !== expectedLocalStateRoot) {
        throw new Error(
            'encryptedLocalState.localStateRoot does not match expectedLocalStateRoot.',
        );
    }

    const kernel = await loadTranscriptCoreKernel();
    const localStateVerification = kernel.verifyLocalTrusteeSetupState({
        setupContext: input.setupContext,
        localStateCommitment: input.localStateCommitment,
    }) as LocalTrusteeSetupStateVerification;
    const decryptedState = await restoreEncryptedLocalTrusteeSetupStateInternal(
        {
            encryptedLocalState:
                input.encryptedLocalState as unknown as LocalTrusteeSetupStateDecryptionInput['encryptedLocalState'],
            expectedLocalStateRoot,
            setupContext: input.setupContext,
            storageKeyBytesHex: input.storageKeyBytesHex,
        },
    );
    const localStatePlaintext =
        decryptedState.localStatePlaintext as LocalTrusteeSetupStateSealedPayload;
    assertRestoredLocalStateBindings(input, localStatePlaintext);

    return {
        ok: true,
        operation: 'restoreLocalTrusteeSetupState',
        setupProfileId: 'CollectiveBgvSetup-v1',
        localStateCommitment: input.localStateCommitment,
        localStatePlaintext,
        localStatePlaintextHash: decryptedState.localStatePlaintextHash,
        storageAadHash: decryptedState.storageAadHash,
        localStateVerification,
    };
};

/** Verifies an accepted setup package with the packaged Rust/WASM kernel. */
export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyCollectiveBgvSetup(input);
};

/** Verifies a transcript-core fixture with the packaged WASM kernel. */
export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreVerificationResult> => {
    const kernel = await loadTranscriptCoreKernel();
    const verification = kernel.verifyFixture(fixture);

    if ('expectedErrorCode' in verification) {
        return {
            caseName: verification.caseName,
            label: 'TranscriptCoreRejected',
            statusLabels: [],
            rejection: {
                code: verification.expectedErrorCode,
            },
        };
    }

    return {
        caseName: verification.caseName,
        label: 'TranscriptCoreVerified',
        objectHash512: verification.objectHash512,
        chunkRoot: verification.chunkRoot,
        statusLabels: verification.statusLabels,
    };
};
