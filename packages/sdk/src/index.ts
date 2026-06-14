import {
    createBinaryChunkedEvaluationKeyShareMaterialTransport as createBinaryChunkedEvaluationKeyShareMaterialTransportInternal,
    createBinaryChunkedPublicEvaluationKeyMaterialTransport as createBinaryChunkedPublicEvaluationKeyMaterialTransportInternal,
    createBinaryChunkedPublicKeyShareMaterialTransport as createBinaryChunkedPublicKeyShareMaterialTransportInternal,
    createBinaryChunkedPublicKeyShareProofMaterialTransport as createBinaryChunkedPublicKeyShareProofMaterialTransportInternal,
    createBinaryChunkedSameSecretProofMaterialTransport as createBinaryChunkedSameSecretProofMaterialTransportInternal,
    createCommonRandomnessCommit as createCommonRandomnessCommitInternal,
    createCommonRandomnessReveal as createCommonRandomnessRevealInternal,
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares as exportEncryptedLocalTrusteeSetupStateInternal,
    createEvaluatorKeySchedule as createEvaluatorKeyScheduleInternal,
    createGaloisKeyShareBatches as createGaloisKeyShareBatchesInternal,
    createPublicKeyShareSuccinctProofSet as createPublicKeyShareSuccinctProofSetInternal,
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
    createSetupPackageVerificationInput as createSetupPackageVerificationInputInternal,
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
    BinaryChunkedEvaluationKeyShareMaterialTransport as ProtocolBinaryChunkedEvaluationKeyShareMaterialTransport,
    EvaluatorKeySchedule as ProtocolEvaluatorKeySchedule,
    EvaluatorKeyScheduleInput as ProtocolEvaluatorKeyScheduleInput,
    GaloisKeyRootReference as ProtocolGaloisKeyRootReference,
    GaloisKeyShareBatch as ProtocolGaloisKeyShareBatch,
    GaloisKeyShareBatchContribution as ProtocolGaloisKeyShareBatchContribution,
    GaloisKeyShareBatchRootReference as ProtocolGaloisKeyShareBatchRootReference,
    GaloisKeyShareContribution as ProtocolGaloisKeyShareContribution,
    GaloisKeyShareMaterialRecord as ProtocolGaloisKeyShareMaterialRecord,
    EvaluationKeyShareMaterial as ProtocolEvaluationKeyShareMaterial,
    EvaluationKeyShareMaterialTransportInput as ProtocolEvaluationKeyShareMaterialTransportInput,
    GaloisKeyShareRootReference as ProtocolGaloisKeyShareRootReference,
    LocalTrusteeSetupStateDecryptionInput,
    PublicEvaluationKeySet as ProtocolPublicEvaluationKeySet,
    PublicEvaluationKeySetInput as ProtocolPublicEvaluationKeySetInput,
    BinaryChunkedSameSecretProofMaterialTransport as ProtocolBinaryChunkedSameSecretProofMaterialTransport,
    BinaryChunkedPublicKeyShareMaterialSet as ProtocolBinaryChunkedPublicKeyShareMaterialSet,
    BinaryChunkedPublicKeyShareMaterialTransport as ProtocolBinaryChunkedPublicKeyShareMaterialTransport,
    BinaryChunkedPublicKeyShareProofMaterialTransport as ProtocolBinaryChunkedPublicKeyShareProofMaterialTransport,
    PublicKeyShareCoefficientVectorHash as ProtocolPublicKeyShareCoefficientVectorHash,
    PublicKeyShareCoefficientVectorMaterial as ProtocolPublicKeyShareCoefficientVectorMaterial,
    PublicKeyShareContributionInput as ProtocolPublicKeyShareContributionInput,
    PublicKeyShareMaterialContributionInput as ProtocolPublicKeyShareMaterialContributionInput,
    PublicKeyShareMaterialRecord as ProtocolPublicKeyShareMaterialRecord,
    PublicKeyShareMaterialSet as ProtocolPublicKeyShareMaterialSet,
    PublicKeyShareMaterialSetInput as ProtocolPublicKeyShareMaterialSetInput,
    PublicKeyShareSuccinctProofMaterial as ProtocolPublicKeyShareSuccinctProofMaterial,
    PublicKeyShareSuccinctProofRecord as ProtocolPublicKeyShareSuccinctProofRecord,
    PublicKeyShareSuccinctProofSet as ProtocolPublicKeyShareSuccinctProofSet,
    PublicKeyShareSuccinctProofSetInput as ProtocolPublicKeyShareSuccinctProofSetInput,
    SetupPackagePublicKeyShareMaterialSet as ProtocolSetupPackagePublicKeyShareMaterialSet,
    SetupTransportedPublicKeyShareMaterial as ProtocolSetupTransportedPublicKeyShareMaterial,
    PublicKeyShareProofRecord as ProtocolPublicKeyShareProofRecord,
    PublicKeyShareProofSet as ProtocolPublicKeyShareProofSet,
    PublicKeyShareProofSetInput as ProtocolPublicKeyShareProofSetInput,
    PublicKeyShareRecord as ProtocolPublicKeyShareRecord,
    PublicKeyShareSet as ProtocolPublicKeyShareSet,
    PublicKeyShareSetInput as ProtocolPublicKeyShareSetInput,
    PublicEvaluationKeyMaterialTransportInput as ProtocolPublicEvaluationKeyMaterialTransportInput,
    SetupPackageVssCoefficientCommitmentMaterialSet as ProtocolSetupPackageVssCoefficientCommitmentMaterialSet,
    SetupTransportedVssCoefficientCommitmentMaterial as ProtocolSetupTransportedVssCoefficientCommitmentMaterial,
    SetupTransportedVssCoefficientCommitmentMaterialLike as ProtocolSetupTransportedVssCoefficientCommitmentMaterialLike,
    SetupTransportedVssCoefficientCommitmentMaterialReference as ProtocolSetupTransportedVssCoefficientCommitmentMaterialReference,
    VerifiedVssCoefficientCommitmentMaterial as ProtocolVerifiedVssCoefficientCommitmentMaterial,
    VerifiedSetupProofMaterial as ProtocolVerifiedSetupProofMaterial,
    VerifiedSetupProofMaterialSet as ProtocolVerifiedSetupProofMaterialSet,
    RelinearizationKeyRootReference as ProtocolRelinearizationKeyRootReference,
    RelinearizationKeyShareRoundOneRecord as ProtocolRelinearizationKeyShareRoundOneRecord,
    RelinearizationKeyShareRoundTwoRecord as ProtocolRelinearizationKeyShareRoundTwoRecord,
    RelinearizationKeyShareRounds as ProtocolRelinearizationKeyShareRounds,
    RelinearizationKeyShareRoundsInput as ProtocolRelinearizationKeyShareRoundsInput,
    RelinearizationLevelScheduleEntry as ProtocolRelinearizationLevelScheduleEntry,
    RelinearizationRoundOneContribution as ProtocolRelinearizationRoundOneContribution,
    RelinearizationRoundTwoContribution as ProtocolRelinearizationRoundTwoContribution,
    TrusteeEvaluationKeyProofRecord as ProtocolTrusteeEvaluationKeyProofRecord,
    TrusteeEvaluationKeyProofSet as ProtocolTrusteeEvaluationKeyProofSet,
    RequiredGaloisKeyScheduleEntry as ProtocolRequiredGaloisKeyScheduleEntry,
    RequiredGaloisSet as ProtocolRequiredGaloisSet,
    SameSecretProofMaterial as ProtocolSameSecretProofMaterial,
    SameSecretProofRecord as ProtocolSameSecretProofRecord,
    SameSecretProofReference as ProtocolSameSecretProofReference,
    SameSecretProofSet as ProtocolSameSecretProofSet,
    SameSecretProofSetInput as ProtocolSameSecretProofSetInput,
    TransportedSameSecretProofMaterialSet as ProtocolTransportedSameSecretProofMaterialSet,
    TransportedPublicKeyShareProofMaterialSet as ProtocolTransportedPublicKeyShareProofMaterialSet,
    TransportedEvaluationKeyShareComponentMaterialSet as ProtocolTransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet as ProtocolTransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicEvaluationKeyMaterialSet as ProtocolTransportedPublicEvaluationKeyMaterialSet,
    BinaryChunkedPublicEvaluationKeyMaterialTransport as ProtocolBinaryChunkedPublicEvaluationKeyMaterialTransport,
    BgvHeSecurityCertificate as ProtocolBgvHeSecurityCertificate,
    SetupCertificates as ProtocolSetupCertificates,
    SetupCommitmentSecurityCertificate as ProtocolSetupCommitmentSecurityCertificate,
    SetupProofAccountingCertificate as ProtocolSetupProofAccountingCertificate,
    SetupCertificateTransportedObjectInput as ProtocolSetupCertificateTransportedObjectInput,
    SetupTransportCertificate as ProtocolSetupTransportCertificate,
    SetupContributionAssemblyInput,
    SetupKeyCorrectnessCertificate as ProtocolSetupKeyCorrectnessCertificate,
    SetupPackage as ProtocolSetupPackage,
    SetupPackageInput as ProtocolSetupPackageInput,
    SetupPackageVerificationInputSource as ProtocolSetupPackageVerificationInputSource,
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
import type { TranscriptCoreKernel } from '@sealed-lattice/wasm';

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
    readonly transportedObjects?: readonly ProtocolSetupCertificateTransportedObjectInput[];
}>;
export type SetupCertificateTransportedObjectInput =
    ProtocolSetupCertificateTransportedObjectInput;

export type SetupCertificatesInput = Readonly<{
    readonly setupProfile: JsonRecord;
    readonly bgvProfile: JsonRecord;
    readonly vssCoefficientCommitmentMaterial: JsonRecord;
    readonly transport: SetupCertificateTransportInput;
    readonly sameSecretLinkageAnchorProofAccounting?: JsonRecord;
    readonly publicKeyShareProofAccounting?: JsonRecord;
    readonly trusteeEvaluationKeyProofAccounting?: JsonRecord;
}>;

export type SetupCertificates = ProtocolSetupCertificates;
export type SetupCommitmentSecurityCertificate =
    ProtocolSetupCommitmentSecurityCertificate;
export type SetupProofAccountingCertificate =
    ProtocolSetupProofAccountingCertificate;
export type SetupTransportCertificate = ProtocolSetupTransportCertificate;
export type BgvHeSecurityCertificate = ProtocolBgvHeSecurityCertificate;
export type SetupKeyCorrectnessCertificate =
    ProtocolSetupKeyCorrectnessCertificate;

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly JsonRecord[];
    readonly commonRandomness: JsonRecord;
    readonly vssCoefficientCommitments: JsonRecord;
    readonly vssCoefficientCommitmentMaterial:
        | SetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly transportedVssCoefficientCommitmentMaterial?: SetupTransportedVssCoefficientCommitmentMaterial;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: JsonRecord;
    readonly vssComplaints?: JsonRecord;
    readonly thresholdShareCommitments?: JsonRecord;
    readonly sameSecretConsistency: JsonRecord;
    readonly sameSecretProofs: JsonRecord;
    readonly publicKeyShares: JsonRecord;
    readonly publicKeyShareProofs: JsonRecord;
    readonly publicKeyShareMaterial:
        | SetupPackagePublicKeyShareMaterialSet
        | JsonRecord;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly publicKeyShareSuccinctProofs: JsonRecord;
    readonly evaluatorKeySchedule: JsonRecord;
    readonly relinearizationKeyShareRounds: JsonRecord;
    readonly galoisKeyShareBatches: readonly JsonRecord[];
    readonly trusteeEvaluationKeyProofs: JsonRecord;
    readonly evaluationKeys: JsonRecord;
    readonly setupCertificateInput?: Omit<
        SetupCertificatesInput,
        'vssCoefficientCommitmentMaterial'
    >;
    readonly setupCommitmentSecurityCertificate?: JsonRecord;
    readonly setupTransportCertificate?: JsonRecord;
    readonly setupProofAccountingCertificate?: JsonRecord;
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
export type BinaryChunkedSameSecretProofMaterialTransport =
    ProtocolBinaryChunkedSameSecretProofMaterialTransport;
export type BinaryChunkedPublicKeyShareMaterialSet =
    ProtocolBinaryChunkedPublicKeyShareMaterialSet;
export type BinaryChunkedPublicKeyShareMaterialTransport =
    ProtocolBinaryChunkedPublicKeyShareMaterialTransport;
export type BinaryChunkedPublicKeyShareProofMaterialTransport =
    ProtocolBinaryChunkedPublicKeyShareProofMaterialTransport;
export type BinaryChunkedEvaluationKeyShareMaterialTransport =
    ProtocolBinaryChunkedEvaluationKeyShareMaterialTransport;
export type SetupPackageVssCoefficientCommitmentMaterialSet =
    ProtocolSetupPackageVssCoefficientCommitmentMaterialSet;
export type SetupTransportedVssCoefficientCommitmentMaterial =
    ProtocolSetupTransportedVssCoefficientCommitmentMaterial;
export type SetupTransportedVssCoefficientCommitmentMaterialReference =
    ProtocolSetupTransportedVssCoefficientCommitmentMaterialReference;
export type SetupTransportedVssCoefficientCommitmentMaterialLike =
    ProtocolSetupTransportedVssCoefficientCommitmentMaterialLike;
export type VerifiedVssCoefficientCommitmentMaterial =
    ProtocolVerifiedVssCoefficientCommitmentMaterial;
export type VerifiedSetupProofMaterial = ProtocolVerifiedSetupProofMaterial;
export type VerifiedSetupProofMaterialSet =
    ProtocolVerifiedSetupProofMaterialSet;
export type SetupPackagePublicKeyShareMaterialSet =
    ProtocolSetupPackagePublicKeyShareMaterialSet;
export type SetupTransportedPublicKeyShareMaterial =
    ProtocolSetupTransportedPublicKeyShareMaterial;
export type TransportedSameSecretProofMaterialSet =
    ProtocolTransportedSameSecretProofMaterialSet;
export type TransportedPublicKeyShareProofMaterialSet =
    ProtocolTransportedPublicKeyShareProofMaterialSet;
export type TransportedEvaluationKeyShareProofMaterialSet =
    ProtocolTransportedEvaluationKeyShareProofMaterialSet;
export type TransportedEvaluationKeyShareComponentMaterialSet =
    ProtocolTransportedEvaluationKeyShareComponentMaterialSet;
export type PublicKeyShareSuccinctProofMaterial =
    ProtocolPublicKeyShareSuccinctProofMaterial;
export type PublicKeyShareSuccinctProofRecord =
    ProtocolPublicKeyShareSuccinctProofRecord;
export type PublicKeyShareSuccinctProofSet =
    ProtocolPublicKeyShareSuccinctProofSet;
export type PublicKeyShareSuccinctProofSetInput =
    ProtocolPublicKeyShareSuccinctProofSetInput;
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
export type EvaluationKeyShareMaterial = ProtocolEvaluationKeyShareMaterial;
export type RelinearizationRoundOneContribution =
    ProtocolRelinearizationRoundOneContribution;
export type RelinearizationRoundTwoContribution =
    ProtocolRelinearizationRoundTwoContribution;
export type RelinearizationKeyShareRoundOneRecord =
    ProtocolRelinearizationKeyShareRoundOneRecord;
export type RelinearizationKeyShareRoundTwoRecord =
    ProtocolRelinearizationKeyShareRoundTwoRecord;
export type RelinearizationKeyShareRounds =
    ProtocolRelinearizationKeyShareRounds;
type PublicEvaluationKeyProofCommonInput = Readonly<
    Omit<
        ProtocolRelinearizationKeyShareRoundsInput,
        'roundOneContributions' | 'roundTwoContributions'
    >
>;
export type RelinearizationKeyShareRoundsInput =
    ProtocolRelinearizationKeyShareRoundsInput;
export type GaloisKeyShareRootReference = ProtocolGaloisKeyShareRootReference;
export type GaloisKeyShareContribution = ProtocolGaloisKeyShareContribution;
export type GaloisKeyShareBatchContribution =
    ProtocolGaloisKeyShareBatchContribution;
export type GaloisKeyShareMaterialRecord = ProtocolGaloisKeyShareMaterialRecord;
export type GaloisKeyShareBatch = ProtocolGaloisKeyShareBatch;
export type GaloisKeyShareBatchesInput = PublicEvaluationKeyProofCommonInput &
    Readonly<{
        readonly batchContributions: readonly GaloisKeyShareBatchContribution[];
    }>;
export type TrusteeEvaluationKeyProofRecord =
    ProtocolTrusteeEvaluationKeyProofRecord;
export type TrusteeEvaluationKeyProofSet = ProtocolTrusteeEvaluationKeyProofSet;
export type EvaluationKeyShareMaterialTransportInput =
    ProtocolEvaluationKeyShareMaterialTransportInput;
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
export type TransportedPublicEvaluationKeyMaterialSet =
    ProtocolTransportedPublicEvaluationKeyMaterialSet;
export type BinaryChunkedPublicEvaluationKeyMaterialTransport =
    ProtocolBinaryChunkedPublicEvaluationKeyMaterialTransport;
export type PublicEvaluationKeyMaterialTransportInput =
    PublicEvaluationKeyProofCommonInput &
        Readonly<
            Pick<
                ProtocolPublicEvaluationKeyMaterialTransportInput,
                | 'relinearizationKeyShareRounds'
                | 'galoisKeyShareBatches'
                | 'transportedEvaluationKeyShareComponentMaterial'
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
    readonly sealedLocalStatePayloadHash: ProtocolHash;
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
    readonly sealedLocalStatePayload: LocalTrusteeSetupStateSealedPayload;
    readonly sealedLocalStatePayloadHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
    readonly localStateVerification: LocalTrusteeSetupStateVerification;
}>;

export type VerifySetupPackageInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedSetupPackageHash?: ProtocolHash;
    readonly expectedManifestHash?: ProtocolHash;
    readonly expectedRosterHash?: ProtocolHash;
    readonly transportedVssCoefficientCommitmentMaterial?: SetupTransportedVssCoefficientCommitmentMaterialLike;
    readonly verifiedVssCoefficientCommitmentMaterial?: VerifiedVssCoefficientCommitmentMaterial;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
    readonly verifiedSetupProofMaterials?: VerifiedSetupProofMaterialSet;
}>;

export type SetupPackageVerificationInputSource = Readonly<
    Omit<ProtocolSetupPackageVerificationInputSource, 'setupPackage'> & {
        readonly setupPackage: SetupPackage;
    }
>;

export type AcceptedSetupHandoff = Readonly<{
    readonly objectType: 'CollectiveBgvAcceptedSetupHandoff';
    readonly objectVersion: 1;
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupProfileHash: ProtocolHash;
    readonly qShareHash: ProtocolHash;
    readonly commitmentProfileHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly setupPackageHash: ProtocolHash;
    readonly directBallotEncryptionHandoff: Readonly<{
        readonly status: 'accepted-collective-public-key-root-bound-for-direct-ballot-encryption';
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly publicKeyShareMaterialSetRoot: ProtocolHash;
        readonly publicKeyShareSuccinctProofSetRoot: ProtocolHash;
    }>;
    readonly publicAggregationHandoff: Readonly<{
        readonly status: 'accepted-public-ciphertext-aggregation-bound-to-setup-context-and-collective-public-key-root';
        readonly thresholdShareCommitmentRoot: ProtocolHash;
    }>;
    readonly boundedEvaluatorReplayHandoff: Readonly<{
        readonly status: 'accepted-public-evaluation-keys-bound-to-frozen-evaluator-schedule';
        readonly evaluatorKeyScheduleRoot: ProtocolHash;
        readonly relinearizationKeyShareRoundsRoot: ProtocolHash;
        readonly trusteeEvaluationKeyProofSetRoot: ProtocolHash;
        readonly evaluationKeySetHash: ProtocolHash;
        readonly publicEvaluationKeyMaterialRoot?: ProtocolHash;
    }>;
    readonly futureTargetDecryptionHandoff: Readonly<{
        readonly status: string;
        readonly targetDecryptionProfileId: string;
        readonly claimBoundary: string;
    }>;
    readonly certificateRoots: Readonly<{
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
        readonly heSecurityCertificateHash: ProtocolHash;
    }>;
    readonly acceptedSetupHandoffRoot: ProtocolHash;
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
    readonly acceptedSetupHandoff?: AcceptedSetupHandoff;
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

/** Builds the public-only setup package verification input from package and transported setup material. */
export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): VerifySetupPackageInput =>
    createSetupPackageVerificationInputInternal(input);

type SetupProofMaterialTransportFieldName =
    | 'transportedSameSecretProofMaterial'
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportSet =
    | TransportedSameSecretProofMaterialSet
    | TransportedPublicKeyShareProofMaterialSet
    | TransportedEvaluationKeyShareProofMaterialSet;

type SetupProofMaterialChunk = Readonly<{
    readonly chunkIndex: number;
    readonly bytesHex: string;
}>;

const setupProofMaterialTransportFieldNames = [
    'transportedSameSecretProofMaterial',
    'transportedPublicKeyShareProofMaterial',
    'transportedEvaluationKeyShareProofMaterial',
] as const satisfies readonly SetupProofMaterialTransportFieldName[];

let setupProofMaterialVerificationSequence = 0;

const setupProofMaterialVerificationId = (
    fieldName: SetupProofMaterialTransportFieldName,
    materialIndex: number,
    proofMaterial: JsonRecord,
): string => {
    setupProofMaterialVerificationSequence += 1;
    const proofMaterialRoot =
        typeof proofMaterial.proofMaterialRoot === 'string'
            ? proofMaterial.proofMaterialRoot.slice(0, 24)
            : 'unbound';

    return [
        'sdk-proof-material',
        String(setupProofMaterialVerificationSequence),
        fieldName,
        String(materialIndex),
        proofMaterialRoot,
    ].join('-');
};

const setupProofMaterialReference = (proofMaterial: JsonRecord): JsonRecord => {
    const { chunks: omittedChunks, ...reference } = proofMaterial;
    void omittedChunks;

    return reference;
};

const compactSetupProofMaterialSet = <
    MaterialSet extends SetupProofMaterialTransportSet | undefined,
>(
    materialSet: MaterialSet,
    verifiedSetupProofMaterials: VerifiedSetupProofMaterialSet | undefined,
): MaterialSet => {
    if (
        materialSet === undefined ||
        verifiedSetupProofMaterials === undefined
    ) {
        return materialSet;
    }

    const verifiedProofMaterialRoots = new Set(
        verifiedSetupProofMaterials.proofMaterials.map(
            (proofMaterial) => proofMaterial.proofMaterialRoot,
        ),
    );
    let strippedAnyChunks = false;
    const proofMaterials = materialSet.proofMaterials.map((proofMaterial) => {
        if (
            !Object.prototype.hasOwnProperty.call(proofMaterial, 'chunks') ||
            typeof proofMaterial.proofMaterialRoot !== 'string' ||
            !verifiedProofMaterialRoots.has(proofMaterial.proofMaterialRoot)
        ) {
            return proofMaterial;
        }
        strippedAnyChunks = true;

        return setupProofMaterialReference(proofMaterial);
    });

    if (!strippedAnyChunks) {
        return materialSet;
    }

    return {
        ...materialSet,
        proofMaterials,
    };
};

const setupProofMaterialChunks = (
    proofMaterial: unknown,
): readonly SetupProofMaterialChunk[] | undefined => {
    if (
        proofMaterial === null ||
        typeof proofMaterial !== 'object' ||
        !Object.prototype.hasOwnProperty.call(proofMaterial, 'chunks')
    ) {
        return undefined;
    }

    const chunks = (proofMaterial as JsonRecord).chunks;

    return Array.isArray(chunks)
        ? (chunks as readonly SetupProofMaterialChunk[])
        : undefined;
};

const streamSetupProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    fieldName: SetupProofMaterialTransportFieldName,
    materialSet: SetupProofMaterialTransportSet | undefined,
): readonly VerifiedSetupProofMaterial[] => {
    if (
        materialSet === undefined ||
        !Array.isArray(materialSet.proofMaterials)
    ) {
        return [];
    }

    const verifiedMaterials: VerifiedSetupProofMaterial[] = [];
    materialSet.proofMaterials.forEach((proofMaterialValue, materialIndex) => {
        const chunks = setupProofMaterialChunks(proofMaterialValue);
        if (chunks === undefined) {
            return;
        }
        const proofMaterial = proofMaterialValue as JsonRecord;
        const proofMaterialReference =
            setupProofMaterialReference(proofMaterial);
        const verificationId = setupProofMaterialVerificationId(
            fieldName,
            materialIndex,
            proofMaterial,
        );
        kernel.beginSetupProofMaterialTransportStream({
            verificationId,
            transportedSetupProofMaterial: proofMaterialReference,
        });
        chunks.forEach((chunk) => {
            kernel.absorbSetupProofMaterialTransportStreamChunk({
                verificationId,
                chunkIndex: chunk.chunkIndex,
                bytesHex: chunk.bytesHex,
            });
        });
        const verification = kernel.finishSetupProofMaterialTransportStream({
            verificationId,
        });
        verifiedMaterials.push(
            verification.verifiedSetupProofMaterial as VerifiedSetupProofMaterial,
        );
    });

    return verifiedMaterials;
};

const prepareSetupPackageVerificationInputForKernel = (
    kernel: TranscriptCoreKernel,
    input: VerifySetupPackageInput,
): VerifySetupPackageInput => {
    if (input.verifiedSetupProofMaterials !== undefined) {
        return {
            ...input,
            transportedSameSecretProofMaterial: compactSetupProofMaterialSet(
                input.transportedSameSecretProofMaterial,
                input.verifiedSetupProofMaterials,
            ),
            transportedPublicKeyShareProofMaterial:
                compactSetupProofMaterialSet(
                    input.transportedPublicKeyShareProofMaterial,
                    input.verifiedSetupProofMaterials,
                ),
            transportedEvaluationKeyShareProofMaterial:
                compactSetupProofMaterialSet(
                    input.transportedEvaluationKeyShareProofMaterial,
                    input.verifiedSetupProofMaterials,
                ),
        };
    }

    const verifiedMaterials = setupProofMaterialTransportFieldNames.flatMap(
        (fieldName) =>
            streamSetupProofMaterialSet(kernel, fieldName, input[fieldName]),
    );
    if (verifiedMaterials.length === 0) {
        return input;
    }

    const verifiedSetupProofMaterials = {
        objectType: 'VerifiedSetupProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofMaterials: verifiedMaterials,
    } as const satisfies VerifiedSetupProofMaterialSet;

    return {
        ...input,
        transportedSameSecretProofMaterial: compactSetupProofMaterialSet(
            input.transportedSameSecretProofMaterial,
            verifiedSetupProofMaterials,
        ),
        transportedPublicKeyShareProofMaterial: compactSetupProofMaterialSet(
            input.transportedPublicKeyShareProofMaterial,
            verifiedSetupProofMaterials,
        ),
        transportedEvaluationKeyShareProofMaterial:
            compactSetupProofMaterialSet(
                input.transportedEvaluationKeyShareProofMaterial,
                verifiedSetupProofMaterials,
            ),
        verifiedSetupProofMaterials,
    };
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

/** Creates root-addressed binary transport for same-secret proof material. */
export const createBinaryChunkedSameSecretProofMaterialTransport = (
    proofMaterials: readonly SameSecretProofMaterial[],
): BinaryChunkedSameSecretProofMaterialTransport =>
    createBinaryChunkedSameSecretProofMaterialTransportInternal(proofMaterials);

/** Creates root-bound public-key share material records from public coefficients. */
export const createPublicKeyShareMaterialSet = (
    input: PublicKeyShareMaterialSetInput,
): PublicKeyShareMaterialSet => createPublicKeyShareMaterialSetInternal(input);

/** Creates root-addressed binary transport for public-key share material. */
export const createBinaryChunkedPublicKeyShareMaterialTransport = (
    materialSet: PublicKeyShareMaterialSet,
): BinaryChunkedPublicKeyShareMaterialTransport =>
    createBinaryChunkedPublicKeyShareMaterialTransportInternal(materialSet);

/** Creates root-addressed binary transport for public-key share proof material. */
export const createBinaryChunkedPublicKeyShareProofMaterialTransport = (
    proofMaterials: readonly PublicKeyShareSuccinctProofMaterial[],
): BinaryChunkedPublicKeyShareProofMaterialTransport =>
    createBinaryChunkedPublicKeyShareProofMaterialTransportInternal(
        proofMaterials,
    );

/** Creates root-addressed binary transport for evaluation-key proof and component material. */
export const createBinaryChunkedEvaluationKeyShareMaterialTransport = (
    input: EvaluationKeyShareMaterialTransportInput,
): BinaryChunkedEvaluationKeyShareMaterialTransport =>
    createBinaryChunkedEvaluationKeyShareMaterialTransportInternal(input);

/** Creates root-addressed binary transport for public evaluation-key runtime material. */
export const createBinaryChunkedPublicEvaluationKeyMaterialTransport = (
    input: PublicEvaluationKeyMaterialTransportInput,
): BinaryChunkedPublicEvaluationKeyMaterialTransport =>
    createBinaryChunkedPublicEvaluationKeyMaterialTransportInternal(input);

/** Creates root-bound public-key succinct proof records from generated proof material. */
export const createPublicKeyShareSuccinctProofSet = (
    input: PublicKeyShareSuccinctProofSetInput,
): PublicKeyShareSuccinctProofSet =>
    createPublicKeyShareSuccinctProofSetInternal(input);

/** Freezes the evaluator-key schedule used by setup verification. */
export const createEvaluatorKeySchedule = (
    input: EvaluatorKeyScheduleInput,
): EvaluatorKeySchedule => createEvaluatorKeyScheduleInternal(input);

/** Creates root-bound relinearization share records from public share material. */
export const createRelinearizationKeyShareRounds = (
    input: RelinearizationKeyShareRoundsInput,
): RelinearizationKeyShareRounds =>
    createRelinearizationKeyShareRoundsInternal(input);

/** Creates root-bound Galois share batch records from public share material. */
export const createGaloisKeyShareBatches = (
    input: GaloisKeyShareBatchesInput,
): readonly GaloisKeyShareBatch[] => createGaloisKeyShareBatchesInternal(input);

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
        sealedLocalStatePayloadHash: result.localStatePlaintextHash,
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
    sealedLocalStatePayload: LocalTrusteeSetupStateSealedPayload,
): void => {
    const expectedSetupEpoch =
        input.expectedSetupEpoch ?? input.setupContext.setupEpoch;
    assertExpectedString(
        input.localStateCommitment.setupEpoch,
        expectedSetupEpoch,
        'localStateCommitment.setupEpoch',
    );
    assertExpectedString(
        sealedLocalStatePayload.setupEpoch,
        expectedSetupEpoch,
        'sealedLocalStatePayload.setupEpoch',
    );
    assertExpectedString(
        input.localStateCommitment.trusteeIdentity,
        input.expectedTrusteeIdentity,
        'localStateCommitment.trusteeIdentity',
    );
    assertExpectedString(
        sealedLocalStatePayload.trusteeIdentity,
        input.expectedTrusteeIdentity,
        'sealedLocalStatePayload.trusteeIdentity',
    );
    assertExpectedNumber(
        input.localStateCommitment.trusteeRosterPosition,
        input.expectedTrusteeRosterPosition,
        'localStateCommitment.trusteeRosterPosition',
    );
    assertExpectedNumber(
        sealedLocalStatePayload.trusteeRosterPosition,
        input.expectedTrusteeRosterPosition,
        'sealedLocalStatePayload.trusteeRosterPosition',
    );
    assertExpectedNumber(
        sealedLocalStatePayload.deviceEpoch,
        input.expectedDeviceEpoch,
        'sealedLocalStatePayload.deviceEpoch',
    );
    if (
        input.minimumDeviceEpoch !== undefined &&
        sealedLocalStatePayload.deviceEpoch < input.minimumDeviceEpoch
    ) {
        throw new Error(
            'sealedLocalStatePayload.deviceEpoch is older than the minimum accepted device epoch.',
        );
    }
    assertExpectedHash(
        input.localStateCommitment.thresholdShareCommitmentRecipientRoot,
        input.expectedThresholdShareCommitmentRecipientRoot,
        'localStateCommitment.thresholdShareCommitmentRecipientRoot',
    );
    assertExpectedHash(
        sealedLocalStatePayload.thresholdShareCommitmentRecipientRoot,
        input.expectedThresholdShareCommitmentRecipientRoot,
        'sealedLocalStatePayload.thresholdShareCommitmentRecipientRoot',
    );
    assertExpectedHash(
        input.localStateCommitment.aggregateThresholdShareRoot,
        input.expectedAggregateThresholdShareRoot,
        'localStateCommitment.aggregateThresholdShareRoot',
    );
    assertExpectedHash(
        sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot,
        input.expectedAggregateThresholdShareRoot,
        'sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot',
    );
    assertExpectedHash(
        input.localStateCommitment.issuedVssAcceptanceRoot,
        input.expectedIssuedVssAcceptanceRoot,
        'localStateCommitment.issuedVssAcceptanceRoot',
    );
    if (sealedLocalStatePayload.issuedVssAcceptanceRoots.length !== 1) {
        throw new Error(
            'sealedLocalStatePayload.issuedVssAcceptanceRoots must contain exactly one issued acceptance root.',
        );
    }
    assertExpectedHash(
        sealedLocalStatePayload.issuedVssAcceptanceRoots[0],
        input.expectedIssuedVssAcceptanceRoot ??
            input.localStateCommitment.issuedVssAcceptanceRoot,
        'sealedLocalStatePayload.issuedVssAcceptanceRoots.0',
    );
    if (
        sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot !==
        input.localStateCommitment.aggregateThresholdShareRoot
    ) {
        throw new Error(
            'sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot must match the local state commitment.',
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
    const sealedLocalStatePayload =
        decryptedState.localStatePlaintext as LocalTrusteeSetupStateSealedPayload;
    assertRestoredLocalStateBindings(input, sealedLocalStatePayload);

    return {
        ok: true,
        operation: 'restoreLocalTrusteeSetupState',
        setupProfileId: 'CollectiveBgvSetup-v1',
        localStateCommitment: input.localStateCommitment,
        sealedLocalStatePayload,
        sealedLocalStatePayloadHash: decryptedState.localStatePlaintextHash,
        storageAadHash: decryptedState.storageAadHash,
        localStateVerification,
    };
};

/** Verifies an accepted setup package with the packaged Rust/WASM kernel. */
export const verifySetupPackage = async (
    input: VerifySetupPackageInput,
): Promise<SetupPackageVerification> => {
    const kernel = await loadTranscriptCoreKernel();
    const verificationInput = prepareSetupPackageVerificationInputForKernel(
        kernel,
        input,
    );

    return kernel.verifyCollectiveBgvSetup(verificationInput);
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
