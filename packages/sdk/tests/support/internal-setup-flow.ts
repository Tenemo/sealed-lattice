// Setup-assembly builders relocated out of the public verifier-only SDK surface.
//
// The public `@sealed-lattice` package exposes only setup verifiers and verification-input
// helpers. The setup-assembly `create*` builders and local-trustee-state assembly that the
// accepted-setup tests still drive live here as thin adapters around the `@sealed-lattice/protocol`
// builders, preserving the exact public names, signatures, and adaptation logic the SDK used to
// expose so test callers change only their import source.

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
    createSetupPhaseParticipantObject as createSetupIntentInternal,
    createSetupPhaseRecord as createSetupPhaseRecordInternal,
    createVssShareAcceptanceRecord as createVssShareAcceptanceInternal,
    createVssShareComplaintRecordFromLocalVerification as createVssComplaintInternal,
    decryptLocalTrusteeSetupState as restoreEncryptedLocalTrusteeSetupStateInternal,
} from '@sealed-lattice/protocol';
import type {
    BinaryChunkedEvaluationKeyShareMaterialTransport as ProtocolBinaryChunkedEvaluationKeyShareMaterialTransport,
    BinaryChunkedPublicEvaluationKeyMaterialTransport as ProtocolBinaryChunkedPublicEvaluationKeyMaterialTransport,
    EvaluatorKeySchedule as ProtocolEvaluatorKeySchedule,
    EvaluatorKeyScheduleInput as ProtocolEvaluatorKeyScheduleInput,
    GaloisKeyShareBatch as ProtocolGaloisKeyShareBatch,
    GaloisKeyShareBatchContribution as ProtocolGaloisKeyShareBatchContribution,
    EvaluationKeyShareMaterialTransportInput as ProtocolEvaluationKeyShareMaterialTransportInput,
    PublicEvaluationKeySet as ProtocolPublicEvaluationKeySet,
    PublicEvaluationKeySetInput as ProtocolPublicEvaluationKeySetInput,
    BinaryChunkedSameSecretProofMaterialTransport as ProtocolBinaryChunkedSameSecretProofMaterialTransport,
    BinaryChunkedPublicKeyShareMaterialTransport as ProtocolBinaryChunkedPublicKeyShareMaterialTransport,
    BinaryChunkedPublicKeyShareProofMaterialTransport as ProtocolBinaryChunkedPublicKeyShareProofMaterialTransport,
    PublicKeyShareMaterialContributionInput as ProtocolPublicKeyShareMaterialContributionInput,
    PublicKeyShareMaterialSet as ProtocolPublicKeyShareMaterialSet,
    PublicKeyShareMaterialSetInput as ProtocolPublicKeyShareMaterialSetInput,
    PublicKeyShareSuccinctProofMaterial as ProtocolPublicKeyShareSuccinctProofMaterial,
    PublicKeyShareSuccinctProofSet as ProtocolPublicKeyShareSuccinctProofSet,
    PublicKeyShareSuccinctProofSetInput as ProtocolPublicKeyShareSuccinctProofSetInput,
    SetupPackagePublicKeyShareMaterialSet as ProtocolSetupPackagePublicKeyShareMaterialSet,
    SetupTransportedPublicKeyShareMaterial as ProtocolSetupTransportedPublicKeyShareMaterial,
    PublicKeyShareProofSet as ProtocolPublicKeyShareProofSet,
    PublicKeyShareProofSetInput as ProtocolPublicKeyShareProofSetInput,
    PublicKeyShareSet as ProtocolPublicKeyShareSet,
    PublicKeyShareSetInput as ProtocolPublicKeyShareSetInput,
    PublicEvaluationKeyMaterialTransportInput as ProtocolPublicEvaluationKeyMaterialTransportInput,
    SetupPackageVssCoefficientCommitmentMaterialSet as ProtocolSetupPackageVssCoefficientCommitmentMaterialSet,
    SetupTransportedVssCoefficientCommitmentMaterial as ProtocolSetupTransportedVssCoefficientCommitmentMaterial,
    RelinearizationKeyShareRounds as ProtocolRelinearizationKeyShareRounds,
    RelinearizationKeyShareRoundsInput as ProtocolRelinearizationKeyShareRoundsInput,
    SameSecretProofMaterial as ProtocolSameSecretProofMaterial,
    SameSecretProofSet as ProtocolSameSecretProofSet,
    SameSecretProofSetInput as ProtocolSameSecretProofSetInput,
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
    SetupPhaseParticipantObjectInput as ProtocolSetupPhaseParticipantObjectInput,
    LocalTrusteeSetupStateDecryptionInput,
} from '@sealed-lattice/protocol';
import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import { loadTranscriptCoreKernel } from '../../dist/kernel.js';

type JsonRecord = Record<string, unknown>;

export type CollectiveBgvSetupContext = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
}>;

export type ProtocolRootSigner = (
    signedRoot: unknown,
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
        readonly setupParametersHash: ProtocolHash;
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
        readonly setupParametersHash: ProtocolHash;
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
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
    readonly revealHex: string;
}>;

export type CommonRandomnessReveal = Readonly<
    JsonRecord & {
        readonly objectType: 'CommonRandomnessReveal';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly signerRole: 'Trustee';
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly revealHex: string;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
        readonly revealHash: ProtocolHash;
    }
>;

export type CommonRandomnessCommitInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly rosterPosition: number;
    readonly recoveryEpoch: number;
    readonly deviceEpoch: number;
    readonly signingPublicKeyHash: ProtocolHash;
    readonly signRoot: ProtocolRootSigner;
    readonly revealHash: ProtocolHash;
}>;

export type CommonRandomnessCommit = Readonly<
    JsonRecord & {
        readonly objectType: 'CommonRandomnessCommit';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly signerRole: 'Trustee';
        readonly trusteeIdentity: string;
        readonly rosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly revealHash: ProtocolHash;
        readonly signatureEnvelopeHash: ProtocolHash;
        readonly signatureEnvelope: ProtocolSignatureEnvelope;
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
        readonly setupParametersHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly commitRecords: readonly CommonRandomnessCommit[];
        readonly revealRecords: readonly CommonRandomnessReveal[];
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly publicDerivations: Readonly<
            JsonRecord & {
                readonly objectType: 'SetupPublicDerivations';
                readonly objectVersion: 1;
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
        readonly setupParametersHash: ProtocolHash;
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

export type PrivateVssShareVerification = Readonly<{
    readonly ok: boolean;
    readonly operation: 'verifyPrivateVssShareEnvelope';
    readonly verifierStatus: 'accepted' | 'refused';
    readonly privateEnvelopeHash: ProtocolHash | null;
    readonly localVerificationRoot: ProtocolHash | null;
    readonly limbVerifications: readonly JsonRecord[];
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
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
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
        readonly storageRequirement: 'encrypted-local-device-state-required';
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
        readonly storageScheme: string;
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
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupParametersHash: ProtocolHash;
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
    readonly setupParameters: JsonRecord;
    readonly bgvParameters: JsonRecord;
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
        | ProtocolSetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly transportedVssCoefficientCommitmentMaterial?: ProtocolSetupTransportedVssCoefficientCommitmentMaterial;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: JsonRecord;
    readonly vssComplaints?: JsonRecord;
    readonly thresholdShareCommitments?: JsonRecord;
    readonly sameSecretConsistency: JsonRecord;
    readonly sameSecretProofs: JsonRecord;
    readonly publicKeyShares: JsonRecord;
    readonly publicKeyShareProofs: JsonRecord;
    readonly publicKeyShareMaterial:
        | ProtocolSetupPackagePublicKeyShareMaterialSet
        | JsonRecord;
    readonly transportedPublicKeyShareMaterial?: ProtocolSetupTransportedPublicKeyShareMaterial;
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

export type PublicKeyShareSet = ProtocolPublicKeyShareSet;
export type PublicKeyShareSetInput = ProtocolPublicKeyShareSetInput;
export type PublicKeyShareProofSet = ProtocolPublicKeyShareProofSet;
export type PublicKeyShareProofSetInput = ProtocolPublicKeyShareProofSetInput;
export type PublicKeyShareMaterialSet = ProtocolPublicKeyShareMaterialSet;
export type PublicKeyShareMaterialSetInput =
    ProtocolPublicKeyShareMaterialSetInput;
export type BinaryChunkedSameSecretProofMaterialTransport =
    ProtocolBinaryChunkedSameSecretProofMaterialTransport;
export type BinaryChunkedPublicKeyShareMaterialTransport =
    ProtocolBinaryChunkedPublicKeyShareMaterialTransport;
export type BinaryChunkedPublicKeyShareProofMaterialTransport =
    ProtocolBinaryChunkedPublicKeyShareProofMaterialTransport;
export type BinaryChunkedEvaluationKeyShareMaterialTransport =
    ProtocolBinaryChunkedEvaluationKeyShareMaterialTransport;
export type PublicKeyShareSuccinctProofMaterial =
    ProtocolPublicKeyShareSuccinctProofMaterial;
export type PublicKeyShareSuccinctProofSet =
    ProtocolPublicKeyShareSuccinctProofSet;
export type PublicKeyShareSuccinctProofSetInput =
    ProtocolPublicKeyShareSuccinctProofSetInput;
export type EvaluatorKeySchedule = ProtocolEvaluatorKeySchedule;
export type EvaluatorKeyScheduleInput = ProtocolEvaluatorKeyScheduleInput;
export type SameSecretProofMaterial = ProtocolSameSecretProofMaterial;
export type SameSecretProofSet = ProtocolSameSecretProofSet;
export type SameSecretProofSetInput = ProtocolSameSecretProofSetInput;
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
export type GaloisKeyShareBatchContribution =
    ProtocolGaloisKeyShareBatchContribution;
export type GaloisKeyShareBatch = ProtocolGaloisKeyShareBatch;
export type GaloisKeyShareBatchesInput = PublicEvaluationKeyProofCommonInput &
    Readonly<{
        readonly batchContributions: readonly GaloisKeyShareBatchContribution[];
    }>;
export type EvaluationKeyShareMaterialTransportInput =
    ProtocolEvaluationKeyShareMaterialTransportInput;
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
export type PublicKeyShareMaterialContributionInput =
    ProtocolPublicKeyShareMaterialContributionInput;

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
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteePoint: number;
    readonly localStateRoot: ProtocolHash;
    readonly deletionReceiptRoot: ProtocolHash;
    readonly exportPolicy: 'roots-only-no-raw-share-or-opening-export';
    readonly storageRequirement: 'encrypted-local-device-state-required';
    readonly deletionBoundary: 'after-private-vss-aggregation';
}>;

export type RestoredLocalTrusteeSetupState = Readonly<{
    readonly ok: true;
    readonly operation: 'restoreLocalTrusteeSetupState';
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly sealedLocalStatePayload: LocalTrusteeSetupStateSealedPayload;
    readonly sealedLocalStatePayloadHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
    readonly localStateVerification: LocalTrusteeSetupStateVerification;
}>;

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
            kernel.describeCollectiveBgvSetupParameters().phaseOrder,
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
): Promise<CommonRandomnessReveal> =>
    createCommonRandomnessRevealInternal(input);

/** Creates a public common-randomness commit record for one trustee. */
export const createCommonRandomnessCommit = (
    input: CommonRandomnessCommitInput,
): Promise<CommonRandomnessCommit> =>
    createCommonRandomnessCommitInternal(input);

/** Assembles full-roster common randomness and accepted public derivations. */
export const createSetupCommonRandomness = async (
    input: SetupCommonRandomnessInput,
): Promise<SetupCommonRandomness> => {
    const kernel = await loadTranscriptCoreKernel();
    const parameters = kernel.describeCollectiveBgvSetupParameters();

    return createSetupCommonRandomnessInternal({
        ...input,
        participantCount: parameters.participantCount,
        derivePublicDerivations: (publicMatrixSeedHash: ProtocolHash) =>
            kernel.deriveCollectiveBgvSetupPublicDerivations({
                publicMatrixSeedHash,
            }),
    });
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

/** Creates root-bound setup certificates from parameters and transport evidence. */
export const createSetupCertificates = (
    input: SetupCertificatesInput,
): SetupCertificates => createSetupCertificatesInternal(input);

/** Creates a hash-bound setup package from canonical public setup records. */
export const createSetupPackage = (input: SetupPackageInput): SetupPackage =>
    createSetupPackageInternal(input as unknown as ProtocolSetupPackageInput);

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

// Unconditional payload-to-commitment binding comes from the kernel localStateRoot check; the optional expected* arguments only add extra caller pins and are skipped when undefined.
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
        localStateCommitment: input.localStateCommitment,
        sealedLocalStatePayload,
        sealedLocalStatePayloadHash: decryptedState.localStatePlaintextHash,
        storageAadHash: decryptedState.storageAadHash,
        localStateVerification,
    };
};
