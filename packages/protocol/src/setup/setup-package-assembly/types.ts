import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from '../common-randomness-records.js';
import type {
    CompactVssAggregateThresholdCommitmentSet,
    CompactVssCoefficientCommitmentSet,
    CompactVssRecipientShareCommitmentSet,
    CompactVssShareLinkageProofMaterialSet,
    CompactVssShareLinkageStatement,
} from '../compact-vss-commitments.js';
import type {
    GaloisKeyShareBatch,
    PublicEvaluationKeySet,
    RelinearizationKeyShareRounds,
    TransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet,
    TransportedPublicEvaluationKeyMaterialSet,
    TrusteeEvaluationKeyProofSet,
} from '../evaluation-key-proof-records.js';
import type { EvaluatorKeySchedule } from '../evaluator-key-schedule.js';
import type {
    CollectivePublicKey,
    PublicKeyShareProofSet,
    SetupPackagePublicKeyShareMaterialSet,
    SetupTransportedPublicKeyShareMaterial,
    PublicKeyShareSet,
    PublicKeyShareSuccinctProofSet,
    TransportedPublicKeyShareProofMaterialSet,
} from '../public-key-share-records.js';
import type {
    CompactVssSameSecretBridgeProofMaterialSet,
    CompactVssSameSecretBridgeStatementSet,
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
    TransportedSameSecretProofMaterialSet,
} from '../same-secret-consistency-records.js';
import type { SetupCertificatesInput } from '../setup-certificates.js';
import type { SetupPhaseRecord } from '../setup-phase-records.js';
import type { VerifiedSetupProofMaterialSet } from '../setup-proof-material-transport.js';
import type { ThresholdShareCommitmentSet } from '../threshold-share-commitments.js';
import type {
    SetupPackageVssCoefficientCommitmentMaterialSet,
    SetupTransportedVssCoefficientCommitmentMaterial,
    SetupTransportedVssCoefficientCommitmentMaterialLike,
    VerifiedVssCoefficientCommitmentMaterial,
    VssCoefficientCommitmentSet,
} from '../vss-coefficient-commitments.js';
import type {
    CollectiveBgvSetupContext,
    VssComplaintSet,
    VssShareAcceptanceSet,
} from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

export type SetupPackageCertificateInput = Omit<
    SetupCertificatesInput,
    'vssCoefficientCommitmentMaterial'
>;

export type SetupPackageCertificateRecords = Readonly<{
    readonly setupCommitmentSecurityCertificate: JsonRecord;
    readonly setupTransportCertificate: JsonRecord;
    readonly setupProofAccountingCertificate: JsonRecord;
    readonly heSecurityCertificate: JsonRecord;
}>;

export type SetupKeyCorrectnessCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupKeyCorrectnessCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
    }
>;

export type SetupKeyCorrectnessCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupKeyCorrectnessCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type ActiveStaticSetupTheoremCertificate = Readonly<
    JsonRecord & {
        readonly objectType: 'ActiveStaticSetupTheoremCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
    }
>;

export type ActiveStaticSetupTheoremCertificateBody = Readonly<
    JsonRecord & {
        readonly objectType: 'ActiveStaticSetupTheoremCertificate';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
    }
>;

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly SetupPhaseRecord[];
    readonly commonRandomness: SetupCommonRandomness;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssCoefficientCommitmentMaterial:
        | SetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly transportedVssCoefficientCommitmentMaterial?:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly vssComplaints?: VssComplaintSet | JsonRecord;
    readonly thresholdShareCommitments?:
        | ThresholdShareCommitmentSet
        | JsonRecord;
    readonly compactVssCoefficientCommitmentSet?:
        | CompactVssCoefficientCommitmentSet
        | JsonRecord;
    readonly compactVssRecipientShareCommitmentSet?:
        | CompactVssRecipientShareCommitmentSet
        | JsonRecord;
    readonly compactVssAggregateThresholdCommitmentSet?:
        | CompactVssAggregateThresholdCommitmentSet
        | JsonRecord;
    readonly compactVssShareLinkageStatement?:
        | CompactVssShareLinkageStatement
        | JsonRecord;
    readonly compactVssShareLinkageProofMaterialSet?:
        | CompactVssShareLinkageProofMaterialSet
        | JsonRecord;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
    readonly transportedSameSecretProofMaterial?:
        | TransportedSameSecretProofMaterialSet
        | JsonRecord;
    readonly compactSameSecretBridgeStatementSet?:
        | CompactVssSameSecretBridgeStatementSet
        | JsonRecord;
    readonly compactSameSecretBridgeProofMaterialSet?:
        | CompactVssSameSecretBridgeProofMaterialSet
        | JsonRecord;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareProofs: PublicKeyShareProofSet;
    readonly publicKeyShareMaterial:
        | SetupPackagePublicKeyShareMaterialSet
        | JsonRecord;
    readonly transportedPublicKeyShareMaterial?:
        | SetupTransportedPublicKeyShareMaterial
        | JsonRecord;
    readonly publicKeyShareSuccinctProofs:
        | PublicKeyShareSuccinctProofSet
        | JsonRecord;
    readonly transportedPublicKeyShareProofMaterial?:
        | TransportedPublicKeyShareProofMaterialSet
        | JsonRecord;
    readonly collectivePublicKey?: never;
    readonly evaluatorKeySchedule: EvaluatorKeySchedule;
    readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
    readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial?:
        | TransportedEvaluationKeyShareProofMaterialSet
        | JsonRecord;
    readonly transportedEvaluationKeyShareComponentMaterial?:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | JsonRecord;
    readonly evaluationKeys: PublicEvaluationKeySet;
    readonly transportedPublicEvaluationKeyMaterial?:
        | TransportedPublicEvaluationKeyMaterialSet
        | JsonRecord;
    readonly setupCertificateInput?: SetupPackageCertificateInput;
    readonly setupCommitmentSecurityCertificate?: JsonRecord;
    readonly setupTransportCertificate?: JsonRecord;
    readonly setupProofAccountingCertificate?: JsonRecord;
    readonly heSecurityCertificate?: JsonRecord;
}>;

export type SetupPackage = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPackage';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupContext: CollectiveBgvSetupContext;
        readonly qShare: JsonRecord;
        readonly phaseTranscript: readonly SetupPhaseRecord[];
        readonly commonRandomness: SetupCommonRandomness;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly vssCoefficientCommitmentMaterial:
            | SetupPackageVssCoefficientCommitmentMaterialSet
            | JsonRecord;
        readonly privateVssEnvelopeCommitments: JsonRecord;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
        readonly vssComplaints?: VssComplaintSet | JsonRecord;
        readonly thresholdShareCommitments: ThresholdShareCommitmentSet;
        readonly compactVssCoefficientCommitmentSet?:
            | CompactVssCoefficientCommitmentSet
            | JsonRecord;
        readonly compactVssRecipientShareCommitmentSet?:
            | CompactVssRecipientShareCommitmentSet
            | JsonRecord;
        readonly compactVssAggregateThresholdCommitmentSet?:
            | CompactVssAggregateThresholdCommitmentSet
            | JsonRecord;
        readonly compactVssShareLinkageStatement?:
            | CompactVssShareLinkageStatement
            | JsonRecord;
        readonly compactVssShareLinkageProofMaterialSet?:
            | CompactVssShareLinkageProofMaterialSet
            | JsonRecord;
        readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
        readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
        readonly compactSameSecretBridgeStatementSet?:
            | CompactVssSameSecretBridgeStatementSet
            | JsonRecord;
        readonly compactSameSecretBridgeProofMaterialSet?:
            | CompactVssSameSecretBridgeProofMaterialSet
            | JsonRecord;
        readonly publicKeyShares: PublicKeyShareSet;
        readonly publicKeyShareProofs: PublicKeyShareProofSet;
        readonly publicKeyShareMaterial:
            | SetupPackagePublicKeyShareMaterialSet
            | JsonRecord;
        readonly publicKeyShareSuccinctProofs:
            | PublicKeyShareSuccinctProofSet
            | JsonRecord;
        readonly collectivePublicKey: CollectivePublicKey | JsonRecord;
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly evaluatorKeySchedule: EvaluatorKeySchedule;
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
        readonly evaluationKeys: PublicEvaluationKeySet;
        readonly setupCommitmentSecurityCertificate: JsonRecord;
        readonly setupCommitmentSecurityCertificateHash: ProtocolHash;
        readonly setupTransportCertificate: JsonRecord;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupProofAccountingCertificate: JsonRecord;
        readonly setupProofAccountingCertificateHash: ProtocolHash;
        readonly setupKeyCorrectnessCertificate: SetupKeyCorrectnessCertificate;
        readonly setupKeyCorrectnessCertificateHash: ProtocolHash;
        readonly activeStaticSetupTheoremCertificate: ActiveStaticSetupTheoremCertificate;
        readonly activeStaticSetupTheoremCertificateHash: ProtocolHash;
        readonly heSecurityCertificate: JsonRecord;
        readonly heSecurityCertificateHash: ProtocolHash;
        readonly setupPackageHash: ProtocolHash;
    }
>;

export type SetupPackageVerificationInputSource = Readonly<{
    readonly setupPackage: SetupPackage;
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

export type SetupPackageVerificationInput = SetupPackageVerificationInputSource;

export type SetupPackageInputWithDerivedCollectivePublicKey = Omit<
    SetupPackageInput,
    'collectivePublicKey'
> &
    Readonly<{
        readonly collectivePublicKey: CollectivePublicKey;
    }>;
