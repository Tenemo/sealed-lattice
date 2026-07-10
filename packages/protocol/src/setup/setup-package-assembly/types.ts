import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from '../common-randomness-records.js';
import type {
    GaloisKeyShareBatch,
    PublicEvaluationKeySet,
    RelinearizationKeyShareRounds,
    TransportedEvaluationKeyAggregateBindingOpeningSet,
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
import type { SetupCertificatesInput } from '../setup-certificates.js';
import type { SetupPhaseRecord } from '../setup-phase-records.js';
import type { VerifiedSetupProofMaterialSet } from '../setup-proof-material-transport.js';
import type {
    SetupPackageVssCoefficientCommitmentMaterialSet,
    VssCoefficientCommitmentSet,
    VssCoefficientCommitmentMaterialBinaryReference,
} from '../vss-coefficient-commitments.js';
import type {
    VssPublicAggregateThresholdCommitmentSet,
    VssPublicCoefficientCommitmentSet,
    VssPublicRecipientShareCommitmentSet,
    VssSameSecretBridgeProofMaterialSet,
    VssSameSecretBridgeStatementSet,
    VssShareLinkageStatement,
    TransportedSameSecretBridgeProofMaterialSet,
    TransportedVssShareLinkageProofMaterialSet,
} from '../vss-commitments.js';
import type {
    CollectiveBgvSetupContext,
    VssComplaintSet,
    VssShareAcceptanceSet,
} from '../vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

export type SetupPackageCertificateInput = SetupCertificatesInput;

export type SetupPackageCertificateRecords = Readonly<{
    readonly setupTransportCertificate: JsonRecord;
}>;

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly SetupPhaseRecord[];
    readonly commonRandomness: SetupCommonRandomness;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssCoefficientCommitmentMaterial:
        | SetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly vssPublicRecipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly vssPublicAggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
    readonly vssShareLinkageStatement: VssShareLinkageStatement;
    readonly vssShareLinkageProofMaterialSet: JsonRecord;
    readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
    readonly sameSecretBridgeProofMaterialSet: VssSameSecretBridgeProofMaterialSet;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly vssComplaints?: VssComplaintSet | JsonRecord;
    readonly thresholdShareCommitments: JsonRecord;
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
    readonly setupTransportCertificate?: JsonRecord;
}>;

export type SetupPackage = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPackage';
        readonly setupContext: CollectiveBgvSetupContext;
        readonly qShare: JsonRecord;
        readonly phaseTranscript: readonly SetupPhaseRecord[];
        readonly commonRandomness: SetupCommonRandomness;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
        readonly vssCoefficientCommitmentMaterial: VssCoefficientCommitmentMaterialBinaryReference;
        readonly vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
        readonly vssPublicRecipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
        readonly vssPublicAggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
        readonly vssShareLinkageStatement: VssShareLinkageStatement;
        readonly vssShareLinkageProofMaterialSet: JsonRecord;
        readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
        readonly sameSecretBridgeProofMaterialSet: VssSameSecretBridgeProofMaterialSet;
        readonly privateVssEnvelopeCommitments: JsonRecord;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
        readonly vssComplaints?: VssComplaintSet | JsonRecord;
        readonly thresholdShareCommitments: JsonRecord;
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
        readonly setupTransportCertificate: JsonRecord;
        readonly setupTransportCertificateHash: ProtocolHash;
        readonly setupPackageHash: ProtocolHash;
    }
>;

export type SetupPackageVerificationInputSource = Readonly<{
    readonly setupPackage: SetupPackage;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial?: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial?: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    // Optional per-trustee batched linear-evaluation openings for the package
    // aggregate binding. Carried alongside the package when the evaluation-key
    // set publishes an aggregate binding; the kernel skips the check otherwise.
    readonly transportedEvaluationKeyAggregateBindingOpenings?: TransportedEvaluationKeyAggregateBindingOpeningSet;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
    readonly verifiedSetupProofMaterials?: VerifiedSetupProofMaterialSet;
}>;

export type SetupPackageVerificationInput = SetupPackageVerificationInputSource;
