import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from '../common-randomness-records.js';
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
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
    TransportedSameSecretProofMaterialSet,
} from '../same-secret-consistency-records.js';
import type { SetupCertificatesInput } from '../setup-certificates.js';
import type { SetupPhaseRecord } from '../setup-phase-records.js';
import type { VerifiedSetupProofMaterialSet } from '../setup-proof-material-transport.js';
import type {
    VssPublicAggregateThresholdCommitmentSet,
    VssPublicCoefficientCommitmentSet,
    VssPublicRecipientShareCommitmentSet,
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

export type SetupPackageCertificateInput = Omit<
    SetupCertificatesInput,
    'vssCoefficientCommitmentMaterial'
>;

export type SetupPackageCertificateRecords = Readonly<{
    readonly setupTransportCertificate: JsonRecord;
}>;

export type SetupPackageInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qShare: JsonRecord;
    readonly phaseTranscript: readonly SetupPhaseRecord[];
    readonly commonRandomness: SetupCommonRandomness;
    readonly vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly vssPublicRecipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly vssPublicAggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
    readonly vssShareLinkageStatement: VssShareLinkageStatement;
    readonly vssShareLinkageProofMaterialSet: JsonRecord;
    readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
    readonly sameSecretBridgeProofMaterialSet: JsonRecord;
    readonly privateVssEnvelopeCommitments: JsonRecord;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly vssComplaints?: VssComplaintSet | JsonRecord;
    readonly thresholdShareCommitments: JsonRecord;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
    readonly transportedSameSecretProofMaterial?:
        | TransportedSameSecretProofMaterialSet
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
    readonly setupTransportCertificate?: JsonRecord;
}>;

export type SetupPackage = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPackage';
        readonly setupContext: CollectiveBgvSetupContext;
        readonly qShare: JsonRecord;
        readonly phaseTranscript: readonly SetupPhaseRecord[];
        readonly commonRandomness: SetupCommonRandomness;
        readonly vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
        readonly vssPublicRecipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
        readonly vssPublicAggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
        readonly vssShareLinkageStatement: VssShareLinkageStatement;
        readonly vssShareLinkageProofMaterialSet: JsonRecord;
        readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
        readonly sameSecretBridgeProofMaterialSet: JsonRecord;
        readonly privateVssEnvelopeCommitments: JsonRecord;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly vssShareAcceptances: VssShareAcceptanceSet;
        readonly vssComplaints?: VssComplaintSet | JsonRecord;
        readonly thresholdShareCommitments: JsonRecord;
        readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
        readonly sameSecretProofs: SameSecretProofSet | JsonRecord;
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
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
    readonly transportedPublicKeyShareMaterial?: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial?: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial?: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial?: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial?: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial?: TransportedEvaluationKeyShareComponentMaterialSet;
    readonly transportedPublicEvaluationKeyMaterial?: TransportedPublicEvaluationKeyMaterialSet;
    readonly verifiedSetupProofMaterials?: VerifiedSetupProofMaterialSet;
}>;

export type SetupPackageVerificationInput = SetupPackageVerificationInputSource;
