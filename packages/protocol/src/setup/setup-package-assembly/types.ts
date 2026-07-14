import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from '../common-randomness-records.js';
import type {
    GaloisKeyShareBatch,
    RelinearizationKeyShareRounds,
    TransportedEvaluationKeyShareComponentMaterialSet,
    TransportedEvaluationKeyShareProofMaterialSet,
    TrusteeEvaluationKeyProofSet,
} from '../evaluation-key-proof-records.js';
import type { EvaluatorKeySchedule } from '../evaluator-key-schedule.js';
import type {
    CollectivePublicKey,
    SetupPackagePublicKeyShareMaterialSet,
    SetupTransportedPublicKeyShareMaterial,
    PublicKeyShareSet,
    PublicKeyShareSuccinctProofSet,
    TransportedPublicKeyShareProofMaterialSet,
} from '../public-key-share-records.js';
import type { CollectiveBgvSetupIntent } from '../setup-intent.js';
import type { VssCoefficientCommitmentSet } from '../vss-coefficient-commitments.js';
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

export type SetupPackage = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupPackage';
        readonly setupContext: CollectiveBgvSetupContext;
        readonly setupIntent: CollectiveBgvSetupIntent;
        readonly commonRandomness: SetupCommonRandomness;
        readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
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
        readonly publicKeyShares: PublicKeyShareSet;
        readonly publicKeyShareMaterial:
            | SetupPackagePublicKeyShareMaterialSet
            | JsonRecord;
        readonly publicKeyShareSuccinctProofs:
            | PublicKeyShareSuccinctProofSet
            | JsonRecord;
        readonly collectivePublicKey: CollectivePublicKey | JsonRecord;
        readonly evaluatorKeySchedule: EvaluatorKeySchedule;
        readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
        readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
        readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
        readonly setupPackageHash: ProtocolHash;
    }
>;

export type SetupPackageVerificationInputSource = Readonly<{
    readonly setupPackage: SetupPackage;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
    readonly transportedPublicKeyShareMaterial: SetupTransportedPublicKeyShareMaterial;
    readonly transportedPublicKeyShareProofMaterial: TransportedPublicKeyShareProofMaterialSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
    readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
    readonly transportedEvaluationKeyShareComponentMaterial: TransportedEvaluationKeyShareComponentMaterialSet;
}>;

export type SetupPackageVerificationInput = Pick<
    SetupPackageVerificationInputSource,
    'setupPackage' | 'expectedManifestHash' | 'expectedRosterHash'
>;
