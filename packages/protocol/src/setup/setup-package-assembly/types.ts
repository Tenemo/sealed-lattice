import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommonRandomness } from '../common-randomness-records.js';
import type {
    GaloisKeyShareBatch,
    RelinearizationKeyShareRounds,
    TrusteeEvaluationKeyProofSet,
} from '../evaluation-key-proof-records.js';
import type { PrivateVssEnvelopeCommitmentSet } from '../private-vss-envelope-commitment.js';
import type {
    CollectivePublicKey,
    SetupPackagePublicKeyShareMaterialSet,
    PublicKeyShareSet,
    PublicKeyShareSuccinctProofSet,
} from '../public-key-share-records.js';
import type { CollectiveBgvSetupIntent } from '../setup-intent.js';
import type { VssCoefficientCommitmentSet } from '../vss-coefficient-commitments.js';
import type {
    VssPublicAggregateThresholdCommitmentSet,
    VssPublicCoefficientCommitmentSet,
    VssPublicRecipientShareCommitmentSet,
    VssSameSecretBridgeProofMaterialSet,
    VssSameSecretBridgeStatementSet,
    VssShareLinkageProofMaterialSet,
    VssShareLinkageStatement,
} from '../vss-commitments.js';
import type {
    CollectiveBgvSetupContext,
    VssComplaintSet,
    VssShareAcceptanceSet,
} from '../vss-share-verification-records.js';

export type SetupPackage = Readonly<{
    readonly objectType: 'SetupPackage';
    readonly setupContext: CollectiveBgvSetupContext;
    readonly setupIntent: CollectiveBgvSetupIntent;
    readonly commonRandomness: SetupCommonRandomness;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly vssPublicRecipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly vssPublicAggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
    readonly vssShareLinkageStatement: VssShareLinkageStatement;
    readonly vssShareLinkageProofMaterialSet: VssShareLinkageProofMaterialSet;
    readonly sameSecretBridgeStatementSet: VssSameSecretBridgeStatementSet;
    readonly sameSecretBridgeProofMaterialSet: VssSameSecretBridgeProofMaterialSet;
    readonly privateVssEnvelopeCommitments: PrivateVssEnvelopeCommitmentSet;
    readonly vssShareAcceptances: VssShareAcceptanceSet;
    readonly vssComplaints?: VssComplaintSet;
    readonly publicKeyShares: PublicKeyShareSet;
    readonly publicKeyShareMaterial: SetupPackagePublicKeyShareMaterialSet;
    readonly publicKeyShareSuccinctProofs: PublicKeyShareSuccinctProofSet;
    readonly collectivePublicKey: CollectivePublicKey;
    readonly relinearizationKeyShareRounds: RelinearizationKeyShareRounds;
    readonly galoisKeyShareBatches: readonly GaloisKeyShareBatch[];
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
}>;

export type SetupPackageVerificationInput = Readonly<{
    readonly setupPackage: unknown;
    readonly expectedManifestHash: ProtocolHash;
    readonly expectedRosterHash: ProtocolHash;
}>;
