export {
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    assembleVssPublicAggregateThresholdCommitmentSet,
} from './vss-commitments/commitment-sets.js';
export type {
    VssCommittedMaterialCommitmentValue,
    VssCommittedMaterialCommitmentComputer,
    VssAggregateThresholdProofComputer,
    VssPublicCoefficientCommitmentSet,
    VssPublicRecipientShareCommitmentSet,
    VssPublicAggregateThresholdCommitmentSet,
    LocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
    VssPublicSourceTrusteeOpeningState,
} from './vss-commitments/commitment-sets.js';
export { createVssSameSecretBridgeStatementSet } from './vss-commitments/linkage-and-bridge.js';
export type {
    VssShareLinkageStatement,
    VssSameSecretBridgeProofMaterialSet,
    VssSameSecretBridgeStatementSet,
} from './vss-commitments/linkage-and-bridge.js';
export {
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    appendVssAggregateThresholdProofMaterials,
} from './vss-commitments/proof-material-transport.js';
export type {
    TransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet,
} from './vss-commitments/proof-material-transport.js';
