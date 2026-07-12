// VSS public material assembly. Split across the vss-commitments/ modules by
// domain (commitment sets, linkage and bridge statements/proofs, and proof
// material transport); this file re-exports the public surface so import paths
// are unchanged.
export {
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    assembleVssPublicAggregateThresholdCommitmentSet,
} from './vss-commitments/commitment-sets.js';
export type {
    VssCommittedMaterialCommitmentValue,
    VssCommittedMaterialCommitmentComputer,
    VssCommittedMaterialSeedProvider,
    VssShareLinkageProofComputer,
    VssAggregateThresholdProofComputer,
    VssAggregateThresholdProofMaterial,
    VssPublicCoefficientCommitmentSet,
    VssPublicRecipientShareCommitmentSet,
    VssPublicAggregateThresholdCommitmentSet,
    LocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
    VssPublicSourceTrusteeOpeningState,
    VssPublicCoefficientCredential,
} from './vss-commitments/commitment-sets.js';
export {
    createVssShareLinkageStatement,
    createVssShareLinkageProofMaterialSet,
    createThresholdShareCommitmentBinding,
    createVssSameSecretBridgeStatementSet,
    createVssSameSecretBridgeProofMaterialSet,
} from './vss-commitments/linkage-and-bridge.js';
export type {
    VssShareLinkageStatement,
    VssSameSecretBridgeProofMaterialSet,
    VssSameSecretBridgeStatementSet,
    SameSecretBridgeProofComputer,
} from './vss-commitments/linkage-and-bridge.js';
export {
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    appendVssAggregateThresholdProofMaterials,
} from './vss-commitments/proof-material-transport.js';
export type {
    TransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet,
    BinaryChunkedVssShareLinkageProofMaterialTransport,
    BinaryChunkedSameSecretBridgeProofMaterialTransport,
} from './vss-commitments/proof-material-transport.js';
