// VSS public material assembly. Split across the vss-commitments/ modules by
// domain (commitment sets, linkage and bridge statements/proofs, and proof
// material transport); this file re-exports the public surface so import paths
// are unchanged.
export {
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    createVssPublicAggregateThresholdCommitmentSet,
} from './vss-commitments/commitment-sets.js';
export type {
    VssPublicCommitmentValue,
    VssPublicCommitmentComputer,
    VssPublicCoefficientCommitmentSet,
    VssPublicRecipientShareCommitmentSet,
    VssPublicAggregateThresholdCommitmentSet,
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
    VssShareLinkageProofComputer,
    VssSameSecretBridgeStatementSet,
    SameSecretBridgeProofComputer,
} from './vss-commitments/linkage-and-bridge.js';
export {
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
} from './vss-commitments/proof-material-transport.js';
export type {
    TransportedVssShareLinkageProofMaterialSet,
    TransportedSameSecretBridgeProofMaterialSet,
    BinaryChunkedVssShareLinkageProofMaterialTransport,
    BinaryChunkedSameSecretBridgeProofMaterialTransport,
} from './vss-commitments/proof-material-transport.js';
