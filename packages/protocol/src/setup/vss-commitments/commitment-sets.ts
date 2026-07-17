import type { ProtocolHash } from '@sealed-lattice/types';

// A salted Merkle root over a message's canonical digit columns.
// The private material seed and opening never appear in the published package.
type VssCommittedMaterialCommitmentValue = {
    readonly objectType: 'VssCommittedMaterialCommitment';
    readonly commitmentContextHash: ProtocolHash;
    readonly materialRootHex: string;
};

type VssPublicSourceCoefficientCommitments = {
    readonly objectType: 'VssPublicSourceCoefficientCommitments';
    readonly coefficientCommitments: readonly VssCommittedMaterialCommitmentValue[];
};

export type VssPublicCoefficientCommitmentSet = {
    readonly objectType: 'VssPublicCoefficientCommitmentSet';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssPublicSourceCoefficientCommitments[];
};

type VssPublicSourceRecipientShareCommitments = {
    readonly objectType: 'VssPublicSourceRecipientShareCommitments';
    readonly recipientShareCommitments: readonly VssCommittedMaterialCommitmentValue[];
};

export type VssPublicRecipientShareCommitmentSet = {
    readonly objectType: 'VssPublicRecipientShareCommitmentSet';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssPublicSourceRecipientShareCommitments[];
};

type VssPublicAggregateThresholdCommitment = {
    readonly objectType: 'VssPublicAggregateThresholdCommitment';
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

export type VssPublicAggregateThresholdCommitmentSet = {
    readonly objectType: 'VssPublicAggregateThresholdCommitmentSet';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly recipientRecords: readonly VssPublicAggregateThresholdCommitment[];
    readonly aggregateThresholdProofBytesHashes: readonly ProtocolHash[];
};
