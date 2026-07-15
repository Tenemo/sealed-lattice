import type { ProtocolHash } from '@sealed-lattice/types';

type VssCommittedMaterialCommitmentField = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly materialRootHex: string;
};

// Per-field salted Merkle roots over a message's canonical digit columns.
// The private material seed and opening never appear in the published package.
type VssCommittedMaterialCommitmentValue = {
    readonly objectType: 'VssCommittedMaterialCommitment';
    readonly commitmentRole:
        | 'coefficient'
        | 'recipient-share'
        | 'aggregate-threshold-share';
    readonly commitmentContextHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly commitmentFields: readonly VssCommittedMaterialCommitmentField[];
};

type VssPublicCoefficientCommitment = {
    readonly objectType: 'VssPublicCoefficientCommitment';
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssPublicSourceCoefficientCommitments = {
    readonly objectType: 'VssPublicSourceCoefficientCommitments';
    readonly sourceTrusteeIdentity: string;
    readonly coefficientCommitments: readonly VssPublicCoefficientCommitment[];
};

export type VssPublicCoefficientCommitmentSet = {
    readonly objectType: 'VssPublicCoefficientCommitmentSet';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssPublicSourceCoefficientCommitments[];
};

type VssPublicRecipientShareCommitment = {
    readonly objectType: 'VssPublicRecipientShareCommitment';
    readonly recipientIdentity: string;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssPublicSourceRecipientShareCommitments = {
    readonly objectType: 'VssPublicSourceRecipientShareCommitments';
    readonly sourceTrusteeIdentity: string;
    readonly recipientShareCommitments: readonly VssPublicRecipientShareCommitment[];
};

export type VssPublicRecipientShareCommitmentSet = {
    readonly objectType: 'VssPublicRecipientShareCommitmentSet';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssPublicSourceRecipientShareCommitments[];
};

type VssPublicAggregateThresholdCommitment = {
    readonly objectType: 'VssPublicAggregateThresholdCommitment';
    readonly recipientIdentity: string;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssAggregateThresholdProofRecord = {
    readonly objectType: 'VssAggregateThresholdProofRecord';
    readonly proofBytesHash: ProtocolHash;
};

export type VssPublicAggregateThresholdCommitmentSet = {
    readonly objectType: 'VssPublicAggregateThresholdCommitmentSet';
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly recipientRecords: readonly VssPublicAggregateThresholdCommitment[];
    readonly aggregateThresholdProofs: readonly VssAggregateThresholdProofRecord[];
};
