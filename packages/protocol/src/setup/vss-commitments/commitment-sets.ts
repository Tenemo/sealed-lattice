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
    readonly commitmentRole: string;
    readonly commitmentContextHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly commitmentFields: readonly VssCommittedMaterialCommitmentField[];
};

type VssPublicCoefficientCommitment = {
    readonly objectType: 'VssPublicCoefficientCommitment';
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssPublicSourceCoefficientCommitments = {
    readonly objectType: string;
    readonly sourceTrusteeIdentity: string;
    readonly coefficientCommitments: readonly VssPublicCoefficientCommitment[];
    readonly sourceCoefficientCommitmentRoot: ProtocolHash;
};

export type VssPublicCoefficientCommitmentSet = {
    readonly objectType: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssPublicSourceCoefficientCommitments[];
    readonly coefficientCommitmentRoot: ProtocolHash;
};

type VssPublicRecipientShareCommitment = {
    readonly objectType: 'VssPublicRecipientShareCommitment';
    readonly recipientIdentity: string;
    readonly shareCommitmentRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssPublicSourceRecipientShareCommitments = {
    readonly objectType: string;
    readonly sourceTrusteeIdentity: string;
    readonly recipientShareCommitments: readonly VssPublicRecipientShareCommitment[];
    readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
};

export type VssPublicRecipientShareCommitmentSet = {
    readonly objectType: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly sourceTrusteeRecords: readonly VssPublicSourceRecipientShareCommitments[];
    readonly recipientShareCommitmentRoot: ProtocolHash;
};

type VssPublicAggregateThresholdCommitment = {
    readonly objectType: 'VssPublicAggregateThresholdCommitment';
    readonly recipientIdentity: string;
    readonly aggregateCommitmentRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssAggregateThresholdProofRecord = {
    readonly objectType: 'VssAggregateThresholdProofRecord';
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type VssPublicAggregateThresholdCommitmentSet = {
    readonly objectType: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly recipientRecords: readonly VssPublicAggregateThresholdCommitment[];
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    readonly aggregateThresholdProofs: readonly VssAggregateThresholdProofRecord[];
};

type LocalTrusteeVssPublicAggregateOpeningCredential = {
    readonly objectType: 'LocalTrusteeVssPublicAggregateOpeningCredential';
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly aggregateCommitmentRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly aggregateCommitmentMessageValuesLeHex: string;
    readonly aggregateMaterialSeedHex: string;
};

// Private setup output retained by the recipient that formed the aggregate
// commitment. It is never part of the public setup package.
export type LocalTrusteeVssPublicAggregateOpeningCredentialHandoff = {
    readonly objectType: 'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly aggregateOpeningCredentials: readonly LocalTrusteeVssPublicAggregateOpeningCredential[];
};
