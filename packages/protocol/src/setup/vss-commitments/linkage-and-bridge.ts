import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommitmentValue } from '../vss-coefficient-commitments.js';

export type VssShareLinkageStatement = {
    readonly objectType: string;
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly qShareRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    readonly statementRoot: ProtocolHash;
};

export type GeneratedVssCanonicalProofMaterial = Readonly<{
    readonly proofMaterialRoot: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

export type VssShareLinkageProofMaterialBuild<
    ProofMaterialSet extends Record<string, unknown> = Record<string, unknown>,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;

type VssSameSecretBridgeSourceConstantCommitment = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly commitment: SetupCommitmentValue;
};

type VssSameSecretBridgeStatement = {
    readonly objectType: 'VssSameSecretBridgeStatement';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sourceConstantCoefficientCommitments: readonly VssSameSecretBridgeSourceConstantCommitment[];
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
};

export type VssSameSecretBridgeStatementSet = {
    readonly objectType: 'VssSameSecretBridgeStatementSet';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly qShareRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly statementRecords: readonly VssSameSecretBridgeStatement[];
};

type VssSameSecretBridgeProofRecord = {
    readonly objectType: 'VssSameSecretBridgeProofRecord';
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
    readonly sameSecretBridgeProofRecordRoot: ProtocolHash;
};

export type VssSameSecretBridgeProofMaterialSet = {
    readonly objectType: 'VssSameSecretBridgeProofMaterialSet';
    readonly proofRecords: readonly VssSameSecretBridgeProofRecord[];
};

export type VssSameSecretBridgeProofMaterialBuild<
    ProofMaterialSet extends VssSameSecretBridgeProofMaterialSet =
        VssSameSecretBridgeProofMaterialSet,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;
