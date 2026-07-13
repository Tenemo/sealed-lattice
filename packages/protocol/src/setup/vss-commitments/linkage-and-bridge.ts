import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommitmentValue } from '../vss-coefficient-commitments.js';

export type VssShareLinkageStatement = {
    readonly objectType: string;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
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
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sourceConstantCoefficientCommitments: readonly VssSameSecretBridgeSourceConstantCommitment[];
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
};

export type VssSameSecretBridgeStatementSet = {
    readonly objectType: 'VssSameSecretBridgeStatementSet';
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly qShareRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly statementRecords: readonly VssSameSecretBridgeStatement[];
    readonly sameSecretBridgeStatementSetRoot: ProtocolHash;
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
    readonly proofMaterialSetRoot: ProtocolHash;
};

export type VssSameSecretBridgeProofMaterialBuild<
    ProofMaterialSet extends VssSameSecretBridgeProofMaterialSet =
        VssSameSecretBridgeProofMaterialSet,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;
