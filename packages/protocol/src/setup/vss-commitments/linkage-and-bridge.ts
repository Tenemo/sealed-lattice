import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCommitmentValue } from '../vss-coefficient-commitments.js';

export type VssShareLinkageStatement = {
    readonly objectType: 'VssShareLinkageStatement';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
};

type VssShareLinkageProofRecord = Readonly<{
    readonly objectType: 'VssShareLinkageProofRecord';
    readonly coverage: readonly Readonly<{
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientRosterPosition: number;
        readonly sourceRnsLimbIndex: number;
    }>[];
    readonly proofBytesHash: ProtocolHash;
}>;

export type VssShareLinkageProofMaterialSet = Readonly<{
    readonly objectType: 'VssShareLinkageProofMaterialSet';
    readonly proofRecords: readonly VssShareLinkageProofRecord[];
}>;

export type GeneratedVssCanonicalProofMaterial = Readonly<{
    readonly proofBytesHash: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

export type VssShareLinkageProofMaterialBuild<
    ProofMaterialSet extends VssShareLinkageProofMaterialSet =
        VssShareLinkageProofMaterialSet,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;

type VssSameSecretBridgeStatement = {
    readonly objectType: 'VssSameSecretBridgeStatement';
    readonly sourceConstantCoefficientCommitments: readonly SetupCommitmentValue[];
};

export type VssSameSecretBridgeStatementSet = {
    readonly objectType: 'VssSameSecretBridgeStatementSet';
    readonly setupContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly statementRecords: readonly VssSameSecretBridgeStatement[];
};

type VssSameSecretBridgeProofRecord = {
    readonly objectType: 'VssSameSecretBridgeProofRecord';
    readonly proofBytesHash: ProtocolHash;
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
