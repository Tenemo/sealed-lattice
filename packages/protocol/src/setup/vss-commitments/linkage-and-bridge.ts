import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupProofMaterialStream } from '../setup-proof-material-transport.js';
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

export type VssShareLinkageProofMaterialBuild<
    ProofMaterialSet extends VssShareLinkageProofMaterialSet =
        VssShareLinkageProofMaterialSet,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly proofMaterialStreams: readonly SetupProofMaterialStream[];
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

export type VssSameSecretBridgeProofMaterialSet = {
    readonly objectType: 'VssSameSecretBridgeProofMaterialSet';
    readonly proofBytesHashes: readonly ProtocolHash[];
};

export type VssSameSecretBridgeProofMaterialBuild<
    ProofMaterialSet extends VssSameSecretBridgeProofMaterialSet =
        VssSameSecretBridgeProofMaterialSet,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly proofMaterialStreams: readonly SetupProofMaterialStream[];
}>;
