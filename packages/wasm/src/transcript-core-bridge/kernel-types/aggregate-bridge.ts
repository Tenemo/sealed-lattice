import type { ProtocolHash } from '@sealed-lattice/types';

export type AggregateBridgeEncryptionGeneration = {
    readonly ok: boolean;
    readonly operation: 'generateAggregateBridgeEncryption';
    readonly profileHash: ProtocolHash;
    readonly rustBgvBackendProfileHash: ProtocolHash;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly plaintextRoot: ProtocolHash;
    readonly ciphertextRoot: ProtocolHash;
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentHash: ProtocolHash;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateDerivationStatementHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly bridgeProofBytesHex: string;
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofRoot: ProtocolHash;
    readonly bridgeSharedWitnessProofHash: ProtocolHash;
    readonly sharedWitnessZeroKnowledgeStatusHash: ProtocolHash;
    readonly bgvRandomnessBoundProofStatusHash: ProtocolHash;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
    readonly aggregateDerivationVerificationScope: 'AggregateDerivationFullVerificationPreconditionNotBound';
    readonly plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofMissing';
    readonly bridgeClaimClosureVerified: false;
    readonly bridgeClaimVerificationStatus: 'BridgeProofClaimClosureMissing';
    readonly bridgeVariantEvidenceStatus:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly basisId: string;
    readonly level: number;
    readonly coefficientCount: number;
    readonly suppliedSlotCount: number;
    readonly slotCount: number;
    readonly sampledPublicRelationChecks: readonly unknown[];
    readonly sampledPublicRelationCheckPolicy: {
        readonly acceptedForBridgeProofVerification: false;
        readonly diagnosticOnly: true;
        readonly fullBridgeProofRequired: true;
        readonly objectType: 'AggregateBridgeSampledRelationCheckPolicy';
        readonly objectVersion: 1;
        readonly relationCheckSource: 'first-data-prime-diagnostic';
        readonly sampledOnlyBridgeVerificationAccepted: false;
        readonly sampledRelationCheckCount: number;
    };
    readonly privateMaterialDisclosure: Readonly<Record<string, boolean>>;
    readonly statusLabels: readonly string[];
    readonly canonicalBytesHex?: string;
};

export type AggregateBridgeEncryptionVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
    readonly operation: 'verifyAggregateBridgeEncryption';
    readonly statusLabels: readonly string[];
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly bridgeProofVerificationStatus:
        | 'BridgeProofBackendPending'
        | 'BridgeProofRelationChecked';
    readonly bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked';
    readonly aggregateDerivationVerificationScope: 'AggregateDerivationFullVerificationPreconditionNotBound';
    readonly plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofMissing';
    readonly bridgeClaimClosureVerified: false;
    readonly bridgeClaimVerificationStatus: 'BridgeProofClaimClosureMissing';
    readonly bridgeVariantEvidenceStatus:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofRoot: ProtocolHash;
    readonly bridgeSharedWitnessProofHash?: ProtocolHash | null;
    readonly sharedWitnessZeroKnowledgeStatusHash?: ProtocolHash | null;
    readonly bgvRandomnessBoundProofStatusHash?: ProtocolHash | null;
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentHash: ProtocolHash;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateQuotientCoordinateCount: number;
    readonly sharedWitnessChallengeHex?: string | null;
    readonly sharedResponseScalarCount?: number | null;
};

export type AggregateBridgeRelationEvaluation = {
    readonly ok: boolean;
    readonly operation: 'evaluateAggregateBridgeRelation';
    readonly relationEvaluationStatus?: 'AggregateBridgePrivateRelationSatisfied';
    readonly bridgeProofVerificationStatus?:
        | 'BridgeProofBackendPending'
        | 'BridgeProofRelationChecked';
    readonly bridgeEvidenceVerificationStatus?: 'BridgeProofEvidenceChecked';
    readonly bridgeClaimClosureVerified?: false;
    readonly bridgeClaimVerificationStatus?: 'BridgeProofClaimClosureMissing';
    readonly publicArtifactWitnessCleanResult?: boolean;
    readonly bridgeProofBackendStillRequired?: boolean;
    readonly scopedBridgeRelationClosure?: boolean;
    readonly participantCount?: number;
    readonly optionCount?: number;
    readonly claimTier?: string;
    readonly bridgeVariantEvidenceStatus?:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly shareVectorWidth?: number;
    readonly aggregateReducedCoordinateCount?: number;
    readonly aggregateQuotientCoordinateCount?: number;
    readonly proofByteLength?: number;
    readonly ciphertextShape?: unknown;
    readonly acceptedHashes?: readonly ProtocolHash[];
    readonly statusLabels?: readonly string[];
};
