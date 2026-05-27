import type { ProtocolDigest } from '@sealed-lattice/types';

export type AggregateBridgeEncryptionGeneration = {
    readonly ok: boolean;
    readonly operation: 'generateAggregateBridgeEncryption';
    readonly profileDigest: ProtocolDigest;
    readonly rustBgvBackendProfileDigest: ProtocolDigest;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly collectivePublicKeyRoot: ProtocolDigest;
    readonly bgvPublicKeyRoot: ProtocolDigest;
    readonly plaintextRoot: ProtocolDigest;
    readonly ciphertextRoot: ProtocolDigest;
    readonly encryptedAggregateInputRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentDigest: ProtocolDigest;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateDerivationComponentDigest: ProtocolDigest;
    readonly aggregateDerivationStatementDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofBytesHex: string;
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofRoot: ProtocolDigest;
    readonly bridgeSharedWitnessProofDigest: ProtocolDigest;
    readonly sharedWitnessZeroKnowledgeStatusDigest: ProtocolDigest;
    readonly bgvRandomnessBoundProofStatusDigest: ProtocolDigest;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
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
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly unknown[];
    readonly unresolvedReason: string | null;
    readonly bridgeProofVerificationStatus:
        | 'BridgeProofBackendPending'
        | 'BridgeProofRelationChecked';
    readonly bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked';
    readonly bridgeClaimClosureVerified: false;
    readonly bridgeClaimVerificationStatus: 'BridgeProofClaimClosureMissing';
    readonly bridgeVariantEvidenceStatus:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofRoot: ProtocolDigest;
    readonly bridgeSharedWitnessProofDigest?: ProtocolDigest | null;
    readonly sharedWitnessZeroKnowledgeStatusDigest?: ProtocolDigest | null;
    readonly bgvRandomnessBoundProofStatusDigest?: ProtocolDigest | null;
    readonly encryptedAggregateInputRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentDigest: ProtocolDigest;
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
    readonly acceptedDigests?: readonly ProtocolDigest[];
    readonly statusLabels?: readonly string[];
};
