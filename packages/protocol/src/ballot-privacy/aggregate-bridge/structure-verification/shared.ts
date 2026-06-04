import type {
    ActionContext,
    AggregateDerivationComponent,
    BridgeClaimVerificationStatus,
    BridgeProofRecord,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    createAggregateRefusal,
    protocolHashPattern,
} from '../../aggregate-derivation/constants.js';
import { collectForbiddenWitnessFieldRefusals as collectBoundedForbiddenWitnessFieldRefusals } from '../../aggregate-derivation/witness-field-refusals.js';
import type { AggregateDerivationVerificationScope } from '../hashes.js';

export type BridgeSetupEvidence = {
    readonly setupPackageHash: ProtocolHash;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly participantCount: number;
        readonly rosterHash: ProtocolHash;
        readonly thresholdProfileHash: ProtocolHash;
    };
    readonly profileBindings: Readonly<Record<string, unknown>>;
    readonly collectivePublicKey: {
        readonly bgvPublicKeyRoot: ProtocolHash;
        readonly collectivePublicKeyRoot: ProtocolHash;
        readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    };
};

export type BridgeRandomnessSource =
    | 'fresh-csprng'
    | 'development-deterministic-fixture';

export type BridgeRandomnessSourceEvidence = {
    readonly objectType: 'AggregateBridgeRandomnessSourceEvidence';
    readonly objectVersion: 1;
    readonly proverRandomnessSource: BridgeRandomnessSource;
    readonly encryptionRandomnessSeedSource: BridgeRandomnessSource;
    readonly callerSuppliedDevelopmentRandomness: boolean;
    readonly claimBearingEntropyEvidence: boolean;
};

export type BridgeEncryptionEvidence = {
    readonly aggregateDerivationComponentHash: ProtocolHash;
    readonly aggregateDerivationStatementHash: ProtocolHash;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentHash: ProtocolHash;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly basisId: string;
    readonly batchEncodingBoundCertificateHash: ProtocolHash;
    readonly bgvEncryptionKeyMaterialKind: 'passive-transcript-derived-collective-public-key';
    readonly bgvPublicKeyRoot: ProtocolHash;
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofBytesHex: string;
    readonly bridgeProofChallengeContextHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofRoot: ProtocolHash;
    readonly bridgeSharedWitnessProofHash: ProtocolHash;
    readonly sharedWitnessZeroKnowledgeStatusHash: ProtocolHash;
    readonly bgvRandomnessBoundProofStatusHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
    readonly claimBearingBridgeEncryption: boolean;
    readonly plaintextCoefficientBindingCommitmentHash: ProtocolHash;
    readonly proofFriendlyPlaintextLiftBindingHash: ProtocolHash;
    readonly aggregateBridgeRelationHandoffRoot?: ProtocolHash | null;
    readonly aggregateDerivationVerificationScope?: AggregateDerivationVerificationScope;
    readonly plaintextCanonicalLiftProofStatus?: 'PlaintextCanonicalLiftProofChecked';
    readonly bridgeClaimClosureVerified?: boolean;
    readonly bridgeClaimVerificationStatus?: BridgeClaimVerificationStatus;
    readonly bridgeVariantEvidenceStatus?:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly canonicalByteLength: number;
    readonly canonicalBytesHash512: string;
    readonly canonicalCiphertextConventionHash: ProtocolHash;
    readonly ciphertextRoot: ProtocolHash;
    readonly coefficientCount: number;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    readonly developmentKeyOnly: false;
    readonly proverRandomnessSource: BridgeRandomnessSource;
    readonly encryptionRandomnessSeedSource: BridgeRandomnessSource;
    readonly randomnessSourceEvidence: BridgeRandomnessSourceEvidence;
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly level: number;
    readonly plaintextRoot: ProtocolHash;
    readonly profileHash: ProtocolHash;
    readonly rustBgvBackendProfileHash: ProtocolHash;
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
    readonly sampledPublicRelationChecks: readonly unknown[];
    readonly slotCount: number;
    readonly thresholdDecryptable: true;
};

export type BridgeEvidenceVerification = {
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentHash: ProtocolHash;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly bgvEncryptionKeyMaterialKind: 'passive-transcript-derived-collective-public-key';
    readonly bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked';
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofChallengeContextHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofRoot: ProtocolHash;
    readonly bridgeSharedWitnessProofHash: ProtocolHash;
    readonly sharedWitnessZeroKnowledgeStatusHash: ProtocolHash;
    readonly bgvRandomnessBoundProofStatusHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly heParamHash: ProtocolHash;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
    readonly claimBearingBridgeEncryption: boolean;
    readonly plaintextCoefficientBindingCommitmentHash: ProtocolHash;
    readonly proofFriendlyPlaintextLiftBindingHash: ProtocolHash;
    readonly canonicalBytesHash512: string;
    readonly canonicalByteLength: number;
    readonly aggregateBridgeRelationHandoffRoot?: ProtocolHash | null;
    readonly aggregateDerivationVerificationScope?: AggregateDerivationVerificationScope;
    readonly plaintextCanonicalLiftProofStatus?: 'PlaintextCanonicalLiftProofChecked';
    readonly bridgeClaimClosureVerified?: boolean;
    readonly bridgeClaimVerificationStatus?: BridgeClaimVerificationStatus;
    readonly bridgeVariantEvidenceStatus?:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly encryptedAggregateInputRoot: ProtocolHash;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
    readonly developmentKeyOnly: false;
    readonly proverRandomnessSource: BridgeRandomnessSource;
    readonly encryptionRandomnessSeedSource: BridgeRandomnessSource;
    readonly randomnessSourceEvidence: BridgeRandomnessSourceEvidence;
    readonly ok: true;
    readonly thresholdDecryptable: true;
};

export type PendingBridgeProofRecordFromEvidenceInput = {
    readonly aggregateDerivationComponent: AggregateDerivationComponent;
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly bridgeEncryptionEvidence: BridgeEncryptionEvidence;
    readonly bridgeEvidenceVerification: BridgeEvidenceVerification;
    readonly bridgeWitnessPrivacyProfileHash: ProtocolHash;
    readonly heParamHash: ProtocolHash;
    readonly proofEncodingProfileHash?: ProtocolHash;
    readonly proofParameterSetHash?: ProtocolHash;
    readonly publicRandomnessHash?: ProtocolHash;
    readonly setupPackage: BridgeSetupEvidence;
};

export type AggregateContributionFromBridgeProofRecordInput = {
    readonly actionContext: ActionContext;
    readonly boardPosition: number;
    readonly bridgeProofRecord: BridgeProofRecord;
    readonly closeRecordHash: ProtocolHash;
    readonly signature:
        | ProtocolSignatureEnvelope
        | ((input: {
              readonly aggregateContributionHash: ProtocolHash;
          }) => ProtocolSignatureEnvelope);
};

export const bridgeHashFieldNames = [
    'aggregateDerivationComponentHash',
    'aggregateDerivationStatementHash',
    'aggregateShareCommitmentHash',
    'shareCommitmentMessageBoundCertHash',
    'encryptedAggregateBridgeHash',
    'encryptedAggregateTargetBasisRoot',
    'encryptedAggregateInputRoot',
    'encryptedAggregateShareCiphertextRoot',
    'encryptedAggregateReconstructionHash',
    'bridgeProofProfileHash',
    'bridgeProofChallengeContextHash',
    'bridgeProofTargetContractHash',
    'bridgeWitnessPrivacyProfileHash',
    'bgvBatchEncoderHash',
    'bridgeLayoutHash',
    'ballotScoreEncodingProfileHash',
    'ballotShareLayoutProfileHash',
    'aggregateInputEncodingProfileHash',
    'encodedShareVectorLayoutHash',
    'encodedAggregateLayoutHash',
    'encryptedAggregateInputLayoutHash',
    'topKEvaluatorInputLayoutHash',
    'heParamHash',
    'bgvProfileHash',
    'rustBgvBackendProfileHash',
    'canonicalCiphertextConventionHash',
    'bgvPublicKeyRoot',
    'collectivePublicKeyRoot',
    'collectivePublicKeyCoefficientRoot',
    'aggregateSelectionPolicyHash',
    'postVotingClosedContextHash',
    'manifestHash',
    'rosterHash',
    'pollSpecHash',
    'thresholdProfileHash',
    'setupPackageHash',
    'ballotSetHash',
    'votingClosedBoardHeadHash',
    'contributorActionContextHash',
    'contributorRosterExternalAcceptanceHash',
    'plaintextCoefficientBindingCommitmentHash',
    'proofFriendlyPlaintextLiftBindingHash',
    'proofStatementHash',
    'proofRoot',
    'proofBytesHash',
    'proofEncodingProfileHash',
    'proofParameterSetHash',
    'publicRandomnessHash',
] as const;

export const contributionHashFieldNames = [
    'aggregateContributionHash',
    'bridgeProofRecordHash',
    'aggregateDerivationComponentHash',
    'aggregateShareCommitmentHash',
    'shareCommitmentMessageBoundCertHash',
    'encryptedAggregateBridgeHash',
    'encryptedAggregateTargetBasisRoot',
    'encryptedAggregateInputRoot',
    'encryptedAggregateShareCiphertextRoot',
    'encryptedAggregateReconstructionHash',
    'bridgeProofProfileHash',
    'bridgeWitnessPrivacyProfileHash',
    'bgvBatchEncoderHash',
    'bridgeLayoutHash',
    'ballotScoreEncodingProfileHash',
    'ballotShareLayoutProfileHash',
    'aggregateInputEncodingProfileHash',
    'encodedShareVectorLayoutHash',
    'encodedAggregateLayoutHash',
    'encryptedAggregateInputLayoutHash',
    'topKEvaluatorInputLayoutHash',
    'heParamHash',
    'bgvProfileHash',
    'rustBgvBackendProfileHash',
    'canonicalCiphertextConventionHash',
    'bgvPublicKeyRoot',
    'collectivePublicKeyRoot',
    'collectivePublicKeyCoefficientRoot',
    'aggregateSelectionPolicyHash',
    'postVotingClosedContextHash',
    'manifestHash',
    'rosterHash',
    'pollSpecHash',
    'thresholdProfileHash',
    'setupPackageHash',
    'ballotSetHash',
    'votingClosedBoardHeadHash',
    'closeRecordHash',
    'contributorRosterExternalAcceptanceHash',
] as const;

export const aggregateReadyHashFieldNames = [
    'aggregateReadyRecordHash',
    'manifestHash',
    'rosterHash',
    'pollSpecHash',
    'thresholdProfileHash',
    'ballotSetHash',
    'votingClosedBoardHeadHash',
    'postVotingClosedContextHash',
    'aggregateSelectionPolicyHash',
    'firstValidOrderHash',
    'interpolationCoefficientReportHash',
    'encryptedAggregateBridgeHash',
    'encryptedAggregateTargetBasisRoot',
    'encryptedAggregateReconstructionHash',
    'encryptedAggregateReconstructionRoot',
    'bridgeWitnessPrivacyProfileHash',
    'bgvBatchEncoderHash',
    'bridgeLayoutHash',
    'encryptedAggregateInputLayoutHash',
    'topKEvaluatorInputLayoutHash',
    'bgvProfileHash',
    'setupPackageHash',
    'collectivePublicKeyRoot',
    'collectivePublicKeyCoefficientRoot',
] as const;

export const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectHash: ProtocolHash | undefined,
    path: string,
): readonly RefusalRecord[] =>
    collectBoundedForbiddenWitnessFieldRefusals(value, objectHash, path, {
        publicObjectDescription: 'Aggregate contribution public object',
    });

export const collectHashShapeRefusals = (
    value: Record<string, unknown>,
    hashFieldNames: readonly string[],
    objectHash: ProtocolHash | undefined,
): readonly RefusalRecord[] =>
    hashFieldNames.flatMap((fieldName) => {
        const fieldValue = value[fieldName];

        return typeof fieldValue === 'string' &&
            protocolHashPattern.test(fieldValue)
            ? []
            : [
                  createAggregateRefusal(
                      `Aggregate bridge field ${fieldName} must be a canonical protocol hash.`,
                      objectHash,
                  ),
              ];
    });

export const requireProtocolHashField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectName: string,
): ProtocolHash => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue === 'string' &&
        protocolHashPattern.test(fieldValue)
    ) {
        return fieldValue;
    }

    throw new RangeError(
        `${objectName}.${fieldName} must be a canonical protocol hash.`,
    );
};

export const requireMatchingValue = (
    actualValue: unknown,
    expectedValue: unknown,
    description: string,
): void => {
    if (actualValue !== expectedValue) {
        throw new RangeError(
            `Bridge proof record evidence mismatch for ${description}: expected ${String(expectedValue)}, got ${String(actualValue)}.`,
        );
    }
};

export const requireProtocolHash = (
    value: unknown,
    description: string,
): ProtocolHash => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new RangeError(
            `${description} must be a canonical protocol hash.`,
        );
    }

    return value;
};

export const bridgeProofByteLength = (proofBytesHex: string): number => {
    if (
        proofBytesHex.length === 0 ||
        proofBytesHex.length % 2 !== 0 ||
        !/^[0-9a-f]+$/u.test(proofBytesHex)
    ) {
        throw new RangeError(
            'Bridge proof bytes must be non-empty lowercase even-length hex.',
        );
    }

    return proofBytesHex.length / 2;
};

export const aggregateRelationChallengeHexPattern = /^[0-9a-f]{48}$/u;
export const hash512HexPattern = /^[0-9a-f]{128}$/u;

export const requireMatchingSafeInteger = (
    actualValue: number,
    expectedValue: number,
    description: string,
): void => {
    if (
        !Number.isSafeInteger(actualValue) ||
        !Number.isSafeInteger(expectedValue) ||
        actualValue !== expectedValue
    ) {
        throw new RangeError(`${description} does not match.`);
    }
};
