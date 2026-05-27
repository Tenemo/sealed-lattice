import type {
    ActionContext,
    AggregateDerivationComponent,
    BridgeProofRecord,
    ProtocolDigest,
    ProtocolSignatureEnvelope,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    createAggregateRefusal,
    protocolDigestPattern,
} from '../../aggregate-derivation/constants.js';
import { collectForbiddenWitnessFieldRefusals as collectBoundedForbiddenWitnessFieldRefusals } from '../../aggregate-derivation/witness-field-refusals.js';

export type BridgeSetupEvidence = {
    readonly setupPackageDigest: ProtocolDigest;
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestDigest: ProtocolDigest;
        readonly participantCount: number;
        readonly rosterDigest: ProtocolDigest;
        readonly thresholdProfileDigest: ProtocolDigest;
    };
    readonly profileBindings: Readonly<Record<string, unknown>>;
    readonly collectivePublicKey: {
        readonly bgvPublicKeyRoot: ProtocolDigest;
        readonly collectivePublicKeyRoot: ProtocolDigest;
    };
};

export type BridgeEncryptionEvidence = {
    readonly aggregateDerivationComponentDigest: ProtocolDigest;
    readonly aggregateDerivationStatementDigest: ProtocolDigest;
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentDigest: ProtocolDigest;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly basisId: string;
    readonly bgvPublicKeyRoot: ProtocolDigest;
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofBytesHex: string;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofRoot: ProtocolDigest;
    readonly bridgeSharedWitnessProofDigest: ProtocolDigest;
    readonly sharedWitnessZeroKnowledgeStatusDigest: ProtocolDigest;
    readonly bgvRandomnessBoundProofStatusDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
    readonly bridgeClaimClosureVerified?: false;
    readonly bridgeClaimVerificationStatus?: 'BridgeProofClaimClosureMissing';
    readonly bridgeVariantEvidenceStatus?:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly canonicalByteLength: number;
    readonly canonicalBytesHash512: string;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly ciphertextRoot: ProtocolDigest;
    readonly coefficientCount: number;
    readonly collectivePublicKeyRoot: ProtocolDigest;
    readonly encryptedAggregateInputRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly level: number;
    readonly plaintextRoot: ProtocolDigest;
    readonly profileDigest: ProtocolDigest;
    readonly rustBgvBackendProfileDigest: ProtocolDigest;
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
};

export type BridgeEvidenceVerification = {
    readonly aggregateQuotientCoordinateCount: number;
    readonly aggregateReducedCoordinateCount: number;
    readonly aggregateRelationChallengeHex: string;
    readonly aggregateRelationCommitmentDigest: ProtocolDigest;
    readonly aggregateRelationSubproofSizeBytes: number;
    readonly bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked';
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofRoot: ProtocolDigest;
    readonly bridgeSharedWitnessProofDigest: ProtocolDigest;
    readonly sharedWitnessZeroKnowledgeStatusDigest: ProtocolDigest;
    readonly bgvRandomnessBoundProofStatusDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofVerificationStatus: 'BridgeProofRelationChecked';
    readonly bridgeClaimClosureVerified?: false;
    readonly bridgeClaimVerificationStatus?: 'BridgeProofClaimClosureMissing';
    readonly bridgeVariantEvidenceStatus?:
        | 'representative-row-evidence'
        | 'full-matrix-row-evidence-missing';
    readonly encryptedAggregateInputRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly ok: true;
};

export type PendingBridgeProofRecordFromEvidenceInput = {
    readonly aggregateDerivationComponent: AggregateDerivationComponent;
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeEncryptionEvidence: BridgeEncryptionEvidence;
    readonly bridgeEvidenceVerification: BridgeEvidenceVerification;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly heParamDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest?: ProtocolDigest;
    readonly proofParameterSetDigest?: ProtocolDigest;
    readonly publicRandomnessDigest?: ProtocolDigest;
    readonly setupPackage: BridgeSetupEvidence;
};

export type AggregateContributionFromBridgeProofRecordInput = {
    readonly actionContext: ActionContext;
    readonly boardPosition: number;
    readonly bridgeProofRecord: BridgeProofRecord;
    readonly closeRecordDigest: ProtocolDigest;
    readonly signature:
        | ProtocolSignatureEnvelope
        | ((input: {
              readonly aggregateContributionDigest: ProtocolDigest;
          }) => ProtocolSignatureEnvelope);
};

export const bridgeDigestFieldNames = [
    'aggregateDerivationComponentDigest',
    'aggregateShareCommitmentDigest',
    'shareCommitmentMessageBoundCertDigest',
    'encryptedAggregateBridgeDigest',
    'encryptedAggregateTargetBasisDataRoot',
    'encryptedAggregateInputRoot',
    'encryptedAggregateShareCiphertextRoot',
    'encryptedAggregateReconstructionDigest',
    'bridgeProofProfileDigest',
    'bridgeProofTargetContractDigest',
    'bridgeWitnessPrivacyProfileDigest',
    'bgvBatchEncoderDigest',
    'bridgeLayoutDigest',
    'ballotScoreEncodingProfileDigest',
    'ballotShareLayoutProfileDigest',
    'aggregateInputEncodingProfileDigest',
    'encodedShareVectorLayoutDigest',
    'encodedAggregateLayoutDigest',
    'encryptedAggregateInputLayoutDigest',
    'topKEvaluatorInputLayoutDigest',
    'heParamDigest',
    'bgvProfileDigest',
    'rustBgvBackendProfileDigest',
    'canonicalCiphertextConventionDigest',
    'bgvPublicKeyRoot',
    'collectivePublicKeyRoot',
    'aggregateSelectionPolicyDigest',
    'postVotingClosedContextDigest',
    'manifestDigest',
    'rosterDigest',
    'pollSpecDigest',
    'thresholdProfileDigest',
    'setupPackageDigest',
    'ballotSetDigest',
    'votingClosedBoardHeadDigest',
    'contributorActionContextDigest',
    'contributorRosterExternalAcceptanceDigest',
    'proofStatementDigest',
    'proofRoot',
    'proofBytesDigest',
    'proofEncodingProfileDigest',
    'proofParameterSetDigest',
    'publicRandomnessDigest',
] as const;

export const contributionDigestFieldNames = [
    'aggregateContributionDigest',
    'bridgeProofRecordDigest',
    'aggregateDerivationComponentDigest',
    'aggregateShareCommitmentDigest',
    'shareCommitmentMessageBoundCertDigest',
    'encryptedAggregateBridgeDigest',
    'encryptedAggregateTargetBasisDataRoot',
    'encryptedAggregateInputRoot',
    'encryptedAggregateShareCiphertextRoot',
    'encryptedAggregateReconstructionDigest',
    'bridgeProofProfileDigest',
    'bridgeWitnessPrivacyProfileDigest',
    'bgvBatchEncoderDigest',
    'bridgeLayoutDigest',
    'ballotScoreEncodingProfileDigest',
    'ballotShareLayoutProfileDigest',
    'aggregateInputEncodingProfileDigest',
    'encodedShareVectorLayoutDigest',
    'encodedAggregateLayoutDigest',
    'encryptedAggregateInputLayoutDigest',
    'topKEvaluatorInputLayoutDigest',
    'heParamDigest',
    'bgvProfileDigest',
    'rustBgvBackendProfileDigest',
    'canonicalCiphertextConventionDigest',
    'bgvPublicKeyRoot',
    'collectivePublicKeyRoot',
    'aggregateSelectionPolicyDigest',
    'postVotingClosedContextDigest',
    'manifestDigest',
    'rosterDigest',
    'pollSpecDigest',
    'thresholdProfileDigest',
    'setupPackageDigest',
    'ballotSetDigest',
    'votingClosedBoardHeadDigest',
    'closeRecordDigest',
    'contributorRosterExternalAcceptanceDigest',
] as const;

export const aggregateReadyDigestFieldNames = [
    'aggregateReadyRecordDigest',
    'manifestDigest',
    'rosterDigest',
    'pollSpecDigest',
    'thresholdProfileDigest',
    'ballotSetDigest',
    'votingClosedBoardHeadDigest',
    'postVotingClosedContextDigest',
    'aggregateSelectionPolicyDigest',
    'firstValidOrderDigest',
    'interpolationCoefficientReportDigest',
    'encryptedAggregateBridgeDigest',
    'encryptedAggregateTargetBasisDataRoot',
    'encryptedAggregateReconstructionDigest',
    'encryptedAggregateReconstructionRoot',
    'bridgeWitnessPrivacyProfileDigest',
    'bgvBatchEncoderDigest',
    'bridgeLayoutDigest',
    'encryptedAggregateInputLayoutDigest',
    'topKEvaluatorInputLayoutDigest',
    'bgvProfileDigest',
    'setupPackageDigest',
    'collectivePublicKeyRoot',
] as const;

export const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectDigest: ProtocolDigest | undefined,
    path: string,
): readonly RefusalRecord[] =>
    collectBoundedForbiddenWitnessFieldRefusals(value, objectDigest, path, {
        publicObjectDescription: 'Aggregate contribution public object',
    });

export const collectDigestShapeRefusals = (
    value: Record<string, unknown>,
    digestFieldNames: readonly string[],
    objectDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] =>
    digestFieldNames.flatMap((fieldName) => {
        const fieldValue = value[fieldName];

        return typeof fieldValue === 'string' &&
            protocolDigestPattern.test(fieldValue)
            ? []
            : [
                  createAggregateRefusal(
                      `Aggregate bridge field ${fieldName} must be a canonical protocol digest.`,
                      objectDigest,
                  ),
              ];
    });

export const requireProtocolDigestField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectName: string,
): ProtocolDigest => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue === 'string' &&
        protocolDigestPattern.test(fieldValue)
    ) {
        return fieldValue;
    }

    throw new RangeError(
        `${objectName}.${fieldName} must be a canonical protocol digest.`,
    );
};

export const requireMatchingValue = (
    actualValue: unknown,
    expectedValue: unknown,
    description: string,
): void => {
    if (actualValue !== expectedValue) {
        throw new RangeError(
            `Bridge proof record evidence mismatch for ${description}.`,
        );
    }
};

export const requireProtocolDigest = (
    value: ProtocolDigest,
    description: string,
): ProtocolDigest => {
    if (!protocolDigestPattern.test(value)) {
        throw new RangeError(
            `${description} must be a canonical protocol digest.`,
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
