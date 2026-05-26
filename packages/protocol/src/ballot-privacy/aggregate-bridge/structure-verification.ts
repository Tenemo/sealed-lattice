import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type ActionContext,
    type AggregateDerivationComponent,
    type AggregateContribution,
    type AggregateContributionSelection,
    type AggregateContributionSelectionInput,
    type AggregateContributionVerification,
    type AggregateReadyRecord,
    type AggregateReadyRecordBuildInput,
    type BridgeProofRecord,
    type InterpolationCoefficientReport,
    type ProtocolDigest,
    type ProtocolSignatureEnvelope,
    type RefusalRecord,
} from '@sealed-lattice/types';

import {
    createRefusal,
    uniqueStrings,
} from '../../common/verification-helpers.js';
import { deriveValidatedFirstValidOrder } from '../../ordering/index.js';
import { deriveInterpolationCoefficientReport } from '../../plaintext-oracle/index.js';
import {
    createAggregateRefusal,
    forbiddenPublicWitnessFieldNames,
    protocolDigestPattern,
} from '../aggregate-derivation/constants.js';

import {
    deriveAggregateContributionDigest,
    deriveAggregateReadyRecordDigest,
    deriveBridgeProofProfileDigest,
    deriveBridgeProofRecordDigest,
    deriveBridgeProofStatementDigest,
    deriveBridgeProofTargetContractDigest,
    deriveEncryptedAggregateReconstructionRoot,
} from './digests.js';

export type BridgeSetupEvidence = {
    readonly setupInputs: {
        readonly ceremonyId: string;
        readonly manifestDigest: ProtocolDigest;
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
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofVerificationStatus: 'BridgeProofBackendPending';
    readonly canonicalByteLength: number;
    readonly canonicalBytesHash512: string;
    readonly canonicalCiphertextConventionDigest: ProtocolDigest;
    readonly ciphertextRoot: ProtocolDigest;
    readonly coefficientCount: number;
    readonly collectivePublicKeyRoot: ProtocolDigest;
    readonly encryptedAggregateShareCiphertextRoot: ProtocolDigest;
    readonly level: number;
    readonly plaintextRoot: ProtocolDigest;
    readonly profileDigest: ProtocolDigest;
    readonly rustBgvBackendProfileDigest: ProtocolDigest;
    readonly sampledPublicRelationCheckPolicy: {
        readonly acceptedForBridgeProofVerification: false;
        readonly diagnosticOnly: true;
        readonly fullBridgeProofRequired: true;
        readonly objectType: 'M9BridgeSampledRelationCheckPolicy';
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
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly bridgeProofVerificationStatus: 'BridgeProofBackendPending';
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

type AggregateContributionFromBridgeProofRecordInput = {
    readonly actionContext: ActionContext;
    readonly boardPosition: number;
    readonly bridgeProofRecord: BridgeProofRecord;
    readonly closeRecordDigest: ProtocolDigest;
    readonly signature: ProtocolSignatureEnvelope;
};

const bridgeDigestFieldNames = [
    'aggregateDerivationComponentDigest',
    'aggregateShareCommitmentDigest',
    'shareCommitmentMessageBoundCertDigest',
    'encryptedAggregateBridgeDigest',
    'encryptedAggregateTargetBasisDataRoot',
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
    'ballotSetDigest',
    'votingClosedBoardHeadDigest',
    'contributorRosterExternalAcceptanceDigest',
    'proofStatementDigest',
    'proofRoot',
    'proofBytesDigest',
    'proofEncodingProfileDigest',
    'proofParameterSetDigest',
    'publicRandomnessDigest',
] as const;

const contributionDigestFieldNames = [
    'aggregateContributionDigest',
    'bridgeProofRecordDigest',
    'aggregateDerivationComponentDigest',
    'aggregateShareCommitmentDigest',
    'shareCommitmentMessageBoundCertDigest',
    'encryptedAggregateBridgeDigest',
    'encryptedAggregateTargetBasisDataRoot',
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
    'ballotSetDigest',
    'votingClosedBoardHeadDigest',
    'closeRecordDigest',
    'contributorRosterExternalAcceptanceDigest',
] as const;

const collectForbiddenWitnessFieldRefusals = (
    value: unknown,
    objectDigest: ProtocolDigest | undefined,
    path: string,
): readonly RefusalRecord[] => {
    if (Array.isArray(value)) {
        return value.flatMap((item, itemIndex) =>
            collectForbiddenWitnessFieldRefusals(
                item,
                objectDigest,
                `${path}[${itemIndex}]`,
            ),
        );
    }
    if (typeof value !== 'object' || value === null) {
        return [];
    }

    const refusedObjects: RefusalRecord[] = [];
    for (const [fieldName, fieldValue] of Object.entries(value)) {
        if (forbiddenPublicWitnessFieldNames.has(fieldName)) {
            refusedObjects.push(
                createAggregateRefusal(
                    `Aggregate contribution public object must not expose witness field ${path}.${fieldName}.`,
                    objectDigest,
                ),
            );
            continue;
        }
        refusedObjects.push(
            ...collectForbiddenWitnessFieldRefusals(
                fieldValue,
                objectDigest,
                `${path}.${fieldName}`,
            ),
        );
    }

    return refusedObjects;
};

const collectDigestShapeRefusals = (
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

const requireProtocolDigestField = (
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

const requireMatchingValue = (
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

const requireProtocolDigest = (
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

const bridgeProofByteLength = (proofBytesHex: string): number => {
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

const aggregateRelationChallengeHexPattern = /^[0-9a-f]{48}$/u;
const hash512HexPattern = /^[0-9a-f]{128}$/u;

const requireMatchingSafeInteger = (
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

const derivePendingBridgeProofEncodingProfileDigest = (input: {
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        ...input,
        purpose: 'm9-pending-bridge-proof-evidence-encoding-profile-v1',
    });

const derivePendingBridgeProofParameterSetDigest = (input: {
    readonly bgvProfileDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly collectivePublicKeyRoot: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        ...input,
        purpose: 'm9-pending-bridge-proof-parameter-set-v1',
    });

const derivePendingBridgeProofPublicRandomnessDigest = (input: {
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ProofBytesDigest', {
        ...input,
        purpose: 'm9-pending-bridge-proof-public-randomness-v1',
    });

const deriveSampledPublicRelationCheckPolicyDigest = (
    policy: BridgeEncryptionEvidence['sampledPublicRelationCheckPolicy'],
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        policy,
        purpose: 'm9-sampled-public-relation-check-policy-v1',
    });

export const createPendingBridgeProofRecordFromBridgeEvidence = (
    input: PendingBridgeProofRecordFromEvidenceInput,
): BridgeProofRecord => {
    const { aggregateDerivationComponent, bridgeEncryptionEvidence } = input;
    const { statement } = aggregateDerivationComponent;
    const { profileBindings } = input.setupPackage;
    const bridgeProofProfileDigest = deriveBridgeProofProfileDigest({
        bgvEncryptionProofSubrelation: 'SealedLatticeBoundedEncryptionRelation',
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        proofBackend: 'SealedLatticeBridgeRelation',
    });
    const profileDigest = requireProtocolDigestField(
        profileBindings,
        'profileDigest',
        'setupPackage.profileBindings',
    );
    const rustBgvBackendProfileDigest = requireProtocolDigestField(
        profileBindings,
        'backendProfileDigest',
        'setupPackage.profileBindings',
    );
    const canonicalCiphertextConventionDigest = requireProtocolDigestField(
        profileBindings,
        'canonicalCiphertextConventionDigest',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateInputLayoutDigest = requireProtocolDigestField(
        profileBindings,
        'encryptedAggregateInputLayoutDigest',
        'setupPackage.profileBindings',
    );
    const sampledPublicRelationCheckPolicy =
        bridgeEncryptionEvidence.sampledPublicRelationCheckPolicy;
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.objectType,
        'M9BridgeSampledRelationCheckPolicy',
        'sampled public relation check policy object type',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.objectVersion,
        1,
        'sampled public relation check policy version',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.diagnosticOnly,
        true,
        'sampled public relation check diagnostic-only policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.acceptedForBridgeProofVerification,
        false,
        'sampled public relation check acceptance policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.fullBridgeProofRequired,
        true,
        'sampled public relation full-proof policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.sampledOnlyBridgeVerificationAccepted,
        false,
        'sampled-only bridge verification policy',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.relationCheckSource,
        'first-data-prime-diagnostic',
        'sampled public relation check source',
    );
    requireMatchingValue(
        sampledPublicRelationCheckPolicy.sampledRelationCheckCount,
        bridgeEncryptionEvidence.sampledPublicRelationChecks.length,
        'sampled public relation check count',
    );
    const sampledPublicRelationCheckPolicyDigest =
        deriveSampledPublicRelationCheckPolicyDigest(
            sampledPublicRelationCheckPolicy,
        );
    const bridgeProofTargetContractDigest =
        deriveBridgeProofTargetContractDigest({
            aggregateQuotientCoordinateCount: statement.shareVectorWidth,
            aggregateReducedCoordinateCount: statement.shareVectorWidth,
        });
    const expectedBridgeProofStatementDigest = deriveBridgeProofStatementDigest(
        {
            aggregateDerivationComponentDigest:
                aggregateDerivationComponent.aggregateDerivationComponentDigest,
            aggregateInputEncodingProfileDigest: requireProtocolDigestField(
                profileBindings,
                'aggregateInputEncodingProfileDigest',
                'setupPackage.profileBindings',
            ),
            aggregateQuotientCoordinateCount: statement.shareVectorWidth,
            aggregateReducedCoordinateCount: statement.shareVectorWidth,
            aggregateSelectionPolicyDigest: requireProtocolDigest(
                input.aggregateSelectionPolicyDigest,
                'aggregate selection policy digest',
            ),
            aggregateShareCommitmentDigest:
                aggregateDerivationComponent.aggregateCommitment
                    .aggregateShareCommitmentDigest,
            aggregateToPlaintextBindingStatus:
                'AggregateToPlaintextBindingProofPending',
            ballotScoreEncodingProfileDigest: requireProtocolDigestField(
                profileBindings,
                'ballotScoreEncodingProfileDigest',
                'setupPackage.profileBindings',
            ),
            ballotSetDigest: statement.ballotSetDigest,
            ballotShareLayoutProfileDigest: requireProtocolDigestField(
                profileBindings,
                'ballotShareLayoutProfileDigest',
                'setupPackage.profileBindings',
            ),
            basisId: bridgeEncryptionEvidence.basisId,
            bgvBatchEncoderDigest: requireProtocolDigestField(
                profileBindings,
                'batchEncoderDigest',
                'setupPackage.profileBindings',
            ),
            bgvEncryptionProofStatus: 'BoundedEncryptionProofPending',
            bgvProfileDigest: profileDigest,
            bgvPublicKeyRoot:
                input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
            bridgeLayoutDigest: encryptedAggregateInputLayoutDigest,
            bridgeProofTargetContractDigest,
            bridgeWitnessPrivacyProfileDigest: requireProtocolDigest(
                input.bridgeWitnessPrivacyProfileDigest,
                'bridge witness privacy profile digest',
            ),
            canonicalByteLength: bridgeEncryptionEvidence.canonicalByteLength,
            canonicalBytesHash512:
                bridgeEncryptionEvidence.canonicalBytesHash512,
            canonicalCiphertextConventionDigest,
            ceremonyId: statement.ceremonyId,
            ciphertextRoot: bridgeEncryptionEvidence.ciphertextRoot,
            coefficientDomainCanonical: true,
            coefficientCount: bridgeEncryptionEvidence.coefficientCount,
            collectivePublicKeyRoot:
                input.setupPackage.collectivePublicKey.collectivePublicKeyRoot,
            contributorActionContextDigest:
                statement.contributorActionContextDigest,
            contributorIdentity: statement.contributorIdentity,
            contributorRosterExternalAcceptanceDigest:
                statement.contributorRosterExternalAcceptanceDigest,
            contributorRosterPosition: statement.contributorRosterPosition,
            encodedAggregateLayoutDigest: requireProtocolDigestField(
                profileBindings,
                'encodedAggregateLayoutDigest',
                'setupPackage.profileBindings',
            ),
            encodedShareVectorLayoutDigest:
                statement.encodedShareVectorLayoutDigest,
            encryptedAggregateBridgeDigest: requireProtocolDigestField(
                profileBindings,
                'encryptedAggregateBridgeDigest',
                'setupPackage.profileBindings',
            ),
            encryptedAggregateInputLayoutDigest,
            encryptedAggregateReconstructionDigest: requireProtocolDigestField(
                profileBindings,
                'encryptedAggregateReconstructionDigest',
                'setupPackage.profileBindings',
            ),
            encryptedAggregateShareCiphertextRoot:
                bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
            encryptedAggregateTargetBasisDataRoot: requireProtocolDigestField(
                profileBindings,
                'encryptedAggregateTargetBasisDataRoot',
                'setupPackage.profileBindings',
            ),
            heParamDigest: requireProtocolDigest(
                input.heParamDigest,
                'HE parameter digest',
            ),
            hwangPiopStatus:
                'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze',
            level: bridgeEncryptionEvidence.level,
            manifestDigest: statement.manifestDigest,
            plaintextRoot: bridgeEncryptionEvidence.plaintextRoot,
            pollSpecDigest: statement.pollSpecDigest,
            postVotingClosedContextDigest:
                statement.postVotingClosedContextDigest,
            proofProfileDigest: bridgeProofProfileDigest,
            rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyProofPending',
            rosterDigest: statement.rosterDigest,
            rustBgvBackendProfileDigest,
            sampledPublicRelationCheckPolicyDigest,
            sampledOnlyBridgeVerificationAccepted: false,
            shareCommitmentMessageBoundCertDigest:
                statement.shareCommitmentMessageBoundCertDigest,
            sharedWitnessBindingRequired: true,
            sharedWitnessBindingStatus: 'SharedWitnessBindingProofPending',
            slotCount: bridgeEncryptionEvidence.slotCount,
            thresholdProfileDigest: statement.thresholdProfileDigest,
            topKEvaluatorInputLayoutDigest: requireProtocolDigestField(
                profileBindings,
                'topKEvaluatorInputLayoutDigest',
                'setupPackage.profileBindings',
            ),
            votingClosedBoardHeadDigest: statement.votingClosedBoardHeadDigest,
        },
    );

    requireMatchingValue(
        input.bridgeEvidenceVerification.ok,
        true,
        'verified bridge evidence status',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofVerificationStatus,
        'BridgeProofBackendPending',
        'pending bridge proof status',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeEvidenceVerificationStatus,
        'BridgeProofEvidenceChecked',
        'bridge evidence verification label',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationComponentDigest,
        aggregateDerivationComponent.aggregateDerivationComponentDigest,
        'aggregate derivation component digest',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationStatementDigest,
        statement.aggregateDerivationStatementDigest,
        'aggregate derivation statement digest',
    );
    requireMatchingSafeInteger(
        bridgeEncryptionEvidence.aggregateReducedCoordinateCount,
        statement.shareVectorWidth,
        'aggregate reduced coordinate count',
    );
    requireMatchingSafeInteger(
        bridgeEncryptionEvidence.aggregateQuotientCoordinateCount,
        statement.shareVectorWidth,
        'aggregate quotient coordinate count',
    );
    if (
        !aggregateRelationChallengeHexPattern.test(
            bridgeEncryptionEvidence.aggregateRelationChallengeHex,
        )
    ) {
        throw new RangeError(
            'Aggregate relation challenge summary must be canonical lowercase hex.',
        );
    }
    requireProtocolDigest(
        bridgeEncryptionEvidence.aggregateRelationCommitmentDigest,
        'aggregate relation commitment digest',
    );
    if (
        !hash512HexPattern.test(bridgeEncryptionEvidence.canonicalBytesHash512)
    ) {
        throw new RangeError(
            'Canonical ciphertext bytes hash must be lowercase 512-bit hex.',
        );
    }
    if (
        !Number.isSafeInteger(bridgeEncryptionEvidence.canonicalByteLength) ||
        bridgeEncryptionEvidence.canonicalByteLength <= 0
    ) {
        throw new RangeError(
            'Canonical ciphertext byte length must be a positive safe integer.',
        );
    }
    if (
        !Number.isSafeInteger(
            bridgeEncryptionEvidence.aggregateRelationSubproofSizeBytes,
        ) ||
        bridgeEncryptionEvidence.aggregateRelationSubproofSizeBytes <= 0
    ) {
        throw new RangeError(
            'Aggregate relation subproof size must be a positive safe integer.',
        );
    }
    requireMatchingValue(
        aggregateDerivationComponent.aggregateCommitment
            .aggregateShareCommitmentDigest,
        statement.aggregateShareCommitmentDigest,
        'aggregate share commitment digest',
    );
    requireMatchingValue(
        aggregateDerivationComponent.shareCommitmentMessageBoundCert
            .shareCommitmentMessageBoundCertDigest,
        statement.shareCommitmentMessageBoundCertDigest,
        'share commitment message-bound certificate digest',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.ceremonyId,
        statement.ceremonyId,
        'ceremony id',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.manifestDigest,
        statement.manifestDigest,
        'manifest digest',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.rosterDigest,
        statement.rosterDigest,
        'roster digest',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.thresholdProfileDigest,
        statement.thresholdProfileDigest,
        'threshold profile digest',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.collectivePublicKeyRoot,
        input.setupPackage.collectivePublicKey.collectivePublicKeyRoot,
        'collective public key root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bgvPublicKeyRoot,
        input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
        'BGV public key root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.profileDigest,
        profileDigest,
        'BGV profile digest',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.rustBgvBackendProfileDigest,
        rustBgvBackendProfileDigest,
        'Rust BGV backend profile digest',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.canonicalCiphertextConventionDigest,
        canonicalCiphertextConventionDigest,
        'canonical ciphertext convention digest',
    );
    for (const [description, bridgeValue, verificationValue] of [
        [
            'bridge proof profile digest',
            bridgeEncryptionEvidence.bridgeProofProfileDigest,
            input.bridgeEvidenceVerification.bridgeProofProfileDigest,
        ],
        [
            'bridge proof statement digest',
            bridgeEncryptionEvidence.bridgeProofStatementDigest,
            input.bridgeEvidenceVerification.bridgeProofStatementDigest,
        ],
        [
            'bridge proof target contract digest',
            bridgeEncryptionEvidence.bridgeProofTargetContractDigest,
            input.bridgeEvidenceVerification.bridgeProofTargetContractDigest,
        ],
        [
            'bridge proof bytes digest',
            bridgeEncryptionEvidence.bridgeProofBytesDigest,
            input.bridgeEvidenceVerification.bridgeProofBytesDigest,
        ],
        [
            'bridge proof root',
            bridgeEncryptionEvidence.bridgeProofRoot,
            input.bridgeEvidenceVerification.bridgeProofRoot,
        ],
        [
            'encrypted aggregate-share ciphertext root',
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
            input.bridgeEvidenceVerification
                .encryptedAggregateShareCiphertextRoot,
        ],
        [
            'aggregate relation challenge summary',
            bridgeEncryptionEvidence.aggregateRelationChallengeHex,
            input.bridgeEvidenceVerification.aggregateRelationChallengeHex,
        ],
        [
            'aggregate relation commitment digest',
            bridgeEncryptionEvidence.aggregateRelationCommitmentDigest,
            input.bridgeEvidenceVerification.aggregateRelationCommitmentDigest,
        ],
    ] as const) {
        requireMatchingValue(bridgeValue, verificationValue, description);
    }
    for (const [description, bridgeValue, verificationValue] of [
        [
            'aggregate relation subproof size',
            bridgeEncryptionEvidence.aggregateRelationSubproofSizeBytes,
            input.bridgeEvidenceVerification.aggregateRelationSubproofSizeBytes,
        ],
        [
            'aggregate reduced coordinate count',
            bridgeEncryptionEvidence.aggregateReducedCoordinateCount,
            input.bridgeEvidenceVerification.aggregateReducedCoordinateCount,
        ],
        [
            'aggregate quotient coordinate count',
            bridgeEncryptionEvidence.aggregateQuotientCoordinateCount,
            input.bridgeEvidenceVerification.aggregateQuotientCoordinateCount,
        ],
    ] as const) {
        requireMatchingSafeInteger(bridgeValue, verificationValue, description);
    }
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofProfileDigest,
        bridgeProofProfileDigest,
        'canonical bridge proof profile digest',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofStatementDigest,
        expectedBridgeProofStatementDigest,
        'canonical bridge proof statement digest',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofTargetContractDigest,
        bridgeProofTargetContractDigest,
        'canonical bridge proof target contract digest',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeProofVerificationStatus,
        'BridgeProofBackendPending',
        'verification bridge proof status',
    );

    const proofEncodingProfileDigest = requireProtocolDigest(
        input.proofEncodingProfileDigest ??
            derivePendingBridgeProofEncodingProfileDigest({
                bridgeProofBytesDigest:
                    bridgeEncryptionEvidence.bridgeProofBytesDigest,
                bridgeProofProfileDigest,
                bridgeProofStatementDigest: expectedBridgeProofStatementDigest,
            }),
        'proof encoding profile digest',
    );
    const proofParameterSetDigest = requireProtocolDigest(
        input.proofParameterSetDigest ??
            derivePendingBridgeProofParameterSetDigest({
                bgvProfileDigest: profileDigest,
                bridgeProofProfileDigest,
                bridgeProofStatementDigest: expectedBridgeProofStatementDigest,
                collectivePublicKeyRoot:
                    bridgeEncryptionEvidence.collectivePublicKeyRoot,
            }),
        'proof parameter set digest',
    );
    const publicRandomnessDigest = requireProtocolDigest(
        input.publicRandomnessDigest ??
            derivePendingBridgeProofPublicRandomnessDigest({
                bridgeProofBytesDigest:
                    bridgeEncryptionEvidence.bridgeProofBytesDigest,
                bridgeProofStatementDigest: expectedBridgeProofStatementDigest,
            }),
        'public randomness digest',
    );
    const bridgeProofRecordPayload: Omit<
        BridgeProofRecord,
        'bridgeProofRecordDigest'
    > = {
        aggregateDerivationComponentDigest:
            aggregateDerivationComponent.aggregateDerivationComponentDigest,
        aggregateSelectionPolicyDigest: requireProtocolDigest(
            input.aggregateSelectionPolicyDigest,
            'aggregate selection policy digest',
        ),
        aggregateShareCommitmentDigest:
            aggregateDerivationComponent.aggregateCommitment
                .aggregateShareCommitmentDigest,
        aggregateInputEncodingProfileDigest: requireProtocolDigestField(
            profileBindings,
            'aggregateInputEncodingProfileDigest',
            'setupPackage.profileBindings',
        ),
        ballotScoreEncodingProfileDigest: requireProtocolDigestField(
            profileBindings,
            'ballotScoreEncodingProfileDigest',
            'setupPackage.profileBindings',
        ),
        ballotSetDigest: statement.ballotSetDigest,
        ballotShareLayoutProfileDigest: requireProtocolDigestField(
            profileBindings,
            'ballotShareLayoutProfileDigest',
            'setupPackage.profileBindings',
        ),
        bgvBatchEncoderDigest: requireProtocolDigestField(
            profileBindings,
            'batchEncoderDigest',
            'setupPackage.profileBindings',
        ),
        bgvEncryptionProofSubrelation: 'SealedLatticeBoundedEncryptionRelation',
        bgvProfileDigest: profileDigest,
        bgvPublicKeyRoot: bridgeEncryptionEvidence.bgvPublicKeyRoot,
        bridgeLayoutDigest: encryptedAggregateInputLayoutDigest,
        bridgeProofProfileDigest,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofTargetContractDigest,
        bridgeProofVerificationStatus: 'BridgeProofBackendPending',
        bridgeWitnessPrivacyProfileDigest: requireProtocolDigest(
            input.bridgeWitnessPrivacyProfileDigest,
            'bridge witness privacy profile digest',
        ),
        canonicalCiphertextConventionDigest,
        ceremonyId: statement.ceremonyId,
        collectivePublicKeyRoot:
            bridgeEncryptionEvidence.collectivePublicKeyRoot,
        contributorIdentity: statement.contributorIdentity,
        contributorRosterExternalAcceptanceDigest:
            statement.contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: statement.contributorRosterPosition,
        encodedAggregateLayoutDigest: requireProtocolDigestField(
            profileBindings,
            'encodedAggregateLayoutDigest',
            'setupPackage.profileBindings',
        ),
        encodedShareVectorLayoutDigest:
            statement.encodedShareVectorLayoutDigest,
        encryptedAggregateBridgeDigest: requireProtocolDigestField(
            profileBindings,
            'encryptedAggregateBridgeDigest',
            'setupPackage.profileBindings',
        ),
        encryptedAggregateInputLayoutDigest,
        encryptedAggregateReconstructionDigest: requireProtocolDigestField(
            profileBindings,
            'encryptedAggregateReconstructionDigest',
            'setupPackage.profileBindings',
        ),
        encryptedAggregateShareCiphertextRoot:
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisDataRoot: requireProtocolDigestField(
            profileBindings,
            'encryptedAggregateTargetBasisDataRoot',
            'setupPackage.profileBindings',
        ),
        heParamDigest: requireProtocolDigest(
            input.heParamDigest,
            'HE parameter digest',
        ),
        manifestDigest: statement.manifestDigest,
        objectType: 'BridgeProofRecord',
        objectVersion: 1,
        pollSpecDigest: statement.pollSpecDigest,
        postVotingClosedContextDigest: statement.postVotingClosedContextDigest,
        proofBackend: 'SealedLatticeBridgeRelation',
        proofBytesDigest: bridgeEncryptionEvidence.bridgeProofBytesDigest,
        proofEncodingProfileDigest,
        proofParameterSetDigest,
        proofRoot: bridgeEncryptionEvidence.bridgeProofRoot,
        proofSizeBytes: bridgeProofByteLength(
            bridgeEncryptionEvidence.bridgeProofBytesHex,
        ),
        proofStatementDigest: expectedBridgeProofStatementDigest,
        publicRandomnessDigest,
        rosterDigest: statement.rosterDigest,
        rustBgvBackendProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            statement.shareCommitmentMessageBoundCertDigest,
        thresholdProfileDigest: statement.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest: requireProtocolDigestField(
            profileBindings,
            'topKEvaluatorInputLayoutDigest',
            'setupPackage.profileBindings',
        ),
        votingClosedBoardHeadDigest: statement.votingClosedBoardHeadDigest,
    };

    return {
        ...bridgeProofRecordPayload,
        bridgeProofRecordDigest: deriveBridgeProofRecordDigest(
            bridgeProofRecordPayload,
        ),
    };
};

const bridgeProofPublicFieldsMatchContribution = (
    contribution: AggregateContribution,
): boolean => {
    const proofRecord = contribution.bridgeProofRecord;

    return (
        proofRecord.aggregateDerivationComponentDigest ===
            contribution.aggregateDerivationComponentDigest &&
        proofRecord.aggregateShareCommitmentDigest ===
            contribution.aggregateShareCommitmentDigest &&
        proofRecord.shareCommitmentMessageBoundCertDigest ===
            contribution.shareCommitmentMessageBoundCertDigest &&
        proofRecord.encryptedAggregateBridgeDigest ===
            contribution.encryptedAggregateBridgeDigest &&
        proofRecord.encryptedAggregateTargetBasisDataRoot ===
            contribution.encryptedAggregateTargetBasisDataRoot &&
        proofRecord.encryptedAggregateShareCiphertextRoot ===
            contribution.encryptedAggregateShareCiphertextRoot &&
        proofRecord.encryptedAggregateReconstructionDigest ===
            contribution.encryptedAggregateReconstructionDigest &&
        proofRecord.bridgeProofProfileDigest ===
            contribution.bridgeProofProfileDigest &&
        proofRecord.bridgeWitnessPrivacyProfileDigest ===
            contribution.bridgeWitnessPrivacyProfileDigest &&
        proofRecord.bgvBatchEncoderDigest ===
            contribution.bgvBatchEncoderDigest &&
        proofRecord.bridgeLayoutDigest === contribution.bridgeLayoutDigest &&
        proofRecord.ballotScoreEncodingProfileDigest ===
            contribution.ballotScoreEncodingProfileDigest &&
        proofRecord.ballotShareLayoutProfileDigest ===
            contribution.ballotShareLayoutProfileDigest &&
        proofRecord.aggregateInputEncodingProfileDigest ===
            contribution.aggregateInputEncodingProfileDigest &&
        proofRecord.encodedShareVectorLayoutDigest ===
            contribution.encodedShareVectorLayoutDigest &&
        proofRecord.encodedAggregateLayoutDigest ===
            contribution.encodedAggregateLayoutDigest &&
        proofRecord.encryptedAggregateInputLayoutDigest ===
            contribution.encryptedAggregateInputLayoutDigest &&
        proofRecord.topKEvaluatorInputLayoutDigest ===
            contribution.topKEvaluatorInputLayoutDigest &&
        proofRecord.heParamDigest === contribution.heParamDigest &&
        proofRecord.bgvProfileDigest === contribution.bgvProfileDigest &&
        proofRecord.rustBgvBackendProfileDigest ===
            contribution.rustBgvBackendProfileDigest &&
        proofRecord.canonicalCiphertextConventionDigest ===
            contribution.canonicalCiphertextConventionDigest &&
        proofRecord.bgvPublicKeyRoot === contribution.bgvPublicKeyRoot &&
        proofRecord.collectivePublicKeyRoot ===
            contribution.collectivePublicKeyRoot &&
        proofRecord.aggregateSelectionPolicyDigest ===
            contribution.aggregateSelectionPolicyDigest &&
        proofRecord.postVotingClosedContextDigest ===
            contribution.postVotingClosedContextDigest &&
        proofRecord.ceremonyId === contribution.ceremonyId &&
        proofRecord.manifestDigest === contribution.manifestDigest &&
        proofRecord.rosterDigest === contribution.rosterDigest &&
        proofRecord.pollSpecDigest === contribution.pollSpecDigest &&
        proofRecord.thresholdProfileDigest ===
            contribution.thresholdProfileDigest &&
        proofRecord.ballotSetDigest === contribution.ballotSetDigest &&
        proofRecord.votingClosedBoardHeadDigest ===
            contribution.votingClosedBoardHeadDigest &&
        proofRecord.contributorIdentity === contribution.contributorIdentity &&
        proofRecord.contributorRosterPosition ===
            contribution.contributorRosterPosition &&
        proofRecord.contributorRosterExternalAcceptanceDigest ===
            contribution.contributorRosterExternalAcceptanceDigest
    );
};

const actionContextMatchesContribution = (
    contribution: AggregateContribution,
): boolean =>
    protocolDigestPattern.test(
        contribution.actionContext.actionContextDigest,
    ) &&
    contribution.actionContext.ceremonyId === contribution.ceremonyId &&
    contribution.actionContext.electionManifestDigest ===
        contribution.manifestDigest &&
    contribution.actionContext.signerIdentity ===
        contribution.contributorIdentity &&
    contribution.actionContext.boardHeadDigest ===
        contribution.votingClosedBoardHeadDigest &&
    contribution.actionContext.boardSequence === contribution.boardSequence &&
    contribution.actionContext.recoveryEpoch === contribution.recoveryEpoch &&
    contribution.actionContext.deviceEpoch === contribution.deviceEpoch &&
    contribution.actionContext.actionSequence === contribution.actionSequence &&
    contribution.actionContext.rosterExternalAcceptanceDigest ===
        contribution.contributorRosterExternalAcceptanceDigest &&
    contribution.actionContext.contextDigest ===
        contribution.postVotingClosedContextDigest;

const collectBridgeProofRecordRefusals = (
    proofRecord: BridgeProofRecord,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [
        ...collectDigestShapeRefusals(
            proofRecord as unknown as Record<string, unknown>,
            bridgeDigestFieldNames,
            proofRecord.bridgeProofRecordDigest,
        ),
    ];
    const expectedBridgeProofProfileDigest = deriveBridgeProofProfileDigest({
        bgvEncryptionProofSubrelation:
            proofRecord.bgvEncryptionProofSubrelation,
        bridgeProofProfileId: proofRecord.bridgeProofProfileId,
        proofBackend: proofRecord.proofBackend,
    });
    const { bridgeProofRecordDigest, ...proofRecordWithoutDigest } =
        proofRecord;
    void bridgeProofRecordDigest;
    const expectedBridgeProofRecordDigest = deriveBridgeProofRecordDigest(
        proofRecordWithoutDigest,
    );

    if (
        proofRecord.objectType !== 'BridgeProofRecord' ||
        proofRecord.objectVersion !== 1 ||
        proofRecord.bridgeProofProfileId !==
            encryptedAggregateBridgeProfileId ||
        proofRecord.bridgeProofProfileDigest !==
            expectedBridgeProofProfileDigest ||
        proofRecord.proofBackend !== 'SealedLatticeBridgeRelation' ||
        !['BridgeProofBackendPending', 'BridgeProofRelationChecked'].includes(
            proofRecord.bridgeProofVerificationStatus,
        ) ||
        proofRecord.bridgeProofRecordDigest !== expectedBridgeProofRecordDigest
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Bridge proof record digest, profile, or backend status is invalid.',
                proofRecord.bridgeProofRecordDigest,
            ),
        );
    }
    if (
        !Number.isSafeInteger(proofRecord.contributorRosterPosition) ||
        proofRecord.contributorRosterPosition <= 0 ||
        !Number.isSafeInteger(proofRecord.proofSizeBytes) ||
        proofRecord.proofSizeBytes < 0
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Bridge proof record contributor position and proof size must be canonical non-negative integers.',
                proofRecord.bridgeProofRecordDigest,
            ),
        );
    }

    return refusedObjects;
};

const requireCheckedBridgeProofRecord = (
    proofRecord: BridgeProofRecord,
): void => {
    const refusedObjects = collectBridgeProofRecordRefusals(proofRecord);
    if (refusedObjects.length > 0) {
        throw new RangeError(
            `Aggregate contribution requires a structurally valid bridge proof record: ${refusedObjects[0]?.message ?? 'invalid bridge proof record'}`,
        );
    }
    if (
        proofRecord.bridgeProofVerificationStatus !==
        'BridgeProofRelationChecked'
    ) {
        throw new RangeError(
            'Aggregate contribution requires a proof-checked bridge proof record.',
        );
    }
};

const actionContextMatchesBridgeProofRecord = (
    actionContext: ActionContext,
    proofRecord: BridgeProofRecord,
): boolean =>
    protocolDigestPattern.test(actionContext.actionContextDigest) &&
    actionContext.ceremonyId === proofRecord.ceremonyId &&
    actionContext.electionManifestDigest === proofRecord.manifestDigest &&
    actionContext.signerIdentity === proofRecord.contributorIdentity &&
    actionContext.boardHeadDigest === proofRecord.votingClosedBoardHeadDigest &&
    actionContext.contextDigest === proofRecord.postVotingClosedContextDigest &&
    actionContext.rosterExternalAcceptanceDigest ===
        proofRecord.contributorRosterExternalAcceptanceDigest &&
    Number.isSafeInteger(actionContext.boardSequence) &&
    actionContext.boardSequence >= 0 &&
    Number.isSafeInteger(actionContext.recoveryEpoch) &&
    actionContext.recoveryEpoch >= 0 &&
    Number.isSafeInteger(actionContext.deviceEpoch) &&
    actionContext.deviceEpoch >= 0 &&
    Number.isSafeInteger(actionContext.actionSequence) &&
    actionContext.actionSequence >= 0;

const signatureEnvelopeMatchesContributionContext = (
    signature: ProtocolSignatureEnvelope,
    contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest'
    >,
): boolean =>
    signature.signedRoot.objectType === 'AggregateContribution' &&
    signature.signedRoot.objectVersion === 1 &&
    signature.signedRoot.ceremonyId === contributionPayload.ceremonyId &&
    signature.signedRoot.manifestDigest ===
        contributionPayload.manifestDigest &&
    signature.signedRoot.boardHeadDigest ===
        contributionPayload.votingClosedBoardHeadDigest &&
    signature.signedRoot.signerRole === 'Trustee' &&
    signature.signedRoot.signerIdentity ===
        contributionPayload.contributorIdentity &&
    signature.signedRoot.recoveryEpoch === contributionPayload.recoveryEpoch &&
    signature.signedRoot.deviceEpoch === contributionPayload.deviceEpoch &&
    signature.signedRoot.contextDigest ===
        contributionPayload.postVotingClosedContextDigest;

export function verifyAggregateContributionStructure(
    contribution: AggregateContribution,
): AggregateContributionVerification {
    const contributionDigest = contribution.aggregateContributionDigest;
    const { aggregateContributionDigest, ...contributionWithoutDigest } =
        contribution;
    void aggregateContributionDigest;
    const expectedContributionDigest = deriveAggregateContributionDigest(
        contributionWithoutDigest,
    );
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            contribution,
            contributionDigest,
            'contribution',
        ),
        ...collectDigestShapeRefusals(
            contribution as unknown as Record<string, unknown>,
            contributionDigestFieldNames,
            contributionDigest,
        ),
        ...collectBridgeProofRecordRefusals(contribution.bridgeProofRecord),
    ];

    if (
        contribution.objectType !== 'AggregateContribution' ||
        contribution.objectVersion !== 1 ||
        contribution.aggregateContributionDigest !==
            expectedContributionDigest ||
        contribution.bridgeProofRecordDigest !==
            contribution.bridgeProofRecord.bridgeProofRecordDigest ||
        !bridgeProofPublicFieldsMatchContribution(contribution) ||
        !actionContextMatchesContribution(contribution) ||
        !Number.isSafeInteger(contribution.contributorRosterPosition) ||
        contribution.contributorRosterPosition <= 0 ||
        !Number.isSafeInteger(contribution.boardSequence) ||
        contribution.boardSequence < 0 ||
        !Number.isSafeInteger(contribution.boardPosition) ||
        contribution.boardPosition < 0 ||
        !Number.isSafeInteger(contribution.recoveryEpoch) ||
        contribution.recoveryEpoch < 0 ||
        !Number.isSafeInteger(contribution.deviceEpoch) ||
        contribution.deviceEpoch < 0 ||
        !Number.isSafeInteger(contribution.actionSequence) ||
        contribution.actionSequence < 0
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate contribution digest, proof binding, action context, or sequence metadata is invalid.',
                contributionDigest,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedDigests: [],
            aggregateContributionDigest: contributionDigest,
            backendAvailable: false,
            bridgeProofRecordDigest:
                contribution.bridgeProofRecord.bridgeProofRecordDigest,
            ok: false,
            refusedObjects,
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'AggregateShareInvalid',
        };
    }

    const bridgeProofRelationChecked =
        contribution.bridgeProofRecord.bridgeProofVerificationStatus ===
        'BridgeProofRelationChecked';

    return {
        acceptedDigests: [
            contribution.bridgeProofRecord.bridgeProofRecordDigest,
            contribution.aggregateContributionDigest,
        ],
        aggregateContributionDigest: contributionDigest,
        backendAvailable: bridgeProofRelationChecked,
        bridgeProofRecordDigest:
            contribution.bridgeProofRecord.bridgeProofRecordDigest,
        ok: true,
        refusedObjects: [],
        statusLabels: bridgeProofRelationChecked ? [] : ['pending'],
        unresolvedReason: bridgeProofRelationChecked
            ? null
            : 'OperationUnavailable',
    };
}

export const createAggregateContributionFromBridgeProofRecord = (
    input: AggregateContributionFromBridgeProofRecordInput,
): AggregateContribution => {
    requireCheckedBridgeProofRecord(input.bridgeProofRecord);
    if (!protocolDigestPattern.test(input.closeRecordDigest)) {
        throw new RangeError(
            'Aggregate contribution close-record digest must be a protocol digest.',
        );
    }
    if (!Number.isSafeInteger(input.boardPosition) || input.boardPosition < 0) {
        throw new RangeError(
            'Aggregate contribution board position must be a non-negative safe integer.',
        );
    }
    if (
        !actionContextMatchesBridgeProofRecord(
            input.actionContext,
            input.bridgeProofRecord,
        )
    ) {
        throw new RangeError(
            'Aggregate contribution action context does not match the bridge proof record.',
        );
    }

    const proofRecord = input.bridgeProofRecord;
    const contributionPayload: Omit<
        AggregateContribution,
        'aggregateContributionDigest'
    > = {
        actionContext: input.actionContext,
        actionSequence: input.actionContext.actionSequence,
        aggregateDerivationComponentDigest:
            proofRecord.aggregateDerivationComponentDigest,
        aggregateSelectionPolicyDigest:
            proofRecord.aggregateSelectionPolicyDigest,
        aggregateShareCommitmentDigest:
            proofRecord.aggregateShareCommitmentDigest,
        aggregateInputEncodingProfileDigest:
            proofRecord.aggregateInputEncodingProfileDigest,
        ballotScoreEncodingProfileDigest:
            proofRecord.ballotScoreEncodingProfileDigest,
        ballotSetDigest: proofRecord.ballotSetDigest,
        ballotShareLayoutProfileDigest:
            proofRecord.ballotShareLayoutProfileDigest,
        bgvBatchEncoderDigest: proofRecord.bgvBatchEncoderDigest,
        bgvProfileDigest: proofRecord.bgvProfileDigest,
        bgvPublicKeyRoot: proofRecord.bgvPublicKeyRoot,
        boardPosition: input.boardPosition,
        boardSequence: input.actionContext.boardSequence,
        bridgeLayoutDigest: proofRecord.bridgeLayoutDigest,
        bridgeProofProfileDigest: proofRecord.bridgeProofProfileDigest,
        bridgeProofRecord: proofRecord,
        bridgeProofRecordDigest: proofRecord.bridgeProofRecordDigest,
        bridgeWitnessPrivacyProfileDigest:
            proofRecord.bridgeWitnessPrivacyProfileDigest,
        canonicalCiphertextConventionDigest:
            proofRecord.canonicalCiphertextConventionDigest,
        ceremonyId: proofRecord.ceremonyId,
        closeRecordDigest: input.closeRecordDigest,
        collectivePublicKeyRoot: proofRecord.collectivePublicKeyRoot,
        contributorIdentity: proofRecord.contributorIdentity,
        contributorRosterExternalAcceptanceDigest:
            proofRecord.contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: proofRecord.contributorRosterPosition,
        deviceEpoch: input.actionContext.deviceEpoch,
        encodedAggregateLayoutDigest: proofRecord.encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            proofRecord.encodedShareVectorLayoutDigest,
        encryptedAggregateBridgeDigest:
            proofRecord.encryptedAggregateBridgeDigest,
        encryptedAggregateInputLayoutDigest:
            proofRecord.encryptedAggregateInputLayoutDigest,
        encryptedAggregateReconstructionDigest:
            proofRecord.encryptedAggregateReconstructionDigest,
        encryptedAggregateShareCiphertextRoot:
            proofRecord.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisDataRoot:
            proofRecord.encryptedAggregateTargetBasisDataRoot,
        heParamDigest: proofRecord.heParamDigest,
        manifestDigest: proofRecord.manifestDigest,
        objectType: 'AggregateContribution',
        objectVersion: 1,
        pollSpecDigest: proofRecord.pollSpecDigest,
        postVotingClosedContextDigest:
            proofRecord.postVotingClosedContextDigest,
        recoveryEpoch: input.actionContext.recoveryEpoch,
        rosterDigest: proofRecord.rosterDigest,
        rustBgvBackendProfileDigest: proofRecord.rustBgvBackendProfileDigest,
        shareCommitmentMessageBoundCertDigest:
            proofRecord.shareCommitmentMessageBoundCertDigest,
        signature: input.signature,
        thresholdProfileDigest: proofRecord.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest:
            proofRecord.topKEvaluatorInputLayoutDigest,
        votingClosedBoardHeadDigest: proofRecord.votingClosedBoardHeadDigest,
    };

    if (
        !signatureEnvelopeMatchesContributionContext(
            input.signature,
            contributionPayload,
        )
    ) {
        throw new RangeError(
            'Aggregate contribution signature envelope does not match the contribution context.',
        );
    }

    const contribution = {
        ...contributionPayload,
        aggregateContributionDigest:
            deriveAggregateContributionDigest(contributionPayload),
    };
    const verification = verifyAggregateContributionStructure(contribution);
    if (!verification.ok || !verification.backendAvailable) {
        throw new RangeError(
            `Aggregate contribution assembled from a checked bridge proof did not verify: ${verification.unresolvedReason ?? 'unknown refusal'}`,
        );
    }

    return contribution;
};

const deriveSelectedAggregateContributionOrderDigest = (input: {
    readonly requiredPostVotingClosedContextDigest: ProtocolDigest;
    readonly selectedContributions: readonly AggregateContribution[];
    readonly selectionPolicyDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('FirstValidOrderDigest', {
        orderedObjectDigests: input.selectedContributions.map(
            (contribution) => contribution.aggregateContributionDigest,
        ),
        purpose: 'm9-selected-aggregate-contribution-order-v1',
        requiredContextDigest: input.requiredPostVotingClosedContextDigest,
        selectionPolicyDigest: input.selectionPolicyDigest,
    });

export const selectFirstValidAggregateContributions = (
    input: AggregateContributionSelectionInput,
): AggregateContributionSelection => {
    const refusedObjects: RefusalRecord[] = [];
    if (
        !Number.isSafeInteger(input.aggregateContributionQuorum) ||
        input.aggregateContributionQuorum <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'Aggregate contribution quorum must be a positive safe integer.',
                input.expectedAggregateSelectionPolicyDigest,
            ),
        );
    }
    const structurallyValidContributions = input.contributions.filter(
        (contribution) => {
            const verification =
                verifyAggregateContributionStructure(contribution);
            if (!verification.ok) {
                refusedObjects.push(...verification.refusedObjects);
                return false;
            }
            if (
                contribution.bridgeProofRecord.bridgeProofVerificationStatus !==
                'BridgeProofRelationChecked'
            ) {
                refusedObjects.push(
                    createRefusal(
                        'OperationUnavailable',
                        'Aggregate contribution is not proof-valid for the supported bridge relation.',
                        contribution.aggregateContributionDigest,
                        'AggregateContribution',
                    ),
                );
                return false;
            }

            return true;
        },
    );
    const firstValidOrdering = deriveValidatedFirstValidOrder({
        currentRecoveryEpochMap: input.currentRecoveryEpochMap,
        expectedSelectionPolicyDigest:
            input.expectedAggregateSelectionPolicyDigest,
        maxPerIdentity: 1,
        objects: structurallyValidContributions.map((contribution) => ({
            actionSequence: contribution.actionSequence,
            boardPosition: contribution.boardPosition,
            boardSequence: contribution.boardSequence,
            contextDigest: contribution.postVotingClosedContextDigest,
            deviceEpoch: contribution.deviceEpoch,
            isByteIdenticalRetransmission: false,
            objectDigest: contribution.aggregateContributionDigest,
            objectType: 'AggregateContribution',
            recoveryEpoch: contribution.recoveryEpoch,
            signerIdentity: contribution.contributorIdentity,
        })),
        requiredContextDigest: input.requiredPostVotingClosedContextDigest,
        selectionPolicyDigest: input.expectedAggregateSelectionPolicyDigest,
    });
    refusedObjects.push(...firstValidOrdering.refusedObjects);

    const contributionByDigest = new Map(
        structurallyValidContributions.map((contribution) => [
            contribution.aggregateContributionDigest,
            contribution,
        ]),
    );
    const orderedContributions = firstValidOrdering.orderedObjects.flatMap(
        (orderedObject) => {
            const contribution = contributionByDigest.get(
                orderedObject.objectDigest,
            );

            return contribution === undefined ? [] : [contribution];
        },
    );
    const selectedContributions = orderedContributions.slice(
        0,
        input.aggregateContributionQuorum,
    );
    if (selectedContributions.length < input.aggregateContributionQuorum) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'Not enough proof-valid aggregate contributions exist for the aggregate quorum.',
                input.expectedAggregateSelectionPolicyDigest,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedDigests: [],
            firstValidOrderDigest: undefined,
            ok: false,
            orderedContributionDigests: orderedContributions.map(
                (contribution) => contribution.aggregateContributionDigest,
            ),
            refusedObjects,
            selectedContributions: [],
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'FirstValidPolicyMismatch',
        };
    }

    const firstValidOrderDigest =
        deriveSelectedAggregateContributionOrderDigest({
            requiredPostVotingClosedContextDigest:
                input.requiredPostVotingClosedContextDigest,
            selectedContributions,
            selectionPolicyDigest: input.expectedAggregateSelectionPolicyDigest,
        });

    return {
        acceptedDigests: uniqueStrings([
            firstValidOrderDigest,
            ...selectedContributions.map(
                (contribution) => contribution.aggregateContributionDigest,
            ),
        ]),
        firstValidOrderDigest,
        ok: true,
        orderedContributionDigests: orderedContributions.map(
            (contribution) => contribution.aggregateContributionDigest,
        ),
        refusedObjects: [],
        selectedContributions,
        statusLabels: [],
        unresolvedReason: null,
    };
};

const interpolationReportsMatch = (
    leftReport: InterpolationCoefficientReport,
    rightReport: InterpolationCoefficientReport,
): boolean =>
    leftReport.reportDigest === rightReport.reportDigest &&
    leftReport.centeredL1CoefficientSum ===
        rightReport.centeredL1CoefficientSum &&
    leftReport.maxCenteredAbsCoefficient ===
        rightReport.maxCenteredAbsCoefficient &&
    leftReport.rosterSize === rightReport.rosterSize &&
    leftReport.threshold === rightReport.threshold &&
    leftReport.contributorRosterPositions.length ===
        rightReport.contributorRosterPositions.length &&
    leftReport.contributorRosterPositions.every(
        (position, positionIndex) =>
            position === rightReport.contributorRosterPositions[positionIndex],
    ) &&
    leftReport.coefficients.length === rightReport.coefficients.length &&
    leftReport.coefficients.every((coefficient, coefficientIndex) => {
        const rightCoefficient = rightReport.coefficients[coefficientIndex];

        return (
            coefficient.rosterPosition === rightCoefficient?.rosterPosition &&
            coefficient.coefficient === rightCoefficient.coefficient &&
            coefficient.centeredCoefficient ===
                rightCoefficient.centeredCoefficient
        );
    });

const requireSameSelectedContext = (
    selectedContributions: readonly AggregateContribution[],
): AggregateContribution => {
    const firstContribution = selectedContributions[0];
    if (firstContribution === undefined) {
        throw new RangeError(
            'Aggregate-ready record requires at least one selected aggregate contribution.',
        );
    }
    const sharedFields = [
        'ceremonyId',
        'manifestDigest',
        'rosterDigest',
        'pollSpecDigest',
        'thresholdProfileDigest',
        'ballotSetDigest',
        'votingClosedBoardHeadDigest',
        'postVotingClosedContextDigest',
        'aggregateSelectionPolicyDigest',
        'encryptedAggregateBridgeDigest',
        'encryptedAggregateTargetBasisDataRoot',
        'encryptedAggregateReconstructionDigest',
        'bridgeWitnessPrivacyProfileDigest',
        'bgvBatchEncoderDigest',
        'bridgeLayoutDigest',
        'encryptedAggregateInputLayoutDigest',
        'topKEvaluatorInputLayoutDigest',
        'bgvProfileDigest',
        'collectivePublicKeyRoot',
    ] as const;

    for (const contribution of selectedContributions) {
        for (const sharedField of sharedFields) {
            if (contribution[sharedField] !== firstContribution[sharedField]) {
                throw new RangeError(
                    `Aggregate-ready selected contributions must agree on ${sharedField}.`,
                );
            }
        }
    }

    return firstContribution;
};

export const createAggregateReadyRecord = (
    input: AggregateReadyRecordBuildInput,
): AggregateReadyRecord => {
    if (
        input.selectedContributions.length !==
            input.aggregateContributionQuorum ||
        input.aggregateContributionQuorum <= 0
    ) {
        throw new RangeError(
            'Aggregate-ready record requires exactly the aggregate contribution quorum.',
        );
    }
    for (const contribution of input.selectedContributions) {
        const verification = verifyAggregateContributionStructure(contribution);
        if (!verification.ok) {
            throw new RangeError(
                'Aggregate-ready record requires structurally valid selected aggregate contributions.',
            );
        }
        if (
            contribution.bridgeProofRecord.bridgeProofVerificationStatus !==
            'BridgeProofRelationChecked'
        ) {
            throw new RangeError(
                'Aggregate-ready record requires proof-checked selected aggregate contributions.',
            );
        }
    }
    const firstContribution = requireSameSelectedContext(
        input.selectedContributions,
    );
    const selectedContributorRosterPositions = input.selectedContributions.map(
        (contribution) => contribution.contributorRosterPosition,
    );
    const interpolationCoefficientReport = deriveInterpolationCoefficientReport(
        {
            contributorRosterPositions: selectedContributorRosterPositions,
            rosterSize: input.rosterSize,
            threshold: input.aggregateContributionQuorum,
        },
    );
    if (
        input.suppliedInterpolationCoefficientReport !== undefined &&
        !interpolationReportsMatch(
            input.suppliedInterpolationCoefficientReport,
            interpolationCoefficientReport,
        )
    ) {
        throw new RangeError(
            'Supplied aggregate interpolation coefficient report does not match recomputation.',
        );
    }
    const selectedAggregateContributionDigests =
        input.selectedContributions.map(
            (contribution) => contribution.aggregateContributionDigest,
        );
    const encryptedAggregateShareCiphertextRoots =
        input.selectedContributions.map(
            (contribution) =>
                contribution.encryptedAggregateShareCiphertextRoot,
        );
    const encryptedAggregateReconstructionRoot =
        deriveEncryptedAggregateReconstructionRoot({
            aggregateSelectionPolicyDigest:
                firstContribution.aggregateSelectionPolicyDigest,
            encryptedAggregateReconstructionDigest:
                firstContribution.encryptedAggregateReconstructionDigest,
            encryptedAggregateShareCiphertextRoots,
            firstValidOrderDigest: input.firstValidOrderDigest,
            interpolationCoefficientReportDigest:
                interpolationCoefficientReport.reportDigest,
            selectedAggregateContributionDigests,
        });
    const recordPayload: Omit<
        AggregateReadyRecord,
        'aggregateReadyRecordDigest'
    > = {
        aggregateContributionQuorum: input.aggregateContributionQuorum,
        aggregateSelectionPolicyDigest:
            firstContribution.aggregateSelectionPolicyDigest,
        ballotSetDigest: firstContribution.ballotSetDigest,
        bgvBatchEncoderDigest: firstContribution.bgvBatchEncoderDigest,
        bgvProfileDigest: firstContribution.bgvProfileDigest,
        bridgeLayoutDigest: firstContribution.bridgeLayoutDigest,
        bridgeWitnessPrivacyProfileDigest:
            firstContribution.bridgeWitnessPrivacyProfileDigest,
        centeredL1CoefficientSum:
            interpolationCoefficientReport.centeredL1CoefficientSum,
        ceremonyId: firstContribution.ceremonyId,
        collectivePublicKeyRoot: firstContribution.collectivePublicKeyRoot,
        encryptedAggregateBridgeDigest:
            firstContribution.encryptedAggregateBridgeDigest,
        encryptedAggregateInputLayoutDigest:
            firstContribution.encryptedAggregateInputLayoutDigest,
        encryptedAggregateReconstructionDigest:
            firstContribution.encryptedAggregateReconstructionDigest,
        encryptedAggregateReconstructionRoot,
        encryptedAggregateShareCiphertextRoots,
        encryptedAggregateTargetBasisDataRoot:
            firstContribution.encryptedAggregateTargetBasisDataRoot,
        firstValidOrderDigest: input.firstValidOrderDigest,
        interpolationCoefficientReportDigest:
            interpolationCoefficientReport.reportDigest,
        interpolationCoefficients: interpolationCoefficientReport.coefficients,
        manifestDigest: firstContribution.manifestDigest,
        maxCenteredAbsCoefficient:
            interpolationCoefficientReport.maxCenteredAbsCoefficient,
        objectType: 'AggregateReadyRecord',
        objectVersion: 1,
        pollSpecDigest: firstContribution.pollSpecDigest,
        postVotingClosedContextDigest:
            firstContribution.postVotingClosedContextDigest,
        rosterDigest: firstContribution.rosterDigest,
        selectedAggregateContributionDigests,
        selectedContributorIdentities: input.selectedContributions.map(
            (contribution) => contribution.contributorIdentity,
        ),
        selectedContributorInterpolationPoints:
            interpolationCoefficientReport.contributorRosterPositions,
        selectedContributorRosterPositions,
        thresholdProfileDigest: firstContribution.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest:
            firstContribution.topKEvaluatorInputLayoutDigest,
        votingClosedBoardHeadDigest:
            firstContribution.votingClosedBoardHeadDigest,
    };

    return {
        ...recordPayload,
        aggregateReadyRecordDigest:
            deriveAggregateReadyRecordDigest(recordPayload),
    };
};
