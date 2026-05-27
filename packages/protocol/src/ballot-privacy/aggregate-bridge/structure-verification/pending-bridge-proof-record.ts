import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type BridgeProofRecord,
    type ProtocolDigest,
} from '@sealed-lattice/types';

import {
    deriveBridgeProofProfileDigest,
    deriveBridgeProofRecordDigest,
    deriveBridgeProofStatementDigest,
    deriveBridgeProofTargetContractDigest,
} from '../digests.js';

import {
    aggregateRelationChallengeHexPattern,
    bridgeProofByteLength,
    hash512HexPattern,
    requireMatchingSafeInteger,
    requireMatchingValue,
    requireProtocolDigest,
    requireProtocolDigestField,
    type BridgeEncryptionEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from './shared.js';

const derivePendingBridgeProofEncodingProfileDigest = (input: {
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        ...input,
        purpose:
            'sealed-lattice-pending-bridge-proof-evidence-encoding-profile-v1',
    });

const derivePendingBridgeProofParameterSetDigest = (input: {
    readonly bgvProfileDigest: ProtocolDigest;
    readonly bridgeProofProfileDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
    readonly collectivePublicKeyRoot: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        ...input,
        purpose: 'sealed-lattice-pending-bridge-proof-parameter-set-v1',
    });

const derivePendingBridgeProofPublicRandomnessDigest = (input: {
    readonly bridgeProofBytesDigest: ProtocolDigest;
    readonly bridgeProofStatementDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ProofBytesDigest', {
        ...input,
        purpose: 'sealed-lattice-pending-bridge-proof-public-randomness-v1',
    });

const deriveSampledPublicRelationCheckPolicyDigest = (
    policy: BridgeEncryptionEvidence['sampledPublicRelationCheckPolicy'],
): ProtocolDigest =>
    deriveProtocolDigest('BridgeProofRecordDigest', {
        policy,
        purpose:
            'sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1',
    });

export const createPendingBridgeProofRecordFromBridgeEvidence = (
    input: PendingBridgeProofRecordFromEvidenceInput,
): BridgeProofRecord => {
    const { aggregateDerivationComponent, bridgeEncryptionEvidence } = input;
    const { statement } = aggregateDerivationComponent;
    const { profileBindings } = input.setupPackage;
    const bridgeProofProfileDigest = deriveBridgeProofProfileDigest({
        bgvEncryptionProofSubrelation:
            'SealedLatticeDevelopmentCiphertextEquationRelation',
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
        'AggregateBridgeSampledRelationCheckPolicy',
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
    const encryptedAggregateInputRoot = requireProtocolDigest(
        bridgeEncryptionEvidence.encryptedAggregateInputRoot,
        'encrypted aggregate input root',
    );
    requireMatchingValue(
        encryptedAggregateInputRoot,
        bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        'prototype encrypted aggregate input root',
    );
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
                'AggregateToPlaintextBindingProofChecked',
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
            bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
            bgvProfileDigest: profileDigest,
            bgvPublicKeyRoot:
                input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
            bgvRandomnessBoundProofStatus: 'BgvRandomnessBoundProofMissing',
            bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
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
            optionCount: statement.optionCount,
            participantCount: statement.participantCount,
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
            encryptedAggregateInputRoot,
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
            rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
            rosterDigest: statement.rosterDigest,
            rustBgvBackendProfileDigest,
            sampledPublicRelationCheckPolicyDigest,
            sampledOnlyBridgeVerificationAccepted: false,
            setupPackageDigest: requireProtocolDigest(
                input.setupPackage.setupPackageDigest,
                'setup package digest',
            ),
            shareCommitmentMessageBoundCertDigest:
                statement.shareCommitmentMessageBoundCertDigest,
            shareVectorWidth: statement.shareVectorWidth,
            sharedWitnessBindingRequired: true,
            sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
            sharedWitnessChallengeBitsPerCheck: 64,
            sharedWitnessCheckCount: 2,
            sharedWitnessSoundnessBits: 128,
            sharedWitnessZeroKnowledgeStatus:
                'SharedWitnessZeroKnowledgeProofMissing',
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
        'BridgeProofRelationChecked',
        'checked bridge proof status',
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
    requireMatchingSafeInteger(
        input.setupPackage.setupInputs.participantCount,
        statement.participantCount,
        'setup participant count',
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
            'encrypted aggregate input root',
            bridgeEncryptionEvidence.encryptedAggregateInputRoot,
            input.bridgeEvidenceVerification.encryptedAggregateInputRoot,
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
        'BridgeProofRelationChecked',
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
        bgvEncryptionProofSubrelation:
            'SealedLatticeDevelopmentCiphertextEquationRelation',
        bgvProfileDigest: profileDigest,
        bgvPublicKeyRoot: bridgeEncryptionEvidence.bgvPublicKeyRoot,
        bridgeLayoutDigest: encryptedAggregateInputLayoutDigest,
        bridgeProofProfileDigest,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofTargetContractDigest,
        bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
        bridgeWitnessPrivacyProfileDigest: requireProtocolDigest(
            input.bridgeWitnessPrivacyProfileDigest,
            'bridge witness privacy profile digest',
        ),
        canonicalCiphertextConventionDigest,
        ceremonyId: statement.ceremonyId,
        collectivePublicKeyRoot:
            bridgeEncryptionEvidence.collectivePublicKeyRoot,
        contributorIdentity: statement.contributorIdentity,
        contributorActionContextDigest:
            statement.contributorActionContextDigest,
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
        encryptedAggregateInputRoot,
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
        participantCount: statement.participantCount,
        optionCount: statement.optionCount,
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
        setupPackageDigest: requireProtocolDigest(
            input.setupPackage.setupPackageDigest,
            'setup package digest',
        ),
        shareCommitmentMessageBoundCertDigest:
            statement.shareCommitmentMessageBoundCertDigest,
        shareVectorWidth: statement.shareVectorWidth,
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
