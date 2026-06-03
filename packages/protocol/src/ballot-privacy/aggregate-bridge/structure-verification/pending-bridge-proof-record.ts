import { deriveProtocolHash } from '@sealed-lattice/crypto';
import {
    encryptedAggregateBridgeProfileId,
    type BridgeClaimVerificationStatus,
    type BridgeProofRecord,
    type ProtocolHash,
} from '@sealed-lattice/types';

import {
    deriveBridgeProofChallengeContextHash,
    deriveBridgeProofProfileHash,
    deriveBridgeProofRecordHash,
    deriveBridgeProofStatementHash,
} from '../hashes.js';

import {
    aggregateRelationChallengeHexPattern,
    bridgeProofByteLength,
    hash512HexPattern,
    requireMatchingSafeInteger,
    requireMatchingValue,
    requireProtocolHash,
    requireProtocolHashField,
    type BridgeEncryptionEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from './shared.js';

const derivePendingBridgeProofEncodingProfileHash = (input: {
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofChallengeContextHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        ...input,
        purpose:
            'sealed-lattice-pending-bridge-proof-evidence-encoding-profile-v1',
    });

const derivePendingBridgeProofParameterSetHash = (input: {
    readonly bgvProfileHash: ProtocolHash;
    readonly bridgeProofChallengeContextHash: ProtocolHash;
    readonly bridgeProofProfileHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
    readonly collectivePublicKeyRoot: ProtocolHash;
    readonly collectivePublicKeyCoefficientRoot: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        ...input,
        purpose: 'sealed-lattice-pending-bridge-proof-parameter-set-v1',
    });

const derivePendingBridgeProofPublicRandomnessHash = (input: {
    readonly bridgeProofBytesHash: ProtocolHash;
    readonly bridgeProofChallengeContextHash: ProtocolHash;
    readonly bridgeProofStatementHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('ProofBytesHash', {
        ...input,
        purpose: 'sealed-lattice-pending-bridge-proof-public-randomness-v1',
    });

const deriveSampledPublicRelationCheckPolicyHash = (
    policy: BridgeEncryptionEvidence['sampledPublicRelationCheckPolicy'],
): ProtocolHash =>
    deriveProtocolHash('BridgeProofRecordHash', {
        policy,
        purpose:
            'sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1',
    });

const bridgeRandomnessSourceValues = [
    'fresh-csprng',
    'development-deterministic-fixture',
] as const;

const requireBridgeRandomnessSource = (
    value: unknown,
    description: string,
): void => {
    if (
        !bridgeRandomnessSourceValues.some(
            (randomnessSource) => randomnessSource === value,
        )
    ) {
        throw new RangeError(
            `Bridge proof record evidence mismatch for ${description}.`,
        );
    }
};

const requireConsistentBridgeClaimStatus = (input: {
    readonly bridgeClaimClosureVerified?: boolean;
    readonly bridgeClaimVerificationStatus?: BridgeClaimVerificationStatus;
    readonly claimBearingBridgeEncryption: boolean;
}): {
    readonly bridgeClaimClosureVerified: boolean;
    readonly bridgeClaimVerificationStatus: BridgeClaimVerificationStatus;
    readonly claimBearingBridgeEncryption: boolean;
} => {
    const bridgeClaimClosureVerified =
        input.bridgeClaimClosureVerified ?? false;
    const bridgeClaimVerificationStatus =
        input.bridgeClaimVerificationStatus ?? 'BridgeProofClaimClosureMissing';

    if (
        input.claimBearingBridgeEncryption ||
        bridgeClaimClosureVerified ||
        bridgeClaimVerificationStatus !== 'BridgeProofClaimClosureMissing'
    ) {
        throw new RangeError(
            'Bridge proof record evidence cannot claim final bridge closure.',
        );
    }

    return {
        bridgeClaimClosureVerified,
        bridgeClaimVerificationStatus,
        claimBearingBridgeEncryption: false,
    };
};

export const createPendingBridgeProofRecordFromBridgeEvidence = (
    input: PendingBridgeProofRecordFromEvidenceInput,
): BridgeProofRecord => {
    const { aggregateDerivationComponent, bridgeEncryptionEvidence } = input;
    const bridgeClaimStatus = requireConsistentBridgeClaimStatus(
        bridgeEncryptionEvidence,
    );
    const { statement } = aggregateDerivationComponent;
    const { profileBindings } = input.setupPackage;
    const bridgeProofProfileHash = deriveBridgeProofProfileHash({
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofSubrelation:
            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        claimBearingBridgeEncryption:
            bridgeClaimStatus.claimBearingBridgeEncryption,
        developmentKeyOnly: false,
        proofBackend: 'SealedLatticeBridgeRelation',
        thresholdDecryptable: true,
    });
    const profileHash = requireProtocolHashField(
        profileBindings,
        'profileHash',
        'setupPackage.profileBindings',
    );
    const rustBgvBackendProfileHash = requireProtocolHashField(
        profileBindings,
        'backendProfileHash',
        'setupPackage.profileBindings',
    );
    const canonicalCiphertextConventionHash = requireProtocolHashField(
        profileBindings,
        'canonicalCiphertextConventionHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateInputLayoutHash = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateInputLayoutHash',
        'setupPackage.profileBindings',
    );
    const aggregateInputEncodingProfileHash = requireProtocolHashField(
        profileBindings,
        'aggregateInputEncodingProfileHash',
        'setupPackage.profileBindings',
    );
    const ballotScoreEncodingProfileHash = requireProtocolHashField(
        profileBindings,
        'ballotScoreEncodingProfileHash',
        'setupPackage.profileBindings',
    );
    const ballotShareLayoutProfileHash = requireProtocolHashField(
        profileBindings,
        'ballotShareLayoutProfileHash',
        'setupPackage.profileBindings',
    );
    const bgvBatchEncoderHash = requireProtocolHashField(
        profileBindings,
        'batchEncoderHash',
        'setupPackage.profileBindings',
    );
    const encodedAggregateLayoutHash = requireProtocolHashField(
        profileBindings,
        'encodedAggregateLayoutHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateBridgeHash = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateBridgeHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateReconstructionHash = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateReconstructionHash',
        'setupPackage.profileBindings',
    );
    const encryptedAggregateTargetBasisRoot = requireProtocolHashField(
        profileBindings,
        'encryptedAggregateTargetBasisRoot',
        'setupPackage.profileBindings',
    );
    const topKEvaluatorInputLayoutHash = requireProtocolHashField(
        profileBindings,
        'topKEvaluatorInputLayoutHash',
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
    const sampledPublicRelationCheckPolicyHash =
        deriveSampledPublicRelationCheckPolicyHash(
            sampledPublicRelationCheckPolicy,
        );
    const aggregateDerivationVerificationScope =
        bridgeEncryptionEvidence.aggregateDerivationVerificationScope ??
        'AggregateDerivationFullVerificationPreconditionNotBound';
    const bridgeProofTargetContractHash = requireProtocolHash(
        bridgeEncryptionEvidence.bridgeProofTargetContractHash,
        'bridge proof target contract hash',
    );
    const bridgeSharedWitnessProofHash = requireProtocolHash(
        bridgeEncryptionEvidence.bridgeSharedWitnessProofHash,
        'shared-witness proof hash',
    );
    const verifiedBridgeSharedWitnessProofHash = requireProtocolHash(
        input.bridgeEvidenceVerification.bridgeSharedWitnessProofHash,
        'verified shared-witness proof hash',
    );
    const sharedWitnessZeroKnowledgeStatusHash = requireProtocolHash(
        bridgeEncryptionEvidence.sharedWitnessZeroKnowledgeStatusHash,
        'shared-witness zero-knowledge status hash',
    );
    const verifiedSharedWitnessZeroKnowledgeStatusHash = requireProtocolHash(
        input.bridgeEvidenceVerification.sharedWitnessZeroKnowledgeStatusHash,
        'verified shared-witness zero-knowledge status hash',
    );
    const bgvRandomnessBoundProofStatusHash = requireProtocolHash(
        bridgeEncryptionEvidence.bgvRandomnessBoundProofStatusHash,
        'BGV randomness-bound status hash',
    );
    const verifiedBgvRandomnessBoundProofStatusHash = requireProtocolHash(
        input.bridgeEvidenceVerification.bgvRandomnessBoundProofStatusHash,
        'verified BGV randomness-bound status hash',
    );
    const encryptedAggregateInputRoot = requireProtocolHash(
        bridgeEncryptionEvidence.encryptedAggregateInputRoot,
        'encrypted aggregate input root',
    );
    const aggregateBridgeRelationHandoffRoot = requireProtocolHash(
        bridgeEncryptionEvidence.aggregateBridgeRelationHandoffRoot,
        'aggregate bridge relation handoff root',
    );
    requireMatchingValue(
        aggregateBridgeRelationHandoffRoot,
        input.bridgeEvidenceVerification.aggregateBridgeRelationHandoffRoot,
        'verified aggregate bridge relation handoff root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.plaintextCoefficientBindingCommitmentHash,
        input.bridgeEvidenceVerification
            .plaintextCoefficientBindingCommitmentHash,
        'verified plaintext coefficient binding commitment hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.proofFriendlyPlaintextLiftBindingHash,
        input.bridgeEvidenceVerification.proofFriendlyPlaintextLiftBindingHash,
        'verified proof-friendly plaintext lift binding hash',
    );
    requireMatchingValue(
        encryptedAggregateInputRoot,
        bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        'prototype encrypted aggregate input root',
    );
    const expectedBridgeProofStatementHash = deriveBridgeProofStatementHash({
        aggregateDerivationComponentHash:
            aggregateDerivationComponent.aggregateDerivationComponentHash,
        aggregateInputEncodingProfileHash,
        aggregateQuotientCoordinateCount: statement.shareVectorWidth,
        aggregateReducedCoordinateCount: statement.shareVectorWidth,
        aggregateSelectionPolicyHash: requireProtocolHash(
            input.aggregateSelectionPolicyHash,
            'aggregate selection policy hash',
        ),
        aggregateShareCommitmentHash:
            aggregateDerivationComponent.aggregateCommitment
                .aggregateShareCommitmentHash,
        aggregateToPlaintextBindingStatus:
            'AggregateToPlaintextModularBindingChecked',
        ballotScoreEncodingProfileHash,
        ballotSetHash: statement.ballotSetHash,
        ballotShareLayoutProfileHash,
        basisId: bridgeEncryptionEvidence.basisId,
        batchEncodingBoundCertificateHash:
            bridgeEncryptionEvidence.batchEncodingBoundCertificateHash,
        bgvBatchEncoderHash,
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
        bgvProfileHash: profileHash,
        bgvPublicKeyRoot:
            input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
        bgvRandomnessBoundProofStatus:
            'BgvRandomnessErrorSupportPolynomialChecked',
        bridgeClaimClosureStatus:
            bridgeClaimStatus.bridgeClaimVerificationStatus,
        bridgeLayoutHash: encryptedAggregateInputLayoutHash,
        bridgeProofTargetContractHash,
        bridgeWitnessPrivacyProfileHash: requireProtocolHash(
            input.bridgeWitnessPrivacyProfileHash,
            'bridge witness privacy profile hash',
        ),
        canonicalByteLength: bridgeEncryptionEvidence.canonicalByteLength,
        canonicalBytesHash512: bridgeEncryptionEvidence.canonicalBytesHash512,
        canonicalCiphertextConventionHash,
        ceremonyId: statement.ceremonyId,
        ciphertextRoot: bridgeEncryptionEvidence.ciphertextRoot,
        claimBearingBridgeEncryption:
            bridgeClaimStatus.claimBearingBridgeEncryption,
        coefficientDomainCanonical: true,
        coefficientCount: bridgeEncryptionEvidence.coefficientCount,
        collectivePublicKeyRoot:
            input.setupPackage.collectivePublicKey.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            input.setupPackage.collectivePublicKey
                .collectivePublicKeyCoefficientRoot,
        contributorActionContextHash: statement.contributorActionContextHash,
        contributorIdentity: statement.contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            statement.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: statement.contributorRosterPosition,
        developmentKeyOnly: false,
        optionCount: statement.optionCount,
        participantCount: statement.participantCount,
        encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: statement.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash,
        encryptedAggregateInputRoot,
        encryptedAggregateReconstructionHash,
        encryptedAggregateShareCiphertextRoot:
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisRoot,
        heParamHash: requireProtocolHash(
            input.heParamHash,
            'HE parameter hash',
        ),
        hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
        level: bridgeEncryptionEvidence.level,
        manifestHash: statement.manifestHash,
        aggregateDerivationVerificationScope,
        plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofChecked',
        plaintextCoefficientBindingCommitmentHash: requireProtocolHash(
            bridgeEncryptionEvidence.plaintextCoefficientBindingCommitmentHash,
            'plaintext coefficient binding commitment hash',
        ),
        plaintextEncodingBoundCertificateHash:
            bridgeEncryptionEvidence.batchEncodingBoundCertificateHash,
        plaintextEncodingProofModuli: [
            140_737_487_306_753, 140_737_486_716_929,
        ],
        plaintextEncodingProofModulusProduct: '19807040250408114080301121537',
        plaintextEncodingProofModulusProductBitsFloor: 93,
        plaintextRoot: bridgeEncryptionEvidence.plaintextRoot,
        pollSpecHash: statement.pollSpecHash,
        postVotingClosedContextHash: statement.postVotingClosedContextHash,
        proofFriendlyPlaintextBindingStatus:
            'ProofFriendlyPlaintextCoefficientBindingRelationChecked',
        proofFriendlyPlaintextLiftBindingHash: requireProtocolHash(
            bridgeEncryptionEvidence.proofFriendlyPlaintextLiftBindingHash,
            'proof-friendly plaintext lift binding hash',
        ),
        proofFriendlyPlaintextLiftBindingStatus:
            'ProofFriendlyPlaintextCoefficientLiftBindingChecked',
        proofProfileHash: bridgeProofProfileHash,
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
        rosterHash: statement.rosterHash,
        rustBgvBackendProfileHash,
        sampledPublicRelationCheckPolicyHash,
        sampledOnlyBridgeVerificationAccepted: false,
        setupPackageHash: requireProtocolHash(
            input.setupPackage.setupPackageHash,
            'setup package hash',
        ),
        shareCommitmentMessageBoundCertHash:
            statement.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: statement.shareVectorWidth,
        sharedWitnessBindingRequired: true,
        sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
        sharedWitnessChallengeBitsPerCheck: 46,
        sharedWitnessCheckCount: 5,
        sharedWitnessChallengeSamplingModel:
            'nonzero-weakest-relation-46-bit-rejection-sampled-from-64-bit-lanes-v1',
        sharedWitnessRejectionAttemptLimit: 64,
        sharedWitnessGrindingDiscountBitsPerCheck: 6,
        sharedWitnessRejectionRetryLossBits: 30,
        sharedWitnessFullMatrixUnionBoundBits: 9,
        sharedWitnessRandomOracleQueryBoundBits: 32,
        sharedWitnessRandomOracleAccountingModel:
            'classical-random-oracle-query-loss-with-explicit-bound-v1',
        sharedWitnessQromAccountingStatus:
            'QromAccountingNotProvidedForHandoff',
        sharedWitnessProofSystemLossBits: 0,
        sharedWitnessChallengeBiasAccountingModel:
            'crt-product-challenge-reduced-to-aggregate-field-with-one-bit-loss-v1',
        sharedWitnessChallengeBiasBits: 1,
        sharedWitnessAdditionalRelationLossBits: 9,
        sharedWitnessBgvSupportRelation:
            'BgvRandomnessErrorSupportPolynomialBatchRelation',
        sharedWitnessBgvSupportChallengeDistribution:
            'shared-witness-challenge-reduced-modulo-bgv-support-prime-v1',
        sharedWitnessBgvSupportCancellationModel:
            'random-linear-batched-support-cancellation-accounted-by-union-loss-v1',
        sharedWitnessBgvSupportUnionBoundBits: 9,
        sharedWitnessTargetBindingSoundnessBits: 128,
        sharedWitnessRawWeakestRelationSoundnessBitsFloor: 230,
        sharedWitnessEffectiveBindingSoundnessBitsFloor: 149,
        sharedWitnessEffectiveBindingBelowTarget: false,
        sharedWitnessWeakestRelation: 'AggregateReductionFieldRelation',
        sharedWitnessWeakestRelationModel:
            'aggregate-proof-ring-effective-binding-floor-v1',
        sharedWitnessWeakestRelationEffectiveModulus: '70368744177829',
        sharedWitnessWeakestRelationBitsPerCheck: 46,
        batchIntegerLiftProofModuli: [140_737_487_306_753, 140_737_486_716_929],
        batchIntegerLiftProofModulusProduct: '19807040250408114080301121537',
        batchIntegerLiftProofModulusProductBitsFloor: 93,
        sharedWitnessZeroKnowledgeStatus:
            'SharedWitnessZeroKnowledgeResponseDistributionChecked',
        slotCount: bridgeEncryptionEvidence.slotCount,
        thresholdProfileHash: statement.thresholdProfileHash,
        thresholdDecryptable: true,
        topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: statement.votingClosedBoardHeadHash,
    });
    const expectedBridgeProofChallengeContextHash =
        deriveBridgeProofChallengeContextHash({
            bridgeProofProfileHash,
            bridgeProofStatementHash: expectedBridgeProofStatementHash,
            bridgeProofTargetContractHash,
        });

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
        bridgeEncryptionEvidence.bgvEncryptionKeyMaterialKind,
        'passive-transcript-derived-collective-public-key',
        'BGV encryption key material kind',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.developmentKeyOnly,
        false,
        'development key-only evidence flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.thresholdDecryptable,
        true,
        'threshold-decryptable evidence flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.claimBearingBridgeEncryption,
        bridgeClaimStatus.claimBearingBridgeEncryption,
        'bridge encryption evidence claim status flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeClaimClosureVerified,
        bridgeClaimStatus.bridgeClaimClosureVerified,
        'bridge proof claim closure evidence flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeClaimVerificationStatus,
        bridgeClaimStatus.bridgeClaimVerificationStatus,
        'bridge proof claim verification evidence status',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationVerificationScope ??
            'AggregateDerivationFullVerificationPreconditionNotBound',
        aggregateDerivationVerificationScope,
        'aggregate derivation verification scope',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.plaintextCanonicalLiftProofStatus,
        'PlaintextCanonicalLiftProofChecked',
        'plaintext canonical lift proof status',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeEvidenceVerificationStatus,
        'BridgeProofEvidenceChecked',
        'bridge evidence verification label',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bgvEncryptionKeyMaterialKind,
        'passive-transcript-derived-collective-public-key',
        'verified BGV encryption key material kind',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.developmentKeyOnly,
        false,
        'verified development key-only flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.thresholdDecryptable,
        true,
        'verified threshold-decryptable flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.claimBearingBridgeEncryption,
        bridgeClaimStatus.claimBearingBridgeEncryption,
        'verified bridge encryption claim status flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeClaimClosureVerified,
        bridgeClaimStatus.bridgeClaimClosureVerified,
        'verified bridge proof claim closure flag',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeClaimVerificationStatus,
        bridgeClaimStatus.bridgeClaimVerificationStatus,
        'verified bridge proof claim verification status',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.aggregateDerivationVerificationScope ??
            'AggregateDerivationFullVerificationPreconditionNotBound',
        aggregateDerivationVerificationScope,
        'verified aggregate derivation verification scope',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.plaintextCanonicalLiftProofStatus,
        'PlaintextCanonicalLiftProofChecked',
        'verified plaintext canonical lift proof status',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationComponentHash,
        aggregateDerivationComponent.aggregateDerivationComponentHash,
        'aggregate derivation component hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.aggregateDerivationStatementHash,
        statement.aggregateDerivationStatementHash,
        'aggregate derivation statement hash',
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
    requireProtocolHash(
        bridgeEncryptionEvidence.aggregateRelationCommitmentHash,
        'aggregate relation commitment hash',
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
            .aggregateShareCommitmentHash,
        statement.aggregateShareCommitmentHash,
        'aggregate share commitment hash',
    );
    requireMatchingValue(
        aggregateDerivationComponent.shareCommitmentMessageBoundCert
            .shareCommitmentMessageBoundCertHash,
        statement.shareCommitmentMessageBoundCertHash,
        'share commitment message-bound certificate hash',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.ceremonyId,
        statement.ceremonyId,
        'ceremony id',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.manifestHash,
        statement.manifestHash,
        'manifest hash',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.rosterHash,
        statement.rosterHash,
        'roster hash',
    );
    requireMatchingValue(
        input.setupPackage.setupInputs.thresholdProfileHash,
        statement.thresholdProfileHash,
        'threshold profile hash',
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
        bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
        input.setupPackage.collectivePublicKey
            .collectivePublicKeyCoefficientRoot,
        'collective public key coefficient root',
    );
    requireBridgeRandomnessSource(
        bridgeEncryptionEvidence.proverRandomnessSource,
        'prover randomness source',
    );
    requireBridgeRandomnessSource(
        bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        'encryption randomness source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectType,
        'AggregateBridgeRandomnessSourceEvidence',
        'randomness source evidence object type',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectVersion,
        1,
        'randomness source evidence object version',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .proverRandomnessSource,
        bridgeEncryptionEvidence.proverRandomnessSource,
        'randomness source evidence prover source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .encryptionRandomnessSeedSource,
        bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        'randomness source evidence encryption source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .callerSuppliedDevelopmentRandomness,
        bridgeEncryptionEvidence.proverRandomnessSource ===
            'development-deterministic-fixture' ||
            bridgeEncryptionEvidence.encryptionRandomnessSeedSource ===
                'development-deterministic-fixture',
        'randomness source evidence development flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .claimBearingEntropyEvidence,
        false,
        'randomness source evidence claim-bearing entropy flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
        input.bridgeEvidenceVerification.collectivePublicKeyCoefficientRoot,
        'verified collective public key coefficient root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.proverRandomnessSource,
        input.bridgeEvidenceVerification.proverRandomnessSource,
        'verified prover randomness source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        input.bridgeEvidenceVerification.encryptionRandomnessSeedSource,
        'verified encryption randomness source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectType,
        input.bridgeEvidenceVerification.randomnessSourceEvidence.objectType,
        'verified randomness source evidence object type',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence.objectVersion,
        input.bridgeEvidenceVerification.randomnessSourceEvidence.objectVersion,
        'verified randomness source evidence object version',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .proverRandomnessSource,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .proverRandomnessSource,
        'verified randomness source evidence prover source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .encryptionRandomnessSeedSource,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .encryptionRandomnessSeedSource,
        'verified randomness source evidence encryption source',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .callerSuppliedDevelopmentRandomness,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .callerSuppliedDevelopmentRandomness,
        'verified randomness source evidence development flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.randomnessSourceEvidence
            .claimBearingEntropyEvidence,
        input.bridgeEvidenceVerification.randomnessSourceEvidence
            .claimBearingEntropyEvidence,
        'verified randomness source evidence claim-bearing entropy flag',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bgvPublicKeyRoot,
        input.setupPackage.collectivePublicKey.bgvPublicKeyRoot,
        'BGV public key root',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.profileHash,
        profileHash,
        'BGV profile hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.rustBgvBackendProfileHash,
        rustBgvBackendProfileHash,
        'Rust BGV backend profile hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.canonicalCiphertextConventionHash,
        canonicalCiphertextConventionHash,
        'canonical ciphertext convention hash',
    );
    for (const [description, bridgeValue, verificationValue] of [
        [
            'bridge proof profile hash',
            bridgeEncryptionEvidence.bridgeProofProfileHash,
            input.bridgeEvidenceVerification.bridgeProofProfileHash,
        ],
        [
            'bridge proof statement hash',
            bridgeEncryptionEvidence.bridgeProofStatementHash,
            input.bridgeEvidenceVerification.bridgeProofStatementHash,
        ],
        [
            'bridge proof challenge context hash',
            bridgeEncryptionEvidence.bridgeProofChallengeContextHash,
            input.bridgeEvidenceVerification.bridgeProofChallengeContextHash,
        ],
        [
            'bridge proof target contract hash',
            bridgeEncryptionEvidence.bridgeProofTargetContractHash,
            input.bridgeEvidenceVerification.bridgeProofTargetContractHash,
        ],
        [
            'bridge proof bytes hash',
            bridgeEncryptionEvidence.bridgeProofBytesHash,
            input.bridgeEvidenceVerification.bridgeProofBytesHash,
        ],
        [
            'bridge proof root',
            bridgeEncryptionEvidence.bridgeProofRoot,
            input.bridgeEvidenceVerification.bridgeProofRoot,
        ],
        [
            'shared-witness proof hash',
            bridgeSharedWitnessProofHash,
            verifiedBridgeSharedWitnessProofHash,
        ],
        [
            'shared-witness zero-knowledge status hash',
            sharedWitnessZeroKnowledgeStatusHash,
            verifiedSharedWitnessZeroKnowledgeStatusHash,
        ],
        [
            'BGV randomness-bound status hash',
            bgvRandomnessBoundProofStatusHash,
            verifiedBgvRandomnessBoundProofStatusHash,
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
            'aggregate relation commitment hash',
            bridgeEncryptionEvidence.aggregateRelationCommitmentHash,
            input.bridgeEvidenceVerification.aggregateRelationCommitmentHash,
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
        bridgeEncryptionEvidence.bridgeProofProfileHash,
        bridgeProofProfileHash,
        'canonical bridge proof profile hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofStatementHash,
        expectedBridgeProofStatementHash,
        'canonical bridge proof statement hash',
    );
    requireMatchingValue(
        bridgeEncryptionEvidence.bridgeProofChallengeContextHash,
        expectedBridgeProofChallengeContextHash,
        'canonical bridge proof challenge context hash',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeProofTargetContractHash,
        bridgeProofTargetContractHash,
        'verified bridge proof target contract hash',
    );
    requireMatchingValue(
        input.bridgeEvidenceVerification.bridgeProofVerificationStatus,
        'BridgeProofRelationChecked',
        'verification bridge proof status',
    );

    const proofEncodingProfileHash = requireProtocolHash(
        input.proofEncodingProfileHash ??
            derivePendingBridgeProofEncodingProfileHash({
                bridgeProofBytesHash:
                    bridgeEncryptionEvidence.bridgeProofBytesHash,
                bridgeProofChallengeContextHash:
                    expectedBridgeProofChallengeContextHash,
                bridgeProofProfileHash,
                bridgeProofStatementHash: expectedBridgeProofStatementHash,
            }),
        'proof encoding profile hash',
    );
    const proofParameterSetHash = requireProtocolHash(
        input.proofParameterSetHash ??
            derivePendingBridgeProofParameterSetHash({
                bgvProfileHash: profileHash,
                bridgeProofChallengeContextHash:
                    expectedBridgeProofChallengeContextHash,
                bridgeProofProfileHash,
                bridgeProofStatementHash: expectedBridgeProofStatementHash,
                collectivePublicKeyRoot:
                    bridgeEncryptionEvidence.collectivePublicKeyRoot,
                collectivePublicKeyCoefficientRoot:
                    bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
            }),
        'proof parameter set hash',
    );
    const publicRandomnessHash = requireProtocolHash(
        input.publicRandomnessHash ??
            derivePendingBridgeProofPublicRandomnessHash({
                bridgeProofBytesHash:
                    bridgeEncryptionEvidence.bridgeProofBytesHash,
                bridgeProofChallengeContextHash:
                    expectedBridgeProofChallengeContextHash,
                bridgeProofStatementHash: expectedBridgeProofStatementHash,
            }),
        'public randomness hash',
    );
    const bridgeProofRecordPayload: Omit<
        BridgeProofRecord,
        'bridgeProofRecordHash'
    > = {
        aggregateDerivationComponentHash:
            aggregateDerivationComponent.aggregateDerivationComponentHash,
        aggregateDerivationStatementHash:
            statement.aggregateDerivationStatementHash,
        aggregateSelectionPolicyHash: requireProtocolHash(
            input.aggregateSelectionPolicyHash,
            'aggregate selection policy hash',
        ),
        aggregateBridgeRelationHandoffRoot,
        aggregateShareCommitmentHash:
            aggregateDerivationComponent.aggregateCommitment
                .aggregateShareCommitmentHash,
        aggregateDerivationVerificationScope,
        aggregateInputEncodingProfileHash,
        ballotScoreEncodingProfileHash,
        ballotSetHash: statement.ballotSetHash,
        ballotShareLayoutProfileHash,
        bgvBatchEncoderHash,
        bgvEncryptionKeyMaterialKind:
            'passive-transcript-derived-collective-public-key',
        bgvEncryptionProofSubrelation:
            'SealedLatticePassiveCollectiveCiphertextEquationRelation',
        bgvProfileHash: profileHash,
        bgvPublicKeyRoot: bridgeEncryptionEvidence.bgvPublicKeyRoot,
        bridgeLayoutHash: encryptedAggregateInputLayoutHash,
        bridgeProofProfileHash,
        bridgeProofProfileId: encryptedAggregateBridgeProfileId,
        bridgeProofChallengeContextHash:
            expectedBridgeProofChallengeContextHash,
        bridgeProofTargetContractHash,
        bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
        bridgeWitnessPrivacyProfileHash: requireProtocolHash(
            input.bridgeWitnessPrivacyProfileHash,
            'bridge witness privacy profile hash',
        ),
        bridgeClaimClosureVerified:
            bridgeClaimStatus.bridgeClaimClosureVerified,
        bridgeClaimVerificationStatus:
            bridgeClaimStatus.bridgeClaimVerificationStatus,
        claimBearingBridgeEncryption:
            bridgeClaimStatus.claimBearingBridgeEncryption,
        canonicalCiphertextConventionHash,
        ceremonyId: statement.ceremonyId,
        collectivePublicKeyRoot:
            bridgeEncryptionEvidence.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            bridgeEncryptionEvidence.collectivePublicKeyCoefficientRoot,
        contributorIdentity: statement.contributorIdentity,
        contributorActionContextHash: statement.contributorActionContextHash,
        contributorRosterExternalAcceptanceHash:
            statement.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: statement.contributorRosterPosition,
        developmentKeyOnly: false,
        encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash: statement.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash,
        encryptedAggregateInputRoot,
        encryptedAggregateReconstructionHash,
        encryptedAggregateShareCiphertextRoot:
            bridgeEncryptionEvidence.encryptedAggregateShareCiphertextRoot,
        encryptedAggregateTargetBasisRoot,
        heParamHash: requireProtocolHash(
            input.heParamHash,
            'HE parameter hash',
        ),
        manifestHash: statement.manifestHash,
        objectType: 'BridgeProofRecord',
        objectVersion: 1,
        pollSpecHash: statement.pollSpecHash,
        postVotingClosedContextHash: statement.postVotingClosedContextHash,
        participantCount: statement.participantCount,
        optionCount: statement.optionCount,
        plaintextCoefficientBindingCommitmentHash:
            bridgeEncryptionEvidence.plaintextCoefficientBindingCommitmentHash,
        proofBackend: 'SealedLatticeBridgeRelation',
        proofBytesHash: bridgeEncryptionEvidence.bridgeProofBytesHash,
        proofEncodingProfileHash,
        proofParameterSetHash,
        proofRoot: bridgeEncryptionEvidence.bridgeProofRoot,
        proofSizeBytes: bridgeProofByteLength(
            bridgeEncryptionEvidence.bridgeProofBytesHex,
        ),
        proofFriendlyPlaintextLiftBindingHash:
            bridgeEncryptionEvidence.proofFriendlyPlaintextLiftBindingHash,
        proofStatementHash: expectedBridgeProofStatementHash,
        proverRandomnessSource: bridgeEncryptionEvidence.proverRandomnessSource,
        publicRandomnessHash,
        encryptionRandomnessSeedSource:
            bridgeEncryptionEvidence.encryptionRandomnessSeedSource,
        randomnessSourceEvidence:
            bridgeEncryptionEvidence.randomnessSourceEvidence,
        rosterHash: statement.rosterHash,
        rustBgvBackendProfileHash,
        setupPackageHash: requireProtocolHash(
            input.setupPackage.setupPackageHash,
            'setup package hash',
        ),
        shareCommitmentMessageBoundCertHash:
            statement.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: statement.shareVectorWidth,
        thresholdProfileHash: statement.thresholdProfileHash,
        thresholdDecryptable: true,
        topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: statement.votingClosedBoardHeadHash,
    };

    return {
        ...bridgeProofRecordPayload,
        bridgeProofRecordHash: deriveBridgeProofRecordHash(
            bridgeProofRecordPayload,
        ),
    };
};
